"""Train and evaluate the ML ranker (needs the `ml` extra: scikit-learn).

    # 1. Label a scan's findings against a target app's ground truth
    python -m app.rank.train label --report scan.json --truth truth.json --project app1 >> labeled.jsonl

    # 2. Train with project-level cross-validation, write JSON weights
    python -m app.rank.train fit --data labeled.jsonl --out sentinel-model.json

    # Or both at once for every app in targets/ (taint, Bandit and Semgrep if installed)
    python -m app.rank.train targets --out sentinel-model.json

labeled.jsonl: one {"project": str, "label": 0|1, "finding": {...Finding fields...}} per line.
truth.json:    [{"file": "app/routes.py", "line": 42, "cwe": "CWE-78"}, ...]

Evaluation holds out whole projects (GroupKFold), so the reported numbers are
on projects the model never saw. "False-positive reduction" compares how many
false positives a reviewer must read to reach a target recall when findings are
ordered by the model versus by detector confidence alone.
"""

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path

from app.rank.features import FEATURES, extract
from app.rank.model import LinearModel

BASELINE_FEATURE = FEATURES.index("detector_confidence")
LINE_TOLERANCE = 2


@dataclass(frozen=True)
class Dataset:
    X: list[list[float]]
    y: list[int]
    groups: list[str]

    @property
    def projects(self) -> int:
        return len(set(self.groups))


# --- labelling ---------------------------------------------------------------

def match_truth(findings: list[dict], truth: list[dict],
                tolerance: int = LINE_TOLERANCE) -> list[dict | None]:
    """The ground-truth bug each finding matches (same file and CWE, line within
    tolerance), or None.

    Closest pairs are matched first, so a finding on the exact line wins over a
    neighbour. Each bug is claimed by at most one finding, so duplicate reports
    of the same bug count as false positives.
    """
    pairs = []
    for i, f in enumerate(findings):
        for j, t in enumerate(truth):
            if t.get("file") == f.get("file") and t.get("cwe") == f.get("cwe"):
                distance = abs(int(t.get("line", 0)) - int(f.get("line", 0)))
                if distance <= tolerance:
                    pairs.append((distance, i, j))
    matches: list[dict | None] = [None] * len(findings)
    claimed: set[int] = set()
    for _, i, j in sorted(pairs):
        if matches[i] is None and j not in claimed:
            matches[i] = truth[j]
            claimed.add(j)
    return matches


def label_findings(findings: list[dict], truth: list[dict],
                   tolerance: int = LINE_TOLERANCE) -> list[int]:
    """1 if a finding matches a ground-truth bug, else 0 (see match_truth)."""
    return [int(m is not None) for m in match_truth(findings, truth, tolerance)]


def load_dataset(path: Path) -> Dataset:
    X, y, groups = [], [], []
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("label") not in (0, 1) or not isinstance(row.get("finding"), dict) \
                or not row.get("project"):
            raise ValueError(f"{path}:{n}: needs 'project', 'label' (0 or 1) and 'finding'")
        X.append(extract(row["finding"]))
        y.append(int(row["label"]))
        groups.append(str(row["project"]))
    return Dataset(X, y, groups)


# --- metrics -----------------------------------------------------------------

def false_positives_at_recall(scores: list[float], labels: list[int], recall: float) -> int | None:
    """FPs read, in score order, before `recall` of the true issues are found."""
    positives = sum(labels)
    if positives == 0:
        return None
    needed = math.ceil(recall * positives)
    found = fps = 0
    for _, label in sorted(zip(scores, labels), key=lambda p: -p[0]):
        if label:
            found += 1
            if found >= needed:
                return fps
        else:
            fps += 1
    return fps


def precision_at_k(scores: list[float], labels: list[int], k: int) -> float | None:
    if k <= 0:
        return None
    top = sorted(zip(scores, labels), key=lambda p: -p[0])[:k]
    return sum(label for _, label in top) / len(top)


def _pipeline():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return make_pipeline(StandardScaler(),
                         LogisticRegression(class_weight="balanced", max_iter=1000))


def cross_validate(data: Dataset, recall: float = 0.9) -> dict:
    """Out-of-fold scores with whole projects held out, compared with the baseline."""
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupKFold

    if data.projects < 2:
        raise ValueError("need findings from at least 2 projects for a project-level split")
    oof: list[float | None] = [None] * len(data.y)
    skipped = 0
    for train_idx, test_idx in GroupKFold(n_splits=min(5, data.projects)).split(
            data.X, data.y, data.groups):
        y_train = [data.y[i] for i in train_idx]
        if len(set(y_train)) < 2:
            skipped += 1
            continue
        model = _pipeline().fit([data.X[i] for i in train_idx], y_train)
        for i, p in zip(test_idx, model.predict_proba([data.X[i] for i in test_idx])[:, 1]):
            oof[i] = float(p)

    kept = [i for i, p in enumerate(oof) if p is not None]
    labels = [data.y[i] for i in kept]
    model_scores = [oof[i] for i in kept]
    base_scores = [data.X[i][BASELINE_FEATURE] for i in kept]
    fp_model = false_positives_at_recall(model_scores, labels, recall)
    fp_base = false_positives_at_recall(base_scores, labels, recall)
    both_classes = len(set(labels)) == 2
    return {
        "projects": data.projects,
        "findings": len(data.y),
        "evaluated_findings": len(kept),
        "real_issues": sum(labels),
        "skipped_folds": skipped,
        "recall_target": recall,
        "auc_model": round(roc_auc_score(labels, model_scores), 3) if both_classes else None,
        "auc_baseline": round(roc_auc_score(labels, base_scores), 3) if both_classes else None,
        "false_positives_model": fp_model,
        "false_positives_baseline": fp_base,
        "false_positive_reduction": (round(1 - fp_model / fp_base, 3)
                                     if fp_model is not None and fp_base else None),
        "precision_at_k_model": precision_at_k(model_scores, labels, sum(labels)),
        "precision_at_k_baseline": precision_at_k(base_scores, labels, sum(labels)),
    }


def fit(data: Dataset, metrics: dict | None = None) -> LinearModel:
    """Train on all data and export the weights as a LinearModel."""
    pipe = _pipeline().fit(data.X, data.y)
    scaler, clf = pipe[0], pipe[-1]
    return LinearModel(
        mean=tuple(float(v) for v in scaler.mean_),
        scale=tuple(float(v) for v in scaler.scale_),
        coef=tuple(float(v) for v in clf.coef_[0]),
        intercept=float(clf.intercept_[0]),
        meta={"projects": data.projects, "findings": len(data.y),
              "real_issues": sum(data.y), "metrics": metrics or {}},
    )


# --- CLI ---------------------------------------------------------------------

def _report(metrics: dict) -> str:
    def pct(v):
        return "n/a" if v is None else f"{v:.0%}"
    lines = [
        f"Evaluated on held-out projects: {metrics['projects']} projects, "
        f"{metrics['evaluated_findings']} findings, {metrics['real_issues']} real issues.",
        f"To reach {pct(metrics['recall_target'])} recall a reviewer reads "
        f"{metrics['false_positives_model']} false positives with the model vs "
        f"{metrics['false_positives_baseline']} with detector confidence "
        f"(reduction {pct(metrics['false_positive_reduction'])}).",
        f"Precision@k: model {pct(metrics['precision_at_k_model'])}, "
        f"baseline {pct(metrics['precision_at_k_baseline'])}.  "
        f"AUC: model {metrics['auc_model']}, baseline {metrics['auc_baseline']}.",
    ]
    if metrics["projects"] < 10 or metrics["findings"] < 200:
        lines.append("Caveat: small sample. Treat these numbers as indicative, not conclusive.")
    if metrics["skipped_folds"]:
        lines.append(f"Note: {metrics['skipped_folds']} folds skipped (one class only in training).")
    return "\n".join(lines)


def _cmd_label(args) -> int:
    report = json.loads(args.report.read_text())
    findings = report["findings"] if isinstance(report, dict) else report
    truth = json.loads(args.truth.read_text())
    labels = label_findings(findings, truth)
    for finding, label in zip(findings, labels):
        print(json.dumps({"project": args.project, "label": label, "finding": finding}))
    matched = sum(labels)
    print(f"labelled {len(findings)} findings: {matched} real, "
          f"{len(truth) - matched} ground-truth bugs not found", file=sys.stderr)
    return 0


def label_targets(targets: Path, detectors: list) -> list[dict]:
    """Scan every app in `targets` (one with a truth.json) and label each finding."""
    import time
    from app.ingest.filter import filter_project
    from app.pipeline import build_findings, run_detectors
    from app.rank.truth import load_truth

    rows = []
    for truth_path in sorted(targets.glob("*/truth.json")):
        app_dir = truth_path.parent
        files = filter_project(app_dir, 2 * 1024 * 1024).files
        candidates, notes = run_detectors(app_dir, files, detectors, 120, context_files=files)
        for note in notes:
            print(f"{app_dir.name}: {note}", file=sys.stderr)
        findings = [f.model_dump(mode="json")
                    for f in build_findings("S-00000000", candidates, started=time.monotonic())]
        for finding, label in zip(findings, label_findings(findings, load_truth(app_dir))):
            rows.append({"project": app_dir.name, "label": label, "finding": finding})
    return rows


def _cmd_targets(args) -> int:
    from app.detect.adapters import BanditDetector, SemgrepDetector
    from app.detect.taint import TaintDetector

    wanted = {n.strip() for n in args.detectors.split(",") if n.strip()}
    detectors = [d for d in (TaintDetector(), BanditDetector(), SemgrepDetector())
                 if d.name in wanted and d.available()]
    if not detectors:
        raise ValueError(f"none of the detectors {sorted(wanted)} is available")
    print(f"detectors: {', '.join(d.name for d in detectors)}", file=sys.stderr)
    rows = label_targets(args.targets, detectors)
    if args.save_data:
        args.save_data.write_text("".join(json.dumps(r) + "\n" for r in rows))
    by_project: dict[str, list[int]] = {}
    for r in rows:
        by_project.setdefault(r["project"], []).append(r["label"])
    for name, labels in sorted(by_project.items()):
        print(f"{name}: {len(labels)} findings, {sum(labels)} real", file=sys.stderr)
    data = Dataset([extract(r["finding"]) for r in rows], [r["label"] for r in rows],
                   [r["project"] for r in rows])
    metrics = cross_validate(data, args.recall)
    print(_report(metrics))
    model = fit(data, metrics | {"detectors": [d.name for d in detectors]})
    args.out.write_text(json.dumps(model.to_dict(), indent=2) + "\n")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


def _cmd_fit(args) -> int:
    data = load_dataset(args.data)
    metrics = cross_validate(data, args.recall)
    print(_report(metrics))
    model = fit(data, metrics)
    args.out.write_text(json.dumps(model.to_dict(), indent=2) + "\n")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.rank.train")
    sub = p.add_subparsers(dest="command", required=True)
    lab = sub.add_parser("label", help="label a scan report against ground truth")
    lab.add_argument("--report", type=Path, required=True, help="JSON report or findings list")
    lab.add_argument("--truth", type=Path, required=True)
    lab.add_argument("--project", required=True)
    lab.set_defaults(func=_cmd_label)
    fitp = sub.add_parser("fit", help="cross-validate by project, then train and save")
    fitp.add_argument("--data", type=Path, required=True)
    fitp.add_argument("--out", type=Path, default=Path("sentinel-model.json"))
    fitp.add_argument("--recall", type=float, default=0.9)
    fitp.set_defaults(func=_cmd_fit)
    tgt = sub.add_parser("targets", help="scan targets/, label against truth.json, then fit")
    tgt.add_argument("--targets", type=Path, default=Path(__file__).resolve().parents[3] / "targets")
    tgt.add_argument("--out", type=Path, default=Path("sentinel-model.json"))
    tgt.add_argument("--recall", type=float, default=0.9)
    tgt.add_argument("--save-data", type=Path, help="also write the labelled rows as JSON lines")
    tgt.add_argument("--detectors", default="taint,bandit,semgrep",
                     help="comma-separated; unavailable ones are skipped (default: %(default)s)")
    tgt.set_defaults(func=_cmd_targets)
    args = p.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
    except json.JSONDecodeError as exc:
        print(f"error: not valid JSON ({exc})", file=sys.stderr)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
