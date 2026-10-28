#!/usr/bin/env python3
"""Head-to-head evaluation on the seeded targets (PRD section 9).

    backend/.venv/bin/python eval/run.py            # writes eval/results.md and results.json
    backend/.venv/bin/python eval/run.py --no-early # skip the commit-hook timing

For every app in targets/ (see targets/README.md) it runs Bandit, default
Semgrep and ZeroDay Sentinel, matches their findings to truth.json (same file
and CWE, line within ±2), and reports caught, missed and precision, split into
wrapper and direct bugs. It adds an ablation and early-detection numbers:
for each app, a commit that adds the routes on top of already-committed
helpers is run through the real pre-commit hook.

Scanning is static: no target app is ever imported or run.
"""

import argparse
import io
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))
# Find bandit/semgrep installed next to this interpreter (the backend venv).
os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
os.environ.setdefault("SENTINEL_RULES", str(BACKEND / "sentinel-rules.toml"))

from app.detect.adapters import BanditDetector, SemgrepDetector  # noqa: E402
from app.detect.registry import use_detectors  # noqa: E402
from app.detect.taint import TaintDetector  # noqa: E402
from app.ingest.filter import filter_project  # noqa: E402
from app.pipeline import build_findings, run_detectors  # noqa: E402
from app.rank.model import load_model  # noqa: E402
from app.rank.train import match_truth  # noqa: E402
from app.rank.truth import load_truth  # noqa: E402

BLOCK_THRESHOLD = 7.0
TIMEOUT_S = 120.0


@dataclass
class AppScore:
    truth: int = 0
    caught: int = 0
    extra: int = 0
    extra_blocking: int = 0
    wrapper_total: int = 0
    wrapper_caught: int = 0
    direct_total: int = 0
    direct_caught: int = 0
    seconds: float = 0.0
    missed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class ToolScore:
    name: str
    available: bool
    note: str = ""
    apps: dict[str, AppScore] = field(default_factory=dict)

    def total(self, attr: str) -> float:
        return sum(getattr(a, attr) for a in self.apps.values())

    @property
    def precision(self) -> float | None:
        reported = self.total("caught") + self.total("extra")
        return self.total("caught") / reported if reported else None

    @property
    def recall(self) -> float | None:
        truth = self.total("truth")
        return self.total("caught") / truth if truth else None


def default_tools() -> list[tuple[str, list]]:
    return [
        ("Bandit", [BanditDetector()]),
        (f"Semgrep ({SemgrepDetector().config} rules)", [SemgrepDetector()]),
        ("ZeroDay Sentinel (taint)", [TaintDetector()]),
    ]


def target_apps(targets: Path) -> list[Path]:
    return sorted(p.parent for p in targets.glob("*/truth.json"))


def score_app(app_dir: Path, detectors: list) -> AppScore:
    truth = load_truth(app_dir)
    files = filter_project(app_dir, 2 * 1024 * 1024).files
    started = time.perf_counter()
    candidates, notes = run_detectors(app_dir, files, detectors, TIMEOUT_S, context_files=files)
    findings = [f.model_dump(mode="json")
                for f in build_findings("S-00000000", candidates, started=time.monotonic())]
    seconds = time.perf_counter() - started

    matches = match_truth(findings, truth)
    caught = {id(m) for m in matches if m is not None}
    score = AppScore(truth=len(truth), seconds=round(seconds, 3), errors=notes)
    for t in truth:
        hit = id(t) in caught
        kind = t.get("kind", "wrapper")
        if kind == "direct":
            score.direct_total += 1
            score.direct_caught += hit
        else:
            score.wrapper_total += 1
            score.wrapper_caught += hit
        if hit:
            score.caught += 1
        else:
            score.missed.append(f"{t['file']}:{t['line']} {t['cwe']} ({kind})")
    for f, m in zip(findings, matches):
        if m is None:
            score.extra += 1
            score.extra_blocking += f["severity"] >= BLOCK_THRESHOLD
    return score


def evaluate(apps: list[Path], tools: list[tuple[str, list]]) -> list[ToolScore]:
    results = []
    for name, detectors in tools:
        missing = [d.name for d in detectors if not d.available()]
        tool = ToolScore(name, available=not missing,
                         note=f"{', '.join(missing)} not installed" if missing else "")
        if tool.available:
            for app_dir in apps:
                tool.apps[app_dir.name] = score_app(app_dir, detectors)
        results.append(tool)
    return results


# --- early detection ----------------------------------------------------------

def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def early_detection(app_dir: Path, route_file: str = "app.py") -> dict | None:
    """Commit everything except the routes, then stage the routes and run the hook."""
    from app.early import hook
    if not (app_dir / route_file).exists():
        return None
    with tempfile.TemporaryDirectory(prefix="sentinel-eval-") as tmp:
        repo = Path(tmp)
        _git(repo, "init", "-q", "-b", "main")
        for key, value in (("user.email", "eval@example.com"), ("user.name", "eval"),
                           ("commit.gpgsign", "false")):
            _git(repo, "config", key, value)
        for path in app_dir.rglob("*.py"):
            rel = path.relative_to(app_dir)
            if rel.as_posix() != route_file:
                (repo / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, repo / rel)
        (repo / ".keep").write_text("")
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", "helpers")
        shutil.copy2(app_dir / route_file, repo / route_file)
        _git(repo, "add", route_file)

        out, err = io.StringIO(), io.StringIO()
        with use_detectors([TaintDetector()]), redirect_stdout(out), redirect_stderr(err):
            started = time.perf_counter()
            code = hook.main(["--repo", str(repo), "--no-cache"])
            seconds = time.perf_counter() - started
    return {"app": app_dir.name, "blocked": code == 1, "seconds": round(seconds, 3),
            "blocking_findings": out.getvalue().count("BLOCK ")}


# --- report -------------------------------------------------------------------

def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _ratio(num: float, den: float) -> str:
    return f"{int(num)}/{int(den)}" if den else "-"


def render(apps: list[Path], tools: list[ToolScore], ablation: list[ToolScore],
           early: list[dict]) -> str:
    ran = [t for t in tools if t.available]
    ref = ran[0] if ran else None
    total = int(ref.total("truth")) if ref else 0
    wrappers = int(ref.total("wrapper_total")) if ref else 0
    lines = [
        "# ZeroDay Sentinel evaluation",
        "",
        f"Seeded targets: {len(apps)} apps, {total} bugs ({wrappers} through project helpers, "
        f"{total - wrappers} direct). Generated {time.strftime('%Y-%m-%d %H:%M')} by `eval/run.py`.",
        "",
        "## Head-to-head",
        "",
        "| Tool | Caught | Recall | Wrapper bugs | Direct bugs | Extra findings "
        f"| Precision | Extra at severity ≥ {BLOCK_THRESHOLD:g} | Scan time |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for t in tools:
        if not t.available:
            lines.append(f"| {t.name} | not run ({t.note}) | | | | | | | |")
            continue
        lines.append(
            f"| {t.name} | {_ratio(t.total('caught'), t.total('truth'))} | {_pct(t.recall)} "
            f"| {_ratio(t.total('wrapper_caught'), t.total('wrapper_total'))} "
            f"| {_ratio(t.total('direct_caught'), t.total('direct_total'))} "
            f"| {int(t.total('extra'))} | {_pct(t.precision)} | {int(t.total('extra_blocking'))} "
            f"| {t.total('seconds'):.2f}s |")

    lines += ["", "## Per app", "",
              "| App | Bugs | " + " | ".join(t.name for t in ran) + " |",
              "|---|---|" + "---|" * len(ran)]
    for app_dir in apps:
        name = app_dir.name
        bugs = ref.apps[name].truth if ref else 0
        cells = [_ratio(t.apps[name].caught, t.apps[name].truth) for t in ran]
        lines.append(f"| {name} | {bugs} | " + " | ".join(cells) + " |")

    lines += ["", "## Missed bugs", ""]
    for t in ran:
        missed = [f"{app}/{m}" for app, a in t.apps.items() for m in a.missed]
        lines.append(f"- **{t.name}:** " + (", ".join(missed) if missed else "none"))
    errors = [f"{t.name} on {app}: {e}" for t in ran for app, a in t.apps.items() for e in a.errors]
    if errors:
        lines += ["", "Detector errors:"] + [f"- {e}" for e in errors]

    model, model_status = load_model()
    lines += ["", "## Ablation", "", "| Configuration | Caught | Precision | Note |", "|---|---|---|---|"]
    for t in ablation:
        if t.available:
            lines.append(f"| {t.name} | {_ratio(t.total('caught'), t.total('truth'))} "
                         f"| {_pct(t.precision)} | |")
        else:
            lines.append(f"| {t.name} | not run | | {t.note} |")
    ranked = (model.meta.get("metrics", {}) if model else {}) or {}
    if ranked.get("false_positives_baseline") is not None:
        ranker_note = (f"Reorders findings, does not add or remove them. On held-out apps, false "
                       f"positives read before {_pct(ranked['recall_target'])} recall: "
                       f"{ranked['false_positives_baseline']} -> {ranked['false_positives_model']} "
                       f"({_pct(ranked['false_positive_reduction'])} fewer); {model_status}")
    else:
        ranker_note = f"Reorders findings, does not add or remove them. Ranker: {model_status}"
    lines.append(f"| Taint + ML ranker | same as taint | same as taint | {ranker_note} |")
    lines.append("| Taint + proof runner | | | Not built yet |")

    if early:
        times = [e["seconds"] for e in early]
        blocked = sum(e["blocked"] for e in early)
        lines += ["", "## Early detection (pre-commit hook)", "",
                  "Each app: helpers committed first, then a commit adding the routes, run through "
                  "the real hook with the taint detector.", "",
                  "| App | Commit blocked | Hook time |", "|---|---|---|"]
        lines += [f"| {e['app']} | {'yes' if e['blocked'] else 'no'} | {e['seconds']:.2f}s |"
                  for e in early]
        lines += ["", f"Vulnerable commits blocked before merge: {blocked}/{len(early)} "
                      f"({_pct(blocked / len(early))}). Median hook time: "
                      f"{statistics.median(times):.2f}s."]

    lines += [
        "", "## Caveats", "",
        f"- Small sample: {len(apps)} apps and {total} seeded bugs. These numbers are indicative, "
        "not conclusive.",
        "- The targets were written by our own team, with the bug classes our rules cover. "
        "Results on real-world code will be lower.",
        "- A finding matches a seeded bug when file and CWE agree and the line is within ±2. "
        "Anything else counts as an extra finding, including low-severity reports of the safe "
        "decoys.",
        "- Semgrep uses its public registry ruleset (`p/python` unless SENTINEL_SEMGREP_CONFIG is "
        "set), downloaded at run time with metrics off. `--config auto` is not used because it "
        "requires sending metrics.",
    ]
    lines += [f"- {t.name} was not run: {t.note}." for t in tools if not t.available]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="eval/run.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--targets", type=Path, default=REPO / "targets")
    p.add_argument("--out", type=Path, default=REPO / "eval" / "results.md")
    p.add_argument("--no-early", action="store_true", help="skip the commit-hook timing")
    args = p.parse_args(argv)

    apps = target_apps(args.targets)
    if not apps:
        print(f"no targets with truth.json under {args.targets}", file=sys.stderr)
        return 1
    tools = evaluate(apps, default_tools())
    ablation = evaluate(apps, [
        ("Rules only (Bandit)", [BanditDetector()]),
        ("Taint only", [TaintDetector()]),
        ("Rules + taint", [BanditDetector(), TaintDetector()]),
    ])
    early = [] if args.no_early else [e for a in apps if (e := early_detection(a))]

    report = render(apps, tools, ablation, early)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)
    args.out.with_suffix(".json").write_text(json.dumps({
        "apps": [a.name for a in apps],
        "tools": [asdict(t) | {"precision": t.precision, "recall": t.recall} for t in tools],
        "ablation": [asdict(t) | {"precision": t.precision, "recall": t.recall} for t in ablation],
        "early_detection": early,
    }, indent=2) + "\n")
    print(report)
    shown = args.out.resolve()
    shown = shown.relative_to(REPO) if shown.is_relative_to(REPO) else shown
    print(f"wrote {shown} and {shown.with_suffix('.json')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
