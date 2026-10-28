#!/usr/bin/env python3
"""Head-to-head evaluation on the seeded targets (PRD section 9).

    backend/.venv/bin/python eval/run.py            # writes eval/results.md and results.json
    backend/.venv/bin/python eval/run.py --no-early # skip the commit-hook timing

For every app in targets/ (see targets/README.md) it runs Bandit, default
Semgrep and Kavach, matches their findings to truth.json (same file
and CWE, line within ±2), and reports caught, missed and precision, split into
wrapper and direct bugs. It adds:
- an ablation over detector combinations, up to the full Kavach setup;
- the patch suggester: a patch per seeded bug, checked by Kavach's re-trace, then
  applied to a copy and re-scanned by every detector;
- the secrets and weak-crypto rule layer on the labelled cases in eval/rules_corpus/,
  plus how often each tool reports those problems in our own real code;
- early detection: for each app, a commit that adds the routes on top of
  already-committed helpers is run through the real pre-commit hook.

Scanning is static: no target app or benchmark file is ever imported or run.
"""

import argparse
import io
import json
import os
import re
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
from app.detect.rules import RulesDetector  # noqa: E402
from app.detect.taint import TaintDetector  # noqa: E402
from app.fix.patch import suggest_patch  # noqa: E402
from app.fix.verify import verify  # noqa: E402
from app.ingest.filter import filter_project  # noqa: E402
from app.pipeline import build_findings, run_detectors  # noqa: E402
from app.rank.model import load_model  # noqa: E402
from app.rank.train import match_truth  # noqa: E402
from app.rank.truth import load_truth  # noqa: E402

BLOCK_THRESHOLD = 7.0
TIMEOUT_S = 120.0
CORPUS = REPO / "eval" / "rules_corpus"
OWN_CODE = [BACKEND / "app", REPO / "telemetry", REPO / "demo"]  # real code with no secrets or weak crypto
# Tools number the same problem differently: Bandit calls every hard-coded secret CWE-259.
SAME_PROBLEM = {"CWE-259": "CWE-798", "CWE-328": "CWE-327"}
RULE_CWES = ("CWE-798", "CWE-327", "CWE-916", "CWE-326", "CWE-295", "CWE-330")
_EXPECT = re.compile(r"#\s*expect\s+(CWE-\d+)")
_DECOY = re.compile(r"#\s*decoy\b")


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
        ("Kavach (taint)", [TaintDetector()]),
    ]


def full_suite() -> list:
    """Every detector, as a real Kavach scan runs them."""
    return [TaintDetector(), RulesDetector(), BanditDetector(), SemgrepDetector()]


def ablation_tools() -> list[tuple[str, list]]:
    return [
        ("Pattern rules only (Bandit)", [BanditDetector()]),
        ("Taint only", [TaintDetector()]),
        ("Pattern rules + taint", [BanditDetector(), TaintDetector()]),
        ("Kavach engines (taint + rule layer)", [TaintDetector(), RulesDetector()]),
        ("Full Kavach (taint + rule layer + Bandit + Semgrep)", full_suite()),
    ]


def target_apps(targets: Path) -> list[Path]:
    return sorted(p.parent for p in targets.glob("*/truth.json"))


def scan_dir(root: Path, detectors: list, files: list[str] | None = None) -> tuple[list[dict], list[str], float]:
    """Findings (as dicts) for one folder, the detectors' notes, and the seconds it took."""
    files = files if files is not None else filter_project(root, 2 * 1024 * 1024).files
    started = time.perf_counter()
    candidates, notes = run_detectors(root, files, detectors, TIMEOUT_S, context_files=files)
    findings = [f.model_dump(mode="json")
                for f in build_findings("S-00000000", candidates, started=time.monotonic())]
    return findings, notes, time.perf_counter() - started


def score_app(app_dir: Path, detectors: list) -> AppScore:
    truth = load_truth(app_dir)
    findings, notes, seconds = scan_dir(app_dir, detectors)

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


# --- patch suggester ----------------------------------------------------------

def _same_problem(cwe: str) -> str:
    return SAME_PROBLEM.get(cwe, cwe)


def rescan_patched(app_dir: Path, file: str, patched: str, cwe: str, changed: list[int], detectors: list) -> dict:
    """Apply a patch to a copy of the app and re-scan it: what is still reported at the patched lines."""
    with tempfile.TemporaryDirectory(prefix="kavach-patch-") as tmp:
        copy = Path(tmp) / app_dir.name
        shutil.copytree(app_dir, copy)
        (copy / file).write_text(patched)
        findings, _, _ = scan_dir(copy, detectors)
    left = [f for f in findings if f["file"] == file and _same_problem(f["cwe"]) == _same_problem(cwe)
            and f["line"] in changed]
    return {"left": len(left), "left_serious": sum(f["severity"] >= BLOCK_THRESHOLD for f in left),
            "left_max_severity": max((f["severity"] for f in left), default=0.0),
            "left_by": sorted({d for f in left for d in f["detector"].split("+")})}


def patch_eval(apps: list[Path]) -> list[dict]:
    """For every seeded bug: is there a patch, does Kavach's re-trace confirm it, and what does a
    full re-scan of the patched copy still report? A static stand-in for the patch re-test."""
    detectors = [d for d in full_suite() if d.available()]
    rows = []
    for app_dir in apps:
        sources = {p.relative_to(app_dir).as_posix(): p.read_text() for p in app_dir.rglob("*.py")}
        for bug in load_truth(app_dir):
            patch = suggest_patch(sources[bug["file"]], bug["file"], bug["line"], bug["cwe"])
            row = {"app": app_dir.name, "bug": f"{bug['file']}:{bug['line']} {bug['cwe']}",
                   "kind": bug.get("kind", "wrapper"), "patched": patch.available, "title": patch.title,
                   "reason": patch.reason, "confirmed": False}
            if patch.available:
                check = verify(sources, bug["file"], patch.patched_source, bug["cwe"], patch.changed_lines)
                row["confirmed"] = check.status == "fixed"
                row |= rescan_patched(app_dir, bug["file"], patch.patched_source, bug["cwe"],
                                      patch.changed_lines, detectors)
            rows.append(row)
    return rows


# --- secrets and weak crypto (rule layer) ---------------------------------------

@dataclass
class CorpusScore:
    name: str
    available: bool
    note: str = ""
    expected: int = 0
    caught: int = 0
    decoys: int = 0
    decoys_flagged: int = 0
    extra: int = 0
    seconds: float = 0.0
    by_cwe: dict[str, list[int]] = field(default_factory=dict)  # CWE -> [caught, cases]
    missed: list[str] = field(default_factory=list)
    own_code_reports: int = 0  # reports of these CWEs on our own real code

    @property
    def precision(self) -> float | None:
        reported = self.caught + self.extra
        return self.caught / reported if reported else None

    @property
    def recall(self) -> float | None:
        return self.caught / self.expected if self.expected else None


def corpus_labels(root: Path) -> tuple[list[dict], set[tuple[str, int]]]:
    """Expected findings and decoy lines, read from `# expect CWE-n` / `# decoy` comments."""
    expected, decoys = [], set()
    for path in sorted(root.glob("*.py")):
        for no, text in enumerate(path.read_text().splitlines(), start=1):
            if m := _EXPECT.search(text):
                expected.append({"file": path.name, "line": no, "cwe": m[1]})
            elif _DECOY.search(text):
                decoys.add((path.name, no))
    return expected, decoys


def _rule_findings(findings: list[dict]) -> list[dict]:
    """Only reports about secrets and crypto, with each tool's CWE number for them made the same."""
    out = [f | {"cwe": _same_problem(f["cwe"])} for f in findings]
    return [f for f in out if f["cwe"] in RULE_CWES]


def score_corpus(name: str, detectors: list, root: Path = CORPUS) -> CorpusScore:
    missing = [d.name for d in detectors if not d.available()]
    score = CorpusScore(name, available=not missing, note=f"{', '.join(missing)} not installed" if missing else "")
    if missing:
        return score
    expected, decoys = corpus_labels(root)
    findings, _, seconds = scan_dir(root, detectors, sorted(p.name for p in root.glob("*.py")))
    findings = _rule_findings(findings)
    matches = match_truth(findings, expected, tolerance=0)
    hit = {id(m) for m in matches if m is not None}
    score.expected, score.decoys, score.seconds = len(expected), len(decoys), round(seconds, 3)
    for t in expected:
        cell = score.by_cwe.setdefault(t["cwe"], [0, 0])
        cell[1] += 1
        if id(t) in hit:
            cell[0] += 1
            score.caught += 1
        else:
            score.missed.append(f"{t['file']}:{t['line']} {t['cwe']}")
    unmatched = [f for f, m in zip(findings, matches) if m is None]
    score.extra = len(unmatched)
    score.decoys_flagged = len({(f["file"], f["line"]) for f in unmatched} & decoys)
    score.own_code_reports = sum(len(_rule_findings(scan_dir(d, detectors)[0])) for d in OWN_CODE if d.exists())
    return score


def rule_patch_eval(root: Path = CORPUS) -> dict:
    """Patches for the labelled secrets / crypto cases: how many get one, and how many the re-check confirms."""
    expected, _ = corpus_labels(root)
    patched = confirmed = 0
    for case in expected:
        source = (root / case["file"]).read_text()
        patch = suggest_patch(source, case["file"], case["line"], case["cwe"])
        if patch.available:
            patched += 1
            confirmed += verify({case["file"]: source}, case["file"], patch.patched_source, case["cwe"],
                                patch.changed_lines, case["line"]).status == "fixed"
    return {"cases": len(expected), "patched": patched, "confirmed": confirmed}


def corpus_eval() -> list[CorpusScore]:
    return [score_corpus("Kavach rule layer", [RulesDetector()]),
            score_corpus("Bandit", [BanditDetector()]),
            score_corpus(f"Semgrep ({SemgrepDetector().config} rules)", [SemgrepDetector()])]


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


def render_patches(rows: list[dict]) -> list[str]:
    if not rows:
        return []
    patched = [r for r in rows if r["patched"]]
    confirmed = sum(r["confirmed"] for r in rows)
    serious = sum(r.get("left_serious", 0) for r in patched)
    notes = [r for r in patched if r.get("left") and not r.get("left_serious")]
    lines = ["", "## Patch suggester", "",
             "For each seeded bug: the suggested patch, Kavach's whole-project re-trace of it, and a re-scan of "
             "a patched copy of the app by every detector (taint, rule layer, Bandit, Semgrep). This is a static "
             "re-test; no code is run.", "",
             "| Bug | Patch | Re-trace | Left at the patched lines after a full re-scan |", "|---|---|---|---|"]
    for r in rows:
        if not r["patched"]:
            lines.append(f"| {r['app']}/{r['bug']} | none: {r['reason']} | | |")
            continue
        if not r["left"]:
            after = "nothing"
        else:
            after = (f"{r['left']} report(s), highest severity {r['left_max_severity']:.1f} "
                     f"({', '.join(r['left_by'])})")
        lines.append(f"| {r['app']}/{r['bug']} | {r['title']} | {'fixed' if r['confirmed'] else 'not confirmed'} "
                     f"| {after} |")
    lines += ["", f"Patches written: {len(patched)}/{len(rows)}. Confirmed fixed by the re-trace: "
                  f"{confirmed}/{len(rows)}. Serious reports (severity ≥ {BLOCK_THRESHOLD:g}) left after "
                  f"patching: {serious}."]
    if notes:
        tools = sorted({d for r in notes for d in r["left_by"]})
        lines.append(f"Lower-severity reports left on {len(notes)} patched line(s), none serious, from "
                     f"{', '.join(tools)}: pattern tools that flag any use of a call, safe or not (for "
                     "example Bandit's general warning on every subprocess call).")
    return lines


def render_corpus(scores: list[CorpusScore], rule_patches: dict | None = None) -> list[str]:
    ran = [s for s in scores if s.available]
    if not ran:
        return []
    ref = ran[0]
    lines = ["", "## Secrets and weak crypto (rule layer)", "",
             f"Labelled cases in `eval/rules_corpus/`: {ref.expected} problems to find and {ref.decoys} decoys "
             "that look similar but are fine. Matching is on the exact line; tools that number a problem "
             "differently (Bandit calls every secret CWE-259) are counted as the same problem.", "",
             "| Tool | Caught | Recall | Decoys flagged | Extra reports | Precision | Reports on our own real code "
             "| Scan time |", "|---|---|---|---|---|---|---|---|"]
    for s in scores:
        if not s.available:
            lines.append(f"| {s.name} | not run ({s.note}) | | | | | | |")
            continue
        lines.append(f"| {s.name} | {s.caught}/{s.expected} | {_pct(s.recall)} | {s.decoys_flagged}/{s.decoys} "
                     f"| {s.extra} | {_pct(s.precision)} | {s.own_code_reports} | {s.seconds:.2f}s |")
    lines += ["", "| Problem | Cases | " + " | ".join(s.name for s in ran) + " |", "|---|---|" + "---|" * len(ran)]
    from app.report.owasp import title_for
    for cwe in RULE_CWES:
        if cwe in ref.by_cwe:
            cells = [f"{s.by_cwe.get(cwe, [0, 0])[0]}/{s.by_cwe.get(cwe, [0, 0])[1]}" for s in ran]
            lines.append(f"| {title_for(cwe)} ({cwe}) | {ref.by_cwe[cwe][1]} | " + " | ".join(cells) + " |")
    lines += ["", "Our own real code is " + ", ".join(f"`{d.relative_to(REPO).as_posix()}`" for d in OWN_CODE
                                                     if d.exists())
              + ": it has no hard-coded secrets or weak crypto, so reports there are noise."]
    lines += [f"- Missed by {s.name}: " + ", ".join(s.missed) for s in ran if s.missed]
    if rule_patches:
        lines += ["", f"Patches for these cases: {rule_patches['patched']}/{rule_patches['cases']} get one, "
                      f"{rule_patches['confirmed']} confirmed by re-reading the patched file. The rest are "
                      "advice-only on purpose: a new cipher, a slow password hash or a hard-coded password check "
                      "changes stored data or needs a design decision."]
    return lines


def render(apps: list[Path], tools: list[ToolScore], ablation: list[ToolScore],
           early: list[dict], patches: list[dict] | None = None, corpus: list[CorpusScore] | None = None,
           rule_patches: dict | None = None) -> str:
    ran = [t for t in tools if t.available]
    ref = ran[0] if ran else None
    total = int(ref.total("truth")) if ref else 0
    wrappers = int(ref.total("wrapper_total")) if ref else 0
    lines = [
        "# Kavach evaluation",
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
    lines += ["", "## Ablation", "",
              "Seeded bugs only. Extra reports include low-severity notes; none of them would block a commit "
              f"unless the last column says so.", "",
              f"| Configuration | Caught | Wrapper bugs | Precision | Extra reports | Extra at severity ≥ "
              f"{BLOCK_THRESHOLD:g} | Note |", "|---|---|---|---|---|---|---|"]
    for t in ablation:
        if t.available:
            lines.append(f"| {t.name} | {_ratio(t.total('caught'), t.total('truth'))} "
                         f"| {_ratio(t.total('wrapper_caught'), t.total('wrapper_total'))} "
                         f"| {_pct(t.precision)} | {int(t.total('extra'))} | {int(t.total('extra_blocking'))} | |")
        else:
            lines.append(f"| {t.name} | not run | | | | | {t.note} |")
    ranked = (model.meta.get("metrics", {}) if model else {}) or {}
    if ranked.get("false_positives_baseline") is not None:
        ranker_note = (f"Reorders findings, does not add or remove them. On held-out apps, false "
                       f"positives read before {_pct(ranked['recall_target'])} recall: "
                       f"{ranked['false_positives_baseline']} -> {ranked['false_positives_model']} "
                       f"({_pct(ranked['false_positive_reduction'])} fewer); {model_status}")
    else:
        ranker_note = f"Reorders findings, does not add or remove them. Ranker: {model_status}"
    lines.append(f"| + ML ranker | same | same | same | same | same | {ranker_note} |")
    lines.append("| + patch suggester | same | same | same | same | same | Adds a checked fix per finding; "
                 "see Patch suggester below. |")
    lines.append("| + proof runner | | | | | | Not built: planned as a sandboxed check with no network. "
                 "Patches are re-tested statically instead (below). |")
    lines += render_patches(patches or [])
    lines += render_corpus(corpus or [], rule_patches)

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
        "- The secrets and crypto cases were written by our team to cover what the rule layer checks, "
        "so they favour it. The 'own real code' column is the fairer comparison of noise.",
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
    p.add_argument("--no-patches", action="store_true", help="skip patching and re-scanning each seeded bug")
    p.add_argument("--no-corpus", action="store_true", help="skip the secrets and weak-crypto cases")
    args = p.parse_args(argv)

    apps = target_apps(args.targets)
    if not apps:
        print(f"no targets with truth.json under {args.targets}", file=sys.stderr)
        return 1
    tools = evaluate(apps, default_tools())
    ablation = evaluate(apps, ablation_tools())
    patches = [] if args.no_patches else patch_eval(apps)
    corpus = [] if args.no_corpus or not CORPUS.exists() else corpus_eval()
    rule_patches = rule_patch_eval() if corpus and not args.no_patches else None
    early = [] if args.no_early else [e for a in apps if (e := early_detection(a))]

    report = render(apps, tools, ablation, early, patches, corpus, rule_patches)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)
    args.out.with_suffix(".json").write_text(json.dumps({
        "apps": [a.name for a in apps],
        "tools": [asdict(t) | {"precision": t.precision, "recall": t.recall} for t in tools],
        "ablation": [asdict(t) | {"precision": t.precision, "recall": t.recall} for t in ablation],
        "patches": patches,
        "rule_layer": [asdict(c) | {"precision": c.precision, "recall": c.recall} for c in corpus],
        "rule_layer_patches": rule_patches,
        "early_detection": early,
    }, indent=2) + "\n")
    print(report)
    shown = args.out.resolve()
    shown = shown.relative_to(REPO) if shown.is_relative_to(REPO) else shown
    print(f"wrote {shown} and {shown.with_suffix('.json')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
