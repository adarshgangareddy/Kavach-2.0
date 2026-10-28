"""Detection regression baseline for the seeded targets (targets/<app>/baseline.json).

The baseline records which ground-truth bugs the taint detector caught and how
many false positives it raised. tests/test_targets_regression.py re-scans each
target and fails if a previously caught bug is now missed or false positives
went up. Accept intentional changes with:

    cd backend && SENTINEL_UPDATE_BASELINE=1 .venv/bin/pytest tests/test_targets_regression.py

Only the taint detector is used: its results depend on our code and rules
alone, so the baseline does not move when Bandit or Semgrep are upgraded.
"""

import json
import time
from pathlib import Path

from app.detect.taint import TaintDetector
from app.ingest.filter import filter_project
from app.pipeline import build_findings
from app.rank.train import match_truth
from app.rank.truth import load_truth

BASELINE_NAME = "baseline.json"
MAX_FILE_BYTES = 2 * 1024 * 1024


def truth_key(entry: dict) -> str:
    return f"{entry['file']}:{entry['line']}:{entry['cwe']}"


def scan_target(app_dir: Path, rules_path: Path) -> list[dict]:
    files = filter_project(app_dir, MAX_FILE_BYTES).files
    candidates = TaintDetector(rules_path).scan(app_dir, files, timeout_s=60)
    findings = build_findings("S-00000000", candidates, started=time.monotonic())
    return [f.model_dump(mode="json") for f in findings]


def summarize(app_dir: Path, rules_path: Path) -> dict:
    truth = load_truth(app_dir)
    findings = scan_target(app_dir, rules_path)
    matches = match_truth(findings, truth)
    caught = sorted({truth_key(m) for m in matches if m is not None})
    return {
        "detector": "taint",
        "truth": len(truth),
        "caught": caught,
        "missed": sorted({truth_key(t) for t in truth} - set(caught)),
        "false_positives": sum(m is None for m in matches),
        "findings": len(findings),
    }


def compare(baseline: dict, current: dict) -> tuple[list[str], list[str]]:
    """(regressions, improvements) of `current` against `baseline`."""
    regressions, improvements = [], []
    before, now = set(baseline.get("caught", [])), set(current.get("caught", []))
    regressions += [f"no longer caught: {key}" for key in sorted(before - now)]
    improvements += [f"newly caught: {key}" for key in sorted(now - before)]
    fp_before, fp_now = baseline.get("false_positives", 0), current.get("false_positives", 0)
    if fp_now > fp_before:
        regressions.append(f"false positives went up: {fp_before} -> {fp_now}")
    elif fp_now < fp_before:
        improvements.append(f"false positives went down: {fp_before} -> {fp_now}")
    return regressions, improvements


def load_baseline(app_dir: Path) -> dict | None:
    path = app_dir / BASELINE_NAME
    return json.loads(path.read_text()) if path.exists() else None


def write_baseline(app_dir: Path, summary: dict) -> Path:
    path = app_dir / BASELINE_NAME
    path.write_text(json.dumps(summary, indent=2) + "\n")
    return path
