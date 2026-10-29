"""Run detectors over a project and turn their Candidates into scored Findings."""

import time
from collections import Counter
from pathlib import Path

from app.detect.base import Candidate, Detector, is_whole_program
from app.fix.patch import SAFE_PATH_HELPER, defines_genuine_helper
from app.rank import model as ranker
from app.rank.priority import sort_by_priority
from app.report import owasp, severity
from app.schema import DetectedAt, Finding

_TIER_ORDER = {"pattern-match": 0, "reachable": 1, "proof-confirmed": 2}


def run_detectors(root: Path, files: list[str], detectors: list[Detector],
                  timeout_s: float, context_files: list[str] | None = None,
                  ) -> tuple[list[Candidate], list[str]]:
    """Run each detector; one failing detector is reported, not fatal.

    Per-file detectors see `files`; whole-program detectors see `context_files`
    (the full project) when given, so calls into unchanged helpers are followed.
    """
    candidates: list[Candidate] = []
    notes: list[str] = []
    if not files:
        return candidates, notes
    for det in detectors:
        scope = context_files if context_files and is_whole_program(det) else files
        try:
            candidates.extend(det.scan(root, scope, timeout_s))
        except Exception as exc:  # noqa: BLE001 - surface any detector failure to the user
            notes.append(f"Detector {det.name} failed: {type(exc).__name__}: {exc}")
    return drop_checked_paths(root, candidates, notes), notes


PATH_CWES = {"CWE-22", "CWE-23"}


def drop_checked_paths(root: Path, candidates: list[Candidate], notes: list[str]) -> list[Candidate]:
    """Drop path-traversal reports on lines whose path goes through Kavach's own safe-path helper.

    Other tools do not know the helper and keep reporting a fixed line. The report is dropped
    only when the same file defines the helper exactly as the patch suggester wrote it.
    """
    sources: dict[str, list[str] | None] = {}
    kept = []
    for cand in candidates:
        if cand.cwe in PATH_CWES and _checked_path(root, cand, sources):
            continue
        kept.append(cand)
    if dropped := len(candidates) - len(kept):
        notes.append(f"{dropped} path traversal report(s) dropped: the path is checked by Kavach's "
                     f"{SAFE_PATH_HELPER} helper, which keeps it inside its folder.")
    return kept


def _checked_path(root: Path, cand: Candidate, sources: dict[str, list[str] | None]) -> bool:
    if cand.file not in sources:
        try:
            text = (root / cand.file).read_text(errors="replace")
        except OSError:
            text = None
        sources[cand.file] = text.splitlines() if text and defines_genuine_helper(text) else None
    lines = sources[cand.file]
    return bool(lines) and 0 < cand.line <= len(lines) and f"{SAFE_PATH_HELPER}(" in lines[cand.line - 1]


def _stronger(a: Candidate, b: Candidate) -> Candidate:
    rank = lambda c: (_TIER_ORDER[c.confidence_tier.value], c.confidence, len(c.path))  # noqa: E731
    return a if rank(a) >= rank(b) else b


# CWEs that detectors use for the same problem: Bandit calls every hard-coded secret a
# "hard-coded password" (CWE-259), Kavach's rules say CWE-798 for non-passwords.
_SAME_PROBLEM = {"CWE-259": "CWE-798"}


def deduplicate(candidates: list[Candidate]) -> list[Candidate]:
    """Merge results that several detectors report for the same file, line and CWE."""
    merged: dict[tuple[str, int, str], Candidate] = {}
    for cand in candidates:
        key = (cand.file, cand.line, _SAME_PROBLEM.get(cand.cwe, cand.cwe))
        if key not in merged:
            merged[key] = cand
            continue
        best = _stronger(merged[key], cand)
        names = sorted(set(merged[key].detector.split("+")) | {cand.detector})
        update = {"detector": "+".join(names)}
        if worded := next((c for c in (merged[key], cand) if "rules" in c.detector.split("+")), None):
            update |= {"sink": worded.sink, "fix_suggestion": worded.fix_suggestion}  # plain words, specific fix
        merged[key] = best.model_copy(update=update)
    return sorted(merged.values(), key=lambda c: (c.file, c.line, c.cwe))


def to_finding(cand: Candidate, finding_id: str, scan_id: str, *,
               detected_at: DetectedAt, introduced_in: str | None,
               elapsed_s: float) -> Finding:
    sev, factors = severity.score(
        cand.cwe, reachable=cand.reachable, public_route=cand.public_route,
        confidence=cand.confidence, sanitizer_present=cand.sanitizer_present,
    )
    return Finding(
        id=finding_id, scan_id=scan_id, file=cand.file, line=cand.line,
        cwe=cand.cwe, owasp=owasp.owasp_for(cand.cwe),
        source=cand.source, sink=cand.sink, path=cand.path, detector=cand.detector,
        # Detector confidence until the ML ranker (if a model is trained) rescores it.
        ml_rank=cand.confidence,
        severity=sev, severity_factors=factors,
        confidence_tier=cand.confidence_tier,
        fix_suggestion=cand.fix_suggestion or owasp.remediation_for(cand.cwe),
        introduced_in=introduced_in, detected_at=detected_at,
        time_to_detect=round(elapsed_s, 3),
    )


def build_findings(scan_id: str, candidates: list[Candidate], *, started: float,
                   detected_at: DetectedAt = DetectedAt.REVIEW,
                   introduced_in: str | None = None) -> list[Finding]:
    elapsed = time.monotonic() - started
    prefix = scan_id.removeprefix("S-")
    findings = [
        to_finding(c, f"F-{prefix}-{i:03d}", scan_id, detected_at=_detected_at(c, detected_at),
                   introduced_in=introduced_in, elapsed_s=elapsed)
        for i, c in enumerate(deduplicate(candidates), start=1)
    ]
    return sort_by_priority(ranker.apply(findings))


def _detected_at(cand: Candidate, default: DetectedAt) -> DetectedAt:
    """Fix-watcher leads say so; everything else keeps the stage the scan ran at."""
    return DetectedAt.WATCH if "fixwatch" in cand.detector.split("+") else default


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return dict(Counter(severity.label(f.severity) for f in findings))
