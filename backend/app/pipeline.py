"""Run detectors over a project and turn their Candidates into scored Findings."""

import time
from collections import Counter
from pathlib import Path

from app.detect.base import Candidate, Detector, is_whole_program
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
    return candidates, notes


def _stronger(a: Candidate, b: Candidate) -> Candidate:
    rank = lambda c: (_TIER_ORDER[c.confidence_tier.value], c.confidence, len(c.path))  # noqa: E731
    return a if rank(a) >= rank(b) else b


def deduplicate(candidates: list[Candidate]) -> list[Candidate]:
    """Merge results that several detectors report for the same file, line and CWE."""
    merged: dict[tuple[str, int, str], Candidate] = {}
    for cand in candidates:
        key = (cand.file, cand.line, cand.cwe)
        if key not in merged:
            merged[key] = cand
            continue
        best = _stronger(merged[key], cand)
        names = sorted(set(merged[key].detector.split("+")) | {cand.detector})
        merged[key] = best.model_copy(update={"detector": "+".join(names)})
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
        to_finding(c, f"F-{prefix}-{i:03d}", scan_id, detected_at=detected_at,
                   introduced_in=introduced_in, elapsed_s=elapsed)
        for i, c in enumerate(deduplicate(candidates), start=1)
    ]
    return sort_by_priority(ranker.apply(findings))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return dict(Counter(severity.label(f.severity) for f in findings))
