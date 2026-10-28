"""Check a patch with Kavach's own tracer before the dashboard shows it.

The whole project is analysed twice in memory, before and after the patch, so a bug
whose input comes from another file is still followed. Nothing is written to disk
and no project code runs.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.detect.taint import TaintDetector


@dataclass
class Verification:
    status: str  # "fixed", "still-found" or "not-traced"
    message: str
    paths_before: int = 0
    paths_after: int = 0


def _paths(sources: dict[str, str], file: str, cwe: str, *, unsanitised_only: bool = False) -> list[int]:
    """Lines in `file` where the tracer sees input reach a sink of this CWE."""
    return [c.line for c in TaintDetector().scan_sources(sources)
            if c.file == file and c.cwe == cwe and not (unsanitised_only and c.sanitizer_present)]


def verify(sources: dict[str, str], file: str, patched: str, cwe: str, changed_lines: list[int]) -> Verification:
    before = _paths(sources, file, cwe)
    after = _paths(sources | {file: patched}, file, cwe, unsanitised_only=True)  # a checked path is safe
    still = [line for line in after if line in changed_lines]
    if still:
        return Verification("still-found", f"Kavach still traces input to line {still[0]} after this patch. "
                            "Review it by hand.", len(before), len(after))
    if not before:
        return Verification("not-traced", "Kavach's tracer had not traced this issue (another detector found it), "
                            "so the re-check covers the rewritten call only: it no longer has the risky form.",
                            0, len(after))
    return Verification("fixed", "Checked: Kavach re-traced the whole project with this patch, and user input "
                        "no longer reaches this call in a dangerous way.", len(before), len(after))
