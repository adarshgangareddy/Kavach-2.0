"""Check a patch with Kavach's own tracer before the dashboard shows it.

The whole project is analysed twice in memory, before and after the patch, so a bug
whose input comes from another file is still followed. Nothing is written to disk
and no project code runs.
"""
from __future__ import annotations

from dataclasses import dataclass

import ast

from app.detect.rules import check_module
from app.detect.taint import TaintDetector

RULE_LAYER = {"CWE-798", "CWE-259", "CWE-327", "CWE-916", "CWE-326", "CWE-295", "CWE-330"}
# Tools file some problems under different CWEs: Bandit calls every secret CWE-259, Semgrep files
# old TLS versions under "key too short" (CWE-326) where the rule layer says CWE-327.
SAME_PROBLEM = {"CWE-259": "CWE-798", "CWE-326": "CWE-327"}


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


def _rule_hits(source: str, file: str, cwe: str) -> list[int]:
    """Lines where the rule layer reports this problem (secrets count as one problem whatever the CWE)."""
    want = SAME_PROBLEM.get(cwe, cwe)
    return [c.line for c in check_module(ast.parse(source), file) if SAME_PROBLEM.get(c.cwe, c.cwe) == want]


def _verify_rule(sources: dict[str, str], file: str, patched: str, cwe: str, changed: list[int],
                 line: int | None) -> Verification:
    before = [n for n in _rule_hits(sources[file], file, cwe) if line is None or n == line]
    still = [line for line in _rule_hits(patched, file, cwe) if line in changed]
    if still:
        return Verification("still-found", f"Kavach's rule layer still reports line {still[0]} after this patch. "
                            "Review it by hand.", len(before), len(still))
    if not before:
        return Verification("not-traced", "Kavach's rule layer had not reported this (another detector found "
                            "it), so the re-check covers the rewritten code only.", 0, 0)
    return Verification("fixed", "Checked: Kavach's rule layer re-read the patched file and no longer reports "
                        "this line.", len(before), 0)


def verify(sources: dict[str, str], file: str, patched: str, cwe: str, changed_lines: list[int],
           line: int | None = None) -> Verification:
    """`line` is the finding's line in the original file, when known."""
    if cwe in RULE_LAYER:
        return _verify_rule(sources, file, patched, cwe, changed_lines, line)
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
