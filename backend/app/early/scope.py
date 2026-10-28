"""Limit findings to the code a commit or pull request actually changed."""

from collections.abc import Callable

from app.ingest.diff import ChangedLines, changed_functions, enclosing_function
from app.schema import Finding


def _changed_names(changed: ChangedLines, read_source: Callable[[str], str]) -> set[str]:
    names: set[str] = set()
    for rel, lines in changed.items():
        try:
            names |= changed_functions(read_source(rel), lines)
        except OSError:
            continue
    return names - {"<module>"}


def in_changed_code(findings: list[Finding], changed: ChangedLines,
                    read_source: Callable[[str], str]) -> list[Finding]:
    """Keep findings on a changed line, inside a changed function, or whose
    source-to-sink path passes through a changed function (e.g. a new route
    calling an existing helper in an unchanged file)."""
    touched: dict[str, set[str]] = {}
    changed_names: set[str] | None = None
    kept: list[Finding] = []
    for f in findings:
        if f.path:
            if changed_names is None:
                changed_names = _changed_names(changed, read_source)
            if {step.removesuffix("()") for step in f.path} & changed_names:
                kept.append(f)
                continue
        lines = changed.get(f.file)
        if not lines:
            continue
        if f.line in lines:
            kept.append(f)
            continue
        source = read_source(f.file)
        if f.file not in touched:
            touched[f.file] = changed_functions(source, lines) - {"<module>"}
        if enclosing_function(source, f.line) in touched[f.file]:
            kept.append(f)
    return kept
