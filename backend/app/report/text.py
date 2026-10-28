"""Terminal output for the hook and CLI."""

import sys

from app.report import owasp, severity
from app.schema import Finding

_ANSI = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
         "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


def _paint(text: str, level: str, colour: bool) -> str:
    return f"{_ANSI[level]}{text}{_RESET}" if colour else text


def render(findings: list[Finding], *, threshold: float | None = None,
           colour: bool | None = None) -> str:
    colour = sys.stdout.isatty() if colour is None else colour
    if not findings:
        return "No findings."
    rows = []
    for f in findings:
        level = severity.label(f.severity)
        mark = "BLOCK" if threshold is not None and f.severity >= threshold else "     "
        head = _paint(f"{level.upper():8} {f.severity:4.1f}", level, colour)
        rows.append(f"{mark} {head}  {f.file}:{f.line}  {f.cwe} {owasp.title_for(f.cwe)}"
                    f"  [{f.detector}, {f.confidence_tier.value}]")
        if f.path:
            rows.append(f"{'':16}path: {' -> '.join(f.path)}")
        rows.append(f"{'':16}fix:  {f.fix_suggestion}")
    return "\n".join(rows)
