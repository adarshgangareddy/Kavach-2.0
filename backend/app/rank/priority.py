"""Sort findings by review priority.

Works on plain dicts (API/JSON output) and on Finding objects alike.

Order, most urgent first:
1. Open findings before fixed or accepted ones.
2. Severity band (critical, high, medium, low, info). The PRD formula decides the band.
3. Confidence score within the band: `ml_rank` (the ranker's estimate that the
   finding is real), falling back to `confidence`.
4. Exact severity, then evidence tier (proof-confirmed > reachable > pattern-match).
5. File and line, so the order is stable and repeatable.

The ranker only reorders findings inside a severity band; it never lifts a
medium above a high.
"""

import math
from collections.abc import Iterable, Mapping
from typing import Any, TypeVar

T = TypeVar("T")

_STATUS_ORDER = {"open": 0, "fixed": 1, "accepted": 2}
_TIER_ORDER = {"proof-confirmed": 0, "reachable": 1, "pattern-match": 2}


def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _text(value: Any) -> str:
    """Enum or string -> plain lowercase string."""
    return str(getattr(value, "value", value) or "").lower()


def _number(value: Any, low: float, high: float) -> float:
    """Coerce to a finite float clamped to [low, high]; anything unusable counts as `low`."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return low
    if math.isnan(number):
        return low
    return min(max(number, low), high)


def severity_band(severity: float) -> int:
    """0 = critical ... 4 = info, matching app.report.severity.label()."""
    if severity >= 9.0:
        return 0
    if severity >= 7.0:
        return 1
    if severity >= 4.0:
        return 2
    if severity > 0.0:
        return 3
    return 4


def confidence_score(item: Any) -> float:
    """The ranker's score if present, else the detector's confidence, in [0, 1]."""
    for key in ("ml_rank", "confidence"):
        value = _get(item, key)
        if value is not None:
            return _number(value, 0.0, 1.0)
    return 0.0


def priority_key(item: Any) -> tuple:
    severity = _number(_get(item, "severity"), 0.0, 10.0)
    line = _get(item, "line")
    return (
        _STATUS_ORDER.get(_text(_get(item, "status", "open")), len(_STATUS_ORDER)),
        severity_band(severity),
        -confidence_score(item),
        -severity,
        _TIER_ORDER.get(_text(_get(item, "confidence_tier")), len(_TIER_ORDER)),
        str(_get(item, "file", "") or ""),
        int(line) if isinstance(line, (int, float)) and not math.isnan(line) else 0,
    )


def sort_by_priority(items: Iterable[T]) -> list[T]:
    """Return a new list, most urgent first. The input is not modified."""
    return sorted(items, key=priority_key)
