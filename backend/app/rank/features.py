"""Feature vector for the ML ranker.

Built only from Finding fields, so findings from any detector can be ranked,
and a finding can be scored again later from its JSON alone. Changing this
list invalidates trained models (the model file records the names it was
trained on and is rejected if they differ).
"""

from collections.abc import Mapping
from typing import Any

TIERS = ("pattern-match", "reachable", "proof-confirmed")
DETECTORS = ("taint", "taint-wrapper", "bandit", "semgrep")
CWES = ("CWE-78", "CWE-89", "CWE-22", "CWE-502")
MAX_HOPS = 10

FEATURES: tuple[str, ...] = (
    *(f"tier={t}" for t in TIERS),
    *(f"detector={d}" for d in DETECTORS),
    "detector_count",
    *(f"cwe={c}" for c in CWES),
    "cwe=other",
    "path_hops",
    "has_source",
    "source_is_request",
    "factor_base",
    "factor_reachable",
    "factor_public_route",
    "factor_sanitizer",
    "detector_confidence",
)


def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def extract(item: Any) -> list[float]:
    """Feature values for one finding (dict or Finding), in FEATURES order."""
    tier = str(getattr(_get(item, "confidence_tier"), "value", _get(item, "confidence_tier")) or "")
    detectors = set(str(_get(item, "detector", "") or "").split("+")) - {""}
    cwe = str(_get(item, "cwe", "") or "")
    path = _get(item, "path") or []
    source = str(_get(item, "source", "") or "")
    factors = _get(item, "severity_factors") or {}

    values = [float(tier == t) for t in TIERS]
    values += [float(d in detectors) for d in DETECTORS]
    values.append(float(len(detectors)))
    values += [float(cwe == c) for c in CWES]
    values.append(float(cwe not in CWES))
    values.append(min(len(path), MAX_HOPS) / MAX_HOPS)
    values.append(float(bool(source)))
    values.append(float(source.startswith("request.")))
    values.append(_float(factors.get("base")) / 10.0)
    values.append(float(_float(factors.get("reachable")) > 0))
    values.append(float(_float(factors.get("public_route")) > 0))
    values.append(float(_float(factors.get("sanitizer_present")) < 0))
    # The severity formula stores 1.0 * detector confidence; reuse it so the
    # feature stays the detector's own estimate even after ml_rank is replaced.
    values.append(min(max(_float(factors.get("confidence")), 0.0), 1.0))
    return values
