"""Explainable severity score (PRD section 8, L5).

severity = min(10, base(CWE) + 1.5*reachable + 1.0*public_route
                   + 1.0*confidence - 2.0*sanitizer_present)
"""

BASE_SCORE: dict[str, float] = {
    "CWE-78": 6.0,   # OS command injection
    "CWE-77": 6.0,   # command injection
    "CWE-89": 6.0,   # SQL injection
    "CWE-94": 6.0,   # code injection
    "CWE-502": 6.0,  # unsafe deserialization
    "CWE-22": 5.0,   # path traversal
    "CWE-798": 4.5,  # hard-coded credentials
    "CWE-259": 4.5,  # hard-coded password
    "CWE-327": 3.5,  # broken or risky crypto
    "CWE-328": 3.5,  # weak hash
    "CWE-916": 4.0,  # fast hash for passwords
    "CWE-295": 4.0,  # certificate checks off
    "CWE-326": 3.5,  # key too short
    "CWE-330": 3.5,  # predictable random values
    "CWE-1395": 5.0,  # vulnerable third-party component (fix-watcher)
}
DEFAULT_BASE = 3.0

WEIGHTS = {"reachable": 1.5, "public_route": 1.0, "confidence": 1.0, "sanitizer_present": -2.0}


def score(cwe: str, *, reachable: bool, public_route: bool,
          confidence: float, sanitizer_present: bool) -> tuple[float, dict[str, float]]:
    """Return (severity, per-term contributions). Contributions sum to the raw score."""
    factors = {
        "base": BASE_SCORE.get(cwe, DEFAULT_BASE),
        "reachable": WEIGHTS["reachable"] * float(reachable),
        "public_route": WEIGHTS["public_route"] * float(public_route),
        "confidence": round(WEIGHTS["confidence"] * confidence, 2),
        "sanitizer_present": WEIGHTS["sanitizer_present"] * float(sanitizer_present),
    }
    severity = round(max(0.0, min(10.0, sum(factors.values()))), 1)
    return severity, factors


def label(severity: float) -> str:
    if severity >= 9.0:
        return "critical"
    if severity >= 7.0:
        return "high"
    if severity >= 4.0:
        return "medium"
    if severity > 0.0:
        return "low"
    return "info"
