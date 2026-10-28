"""The shared Finding record. Every layer reads or writes this contract.

Do not change field names or meanings without agreeing with the whole team:
the dashboard, SARIF export and pre-commit hook all depend on it.
"""

from enum import Enum

from pydantic import BaseModel, Field


class ConfidenceTier(str, Enum):
    PATTERN_MATCH = "pattern-match"
    REACHABLE = "reachable"
    PROOF_CONFIRMED = "proof-confirmed"


class Status(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"


class DetectedAt(str, Enum):
    WRITE = "write"    # pre-commit hook
    REVIEW = "review"  # PR scan / uploaded scan
    WATCH = "watch"    # fix-watcher lead


class Finding(BaseModel):
    id: str
    scan_id: str
    file: str
    line: int = Field(ge=1)
    cwe: str
    owasp: str = ""
    source: str = ""
    sink: str = ""
    path: list[str] = Field(default_factory=list)
    detector: str
    ml_rank: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: float = Field(default=0.0, ge=0.0, le=10.0)
    severity_factors: dict[str, float] = Field(default_factory=dict)
    confidence_tier: ConfidenceTier = ConfidenceTier.PATTERN_MATCH
    fix_suggestion: str = ""
    status: Status = Status.OPEN
    introduced_in: str | None = None
    detected_at: DetectedAt = DetectedAt.REVIEW
    time_to_detect: float = 0.0
