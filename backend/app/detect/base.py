"""What a detector returns. The pipeline turns Candidates into Finding records."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from app.schema import ConfidenceTier


class Candidate(BaseModel):
    """One raw result from a detector, before ids, scoring and tagging."""

    file: str
    line: int = Field(ge=1)
    cwe: str
    detector: str
    source: str = ""
    sink: str = ""
    path: list[str] = Field(default_factory=list)
    confidence_tier: ConfidenceTier = ConfidenceTier.PATTERN_MATCH
    # Inputs to the severity formula (PRD section 8, L5).
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reachable: bool = False
    public_route: bool = False
    sanitizer_present: bool = False
    fix_suggestion: str = ""


def is_whole_program(detector: "Detector") -> bool:
    """Whole-program detectors need every project file, and their results for one
    file depend on other files, so they are never cached per file."""
    return bool(getattr(detector, "whole_program", False))


@runtime_checkable
class Detector(Protocol):
    name: str
    version: str

    def available(self) -> bool:
        """False if a required tool is missing; the pipeline then skips it."""

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        """Analyse `files` (paths relative to `root`). Must not execute project code."""
