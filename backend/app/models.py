"""API-level models that wrap the shared Finding record."""

import time
import uuid
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from app.schema import Status

SCAN_ID_PATTERN = r"^S-[0-9a-f]{8}$"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: f"S-{uuid.uuid4().hex[:8]}")
    status: ScanStatus = ScanStatus.QUEUED
    source_kind: Literal["zip", "github", "snippet", "cli"]
    source_ref: str = ""
    created_at: float = Field(default_factory=time.time)
    finished_at: float | None = None
    files_scanned: int = 0
    detectors: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    error: str | None = None
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)


class StatusUpdate(BaseModel):
    status: Status


class SnippetRequest(BaseModel):
    code: str = Field(min_length=1)
    filename: str = "snippet.py"
