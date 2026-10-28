"""API-level models that wrap the shared Finding record."""

import time
import uuid
from enum import Enum
from typing import Literal

import re

from pydantic import BaseModel, Field, field_validator, model_validator

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
    owner_id: str | None = Field(default=None, exclude=True)  # stored, never sent to clients


class StatusUpdate(BaseModel):
    status: Status


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
MIN_PASSWORD = 12


class RegisterRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=MIN_PASSWORD, max_length=128)

    @field_validator("email")
    @classmethod
    def _email_shape(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL.match(value):
            raise ValueError("Enter a valid email address")
        return value

    @model_validator(mode="after")
    def _password_not_email(self):
        local = self.email.split("@")[0]
        if self.password.lower() in {self.email, local} or len(set(self.password)) < 4:
            raise ValueError("Choose a password that is not your email and not a repeated character")
        return self


class SnippetRequest(BaseModel):
    code: str = Field(min_length=1)
    filename: str = "snippet.py"


class AppCreate(BaseModel):
    """A Flask app that will send runtime alerts to Kavach."""
    name: str = Field(min_length=1, max_length=80)


class AlertIn(BaseModel):
    """One alert from a monitored app. Every field is bounded: the sender is not trusted."""
    timestamp: str = Field(max_length=64)
    endpoint: str = Field(max_length=512)
    method: str = Field(max_length=16)
    reason: str = Field(max_length=200)
    client_ip: str | None = Field(None, max_length=64)
    size_bytes: int | None = Field(None, ge=0)
    category: Literal["sql_injection", "path_traversal"] | None = None
    field: str | None = Field(None, max_length=128)  # which input matched, e.g. "query.id"
    sample: str | None = Field(None, max_length=200)  # start of the matching input
