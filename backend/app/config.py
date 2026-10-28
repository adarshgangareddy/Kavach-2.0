"""Runtime limits and paths. Override with SENTINEL_* environment variables."""

import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_DATA = Path(__file__).resolve().parents[1] / ".sentinel-data"


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_upload_bytes: int = 50 * 1024 * 1024
    max_unpacked_bytes: int = 200 * 1024 * 1024
    max_files: int = 20_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_snippet_bytes: int = 200 * 1024
    ingest_timeout_s: float = 30.0
    detector_timeout_s: float = 120.0
    block_threshold: float = 7.0

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sentinel.db"

    @property
    def workspaces(self) -> Path:
        return self.data_dir / "workspaces"


def get_settings() -> Settings:
    data_dir = Path(os.environ.get("SENTINEL_DATA", _DEFAULT_DATA))
    return Settings(data_dir=data_dir)
