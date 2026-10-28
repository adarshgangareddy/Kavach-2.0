"""Per-scan workspace directories."""

import re
import shutil
from pathlib import Path

from app.config import Settings
from app.models import SCAN_ID_PATTERN

_SCAN_ID = re.compile(SCAN_ID_PATTERN)


def workspace_for(scan_id: str, settings: Settings) -> Path:
    if not _SCAN_ID.match(scan_id):
        raise ValueError(f"invalid scan id {scan_id!r}")
    return settings.workspaces / scan_id


def fresh_workspace(scan_id: str, settings: Settings) -> Path:
    path = workspace_for(scan_id, settings)
    shutil.rmtree(path, ignore_errors=True)
    (path / "src").mkdir(parents=True)
    return path


def resolve_source_file(root: Path, rel: str) -> Path | None:
    """Resolve a user-supplied relative path, refusing anything outside `root`."""
    base = root.resolve()
    target = (base / rel).resolve()
    if not target.is_relative_to(base) or not target.is_file() or target.suffix != ".py":
        return None
    return target
