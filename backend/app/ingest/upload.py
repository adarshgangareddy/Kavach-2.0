"""Zip upload handler with zip-slip, symlink and zip-bomb protection."""

import io
import shutil
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath

from app.config import Settings
from app.ingest import IngestError

_CHUNK = 1024 * 1024


def read_limited(stream, limit: int) -> bytes:
    """Read a binary stream, refusing anything larger than `limit` bytes."""
    buf = io.BytesIO()
    while chunk := stream.read(_CHUNK):
        buf.write(chunk)
        if buf.tell() > limit:
            raise IngestError(f"Upload exceeds the {limit // (1024 * 1024)} MB limit.", 413)
    return buf.getvalue()


def _safe_member_path(name: str) -> PurePosixPath | None:
    """Return a safe relative path for a zip member, or None to skip it."""
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise IngestError(f"Archive contains an unsafe path: {name!r}.")
    return path if path.parts else None


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def extract_zip(data: bytes, dest: Path, settings: Settings) -> list[str]:
    """Extract an archive into `dest`. Returns user-facing notes."""
    deadline = time.monotonic() + settings.ingest_timeout_s
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("Upload is not a valid zip archive.") from exc

    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) > settings.max_files:
            raise IngestError(f"Archive has more than {settings.max_files} files.")
        if sum(m.file_size for m in members) > settings.max_unpacked_bytes:
            raise IngestError("Archive is too large when unpacked.", 413)

        dest.mkdir(parents=True, exist_ok=True)
        root = dest.resolve()
        symlinks = 0
        for info in members:
            if time.monotonic() > deadline:
                raise IngestError("Extraction exceeded the time limit.", 408)
            if _is_symlink(info):
                symlinks += 1
                continue
            rel = _safe_member_path(info.filename)
            if rel is None:
                continue
            target = (root / rel).resolve()
            if not target.is_relative_to(root):
                raise IngestError(f"Archive contains an unsafe path: {info.filename!r}.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, _CHUNK)

    notes = [f"Skipped {symlinks} symbolic links in the archive."] if symlinks else []
    return notes


def project_root(dest: Path) -> Path:
    """If the archive wraps everything in one top-level folder, scan inside it.

    A single folder that is itself a Python package is kept, so module names
    (and relative imports) stay correct.
    """
    entries = [p for p in dest.iterdir() if p.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir() and not (entries[0] / "__init__.py").exists():
        return entries[0]
    return dest
