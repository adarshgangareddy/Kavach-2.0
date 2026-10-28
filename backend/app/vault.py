"""Encryption at rest for scan workspaces (AES-256-GCM).

A scan needs plaintext while it runs. As soon as it finishes, the project's
Python files (the only files the code viewer serves) are packed into one zip,
encrypted with AES-256-GCM into `workspaces/<scan>/src.enc`, and every
plaintext file of the workspace is deleted, including non-Python files such
as `.env` that are never needed again. The viewer decrypts in memory.

- Key: SENTINEL_DATA_KEY (32 bytes, url-safe base64) if set, otherwise a key
  file created once in the data folder with permissions 0600. In production,
  set the variable from a secrets manager instead of keeping the key on disk.
- Nonce: 12 random bytes per archive, stored in its header.
- Associated data: the scan id, so an archive copied into another scan's
  folder fails to decrypt, and so does any changed byte (GCM tag check).

Archive format: b"ZDS1" + nonce (12 bytes) + ciphertext (with the 16-byte tag).
"""

import base64
import binascii
import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Settings
from app.ingest.workspace import workspace_for

MAGIC = b"ZDS1"
NONCE_BYTES = 12
KEY_ENV = "SENTINEL_DATA_KEY"
KEY_FILE = "vault.key"
ARCHIVE = "src.enc"
MAX_SOURCE_BYTES = 2 * 1024 * 1024


class VaultError(Exception):
    """The archive is missing, tampered with, or the key is wrong."""


def generate_key() -> str:
    """A new key in the format SENTINEL_DATA_KEY expects."""
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode()


def _decode_key(text: str, where: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(text.strip().encode())
    except (binascii.Error, ValueError) as exc:
        raise VaultError(f"{where} is not valid base64") from exc
    if len(key) != 32:
        raise VaultError(f"{where} must decode to 32 bytes (AES-256), got {len(key)}")
    return key


def load_key(settings: Settings) -> bytes:
    if env := os.environ.get(KEY_ENV):
        return _decode_key(env, KEY_ENV)
    path = settings.data_dir / KEY_FILE
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    try:  # create exactly once, readable by this user only
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w") as fh:
            fh.write(generate_key())
    return _decode_key(path.read_text(), str(path))


def _aad(scan_id: str) -> bytes:
    return f"zeroday-sentinel/workspace/{scan_id}".encode()


def archive_path(scan_id: str, settings: Settings) -> Path:
    return workspace_for(scan_id, settings) / ARCHIVE


def is_sealed(scan_id: str, settings: Settings) -> bool:
    return archive_path(scan_id, settings).is_file()


def _pack(root: Path) -> tuple[bytes, int]:
    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*.py")):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            zf.write(path, path.relative_to(root).as_posix())
            count += 1
    return buf.getvalue(), count


def seal(scan_id: str, root: Path, settings: Settings) -> int:
    """Encrypt the Python files under `root`, then delete the plaintext workspace.

    `root` is the folder scan paths are relative to (the unwrapped project).
    Returns the number of files stored.
    """
    data, count = _pack(root)
    nonce = os.urandom(NONCE_BYTES)
    blob = MAGIC + nonce + AESGCM(load_key(settings)).encrypt(nonce, data, _aad(scan_id))
    target = archive_path(scan_id, settings)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".src-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)
    discard_plaintext(scan_id, settings)
    return count


def discard_plaintext(scan_id: str, settings: Settings) -> None:
    shutil.rmtree(workspace_for(scan_id, settings) / "src", ignore_errors=True)


def _open(scan_id: str, settings: Settings) -> zipfile.ZipFile:
    try:
        blob = archive_path(scan_id, settings).read_bytes()
    except FileNotFoundError as exc:
        raise VaultError("no encrypted workspace for this scan") from exc
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_BYTES + 16:
        raise VaultError("not a Kavach archive")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_BYTES]
    try:
        data = AESGCM(load_key(settings)).decrypt(nonce, blob[len(MAGIC) + NONCE_BYTES:], _aad(scan_id))
    except InvalidTag as exc:
        raise VaultError("archive failed its integrity check (tampered, moved or wrong key)") from exc
    return zipfile.ZipFile(io.BytesIO(data))


def read_file(scan_id: str, rel: str, settings: Settings) -> str | None:
    """Decrypt one stored Python file in memory; None if it is not in the archive."""
    path = PurePosixPath(rel.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or path.suffix != ".py":
        return None
    with _open(scan_id, settings) as zf:
        try:
            return zf.read(path.as_posix()).decode("utf-8", errors="replace")
        except KeyError:
            return None


def read_sources(scan_id: str, settings: Settings) -> dict[str, str]:
    """Every stored Python file, decrypted in memory: {relative/path.py: text}."""
    with _open(scan_id, settings) as zf:
        return {name: zf.read(name).decode("utf-8", errors="replace")
                for name in zf.namelist() if name.endswith(".py")}


def seal_existing(settings: Settings) -> int:
    """Encrypt workspaces left in plaintext (scans from before encryption existed)."""
    from app.service import plaintext_root

    sealed = 0
    if not settings.workspaces.is_dir():
        return 0
    for ws in sorted(settings.workspaces.iterdir()):
        src = ws / "src"
        if ws.is_dir() and src.is_dir() and not (ws / ARCHIVE).exists():
            try:
                seal(ws.name, plaintext_root(src), settings)
            except ValueError:  # not a scan id we created
                continue
            sealed += 1
    return sealed
