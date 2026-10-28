"""Encryption at rest for scan workspaces."""

import io
import os
import stat
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import vault
from app.config import get_settings
from app.main import app
from tests.conftest import APP_SOURCE, write

SECRET_MARKER = "UNIQUE_SOURCE_MARKER_7f3a"


@pytest.fixture
def settings():
    return get_settings()


def _workspace(settings, scan_id="S-0000aaaa"):
    src = settings.workspaces / scan_id / "src"
    write(src, "app/views.py", f"# {SECRET_MARKER}\nx = 1\n")
    write(src, "app/__init__.py", "")
    write(src, ".env", "API_KEY=do-not-keep\n")
    write(src, "static/site.css", "body {}\n")
    return scan_id, src


def test_key_file_is_created_once_and_private(settings, monkeypatch):
    monkeypatch.delenv(vault.KEY_ENV, raising=False)
    first = vault.load_key(settings)
    path = settings.data_dir / vault.KEY_FILE
    assert len(first) == 32 and vault.load_key(settings) == first
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_key_from_environment(settings, monkeypatch):
    key = vault.generate_key()
    monkeypatch.setenv(vault.KEY_ENV, key)
    assert vault.load_key(settings) == __import__("base64").urlsafe_b64decode(key)
    assert not (settings.data_dir / vault.KEY_FILE).exists()
    monkeypatch.setenv(vault.KEY_ENV, "too-short")
    with pytest.raises(vault.VaultError):
        vault.load_key(settings)


def test_seal_encrypts_python_files_and_deletes_all_plaintext(settings):
    scan_id, src = _workspace(settings)
    assert vault.seal(scan_id, src, settings) == 2
    workspace = settings.workspaces / scan_id
    assert sorted(p.name for p in workspace.iterdir()) == [vault.ARCHIVE]  # no src/, no .env
    blob = (workspace / vault.ARCHIVE).read_bytes()
    assert blob.startswith(vault.MAGIC)
    assert SECRET_MARKER.encode() not in blob and b"API_KEY" not in blob
    assert stat.S_IMODE((workspace / vault.ARCHIVE).stat().st_mode) == 0o600

    assert SECRET_MARKER in vault.read_file(scan_id, "app/views.py", settings)
    for bad in ["../app/views.py", "/etc/passwd", ".env", "static/site.css", "missing.py"]:
        assert vault.read_file(scan_id, bad, settings) is None


def test_each_archive_gets_a_fresh_nonce(settings):
    a, src_a = _workspace(settings, "S-0000aaa1")
    b, src_b = _workspace(settings, "S-0000aaa2")
    vault.seal(a, src_a, settings)
    vault.seal(b, src_b, settings)
    nonce = lambda s: vault.archive_path(s, settings).read_bytes()[4:16]  # noqa: E731
    assert nonce(a) != nonce(b)


def test_tampering_moving_or_wrong_key_is_detected(settings, monkeypatch):
    scan_id, src = _workspace(settings)
    vault.seal(scan_id, src, settings)
    path = vault.archive_path(scan_id, settings)
    original = path.read_bytes()

    flipped = bytearray(original)
    flipped[-5] ^= 0x01
    path.write_bytes(bytes(flipped))
    with pytest.raises(vault.VaultError, match="integrity"):
        vault.read_file(scan_id, "app/views.py", settings)

    path.write_bytes(original)
    other = vault.archive_path("S-0000bbbb", settings)
    other.parent.mkdir(parents=True)
    other.write_bytes(original)  # copied into another scan's folder
    with pytest.raises(vault.VaultError, match="integrity"):
        vault.read_file("S-0000bbbb", "app/views.py", settings)

    monkeypatch.setenv(vault.KEY_ENV, vault.generate_key())
    with pytest.raises(vault.VaultError, match="integrity"):
        vault.read_file(scan_id, "app/views.py", settings)


def test_existing_plaintext_workspaces_are_migrated(settings):
    scan_id, _ = _workspace(settings, "S-0000cccc")
    (settings.workspaces / "not-a-scan" / "src").mkdir(parents=True)
    assert vault.seal_existing(settings) == 1
    assert vault.is_sealed(scan_id, settings)
    assert not (settings.workspaces / scan_id / "src").exists()
    assert vault.seal_existing(settings) == 0


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


def test_api_scan_is_stored_encrypted_and_viewer_still_works(marker, settings):
    client = TestClient(app)
    body = _zip({"demo/app/routes.py": APP_SOURCE + f"\n# {SECRET_MARKER}\n", "demo/.env": "TOKEN=x\n"})
    scan = client.post("/scans", files={"file": ("demo.zip", body, "application/zip")}).json()
    workspace = settings.workspaces / scan["id"]
    assert [p.name for p in workspace.iterdir()] == [vault.ARCHIVE]
    assert SECRET_MARKER.encode() not in (workspace / vault.ARCHIVE).read_bytes()
    assert any("encrypted (AES-256-GCM)" in n for n in client.get(f"/scans/{scan['id']}").json()["notes"])

    view = client.get(f"/scans/{scan['id']}/source", params={"path": "app/routes.py"})
    assert view.status_code == 200 and SECRET_MARKER in view.text

    path = workspace / vault.ARCHIVE
    data = bytearray(path.read_bytes())
    data[20] ^= 0xFF
    path.write_bytes(bytes(data))
    assert client.get(f"/scans/{scan['id']}/source", params={"path": "app/routes.py"}).status_code == 409


def test_failed_scan_leaves_no_plaintext(marker, settings):
    client = TestClient(app)
    scan = client.post("/scans", files={"file": ("x.zip", b"not a zip", "application/zip")}).json()
    assert client.get(f"/scans/{scan['id']}").json()["status"] == "failed"
    workspace = settings.workspaces / scan["id"]
    assert not (workspace / "src").exists() and not (workspace / vault.ARCHIVE).exists()


def test_snippet_scan_is_sealed(marker, settings):
    client = TestClient(app)
    body = client.post("/snippet", json={"code": f"x = 1  # {SECRET_MARKER}\n", "filename": "s.py"}).json()
    sid = body["scan"]["id"]
    assert vault.is_sealed(sid, settings) and not (settings.workspaces / sid / "src").exists()
    assert SECRET_MARKER in client.get(f"/scans/{sid}/source", params={"path": "s.py"}).text


def test_key_is_never_written_into_the_archive(settings, monkeypatch):
    key_text = vault.generate_key()
    monkeypatch.setenv(vault.KEY_ENV, key_text)
    scan_id, src = _workspace(settings)
    vault.seal(scan_id, src, settings)
    blob = vault.archive_path(scan_id, settings).read_bytes()
    assert key_text.encode() not in blob and vault.load_key(settings) not in blob
    assert os.environ[vault.KEY_ENV] == key_text
