"""GitHub URL ingestion: shallow, non-interactive clone of a public repo."""

import os
import re
import shutil
import subprocess
from pathlib import Path

from app.config import Settings
from app.ingest import IngestError

_GITHUB_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))"
    r"/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)


def parse_github_url(url: str) -> tuple[str, str]:
    match = _GITHUB_URL.match(url.strip())
    if not match or match["repo"] in {".", ".."}:
        raise IngestError("Expected a URL like https://github.com/owner/repo.")
    return match["owner"], match["repo"]


def _tree_size(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def clone(url: str, dest: Path, settings: Settings) -> None:
    owner, repo = parse_github_url(url)
    if shutil.which("git") is None:
        raise IngestError("git is not installed on the server.", 500)
    cmd = [
        "git", "-c", "core.symlinks=false", "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--", f"https://github.com/{owner}/{repo}.git", str(dest),
    ]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    try:
        subprocess.run(cmd, env=env, capture_output=True, text=True,
                       timeout=settings.ingest_timeout_s, check=True)
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise IngestError("Cloning took longer than the time limit.", 408) from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise IngestError("Could not clone the repository. Is it public?") from exc
    if _tree_size(dest) > settings.max_unpacked_bytes:
        shutil.rmtree(dest, ignore_errors=True)
        raise IngestError("Repository is too large to scan.", 413)
