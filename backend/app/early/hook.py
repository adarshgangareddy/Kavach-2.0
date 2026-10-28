"""Pre-commit hook: scan staged Python changes, block on severity >= threshold.

Bypass for one commit with `SENTINEL_SKIP=1 git commit ...` or `git commit --no-verify`.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from app.config import get_settings
from app.detect.registry import active_detectors
from app.early.incremental import ResultCache, scan_incremental
from app.early.scope import in_changed_code
from app.ingest.diff import staged_diff
from app.ingest.filter import is_ignored
from app.pipeline import build_findings
from app.report.text import render
from app.schema import DetectedAt


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True, check=True).stdout.strip()


def staged_python_files(repo: Path) -> list[str]:
    """Every Python file in the index (the commit being made), minus ignored paths."""
    out = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", "--cached", "--", "*.py"],
                         capture_output=True, check=True).stdout
    return sorted(p for p in out.decode().split("\0") if p and not is_ignored(p))


def export_staged(repo: Path, files: list[str], dest: Path) -> None:
    """Write the staged (index) version of each file, not the working copy."""
    if not files:
        return
    subprocess.run(["git", "-C", str(repo), "checkout-index", "--stdin", "-z",
                    f"--prefix={dest}/"], input="\0".join(files).encode(),
                   capture_output=True, check=True)


def _parse(argv: list[str] | None) -> argparse.Namespace:
    settings = get_settings()
    p = argparse.ArgumentParser(prog="sentinel-hook", description=__doc__)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--threshold", type=float, default=settings.block_threshold,
                   help="block the commit at or above this severity (default %(default)s)")
    p.add_argument("--all", action="store_true",
                   help="report findings anywhere in staged files, not only in changed code")
    p.add_argument("--no-cache", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    if os.environ.get("SENTINEL_SKIP") == "1":
        print("sentinel: skipped (SENTINEL_SKIP=1)", file=sys.stderr)
        return 0
    started = time.monotonic()
    repo = Path(_git(args.repo, "rev-parse", "--show-toplevel"))
    changed = {p: lines for p, lines in staged_diff(repo).items() if not is_ignored(p)}
    if not changed:
        return 0
    detectors = active_detectors()
    if not detectors:
        print("sentinel: no detectors available; commit not checked.", file=sys.stderr)
        return 0

    cache_path = Path(_git(repo, "rev-parse", "--absolute-git-dir")) / "sentinel-cache.json"
    cache = ResultCache(cache_path) if not args.no_cache else ResultCache(Path(os.devnull))
    with tempfile.TemporaryDirectory(prefix="sentinel-hook-") as tmp:
        root = Path(tmp)
        files = sorted(changed)
        context = staged_python_files(repo)
        export_staged(repo, sorted(set(context) | set(files)), root)
        candidates, notes, stats = scan_incremental(
            root, files, detectors, cache, get_settings().detector_timeout_s, context)
        findings = build_findings(f"S-{uuid.uuid4().hex[:8]}", candidates, started=started,
                                  detected_at=DetectedAt.WRITE)
        if not args.all:
            findings = in_changed_code(findings, changed,
                                       lambda rel: (root / rel).read_text(errors="replace"))
    if not args.no_cache:
        cache.save()

    elapsed = time.monotonic() - started
    for note in notes:
        print(f"sentinel: {note}", file=sys.stderr)
    blocking = [f for f in findings if f.severity >= args.threshold]
    if findings:
        print(render(findings, threshold=args.threshold))
    print(f"sentinel: {len(files)} files ({stats['cached']} cached), {len(findings)} findings, "
          f"{elapsed:.2f}s", file=sys.stderr)
    if blocking:
        print(f"sentinel: commit blocked - {len(blocking)} findings at severity "
              f">= {args.threshold}. Fix them, or bypass with SENTINEL_SKIP=1.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
