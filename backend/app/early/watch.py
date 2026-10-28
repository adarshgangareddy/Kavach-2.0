"""Watch a git repository and record which functions are changing (detected_at: "write").

    sentinel watch                      # poll every second, write .git/sentinel-status.json
    sentinel watch --scan               # also scan changed functions and print new findings
    sentinel watch --once --status out.json

Every poll compares each modified, added or untracked Python file in the working
tree with its version at HEAD, function by function, and writes a status JSON
file when anything changes:

    {
      "version": 1, "updated_at": "...", "head": "abc1234",
      "summary": {"files": 1, "added": 0, "modified": 1, "removed": 0, "findings": 0},
      "files": {
        "app/views.py": {
          "status": "modified",
          "functions": {
            "search": {"change": "modified", "lines": [12, 30], "hash": "...",
                       "first_seen": "...", "last_changed": "..."}
          }
        }
      },
      "findings": []
    }

Polling (not filesystem events) keeps it dependency-free and identical on every OS.
Files that fail to parse mid-edit keep their last known functions and get a
"parse_error". The status file is replaced atomically, so readers never see a
half-written file.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from app.early.incremental import function_hashes
from app.ingest.diff import function_spans

STATUS_VERSION = 1
STATUS_NAME = "sentinel-status.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=check)


def repo_root(path: Path) -> Path:
    return Path(_git(path, "rev-parse", "--show-toplevel").stdout.decode().strip())


def default_status_path(repo: Path) -> Path:
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir").stdout.decode().strip())
    return git_dir / STATUS_NAME


def head_sha(repo: Path) -> str | None:
    result = _git(repo, "rev-parse", "--short", "HEAD", check=False)
    return result.stdout.decode().strip() if result.returncode == 0 else None


def modified_python_files(repo: Path) -> dict[str, str]:
    """{path: status} for Python files that differ from HEAD (porcelain v1, -z)."""
    out = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout.decode()
    entries = out.split("\0")
    files: dict[str, str] = {}
    i = 0
    while i < len(entries):
        entry = entries[i]
        i += 1
        if len(entry) < 4:
            continue
        code, path = entry[:2], entry[3:]
        if code[0] in "RC":  # rename/copy: the next entry is the old path
            i += 1
        if not path.endswith(".py"):
            continue
        if code == "??":
            files[path] = "untracked"
        elif "D" in code:
            files[path] = "deleted"
        elif "A" in code or code[0] in "RC":
            files[path] = "added"
        else:
            files[path] = "modified"
    return files


def head_source(repo: Path, path: str) -> str | None:
    result = _git(repo, "show", f"HEAD:{path}", check=False)
    return result.stdout.decode(errors="replace") if result.returncode == 0 else None


def function_changes(old: str | None, new: str | None) -> dict[str, dict]:
    """Functions added, modified or removed between two versions of a file.

    Raises SyntaxError if `new` does not parse. An unparseable `old` counts as empty.
    """
    try:
        before = function_hashes(old) if old else {}
    except SyntaxError:
        before = {}
    after = function_hashes(new) if new else {}
    spans = {name: [start, end] for name, start, end in function_spans(new)} if new else {}
    changes = {}
    for name in sorted(before.keys() | after.keys()):
        if before.get(name) == after.get(name):
            continue
        if name not in before:
            change = "added"
        elif name not in after:
            change = "removed"
        else:
            change = "modified"
        changes[name] = {"change": change, "lines": spans.get(name), "hash": after.get(name)}
    return changes


def _read(repo: Path, path: str) -> str | None:
    try:
        return (repo / path).read_text(errors="replace")
    except (FileNotFoundError, IsADirectoryError):
        return None


def poll(repo: Path, previous: dict | None = None, now: str | None = None) -> dict:
    """Build the next status from the working tree, carrying timestamps over from `previous`."""
    now = now or _now()
    prev_files = (previous or {}).get("files", {})
    files: dict[str, dict] = {}
    for path, git_status in sorted(modified_python_files(repo).items()):
        new_source = None if git_status == "deleted" else _read(repo, path)
        old_source = None if git_status == "untracked" else head_source(repo, path)
        prev = prev_files.get(path, {})
        entry: dict = {"status": git_status, "functions": {}}
        try:
            changes = function_changes(old_source, new_source)
        except SyntaxError as exc:
            entry["functions"] = prev.get("functions", {})
            entry["parse_error"] = f"line {exc.lineno}: {exc.msg}"
            files[path] = entry
            continue
        for name, info in changes.items():
            before = prev.get("functions", {}).get(name, {})
            same = before.get("change") == info["change"] and before.get("hash") == info["hash"]
            info["first_seen"] = before.get("first_seen", now)
            info["last_changed"] = before.get("last_changed", now) if same else now
            entry["functions"][name] = info
        if entry["functions"] or git_status in ("added", "untracked", "deleted"):
            files[path] = entry

    counts = {"added": 0, "modified": 0, "removed": 0}
    for entry in files.values():
        for info in entry["functions"].values():
            counts[info["change"]] += 1
    return {
        "version": STATUS_VERSION,
        "repo": str(repo),
        "head": head_sha(repo),
        "updated_at": now,
        "summary": {"files": len(files), **counts, "findings": 0},
        "files": files,
        "findings": [],
    }


def _comparable(status: dict) -> dict:
    """Status without the fields that change on every poll."""
    return {k: v for k, v in status.items() if k != "updated_at"}


def write_status(path: Path, status: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sentinel-status-")
    with os.fdopen(fd, "w") as fh:
        json.dump(status, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def load_status(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("version") == STATUS_VERSION else None


# --- optional scan of changed functions --------------------------------------

def scan_changed(repo: Path, status: dict) -> list[dict]:
    """Run the active detectors and keep findings inside or passing through changed functions."""
    from app.config import get_settings
    from app.detect.registry import active_detectors
    from app.early.scope import in_changed_code
    from app.ingest.filter import filter_project
    from app.pipeline import build_findings, run_detectors
    from app.schema import DetectedAt

    changed_lines: dict[str, set[int]] = {}
    for path, entry in status["files"].items():
        for info in entry["functions"].values():
            if info["lines"]:
                start, end = info["lines"]
                changed_lines.setdefault(path, set()).update(range(start, end + 1))
    if not changed_lines:
        return []
    detectors = active_detectors()
    if not detectors:
        return []
    settings = get_settings()
    files = filter_project(repo, settings.max_file_bytes).files
    scan_files = [f for f in files if f in changed_lines]
    if not scan_files:
        return []
    started = time.monotonic()
    candidates, _ = run_detectors(repo, scan_files, detectors, settings.detector_timeout_s,
                                  context_files=files)
    findings = build_findings("S-00000000", candidates, started=started,
                              detected_at=DetectedAt.WRITE)
    kept = in_changed_code(findings, changed_lines,
                           lambda rel: (repo / rel).read_text(errors="replace"))
    return [f.model_dump(mode="json") for f in kept]


def _finding_key(f: dict) -> tuple:
    return (f["file"], f["line"], f["cwe"])


def _report(status: dict, previous: dict | None, threshold: float) -> None:
    s = status["summary"]
    print(f"[{status['updated_at']}] {s['files']} files: {s['added']} added, "
          f"{s['modified']} modified, {s['removed']} removed functions"
          + (f", {s['findings']} findings" if status["findings"] else ""), flush=True)
    old = {_finding_key(f) for f in (previous or {}).get("findings", [])}
    for f in status["findings"]:
        if _finding_key(f) not in old:
            mark = "BLOCK" if f["severity"] >= threshold else "warn "
            print(f"  {mark} {f['severity']:4.1f}  {f['file']}:{f['line']}  {f['cwe']}  "
                  f"{' -> '.join(f['path']) or f['sink']}", flush=True)


def watch(repo: Path, status_path: Path, *, interval: float = 1.0, scan: bool = False,
          once: bool = False, max_polls: int | None = None, threshold: float = 7.0) -> dict:
    previous = load_status(status_path)
    polls = 0
    status = previous or {}
    while True:
        status = poll(repo, previous)
        if scan:
            status["findings"] = scan_changed(repo, status)
            status["summary"]["findings"] = len(status["findings"])
        if previous is None or _comparable(status) != _comparable(previous):
            write_status(status_path, status)
            _report(status, previous, threshold)
            previous = status
        polls += 1
        if once or (max_polls is not None and polls >= max_polls):
            return status
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel watch", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--status", type=Path, help=f"status file (default: .git/{STATUS_NAME})")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between polls")
    p.add_argument("--scan", action="store_true", help="scan changed functions for findings")
    p.add_argument("--once", action="store_true", help="poll once, write the status and exit")
    p.add_argument("--threshold", type=float, default=7.0)
    args = p.parse_args(argv)
    if args.interval <= 0:
        p.error("--interval must be positive")
    try:
        repo = repo_root(args.repo.resolve())
    except subprocess.CalledProcessError:
        print(f"sentinel watch: {args.repo} is not inside a git repository", file=sys.stderr)
        return 2
    status_path = (args.status or default_status_path(repo)).resolve()
    print(f"sentinel watch: {repo} -> {status_path}" + ("" if args.once else "  (Ctrl+C to stop)"),
          flush=True)
    try:
        watch(repo, status_path, interval=args.interval, scan=args.scan, once=args.once,
              threshold=args.threshold)
    except KeyboardInterrupt:
        print("\nsentinel watch: stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
