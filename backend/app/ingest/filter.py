"""File filter: choose which Python files in a project tree get scanned."""

import fnmatch
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", "venv", ".venv", "env", ".env", "site-packages",
    "node_modules", "vendor", "vendored", "third_party", "build", "dist",
    "tests", "test", "testing",
})
SKIP_FILES = ("test_*.py", "*_test.py", "conftest.py", "setup.py")


@dataclass
class FilterResult:
    files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def is_ignored(rel_path: str) -> bool:
    """True if a project-relative path should not be scanned."""
    parts = PurePosixPath(rel_path).parts
    if not parts or not rel_path.endswith(".py"):
        return True
    if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts[:-1]):
        return True
    return any(fnmatch.fnmatch(parts[-1], pat) for pat in SKIP_FILES)


def _is_virtualenv(path: Path) -> bool:
    return (path / "pyvenv.cfg").exists()


def filter_project(root: Path, max_file_bytes: int) -> FilterResult:
    result = FilterResult()
    other = Counter()
    ignored = too_big = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(".egg-info")
            and not _is_virtualenv(here / d) and not (here / d).is_symlink()
        )
        for name in sorted(filenames):
            path = here / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                ignored += 1
            elif not name.endswith(".py"):
                other[path.suffix or "(no extension)"] += 1
            elif is_ignored(rel):
                ignored += 1
            elif path.stat().st_size > max_file_bytes:
                too_big += 1
            else:
                result.files.append(rel)
    if other:
        detail = ", ".join(f"{ext}: {n}" for ext, n in other.most_common(5))
        result.notes.append(f"Skipped {sum(other.values())} non-Python files ({detail}).")
    if ignored:
        result.notes.append(f"Skipped {ignored} test, vendored or symlinked Python files.")
    if too_big:
        result.notes.append(f"Skipped {too_big} Python files larger than {max_file_bytes // 1024} KB.")
    if not result.files:
        result.notes.append("No Python files to scan.")
    return result
