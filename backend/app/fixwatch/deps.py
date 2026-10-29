"""The project's pinned dependencies, read from requirements files and pyproject.toml."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from app.ingest.filter import SKIP_DIRS

PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)")
MAX_DEPTH = 3  # requirements files are near the project root


@dataclass(frozen=True)
class Dependency:
    name: str      # normalised (PEP 503): lower case, runs of -_. become -
    version: str
    file: str      # relative to the project root
    line: int
    spec: str      # as written, e.g. "Flask==2.0.1"


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pin(spec: str, file: str, line: int) -> Dependency | None:
    """Only exact pins (==) are checked: a range does not say which version is installed."""
    m = PIN.match(spec.split(";")[0])
    return Dependency(normalise(m[1]), m[2], file, line, spec.strip()) if m else None


def parse_requirements(text: str, file: str) -> list[Dependency]:
    found = []
    for no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #")[0].strip()
        if line and not line.startswith(("#", "-")) and (dep := _pin(line, file, no)):
            found.append(dep)
    return found


def parse_pyproject(text: str, file: str) -> list[Dependency]:
    try:
        specs = tomllib.loads(text).get("project", {}).get("dependencies", [])
    except tomllib.TOMLDecodeError:
        return []
    lines = text.splitlines()
    found = []
    for spec in specs:
        no = next((i for i, l in enumerate(lines, start=1) if spec in l), 1)
        if dep := _pin(spec, file, no):
            found.append(dep)
    return found


def _skipped(rel: Path) -> bool:
    return len(rel.parts) > MAX_DEPTH or any(p in SKIP_DIRS for p in rel.parts[:-1])


def find_dependencies(root: Path) -> list[Dependency]:
    """Pinned dependencies from requirements*.txt and pyproject.toml, first mention of each kept."""
    found: dict[str, Dependency] = {}
    # The main files first (requirements.txt, pyproject.toml), shallowest first, then -dev and friends.
    files = sorted([*root.rglob("requirements*.txt"), *root.rglob("pyproject.toml")],
                   key=lambda p: (p.name not in {"requirements.txt", "pyproject.toml"}, len(p.parts), p.as_posix()))
    for path in files:
        rel = path.relative_to(root)
        if _skipped(rel) or path.is_symlink() or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        parse = parse_pyproject if path.name == "pyproject.toml" else parse_requirements
        for dep in parse(text, rel.as_posix()):
            found.setdefault(dep.name, dep)
    return list(found.values())
