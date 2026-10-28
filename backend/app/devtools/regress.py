"""Regression test runner: run only the pytest tests affected by changed files.

    cd backend
    .venv/bin/python -m app.devtools.regress                    # uncommitted changes
    .venv/bin/python -m app.devtools.regress --base origin/main # plus everything on this branch
    .venv/bin/python -m app.devtools.regress --files backend/app/pipeline.py --dry-run

Same idea as the scanner's incremental mode (L3), applied to our own code:
1. Find changed files with git (committed since --base, staged, unstaged, untracked).
2. Build the import graph of `app/` and `tests/` with `ast` (no code is imported).
3. A changed module affects every module that imports it, directly or indirectly;
   a test runs if it imports an affected module, or is itself changed.
4. Fall back to the full suite whenever narrowing would be unsafe: conftest or
   packaging changes, a change to something conftest imports, or an unrecognised
   backend file.
"""

import argparse
import ast
import subprocess
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent

RUN_ALL_FILES = {"pyproject.toml", "tests/conftest.py", "tests/__init__.py"}
# Non-Python files whose contents change a module's behaviour.
CONFIG_MODULES = {
    "sentinel-rules.toml": "app.detect.taint",
    "sentinel-model.json": "app.rank.model",
}
# Detection regression tests also depend on the seeded targets (outside backend/).
TARGET_TESTS = ("tests/test_targets_regression.py",)
IGNORED_SUFFIXES = (".md", ".txt", ".png", ".svg")


@dataclass
class Selection:
    tests: dict[str, list[str]] = field(default_factory=dict)  # test file -> reasons
    run_all: str | None = None
    notes: list[str] = field(default_factory=list)

    def add(self, test: str, reason: str) -> None:
        self.tests.setdefault(test, [])
        if reason not in self.tests[test]:
            self.tests[test].append(reason)


# --- import graph ------------------------------------------------------------

def module_name(rel: PurePosixPath) -> str:
    """'app/rank/model.py' -> 'app.rank.model'; 'app/rank/__init__.py' -> 'app.rank'."""
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _parents(name: str) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[:i]) for i in range(1, len(parts))]


def _imports(path: Path, own_name: str, is_package: bool, known: set[str]) -> set[str]:
    """Project modules imported by a file, including the packages Python runs on the way."""
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except SyntaxError:
        return set()
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = own_name.split(".")
                base = base[:len(base) - node.level + (1 if is_package else 0)]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            found.add(module)
            found.update(f"{module}.{a.name}" for a in node.names)  # `from pkg import submodule`
    resolved = set()
    for name in found:
        while name and name not in known:  # `import app.x.Y` (a class) -> app.x
            name = name.rpartition(".")[0]
        if name:
            resolved.add(name)
            resolved.update(p for p in _parents(name) if p in known)
    resolved.discard(own_name)
    return resolved


def build_graph(backend: Path) -> dict[str, set[str]]:
    """module -> project modules it imports. Covers app/ and tests/."""
    files = {}
    for top in ("app", "tests"):
        for path in sorted((backend / top).rglob("*.py")):
            if "__pycache__" not in path.parts:
                files[module_name(PurePosixPath(path.relative_to(backend).as_posix()))] = path
    known = set(files)
    return {name: _imports(path, name, path.name == "__init__.py", known)
            for name, path in files.items()}


def importers_closure(changed: set[str], graph: dict[str, set[str]]) -> set[str]:
    """Changed modules plus every module that imports them, transitively."""
    reverse: dict[str, set[str]] = {}
    for module, deps in graph.items():
        for dep in deps:
            reverse.setdefault(dep, set()).add(module)
    seen = set(changed)
    queue = deque(changed)
    while queue:
        for importer in reverse.get(queue.popleft(), ()):
            if importer not in seen:
                seen.add(importer)
                queue.append(importer)
    return seen


# --- selection ---------------------------------------------------------------

def _test_files(backend: Path) -> list[str]:
    return sorted(p.relative_to(backend).as_posix() for p in (backend / "tests").glob("test_*.py"))


def select(changed_files: list[str], backend: Path = BACKEND, repo: Path = REPO,
           config_modules: dict[str, str] = CONFIG_MODULES) -> Selection:
    """Decide which tests to run. `changed_files` are repo-relative paths."""
    sel = Selection()
    prefix = backend.relative_to(repo).as_posix() + "/" if backend != repo else ""
    changed_modules: dict[str, str] = {}
    targets_changed = False

    for raw in changed_files:
        path = raw.replace("\\", "/")
        if path.startswith("targets/"):
            targets_changed = True
            continue
        if not path.startswith(prefix):
            if path.startswith("frontend/"):
                note = "frontend changed: run `cd frontend && npm run build`"
                if note not in sel.notes:
                    sel.notes.append(note)
            continue
        rel = path[len(prefix):]
        if rel in RUN_ALL_FILES:
            sel.run_all = f"{path} changed"
        elif rel in config_modules:
            changed_modules[config_modules[rel]] = path
        elif rel.startswith("tests/") and PurePosixPath(rel).name.startswith("test_") \
                and rel.endswith(".py"):
            if (backend / rel).exists():
                sel.add(rel, "test file changed")
        elif rel.startswith(("app/", "tests/")) and rel.endswith(".py"):
            changed_modules[module_name(PurePosixPath(rel))] = path
        elif rel.endswith(IGNORED_SUFFIXES) or "/__pycache__/" in f"/{rel}" or \
                rel.startswith((".venv/", ".sentinel-data/", ".pytest_cache/")) or \
                ".egg-info/" in rel or rel.endswith(".jsonl"):
            continue
        elif sel.run_all is None:
            sel.run_all = f"{path} changed and its test impact is unknown"

    if sel.run_all:
        return sel

    graph = build_graph(backend)
    affected = importers_closure(set(changed_modules), graph)
    if "tests.conftest" in affected:
        sel.run_all = "a module that tests/conftest.py imports changed"
        return sel

    reach = {module: importers_closure({module}, graph) for module in changed_modules}
    for test in _test_files(backend):
        name = module_name(PurePosixPath(test))
        for module, path in sorted(changed_modules.items()):
            if name in reach[module]:
                sel.add(test, f"depends on {path}")
    if targets_changed:
        for test in TARGET_TESTS:
            if (backend / test).exists():
                sel.add(test, "seeded targets changed")
    return sel


# --- git ---------------------------------------------------------------------

def _git_names(repo: Path, *args: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                         text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def changed_files(repo: Path = REPO, base: str | None = None) -> list[str]:
    """Repo-relative paths changed since `base` (if given) plus uncommitted work."""
    names: set[str] = set()
    if base:
        names.update(_git_names(repo, "diff", "--name-only", f"{base}...HEAD"))
    names.update(_git_names(repo, "diff", "--name-only", "HEAD"))
    names.update(_git_names(repo, "ls-files", "--others", "--exclude-standard"))
    return sorted(names)


# --- CLI ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.devtools.regress", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", help="also include changes committed since this ref")
    p.add_argument("--files", nargs="+", help="use these repo-relative paths instead of git")
    p.add_argument("--all", action="store_true", help="run the full suite")
    p.add_argument("--dry-run", action="store_true", help="show the selection, run nothing")
    p.add_argument("pytest_args", nargs=argparse.REMAINDER,
                   help="extra arguments for pytest, after --")
    args = p.parse_args(argv)
    extra = [a for a in args.pytest_args if a != "--"]

    try:
        files = args.files if args.files else changed_files(REPO, args.base)
    except subprocess.CalledProcessError as exc:
        print(f"regress: git failed: {exc.stderr.strip() or exc}", file=sys.stderr)
        return 2
    sel = Selection(run_all="--all given") if args.all else select(files)

    print(f"regress: {len(files)} changed files")
    for note in sel.notes:
        print(f"  note: {note}")
    if sel.run_all:
        print(f"regress: running the full suite ({sel.run_all})")
        targets = []
    elif not sel.tests:
        print("regress: no affected tests")
        return 0
    else:
        print(f"regress: {len(sel.tests)} of {len(_test_files(BACKEND))} test files affected")
        for test, reasons in sorted(sel.tests.items()):
            print(f"  {test}  ({'; '.join(reasons[:2])}{', ...' if len(reasons) > 2 else ''})")
        targets = sorted(sel.tests)
    if args.dry_run:
        return 0
    sys.stdout.flush()  # keep our summary above pytest's output
    return subprocess.run([sys.executable, "-m", "pytest", "-q", *targets, *extra],
                          cwd=BACKEND).returncode


if __name__ == "__main__":
    sys.exit(main())
