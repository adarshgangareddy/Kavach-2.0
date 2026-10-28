"""Diff reader: map changed lines in a git diff to the functions that contain them."""

import ast
import re
import subprocess
from pathlib import Path

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

ChangedLines = dict[str, set[int]]


def parse_unified_diff(text: str) -> ChangedLines:
    """Return {new_file_path: {added or modified line numbers}}."""
    changes: ChangedLines = {}
    current: set[int] | None = None
    line_no = 0
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].split("\t")[0]
            current = None if target == "/dev/null" else changes.setdefault(target.removeprefix("b/"), set())
        elif raw.startswith("--- ") or raw.startswith("diff --git"):
            continue
        elif (hunk := _HUNK.match(raw)) and current is not None:
            line_no = int(hunk[1])
            if hunk[2] == "0":  # pure deletion: mark the line it happened at
                current.add(max(line_no, 1))
        elif current is not None and raw.startswith("+"):
            current.add(line_no)
            line_no += 1
        elif current is not None and raw.startswith(" "):
            line_no += 1
    return {path: lines for path, lines in changes.items() if lines}


def function_spans(source: str) -> list[tuple[str, int, int]]:
    """(qualified name, first line, last line) for every function, including methods."""
    spans: list[tuple[str, int, int]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{child.name}"
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                spans.append((name, start, child.end_lineno or child.lineno))
                visit(child, f"{name}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")

    visit(ast.parse(source), "")
    return spans


def changed_functions(source: str, lines: set[int]) -> set[str]:
    """Innermost function names touched by `lines`; '<module>' for top-level changes."""
    try:
        spans = function_spans(source)
    except SyntaxError:
        return {"<module>"}
    touched: set[str] = set()
    for line in lines:
        owners = [s for s in spans if s[1] <= line <= s[2]]
        touched.add(min(owners, key=lambda s: s[2] - s[1])[0] if owners else "<module>")
    return touched


def enclosing_function(source: str, line: int) -> str:
    return next(iter(changed_functions(source, {line})))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True, check=True).stdout


def staged_diff(repo: Path) -> ChangedLines:
    return parse_unified_diff(_git(repo, "diff", "--cached", "-U0", "--no-color", "--", "*.py"))


def diff_against(repo: Path, base: str) -> ChangedLines:
    return parse_unified_diff(_git(repo, "diff", "-U0", "--no-color", f"{base}...HEAD", "--", "*.py"))
