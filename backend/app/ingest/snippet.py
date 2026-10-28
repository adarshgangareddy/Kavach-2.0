"""Snippet scanner: turn one pasted function into a one-file project."""

import ast
import re
import textwrap
from pathlib import Path

from app.config import Settings
from app.ingest import IngestError

_FILENAME = re.compile(r"^[A-Za-z0-9_-]{1,64}\.py$")


def normalize_snippet(code: str) -> tuple[str, list[str]]:
    """Return parseable source and notes. Falls back to dedenting pasted code."""
    notes: list[str] = []
    for candidate in (code, textwrap.dedent(code)):
        try:
            ast.parse(candidate)
            if candidate is not code:
                notes.append("Removed common indentation from the pasted code.")
            return candidate, notes
        except SyntaxError:
            continue
    try:
        ast.parse(code)
    except SyntaxError as exc:
        notes.append(f"Snippet does not parse (line {exc.lineno}: {exc.msg}); "
                     "results may be incomplete.")
    return code, notes


def write_snippet(code: str, filename: str, dest: Path, settings: Settings) -> tuple[str, list[str]]:
    if len(code.encode()) > settings.max_snippet_bytes:
        raise IngestError(f"Snippet exceeds {settings.max_snippet_bytes // 1024} KB.", 413)
    if not _FILENAME.match(filename):
        raise IngestError("Filename must be a plain name ending in .py.")
    source, notes = normalize_snippet(code)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / filename).write_text(source, encoding="utf-8")
    notes.append("Imports are not resolved for snippets; calls into unseen modules are treated as unknown.")
    return filename, notes
