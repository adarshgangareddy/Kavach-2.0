"""Incremental analysis: reuse results for unchanged code.

Two levels:
- ResultCache: content-addressed detector results per file. This is what keeps
  the pre-commit hook fast today.
- function_hashes / affected_functions: per-function change tracking for the
  team's taint engine, which should re-analyse changed functions and their
  callers only (it supplies the caller map from its call graph).
"""

import hashlib
import json
import os
import tempfile
from collections import deque
from collections.abc import Mapping
from pathlib import Path

from app.detect.base import Candidate, Detector, is_whole_program
from app.ingest.diff import function_spans
from app.pipeline import run_detectors

CACHE_VERSION = 1
MAX_ENTRIES = 5000


def detector_signature(detectors: list[Detector]) -> str:
    return ",".join(sorted(f"{d.name}@{d.version}" for d in detectors))


class ResultCache:
    def __init__(self, path: Path):
        self.path = path
        self.entries: dict[str, list[dict]] = {}
        try:
            data = json.loads(path.read_text())
            if data.get("version") == CACHE_VERSION:
                self.entries = data.get("entries", {})
        except (OSError, ValueError):
            pass

    @staticmethod
    def key(rel: str, content: bytes, signature: str) -> str:
        h = hashlib.sha256()
        for part in (signature.encode(), rel.encode(), content):
            h.update(len(part).to_bytes(8, "big"))
            h.update(part)
        return h.hexdigest()

    def get(self, key: str) -> list[Candidate] | None:
        raw = self.entries.get(key)
        return None if raw is None else [Candidate.model_validate(c) for c in raw]

    def put(self, key: str, candidates: list[Candidate]) -> None:
        self.entries.pop(key, None)
        self.entries[key] = [c.model_dump(mode="json") for c in candidates]
        while len(self.entries) > MAX_ENTRIES:
            self.entries.pop(next(iter(self.entries)))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".sentinel-cache-")
        with os.fdopen(fd, "w") as fh:
            json.dump({"version": CACHE_VERSION, "entries": self.entries}, fh)
        os.replace(tmp, self.path)


def scan_incremental(root: Path, files: list[str], detectors: list[Detector],
                     cache: ResultCache, timeout_s: float,
                     context_files: list[str] | None = None):
    """Return (candidates, notes, stats).

    Per-file detectors re-scan only files whose content changed. Whole-program
    detectors always run over `context_files` (or `files`) and are not cached.
    """
    whole = [d for d in detectors if is_whole_program(d)]
    detectors = [d for d in detectors if not is_whole_program(d)]
    candidates, notes = run_detectors(root, files, whole, timeout_s, context_files)
    if not detectors:
        return candidates, notes, {"cached": 0, "scanned": len(files)}
    signature = detector_signature(detectors)
    keys = {rel: ResultCache.key(rel, (root / rel).read_bytes(), signature) for rel in files}
    misses: list[str] = []
    for rel, key in keys.items():
        cached = cache.get(key)
        if cached is None:
            misses.append(rel)
        else:
            candidates.extend(cached)

    fresh, fresh_notes = run_detectors(root, misses, detectors, timeout_s)
    candidates.extend(fresh)
    notes.extend(fresh_notes)
    if not fresh_notes:  # never cache a run where a detector failed
        by_file: dict[str, list[Candidate]] = {rel: [] for rel in misses}
        for cand in fresh:
            by_file.setdefault(cand.file, []).append(cand)
        for rel in misses:
            cache.put(keys[rel], by_file[rel])
    return candidates, notes, {"cached": len(files) - len(misses), "scanned": len(misses)}


def function_hashes(source: str) -> dict[str, str]:
    """Hash of each function's source text, keyed by qualified name."""
    lines = source.splitlines()
    return {
        name: hashlib.sha256("\n".join(lines[start - 1:end]).encode()).hexdigest()
        for name, start, end in function_spans(source)
    }


def changed_since(old: Mapping[str, str], new: Mapping[str, str]) -> set[str]:
    """Functions that were added, edited or removed."""
    return {n for n in old.keys() | new.keys() if old.get(n) != new.get(n)}


def affected_functions(changed: set[str], callers: Mapping[str, set[str]]) -> set[str]:
    """Changed functions plus every transitive caller (callers: callee -> {callers})."""
    seen = set(changed)
    queue = deque(changed)
    while queue:
        for caller in callers.get(queue.popleft(), ()):
            if caller not in seen:
                seen.add(caller)
                queue.append(caller)
    return seen
