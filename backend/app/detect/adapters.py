"""Adapters that convert Bandit and Semgrep JSON output into Candidates.

These are the "rule layer" baseline. They are also what eval/ compares the
team's own engine against.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from app.detect.base import Candidate

_CWE = re.compile(r"CWE-(\d+)")
_CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
_BATCH = 200


def _batches(files: list[str]) -> list[list[str]]:
    return [files[i:i + _BATCH] for i in range(0, len(files), _BATCH)]


def _run_json(cmd: list[str], root: Path, timeout_s: float) -> dict:
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=timeout_s)
    if not proc.stdout.strip():
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"{cmd[0]} failed: {proc.stderr.strip()[:300]}")
        return {}
    return json.loads(proc.stdout)


def _rel(path: str) -> str:
    return path.removeprefix("./")


def _exe(name: str) -> str:
    """Absolute path to a tool, since detectors run with cwd set to the project."""
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"{name} is not installed")
    return str(Path(path).resolve())


class BanditDetector:
    name = "bandit"
    version = "adapter-1"

    def available(self) -> bool:
        return shutil.which("bandit") is not None

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        out: list[Candidate] = []
        for batch in _batches(files):
            data = _run_json([_exe("bandit"), "-q", "-f", "json", "--", *batch], root, timeout_s)
            out.extend(self._convert(r) for r in data.get("results", []))
        return out

    def _convert(self, r: dict) -> Candidate:
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        return Candidate(
            file=_rel(r["filename"]),
            line=max(int(r.get("line_number", 1)), 1),
            cwe=f"CWE-{cwe_id}" if cwe_id else "CWE-unknown",
            detector=self.name,
            sink=f"{r.get('test_id', '')}:{r.get('test_name', '')}",
            confidence=_CONFIDENCE.get(r.get("issue_confidence", ""), 0.5),
        )


class SemgrepDetector:
    name = "semgrep"
    version = "adapter-1"

    def __init__(self) -> None:
        self.config = os.environ.get("SENTINEL_SEMGREP_CONFIG", "p/python")

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        out: list[Candidate] = []
        for batch in _batches(files):
            cmd = [_exe("semgrep"), "scan", "--json", "--quiet", "--metrics=off",
                   "--config", self.config, "--", *batch]
            data = _run_json(cmd, root, timeout_s)
            out.extend(self._convert(r) for r in data.get("results", []))
        return out

    def _convert(self, r: dict) -> Candidate:
        meta = r.get("extra", {}).get("metadata", {})
        cwe_field = meta.get("cwe", "")
        cwe_text = " ".join(cwe_field) if isinstance(cwe_field, list) else str(cwe_field)
        match = _CWE.search(cwe_text)
        return Candidate(
            file=_rel(r["path"]),
            line=max(int(r.get("start", {}).get("line", 1)), 1),
            cwe=f"CWE-{match[1]}" if match else "CWE-unknown",
            detector=self.name,
            sink=r.get("check_id", ""),
            confidence=_CONFIDENCE.get(str(meta.get("confidence", "")).upper(), 0.5),
        )
