"""Shared fixtures.

Tests never use real vulnerable code. `MarkerDetector` stands in for the team's
detection engine: it reports a finding wherever a file contains a comment like

    # sentinel-fixture: CWE-89 reachable public

which lets every layer after detection be tested against known, fake findings
(the PRD's "handoff test with fake findings").
"""

import re
from pathlib import Path

import pytest

from app.detect.base import Candidate
from app.detect.registry import use_detectors
from app.schema import ConfidenceTier

_MARKER = re.compile(r"#\s*sentinel-fixture:\s*(CWE-\d+)((?:\s+\w+)*)")


class MarkerDetector:
    name = "marker"
    version = "test-1"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def available(self) -> bool:
        return True

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        self.calls.append(list(files))
        out = []
        for rel in files:
            for no, text in enumerate((root / rel).read_text().splitlines(), start=1):
                if m := _MARKER.search(text):
                    flags = set(m[2].split())
                    out.append(Candidate(
                        file=rel, line=no, cwe=m[1], detector=self.name,
                        source="request.args['q']" if "reachable" in flags else "",
                        sink="fixture_sink",
                        path=["route()", "helper()", "fixture_sink"] if "reachable" in flags else [],
                        confidence_tier=(ConfidenceTier.REACHABLE if "reachable" in flags
                                         else ConfidenceTier.PATTERN_MATCH),
                        confidence=0.9 if "reachable" in flags else 0.4,
                        reachable="reachable" in flags,
                        public_route="public" in flags,
                        sanitizer_present="sanitized" in flags,
                    ))
        return out


class BrokenDetector:
    name = "broken"
    version = "test-1"

    def available(self) -> bool:
        return True

    def scan(self, root, files, timeout_s):
        raise RuntimeError("boom")


@pytest.fixture
def marker():
    det = MarkerDetector()
    with use_detectors([det]):
        yield det


@pytest.fixture
def no_detectors():
    with use_detectors([]):
        yield


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DATA", str(tmp_path / "data"))
    # Never let a real trained model on disk change test results.
    monkeypatch.setenv("SENTINEL_MODEL", str(tmp_path / "no-model.json"))
    return tmp_path / "data"


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


APP_SOURCE = '''\
def index():
    return "ok"


def search(term):
    value = term.strip()  # sentinel-fixture: CWE-89 reachable public
    return value


def helper(name):
    return name  # sentinel-fixture: CWE-22
'''
