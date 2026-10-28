"""Adapter conversion tests use recorded-shape JSON; Bandit/Semgrep need not be installed."""

import json
import shutil
import subprocess

import pytest

from app.detect.adapters import BanditDetector, SemgrepDetector


@pytest.fixture(autouse=True)
def fake_tools(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: f"/opt/tools/{name}")


class _Proc:
    def __init__(self, payload, returncode=1):
        self.stdout = json.dumps(payload)
        self.stderr = ""
        self.returncode = returncode


def test_bandit_conversion(monkeypatch, tmp_path):
    payload = {"results": [{
        "filename": "./app/views.py", "line_number": 12, "test_id": "B000",
        "test_name": "example_check", "issue_confidence": "HIGH",
        "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
    }]}
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Proc(payload)

    monkeypatch.setattr(subprocess, "run", fake_run)
    [cand] = BanditDetector().scan(tmp_path, ["app/views.py"], 10)
    assert (cand.file, cand.line, cand.cwe, cand.confidence) == ("app/views.py", 12, "CWE-78", 0.9)
    assert cand.sink == "B000:example_check"
    assert seen["cmd"][-2:] == ["--", "app/views.py"]


def test_semgrep_conversion(monkeypatch, tmp_path):
    payload = {"results": [{
        "path": "app/db.py", "start": {"line": 4}, "check_id": "rules.example",
        "extra": {"metadata": {"cwe": ["CWE-89: Improper Neutralization"], "confidence": "medium"}},
    }]}
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Proc(payload))
    [cand] = SemgrepDetector().scan(tmp_path, ["app/db.py"], 10)
    assert (cand.cwe, cand.line, cand.confidence) == ("CWE-89", 4, 0.6)


def test_missing_cwe_and_empty_output(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Proc(
        {"results": [{"filename": "a.py", "line_number": 0}]}))
    [cand] = BanditDetector().scan(tmp_path, ["a.py"], 10)
    assert cand.cwe == "CWE-unknown" and cand.line == 1

    class Empty(_Proc):
        def __init__(self):
            super().__init__({}, 0)
            self.stdout = ""
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: Empty())
    assert SemgrepDetector().scan(tmp_path, ["a.py"], 10) == []
