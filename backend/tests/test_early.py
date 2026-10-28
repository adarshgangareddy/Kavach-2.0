import json
import subprocess
import time

import pytest

from app import cli
from app.detect.registry import use_detectors
from app.early import hook
from app.early.incremental import (ResultCache, affected_functions, changed_since,
                                   function_hashes, scan_incremental)
from tests.conftest import APP_SOURCE, MarkerDetector, write


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test")
    git(path, "config", "commit.gpgsign", "false")
    write(path, "app/routes.py", "def index():\n    return 'ok'\n")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "init")
    return path


# --- incremental cache -------------------------------------------------------

def test_cache_reuses_unchanged_files(tmp_path):
    write(tmp_path, "a.py", APP_SOURCE)
    write(tmp_path, "b.py", "x = 1\n")
    det = MarkerDetector()
    cache = ResultCache(tmp_path / "cache.json")
    first, _, stats = scan_incremental(tmp_path, ["a.py", "b.py"], [det], cache, 10)
    assert stats == {"cached": 0, "scanned": 2} and len(first) == 2
    cache.save()

    write(tmp_path, "b.py", "x = 2\n")
    reloaded = ResultCache(tmp_path / "cache.json")
    second, _, stats = scan_incremental(tmp_path, ["a.py", "b.py"], [det], reloaded, 10)
    assert stats == {"cached": 1, "scanned": 1}
    assert det.calls[-1] == ["b.py"]
    assert [c.model_dump() for c in second] == [c.model_dump() for c in first]


def test_cache_key_depends_on_detector_version():
    assert ResultCache.key("a.py", b"x", "d@1") != ResultCache.key("a.py", b"x", "d@2")
    assert ResultCache.key("a.py", b"x", "d@1") != ResultCache.key("b.py", b"x", "d@1")


def test_corrupt_cache_is_ignored(tmp_path):
    (tmp_path / "cache.json").write_text("{not json")
    assert ResultCache(tmp_path / "cache.json").entries == {}


def test_function_level_change_tracking():
    old = function_hashes("def a():\n    return 1\n\ndef b():\n    return a()\n")
    new = function_hashes("def a():\n    return 2\n\ndef b():\n    return a()\n\ndef c():\n    pass\n")
    assert changed_since(old, new) == {"a", "c"}
    callers = {"a": {"b"}, "b": {"route"}, "route": set()}
    assert affected_functions({"a"}, callers) == {"a", "b", "route"}


# --- pre-commit hook ---------------------------------------------------------

def test_hook_blocks_high_severity_staged_change(repo, capsys):
    write(repo, "app/routes.py", APP_SOURCE)
    git(repo, "add", ".")
    with use_detectors([MarkerDetector()]):
        started = time.monotonic()
        code = hook.main(["--repo", str(repo)])
        elapsed = time.monotonic() - started
    out = capsys.readouterr()
    assert code == 1
    assert "BLOCK" in out.out and "app/routes.py:6" in out.out
    assert "commit blocked" in out.err
    assert elapsed < 5


def test_hook_scans_staged_content_not_working_copy(repo):
    write(repo, "app/routes.py", "def index():\n    return 'clean'\n")
    git(repo, "add", ".")
    write(repo, "app/routes.py", APP_SOURCE)  # unstaged
    with use_detectors([MarkerDetector()]):
        assert hook.main(["--repo", str(repo)]) == 0


def test_hook_ignores_findings_outside_changed_code(repo):
    write(repo, "app/routes.py", APP_SOURCE)
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "existing debt")
    write(repo, "app/routes.py", APP_SOURCE + "\n\ndef added():\n    return 1\n")
    git(repo, "add", ".")
    with use_detectors([MarkerDetector()]):
        assert hook.main(["--repo", str(repo)]) == 0
        assert hook.main(["--repo", str(repo), "--all"]) == 1


def test_hook_threshold_bypass_and_ignored_paths(repo, monkeypatch):
    write(repo, "app/routes.py", APP_SOURCE)
    write(repo, "tests/test_x.py", "# sentinel-fixture: CWE-78 reachable public\n")
    git(repo, "add", ".")
    with use_detectors([MarkerDetector()]):
        assert hook.main(["--repo", str(repo), "--threshold", "9.5"]) == 0
        monkeypatch.setenv("SENTINEL_SKIP", "1")
        assert hook.main(["--repo", str(repo)]) == 0


def test_hook_without_detectors_does_not_block(repo, capsys):
    write(repo, "app/routes.py", APP_SOURCE)
    git(repo, "add", ".")
    with use_detectors([]):
        assert hook.main(["--repo", str(repo)]) == 0
    assert "no detectors" in capsys.readouterr().err


# --- CLI (used by the GitHub Action) ----------------------------------------

def test_cli_diff_scan_writes_valid_sarif(repo, tmp_path):
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, "app/routes.py", APP_SOURCE)
    git(repo, "commit", "-qam", "change")
    out = tmp_path / "out.sarif"
    with use_detectors([MarkerDetector()]):
        code = cli.main(["scan", str(repo), "--diff-base", "main", "--format", "sarif",
                         "--out", str(out), "--fail-on", "7"])
    assert code == 1
    doc = json.loads(out.read_text())
    assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {"CWE-89", "CWE-22"}
    assert cli.main(["validate-sarif", str(out)]) == 0


def test_cli_default_never_fails(repo):
    write(repo, "app/routes.py", APP_SOURCE)
    with use_detectors([MarkerDetector()]):
        assert cli.main(["scan", str(repo), "--format", "json"]) == 0
