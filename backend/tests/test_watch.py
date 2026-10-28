"""sentinel watch, exercised in temporary git repositories with neutral code."""

import json
import subprocess

import pytest

from app import cli
from app.detect.registry import use_detectors
from app.early import watch
from tests.conftest import MarkerDetector, write

BASE = "def keep():\n    return 1\n\n\ndef edit_me(x):\n    return x\n\n\ndef drop_me():\n    pass\n"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "t@example.com")
    git(path, "config", "user.name", "T")
    git(path, "config", "commit.gpgsign", "false")
    write(path, "app/views.py", BASE)
    write(path, "README.md", "hi\n")
    git(path, "add", ".")
    git(path, "commit", "-qm", "init")
    return path


def test_function_changes():
    new = "def keep():\n    return 1\n\n\ndef edit_me(x):\n    return x + 1\n\n\ndef fresh():\n    pass\n"
    changes = watch.function_changes(BASE, new)
    assert {n: c["change"] for n, c in changes.items()} == {
        "edit_me": "modified", "fresh": "added", "drop_me": "removed"}
    assert changes["edit_me"]["lines"] == [5, 6]
    assert changes["drop_me"]["lines"] is None
    with pytest.raises(SyntaxError):
        watch.function_changes(BASE, "def broken(:\n")


def test_moving_a_function_down_is_not_a_change():
    assert watch.function_changes(BASE, "\n\n# comment\n" + BASE) == {}


def test_clean_tree_has_no_files(repo):
    status = watch.poll(repo)
    assert status["files"] == {} and status["summary"]["files"] == 0
    assert status["head"]


def test_modified_added_untracked_and_deleted_files(repo):
    write(repo, "app/views.py", BASE.replace("return x", "return x * 2"))
    write(repo, "app/new_module.py", "def hello():\n    pass\n")       # untracked
    write(repo, "app/staged.py", "def staged():\n    pass\n")
    git(repo, "add", "app/staged.py")                                  # added
    write(repo, "notes.txt", "not python\n")
    status = watch.poll(repo)
    files = status["files"]
    assert set(files) == {"app/views.py", "app/new_module.py", "app/staged.py"}
    assert files["app/views.py"]["status"] == "modified"
    assert list(files["app/views.py"]["functions"]) == ["edit_me"]
    assert files["app/new_module.py"]["functions"]["hello"]["change"] == "added"
    assert files["app/staged.py"]["status"] == "added"
    assert status["summary"] == {"files": 3, "added": 2, "modified": 1, "removed": 0, "findings": 0}

    (repo / "app/views.py").unlink()
    deleted = watch.poll(repo)["files"]["app/views.py"]
    assert deleted["status"] == "deleted"
    assert {i["change"] for i in deleted["functions"].values()} == {"removed"}


def test_module_level_edit_without_function_change_is_not_listed(repo):
    write(repo, "app/views.py", "import os\n" + BASE)
    assert watch.poll(repo)["files"] == {}


def test_timestamps_track_first_seen_and_last_changed(repo):
    write(repo, "app/views.py", BASE.replace("return x", "return x * 2"))
    first = watch.poll(repo, now="t1")
    same = watch.poll(repo, first, now="t2")
    assert same["files"]["app/views.py"]["functions"]["edit_me"]["last_changed"] == "t1"
    write(repo, "app/views.py", BASE.replace("return x", "return x * 3"))
    again = watch.poll(repo, same, now="t3")
    info = again["files"]["app/views.py"]["functions"]["edit_me"]
    assert (info["first_seen"], info["last_changed"]) == ("t1", "t3")


def test_parse_error_keeps_last_known_functions(repo):
    write(repo, "app/views.py", BASE.replace("return x", "return x * 2"))
    good = watch.poll(repo)
    write(repo, "app/views.py", BASE + "\ndef half_typed(:\n")
    broken = watch.poll(repo, good)["files"]["app/views.py"]
    assert "parse_error" in broken
    assert broken["functions"] == good["files"]["app/views.py"]["functions"]


def test_reverting_removes_the_file_from_status(repo):
    write(repo, "app/views.py", BASE.replace("return x", "return x * 2"))
    assert watch.poll(repo)["files"]
    write(repo, "app/views.py", BASE)
    assert watch.poll(repo)["files"] == {}


def test_watch_writes_only_on_change(repo, tmp_path, capsys):
    status_path = tmp_path / "status.json"
    write(repo, "app/views.py", BASE.replace("return x", "return x * 2"))
    watch.watch(repo, status_path, interval=0.01, max_polls=3)
    out = capsys.readouterr().out
    assert out.count("1 modified") == 1  # three polls, one write
    data = json.loads(status_path.read_text())
    assert data["summary"]["modified"] == 1 and data["version"] == 1


def test_scan_reports_findings_in_changed_functions(repo, tmp_path, capsys):
    write(repo, "app/views.py", BASE.replace(
        "return x\n", "return x  # sentinel-fixture: CWE-78 reachable public\n"))
    write(repo, "app/other.py", "def untouched():\n    pass  # sentinel-fixture: CWE-89\n")
    git(repo, "add", "app/other.py")
    git(repo, "commit", "-qm", "other")
    with use_detectors([MarkerDetector()]):
        status = watch.watch(repo, tmp_path / "s.json", once=True, scan=True)
    assert [(f["file"], f["cwe"], f["detected_at"]) for f in status["findings"]] == [
        ("app/views.py", "CWE-78", "write")]
    assert "BLOCK" in capsys.readouterr().out


def test_cli_once_and_default_status_path(repo, capsys):
    write(repo, "app/views.py", BASE.replace("return x", "return x * 2"))
    assert cli.main(["watch", "--repo", str(repo), "--once"]) == 0
    data = json.loads((repo / ".git" / "sentinel-status.json").read_text())
    assert "app/views.py" in data["files"]
    assert "status" not in subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                                          capture_output=True, text=True).stdout


def test_cli_outside_a_repo(tmp_path, capsys):
    assert watch.main(["--repo", str(tmp_path), "--once"]) == 2
    assert "not inside a git repository" in capsys.readouterr().err
