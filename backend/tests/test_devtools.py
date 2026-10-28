"""Tests for the regression runner and the detection baseline (neutral made-up code)."""

import json
import subprocess
import textwrap

import pytest

from app.devtools import baseline, regress
from tests.conftest import write


# --- test-impact selection on a small fake project ---------------------------

@pytest.fixture
def project(tmp_path):
    repo = tmp_path / "repo"
    backend = repo / "backend"
    write(backend, "pyproject.toml", "")
    write(backend, "app/__init__.py", "")
    write(backend, "app/core/__init__.py", "")
    write(backend, "app/core/a.py", "X = 1\n")
    write(backend, "app/core/b.py", "from .a import X\n")
    write(backend, "app/c.py", "import app.core.b\n")
    write(backend, "app/shared.py", "Y = 2\n")
    write(backend, "app/rules.py", "Z = 3\n")
    write(backend, "tests/__init__.py", "")
    write(backend, "tests/conftest.py", "from app.shared import Y\n")
    write(backend, "tests/test_a.py", "from app.core.a import X\n")
    write(backend, "tests/test_c.py", "def test():\n    from app import c\n")
    write(backend, "tests/test_rules.py", "from app.rules import Z\n")
    write(backend, "tests/test_none.py", "def test():\n    pass\n")
    write(backend, "tests/test_targets_regression.py", "")
    return repo, backend


def pick(project, *files):
    repo, backend = project
    return regress.select(list(files), backend, repo, config_modules={"rules.toml": "app.rules"})


def test_changed_module_selects_direct_and_transitive_importers(project):
    sel = pick(project, "backend/app/core/a.py")
    assert sel.run_all is None
    assert sorted(sel.tests) == ["tests/test_a.py", "tests/test_c.py"]  # c -> b -> a (relative)


def test_import_inside_function_and_from_package_import_module(project):
    assert sorted(pick(project, "backend/app/c.py").tests) == ["tests/test_c.py"]


def test_changed_test_file_runs_itself(project):
    assert sorted(pick(project, "backend/tests/test_none.py").tests) == ["tests/test_none.py"]


def test_config_file_maps_to_its_module(project):
    assert sorted(pick(project, "backend/rules.toml").tests) == ["tests/test_rules.py"]


@pytest.mark.parametrize("path,reason", [
    ("backend/pyproject.toml", "pyproject.toml changed"),
    ("backend/tests/conftest.py", "conftest.py changed"),
    ("backend/app/shared.py", "conftest.py imports changed"),
    ("backend/scripts/odd.sh", "test impact is unknown"),
])
def test_unsafe_changes_run_everything(project, path, reason):
    assert reason in pick(project, path).run_all


def test_docs_frontend_and_targets(project):
    sel = pick(project, "docs/x.md", "frontend/src/App.jsx", "backend/README.md")
    assert not sel.tests and sel.run_all is None
    assert any("npm run build" in n for n in sel.notes)
    assert list(pick(project, "targets/app1/truth.json").tests) == ["tests/test_targets_regression.py"]


def test_deleted_test_file_is_not_selected(project):
    assert pick(project, "backend/tests/test_gone.py").tests == {}


def test_changed_files_from_git(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True,  # noqa: E731
                                    capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    git("config", "commit.gpgsign", "false")
    write(repo, "a.py", "1\n")
    git("add", ".")
    git("commit", "-qm", "init")
    git("checkout", "-qb", "feature")
    write(repo, "b.py", "1\n")
    git("add", ".")
    git("commit", "-qm", "b")
    write(repo, "a.py", "2\n")          # unstaged
    write(repo, "c.py", "1\n")          # untracked
    assert regress.changed_files(repo) == ["a.py", "c.py"]
    assert regress.changed_files(repo, base="main") == ["a.py", "b.py", "c.py"]


def test_cli_dry_run_on_this_repo(capsys):
    code = regress.main(["--files", "backend/app/report/annotations.py", "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0
    assert "tests/test_exports.py" in out and "tests/test_ingest.py" not in out


# --- detection baseline -------------------------------------------------------

RULES = """
entry_decorators = ["*.route"]
[[rule]]
id = "demo"
cwe = "CWE-78"
sinks = ["store"]
sanitizers = ["clean"]
"""


@pytest.fixture
def target(tmp_path):
    app_dir = tmp_path / "app1"
    write(app_dir, "helpers.py", textwrap.dedent("""\
        def record(value):
            store(value)
    """))
    write(app_dir, "app.py", textwrap.dedent("""\
        from helpers import record


        @app.route("/a")
        def wrapped(q):
            record(q)


        @app.route("/b")
        def direct(q):
            store(q)


        @app.route("/c")
        def decoy(q):
            store(clean(q))
    """))
    (app_dir / "truth.json").write_text(json.dumps([
        {"file": "helpers.py", "line": 2, "cwe": "CWE-78", "kind": "wrapper"},
        {"file": "app.py", "line": 11, "cwe": "CWE-78", "kind": "direct"},
    ]))
    rules = tmp_path / "rules.toml"
    rules.write_text(RULES)
    return app_dir, rules


def test_summarize_counts_caught_missed_and_false_positives(target):
    app_dir, rules = target
    summary = baseline.summarize(app_dir, rules)
    assert summary["caught"] == ["app.py:11:CWE-78", "helpers.py:2:CWE-78"]
    assert summary["missed"] == []
    assert summary["false_positives"] == 1  # the sanitized decoy is still reported (low severity)


def test_compare_flags_regressions_and_improvements():
    base = {"caught": ["a:1:CWE-78", "b:2:CWE-89"], "false_positives": 1}
    worse = {"caught": ["a:1:CWE-78"], "false_positives": 3}
    better = {"caught": ["a:1:CWE-78", "b:2:CWE-89", "c:3:CWE-22"], "false_positives": 0}
    regressions, _ = baseline.compare(base, worse)
    assert regressions == ["no longer caught: b:2:CWE-89", "false positives went up: 1 -> 3"]
    regressions, improvements = baseline.compare(base, better)
    assert regressions == []
    assert improvements == ["newly caught: c:3:CWE-22", "false positives went down: 1 -> 0"]


def test_baseline_round_trip_and_regression_detection(target):
    app_dir, rules = target
    baseline.write_baseline(app_dir, baseline.summarize(app_dir, rules))
    assert baseline.compare(baseline.load_baseline(app_dir), baseline.summarize(app_dir, rules)) == ([], [])

    (app_dir / "helpers.py").write_text("def record(value):\n    return value\n")  # bug "fixed" by a change
    regressions, _ = baseline.compare(baseline.load_baseline(app_dir),
                                      baseline.summarize(app_dir, rules))
    assert regressions == ["no longer caught: helpers.py:2:CWE-78"]
