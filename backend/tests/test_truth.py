import json

import pytest

from app.rank.truth import TruthError, check, load_truth, main
from tests.conftest import write


@pytest.fixture
def app_dir(tmp_path):
    root = tmp_path / "app1"
    write(root, "app.py", "line1\nline2\nline3\n")
    write(root, "lib/helpers.py", "a\nb\n")
    return root


def put(app_dir, entries):
    (app_dir / "truth.json").write_text(json.dumps(entries))


def test_valid_truth(app_dir, capsys):
    put(app_dir, [{"file": "app.py", "line": 2, "cwe": "CWE-78", "kind": "direct"},
                  {"file": "lib/helpers.py", "line": 1, "cwe": "CWE-89", "kind": "wrapper",
                   "note": "route -> helper"}])
    assert len(load_truth(app_dir)) == 2
    assert main([str(app_dir)]) == 0
    assert "ok, 2 seeded bugs" in capsys.readouterr().out


@pytest.mark.parametrize("entry,problem", [
    ({"file": "app.py", "line": 9, "cwe": "CWE-78"}, "outside app.py (1-3)"),
    ({"file": "nope.py", "line": 1, "cwe": "CWE-78"}, "file not found"),
    ({"file": "../app.py", "line": 1, "cwe": "CWE-78"}, "relative to the app folder"),
    ({"file": "app.py", "line": "2", "cwe": "CWE-78"}, "whole number"),
    ({"file": "app.py", "line": 1, "cwe": "CWE-79"}, "'cwe' must be one of"),
    ({"file": "app.py", "line": 1, "cwe": "CWE-78", "kind": "other"}, "'kind'"),
    ({"file": "app.py", "line": 1, "cwe": "CWE-78", "lines": 1}, "unknown fields"),
])
def test_invalid_entries(app_dir, entry, problem):
    put(app_dir, [entry])
    _, problems = check(app_dir)
    assert any(problem in p for p in problems), problems
    with pytest.raises(TruthError):
        load_truth(app_dir)


def test_missing_bad_json_empty_and_duplicates(app_dir, capsys):
    assert "missing" in check(app_dir)[1][0]
    (app_dir / "truth.json").write_text("{oops")
    assert "not valid JSON" in check(app_dir)[1][0]
    put(app_dir, [])
    assert "non-empty" in check(app_dir)[1][0]
    entry = {"file": "app.py", "line": 1, "cwe": "CWE-22"}
    put(app_dir, [entry, entry])
    assert any("duplicate" in p for p in check(app_dir)[1])
    assert main([str(app_dir)]) == 1
    assert "problems" in capsys.readouterr().out
