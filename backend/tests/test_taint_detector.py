"""Taint detector wired through the real pipeline, using neutral made-up sink names."""

import textwrap

import pytest
from fastapi.testclient import TestClient

from app.detect.registry import use_detectors
from app.detect.taint import RulesError, TaintDetector, load_rules
from app.main import app
from tests.conftest import write, signed_in_client

RULES = """
entry_decorators = ["*.route"]
sources = ["inbox.data"]

[[rule]]
id = "demo-store"
cwe = "CWE-78"
sinks = ["store", "*.store"]
sanitizers = ["clean"]

[[rule]]
id = "unused"
cwe = "CWE-89"
sinks = []
"""

APP = textwrap.dedent("""\
    from .helpers import record, tidy


    @app.route("/a")
    def direct(q):
        store(q)


    @app.route("/b")
    def wrapped(q):
        record(q)


    @app.route("/c")
    def cleaned(q):
        store(tidy(q))


    def reads_source():
        record(inbox.data.get("k"))


    def internal(q):
        store(q)
""")

HELPERS = textwrap.dedent("""\
    def record(value):
        store(value)


    def tidy(value):
        return clean(value)
""")


@pytest.fixture
def rules_file(tmp_path, monkeypatch):
    path = tmp_path / "rules.toml"
    path.write_text(RULES)
    monkeypatch.setenv("SENTINEL_RULES", str(path))
    return path


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    write(root, "web/__init__.py", "")
    write(root, "web/views.py", APP)
    write(root, "web/helpers.py", HELPERS)
    return root


def _scan(project):
    files = ["web/__init__.py", "web/helpers.py", "web/views.py"]
    return {(c.source, c.sink): c for c in TaintDetector().scan(project, files, 10)}


def test_rules_load_and_only_rules_with_sinks_are_active(rules_file):
    rules = load_rules(rules_file)
    assert [r.id for r in rules.active()] == ["demo-store"]
    assert rules.sources == ("inbox.data",)


@pytest.mark.parametrize("bad", ["not = [toml", "[[rule]]\nid = 1\ncwe = 'CWE-1'",
                                 "[[rule]]\nid = 'x'\ncwe = 'X'",
                                 "[[rule]]\nid = 'x'\ncwe = 'CWE-1'\nsinks = 'store'"])
def test_invalid_rules_are_rejected(tmp_path, bad):
    path = tmp_path / "r.toml"
    path.write_text(bad)
    with pytest.raises(RulesError):
        load_rules(path)


def test_disabled_until_a_sink_is_configured(tmp_path):
    path = tmp_path / "r.toml"
    path.write_text("[[rule]]\nid = 'x'\ncwe = 'CWE-78'\nsinks = []\n")
    assert TaintDetector(path).available() is False
    path.write_text("[[rule]]\nid = 'x'\ncwe = 'CWE-78'\nsinks = ['store']\n")
    assert TaintDetector(path).available() is True


def test_version_tracks_rules_content(rules_file):
    before = TaintDetector().version
    rules_file.write_text(RULES.replace('"clean"', '"clean2"'))
    assert TaintDetector().version != before


def test_candidates(rules_file, project):
    found = _scan(project)
    direct = found[("direct(q)", "store")]
    assert (direct.detector, direct.public_route, direct.reachable) == ("taint", True, True)
    assert direct.file == "web/views.py" and direct.line == 6

    wrapped = found[("wrapped(q)", "store")]
    assert wrapped.detector == "taint-wrapper"
    assert wrapped.path == ["wrapped()", "record()", "store"]
    assert wrapped.file == "web/helpers.py" and wrapped.line == 2

    cleaned = found[("cleaned(q)", "store")]
    assert cleaned.sanitizer_present and cleaned.confidence < direct.confidence

    source = found[("inbox.data", "store")]
    assert source.public_route is False and source.path[0] == "reads_source()"

    assert ("internal(q)", "store") not in found  # not a route, no source


def test_end_to_end_scores_and_api(rules_file, project, tmp_path):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in project.rglob("*.py"):
            zf.write(path, path.relative_to(project).as_posix())
    client = signed_in_client()
    with use_detectors([TaintDetector()]):
        scan = client.post("/scans", files={"file": ("p.zip", buf.getvalue(), "application/zip")}).json()
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    by_line = {(f["file"], f["line"]): f for f in findings}

    route = by_line[("web/views.py", 6)]
    assert route["confidence_tier"] == "reachable"
    assert route["severity_factors"]["reachable"] == 1.5
    assert route["severity_factors"]["public_route"] == 1.0
    assert route["severity"] >= 9

    cleaned = by_line[("web/views.py", 16)]
    assert cleaned["severity_factors"]["sanitizer_present"] == -2.0
    assert cleaned["severity"] < 7  # does not block commits


def test_broken_rules_are_reported_as_a_scan_note(tmp_path, monkeypatch, project):
    bad = tmp_path / "bad.toml"
    bad.write_text("not = [toml")
    monkeypatch.setenv("SENTINEL_RULES", str(bad))
    from app.pipeline import run_detectors
    _, notes = run_detectors(project, ["web/views.py"], [TaintDetector()], 10)
    assert notes and "taint failed" in notes[0] and "bad.toml" in notes[0]


# --- whole-program behaviour in the hook and PR scan -------------------------

from types import SimpleNamespace

ROUTE = '\n\n@app.route("/new")\ndef added(q):\n    record(q)\n'


@pytest.fixture
def repo(tmp_path, rules_file):
    import subprocess
    path = tmp_path / "repo"
    path.mkdir()
    git = lambda *a: subprocess.run(["git", "-C", str(path), *a], check=True,  # noqa: E731
                                    capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    git("config", "commit.gpgsign", "false")
    write(path, "web/__init__.py", "")
    write(path, "web/helpers.py", HELPERS)
    write(path, "web/views.py", "from .helpers import record\n")
    git("add", ".")
    git("commit", "-qm", "base")
    return SimpleNamespace(path=path, git=git)


def test_hook_follows_new_route_into_unchanged_helper(repo, capsys):
    import time
    from app.early import hook
    with open(repo.path / "web/views.py", "a") as fh:
        fh.write(ROUTE)
    repo.git("add", ".")
    with use_detectors([TaintDetector()]):
        started = time.monotonic()
        assert hook.main(["--repo", str(repo.path)]) == 1
        assert time.monotonic() - started < 5
    out = capsys.readouterr().out
    assert "web/helpers.py:2" in out and "added() -> record() -> store" in out


def test_pr_scan_follows_new_route_into_unchanged_helper(repo, tmp_path):
    import json
    from app import cli
    repo.git("checkout", "-qb", "feature")
    with open(repo.path / "web/views.py", "a") as fh:
        fh.write(ROUTE)
    repo.git("commit", "-qam", "add route")
    out = tmp_path / "pr.sarif"
    with use_detectors([TaintDetector()]):
        code = cli.main(["scan", str(repo.path), "--diff-base", "main", "--format", "sarif",
                         "--out", str(out), "--fail-on", "7"])
    assert code == 1
    [result] = json.loads(out.read_text())["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "web/helpers.py"


def test_sink_tables_in_rules(tmp_path):
    from app.detect.propagation import SinkSpec
    path = tmp_path / "r.toml"
    path.write_text("""
[[rule]]
id = "x"
cwe = "CWE-89"
sinks = ["plain", { call = "*.query", args = [0], kwargs = ["sql"] },
         { call = "run", args = [0], when = { shell = true } }, { call = "kw", kwargs = ["cmd"] }]
""")
    sinks = load_rules(path).rules[0].sinks
    assert sinks[0] == "plain"
    assert sinks[1] == SinkSpec("*.query", (0,), ("sql",))
    assert sinks[2] == SinkSpec("run", (0,), (), (("shell", True),))
    assert sinks[3] == SinkSpec("kw", (), ("cmd",))


@pytest.mark.parametrize("sink", ['{ args = [0] }', '{ call = "x", args = [-1] }',
                                  '{ call = "x", args = "0" }', '{ call = "x", when = 1 }',
                                  '{ call = "x", extra = 1 }', '3'])
def test_invalid_sink_tables_are_rejected(tmp_path, sink):
    path = tmp_path / "r.toml"
    path.write_text(f'[[rule]]\nid = "x"\ncwe = "CWE-78"\nsinks = [{sink}]\n')
    with pytest.raises(RulesError):
        load_rules(path)
