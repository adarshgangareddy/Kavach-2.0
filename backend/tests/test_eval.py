"""eval/run.py on a tiny neutral target (made-up sink and sanitizer names)."""

import importlib.util
import json
import textwrap
from pathlib import Path

import pytest

from app.detect.taint import TaintDetector
from tests.conftest import MarkerDetector, write

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def evalmod():
    spec = importlib.util.spec_from_file_location("eval_run", REPO / "eval" / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RULES = """
entry_decorators = ["*.route"]
[[rule]]
id = "demo"
cwe = "CWE-78"
sinks = ["store"]
sanitizers = ["clean"]
"""


@pytest.fixture
def targets(tmp_path, monkeypatch):
    rules = tmp_path / "rules.toml"
    rules.write_text(RULES)
    monkeypatch.setenv("SENTINEL_RULES", str(rules))
    root = tmp_path / "targets"
    app = root / "app1"
    write(app, "helpers.py", "def record(value):\n    store(value)\n")
    write(app, "app.py", textwrap.dedent("""\
        from helpers import record


        @app.route("/a")
        def wrapped(q):
            record(q)


        @app.route("/b")
        def direct(q):
            store(q)  # sentinel-fixture: CWE-78


        @app.route("/c")
        def decoy(q):
            store(clean(q))
    """))
    (app / "truth.json").write_text(json.dumps([
        {"file": "helpers.py", "line": 2, "cwe": "CWE-78", "kind": "wrapper"},
        {"file": "app.py", "line": 11, "cwe": "CWE-78", "kind": "direct"},
    ]))
    return root


def test_scores_caught_missed_and_extra(evalmod, targets):
    apps = evalmod.target_apps(targets)
    taint, marker = evalmod.evaluate(apps, [("taint", [TaintDetector()]),
                                            ("marker", [MarkerDetector()])])
    a = taint.apps["app1"]
    assert (a.caught, a.truth, a.wrapper_caught, a.direct_caught) == (2, 2, 1, 1)
    assert a.extra == 1 and a.extra_blocking == 0  # sanitized decoy, low severity
    assert taint.precision == pytest.approx(2 / 3) and taint.recall == 1.0

    m = marker.apps["app1"]  # only flags the line with the marker comment
    assert (m.caught, m.extra) == (1, 0)
    assert m.missed == ["helpers.py:2 CWE-78 (wrapper)"]


def test_unavailable_tool_is_reported_not_run(evalmod, targets):
    class Missing(MarkerDetector):
        name = "missing"

        def available(self):
            return False

    [tool] = evalmod.evaluate(evalmod.target_apps(targets), [("Missing tool", [Missing()])])
    assert not tool.available and tool.note == "missing not installed" and tool.apps == {}


def test_early_detection_blocks_the_route_commit(evalmod, targets):
    result = evalmod.early_detection(targets / "app1")
    assert result["blocked"] is True and result["blocking_findings"] >= 1
    assert result["seconds"] < 5


def test_report_and_cli(evalmod, targets, tmp_path, capsys):
    out = tmp_path / "results.md"
    assert evalmod.main(["--targets", str(targets), "--out", str(out)]) == 0
    report = out.read_text()
    assert "## Head-to-head" in report and "Kavach (taint)" in report
    assert "| Kavach (taint) | 2/2 | 100% | 1/1 | 1/1 | 1 |" in report
    assert "Small sample: 1 apps and 2 seeded bugs" in report
    assert "Vulnerable commits blocked before merge: 1/1" in report
    data = json.loads(out.with_suffix(".json").read_text())
    assert data["apps"] == ["app1"] and data["early_detection"][0]["blocked"] is True


def test_no_targets_is_an_error(evalmod, tmp_path, capsys):
    assert evalmod.main(["--targets", str(tmp_path / "none"), "--out", str(tmp_path / "r.md")]) == 1
