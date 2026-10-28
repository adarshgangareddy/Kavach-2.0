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
    assert evalmod.main(["--targets", str(targets), "--out", str(out), "--no-corpus"]) == 0
    report = out.read_text()
    assert "## Head-to-head" in report and "Kavach (taint)" in report
    assert "| Kavach (taint) | 2/2 | 100% | 1/1 | 1/1 | 1 |" in report
    assert "Small sample: 1 apps and 2 seeded bugs" in report
    assert "Vulnerable commits blocked before merge: 1/1" in report
    data = json.loads(out.with_suffix(".json").read_text())
    assert data["apps"] == ["app1"] and data["early_detection"][0]["blocked"] is True


def test_no_targets_is_an_error(evalmod, tmp_path, capsys):
    assert evalmod.main(["--targets", str(tmp_path / "none"), "--out", str(tmp_path / "r.md")]) == 1


# ablation, patch re-test and the secrets / weak-crypto cases ------------------------

def test_ablation_ends_with_the_full_kavach_setup(evalmod):
    names = [name for name, _ in evalmod.ablation_tools()]
    assert names[0] == "Pattern rules only (Bandit)" and names[-1].startswith("Full Kavach")
    assert {d.name for d in evalmod.ablation_tools()[-1][1]} == {"taint", "rules", "bandit", "semgrep"}


def test_corpus_labels_come_from_comments(evalmod):
    expected, decoys = evalmod.corpus_labels(evalmod.CORPUS)
    assert len(expected) == 36 and len(decoys) == 25
    assert {e["cwe"] for e in expected} <= set(evalmod.RULE_CWES)


def test_rule_layer_catches_every_labelled_case_and_no_decoy(evalmod):
    from app.detect.rules import RulesDetector
    score = evalmod.score_corpus("rules", [RulesDetector()])
    assert (score.caught, score.expected, score.decoys_flagged, score.extra) == (36, 36, 0, 0), score.missed
    assert score.own_code_reports == 0  # Kavach's own code has no secrets or weak crypto


def test_rule_findings_count_bandit_numbering_as_the_same_problem(evalmod):
    found = [{"cwe": "CWE-259", "line": 1}, {"cwe": "CWE-328", "line": 2}, {"cwe": "CWE-78", "line": 3}]
    assert [f["cwe"] for f in evalmod._rule_findings(found)] == ["CWE-798", "CWE-327"]


def test_patch_eval_patches_rescans_and_finds_nothing_serious(evalmod, monkeypatch):
    from app.detect.rules import RulesDetector
    monkeypatch.setattr(evalmod, "full_suite", lambda: [TaintDetector(), RulesDetector()])
    monkeypatch.setenv("SENTINEL_RULES", str(REPO / "backend" / "sentinel-rules.toml"))
    rows = evalmod.patch_eval([REPO / "targets" / "app1"])
    assert len(rows) == 4 and all(r["patched"] and r["confirmed"] for r in rows)
    assert sum(r["left_serious"] for r in rows) == 0


def test_report_has_patch_and_rule_layer_sections(evalmod, targets):
    from app.detect.rules import RulesDetector
    apps = evalmod.target_apps(targets)
    tools = evalmod.evaluate(apps, [("taint", [TaintDetector()])])
    rows = [{"app": "app1", "bug": "a.py:3 CWE-89", "kind": "direct", "patched": True, "confirmed": True,
             "title": "Use a parameterised query", "reason": "", "left": 0, "left_serious": 0,
             "left_max_severity": 0.0, "left_by": []},
            {"app": "app1", "bug": "b.py:9 CWE-78", "kind": "direct", "patched": False, "confirmed": False,
             "title": "", "reason": "uses the shell feature '|'"}]
    corpus = [evalmod.score_corpus("Kavach rule layer", [RulesDetector()])]
    report = evalmod.render(apps, tools, tools, [], rows, corpus)
    assert "Patches written: 1/2. Confirmed fixed by the re-trace: 1/2." in report
    assert "| app1/b.py:9 CWE-78 | none: uses the shell feature '|' | | |" in report
    assert "| Kavach rule layer | 36/36 | 100% | 0/25 | 0 | 100% | 0 |" in report
    assert "| Hard-coded credentials (CWE-798) | 18 | 18/18 |" in report
