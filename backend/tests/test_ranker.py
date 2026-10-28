"""ML ranker tests. Training data is synthetic finding records (numbers and labels only)."""

import importlib.util
import json
import random

import pytest

from app.detect.base import Candidate
from app.pipeline import build_findings
from app.rank import model as ranker
from app.rank.features import FEATURES, extract
from app.rank.model import LinearModel, ModelError, load_model
from app.rank.train import (Dataset, false_positives_at_recall, label_findings, load_dataset,
                            main, precision_at_k)


def synthetic_rows(seed=7, projects=6, per_project=60):
    """Real issues are mostly reachable and unsanitized; detector confidence is noise."""
    rng = random.Random(seed)
    rows = []
    for p in range(projects):
        for i in range(per_project):
            reachable = rng.random() < 0.5
            sanitized = rng.random() < 0.3
            real = reachable and not sanitized
            if rng.random() < 0.1:
                real = not real
            hops = rng.randint(2, 4) if reachable else 0
            rows.append({"project": f"p{p}", "label": int(real), "finding": {
                "id": f"F-{p}-{i}", "file": f"m{i % 7}.py", "line": i + 1,
                "cwe": rng.choice(["CWE-78", "CWE-89", "CWE-22"]),
                "detector": "taint-wrapper" if reachable else "bandit",
                "confidence_tier": "reachable" if reachable else "pattern-match",
                "source": "request.args" if reachable else "",
                "path": [f"f{k}()" for k in range(hops)],
                "severity": 6.0,
                "severity_factors": {"base": 6.0, "reachable": 1.5 * reachable,
                                     "public_route": 1.0 * reachable,
                                     "confidence": round(rng.random(), 2),
                                     "sanitizer_present": -2.0 * sanitized},
            }})
    return rows


def write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


# --- features ----------------------------------------------------------------

def test_feature_vector_shape_and_values():
    finding = synthetic_rows()[0]["finding"]
    values = extract(finding)
    assert len(values) == len(FEATURES)
    named = dict(zip(FEATURES, values))
    assert sum(named[f"tier={t}"] for t in ("pattern-match", "reachable", "proof-confirmed")) == 1
    assert named["detector_confidence"] == finding["severity_factors"]["confidence"]
    assert extract({}) == extract({"detector": None, "path": None})  # no crash on missing data


# --- metrics -----------------------------------------------------------------

def test_false_positives_at_recall_and_precision():
    scores = [0.9, 0.8, 0.7, 0.6, 0.5]
    labels = [1, 0, 1, 0, 1]
    assert false_positives_at_recall(scores, labels, 0.6) == 1   # need 2 of 3 real
    assert false_positives_at_recall(scores, labels, 1.0) == 2
    assert false_positives_at_recall(scores, [0, 0, 0, 0, 0], 0.9) is None
    assert precision_at_k(scores, labels, 3) == pytest.approx(2 / 3)


def test_label_findings_matches_file_cwe_and_nearby_line():
    findings = [
        {"file": "a.py", "line": 10, "cwe": "CWE-78"},
        {"file": "a.py", "line": 11, "cwe": "CWE-78"},   # duplicate report of the same bug
        {"file": "a.py", "line": 30, "cwe": "CWE-78"},
        {"file": "b.py", "line": 5, "cwe": "CWE-89"},
    ]
    truth = [{"file": "a.py", "line": 12, "cwe": "CWE-78"}, {"file": "b.py", "line": 5, "cwe": "CWE-22"}]
    assert label_findings(findings, truth) == [1, 0, 0, 0]


# --- training (needs scikit-learn) -------------------------------------------

needs_sklearn = pytest.mark.skipif(importlib.util.find_spec("sklearn") is None,
                                   reason="training needs the ml extra (scikit-learn)")


@needs_sklearn
def test_train_cli_reports_fp_reduction_and_writes_json_model(tmp_path, capsys):
    data = write_jsonl(tmp_path / "labeled.jsonl", synthetic_rows())
    out = tmp_path / "model.json"
    assert main(["fit", "--data", str(data), "--out", str(out)]) == 0
    report = capsys.readouterr().out
    assert "held-out projects: 6 projects" in report and "Caveat: small sample" in report

    saved = json.loads(out.read_text())
    metrics = saved["meta"]["metrics"]
    assert metrics["false_positive_reduction"] > 0.3
    assert metrics["auc_model"] > 0.8 > metrics["auc_baseline"]
    assert saved["features"] == list(FEATURES)


@needs_sklearn
def test_pure_python_scoring_matches_scikit_learn(tmp_path):
    from app.rank.train import _pipeline, fit
    dataset = load_dataset(write_jsonl(tmp_path / "d.jsonl", synthetic_rows()))
    exported = fit(dataset)
    reference = _pipeline().fit(dataset.X, dataset.y)
    expected = reference.predict_proba(dataset.X[:25])[:, 1]
    for x, p in zip(dataset.X[:25], expected):
        assert exported.score_vector(x) == pytest.approx(p, abs=1e-9)


@needs_sklearn
def test_project_split_needs_two_projects():
    from app.rank.train import cross_validate
    one = Dataset([[0.0] * len(FEATURES)] * 4, [0, 1, 0, 1], ["only"] * 4)
    with pytest.raises(ValueError, match="at least 2 projects"):
        cross_validate(one)


# --- loading and pipeline integration ----------------------------------------

def _trained(tmp_path):
    from app.rank.train import fit
    dataset = load_dataset(write_jsonl(tmp_path / "d.jsonl", synthetic_rows()))
    path = tmp_path / "model.json"
    path.write_text(json.dumps(fit(dataset).to_dict()))
    return path


@needs_sklearn
def test_model_file_is_validated(tmp_path):
    good = json.loads(_trained(tmp_path).read_text())
    for broken in (
        {**good, "version": 99},
        {**good, "features": good["features"][:-1]},
        {**good, "coef": good["coef"][:-1]},
        {**good, "scale": [0.0] * len(FEATURES)},
        {**good, "intercept": float("inf")},
        {**good, "mean": ["x"] * len(FEATURES)},
    ):
        with pytest.raises(ModelError):
            LinearModel.from_dict(broken)


def test_rejected_or_missing_model_falls_back_to_heuristic(tmp_path):
    model, status = load_model(tmp_path / "missing.json")
    assert model is None and "no model file" in status
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    model, status = load_model(bad)
    assert model is None and "rejected" in status


@needs_sklearn
def test_pipeline_uses_model_when_present(tmp_path, monkeypatch):
    cands = [
        Candidate(file="a.py", line=1, cwe="CWE-78", detector="taint-wrapper",
                  path=["r()", "h()", "sink"], source="request.args", reachable=True,
                  public_route=True, confidence=0.4),
        Candidate(file="b.py", line=2, cwe="CWE-78", detector="bandit", confidence=0.9),
    ]
    without = build_findings("S-0000bbbb", cands, started=0)
    assert [f.ml_rank for f in without] == [0.4, 0.9]  # detector confidence

    monkeypatch.setenv("SENTINEL_MODEL", str(_trained(tmp_path)))
    with_model = {f.file: f for f in build_findings("S-0000bbbb", cands, started=0)}
    assert with_model["a.py"].ml_rank > 0.7 > with_model["b.py"].ml_rank
    assert with_model["a.py"].severity == {f.file: f for f in without}["a.py"].severity
    assert "trained on 360 findings from 6 projects" in ranker.load_model()[1]


def test_cli_reports_missing_files_without_a_traceback(tmp_path, capsys):
    code = main(["label", "--report", str(tmp_path / "scan.json"),
                 "--truth", str(tmp_path / "truth.json"), "--project", "app1"])
    assert code == 1
    assert capsys.readouterr().err.strip() == f"error: file not found: {tmp_path / 'scan.json'}"
