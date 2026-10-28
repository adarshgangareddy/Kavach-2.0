import copy

from app.detect.base import Candidate
from app.pipeline import build_findings
from app.rank.priority import confidence_score, priority_key, sort_by_priority


def item(fid, severity, confidence=None, **extra):
    data = {"id": fid, "severity": severity, "file": "a.py", "line": 1, **extra}
    if confidence is not None:
        data["confidence"] = confidence
    return data


def ids(items):
    return [i["id"] for i in items]


def test_severity_band_first_then_confidence_within_band():
    items = [
        item("medium-sure", 6.9, 0.99),
        item("high-unsure", 7.1, 0.10),
        item("high-sure", 7.4, 0.95),
        item("critical", 9.3, 0.20),
    ]
    assert ids(sort_by_priority(items)) == ["critical", "high-sure", "high-unsure", "medium-sure"]


def test_ml_rank_preferred_over_confidence():
    items = [item("a", 8.0, 0.9, ml_rank=0.2), item("b", 8.0, 0.1, ml_rank=0.8)]
    assert ids(sort_by_priority(items)) == ["b", "a"]


def test_open_findings_before_fixed_and_accepted():
    items = [item("fixed", 9.5, 0.9, status="fixed"), item("accepted", 9.5, 0.9, status="accepted"),
             item("open", 4.0, 0.1, status="open")]
    assert ids(sort_by_priority(items)) == ["open", "fixed", "accepted"]


def test_ties_break_on_severity_tier_then_location():
    items = [
        item("pattern", 8.0, 0.5, confidence_tier="pattern-match"),
        item("proof", 8.0, 0.5, confidence_tier="proof-confirmed"),
        item("z-file", 8.0, 0.5, confidence_tier="reachable", file="z.py"),
        item("a-file", 8.0, 0.5, confidence_tier="reachable", file="a.py"),
        item("higher", 8.2, 0.5, confidence_tier="pattern-match"),
    ]
    assert ids(sort_by_priority(items)) == ["higher", "proof", "a-file", "z-file", "pattern"]


def test_tolerates_missing_and_bad_values():
    items = [
        {"id": "empty"},
        item("nan", 8.0, float("nan")),
        item("text", "not a number", "high"),
        item("too-big", 8.0, 7.5),
        item("ok", 8.0, 0.5),
    ]
    result = ids(sort_by_priority(items))
    assert result[:3] == ["too-big", "ok", "nan"]  # 7.5 clamps to 1.0; NaN counts as 0
    assert set(result[3:]) == {"empty", "text"}
    assert confidence_score({"confidence": -3}) == 0.0


def test_does_not_mutate_input():
    items = [item("b", 4.0, 0.1), item("a", 9.0, 0.9)]
    before = copy.deepcopy(items)
    result = sort_by_priority(items)
    assert items == before and result is not items


def test_works_on_finding_objects_and_matches_dicts():
    findings = build_findings("S-0000aaaa", [
        Candidate(file="a.py", line=1, cwe="CWE-22", detector="x", confidence=0.9),
        Candidate(file="b.py", line=2, cwe="CWE-78", detector="x", confidence=0.2, reachable=True),
    ], started=0)
    as_dicts = [f.model_dump(mode="json") for f in findings]
    assert [priority_key(f) for f in findings] == [priority_key(d) for d in as_dicts]
    assert [f.cwe for f in findings] == ["CWE-78", "CWE-22"]
