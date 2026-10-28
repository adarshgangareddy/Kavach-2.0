import pytest
from pydantic import ValidationError

from app.detect.base import Candidate
from app.pipeline import build_findings, deduplicate
from app.report import owasp, severity
from app.schema import ConfidenceTier, Finding, Status


def test_finding_matches_prd_example():
    f = Finding.model_validate({
        "id": "F-001", "scan_id": "S-01", "file": "app/routes.py", "line": 42,
        "cwe": "CWE-78", "owasp": "A03:2021 Injection",
        "source": "request.args['name']", "sink": "os.system",
        "path": ["download()", "run_report()", "helper()", "os.system"],
        "detector": "taint-wrapper", "ml_rank": 0.87, "severity": 8.1,
        "severity_factors": {}, "confidence_tier": "reachable", "fix_suggestion": "",
        "status": "open", "introduced_in": "abc123", "detected_at": "write",
        "time_to_detect": 0,
    })
    assert f.confidence_tier is ConfidenceTier.REACHABLE
    assert f.status is Status.OPEN


@pytest.mark.parametrize("field,value", [("line", 0), ("severity", 11), ("ml_rank", 1.5),
                                         ("status", "closed")])
def test_finding_rejects_invalid_values(field, value):
    base = {"id": "F-1", "scan_id": "S-1", "file": "a.py", "line": 1, "cwe": "CWE-78",
            "detector": "x"}
    with pytest.raises(ValidationError):
        Finding.model_validate({**base, field: value})


def test_severity_formula_terms():
    sev, factors = severity.score("CWE-78", reachable=True, public_route=True,
                                  confidence=0.8, sanitizer_present=False)
    assert factors == {"base": 6.0, "reachable": 1.5, "public_route": 1.0,
                       "confidence": 0.8, "sanitizer_present": 0.0}
    assert sev == 9.3


def test_severity_is_capped_and_floored():
    hi, _ = severity.score("CWE-89", reachable=True, public_route=True,
                           confidence=1.0, sanitizer_present=False)
    assert hi == 9.5
    lo, factors = severity.score("CWE-327", reachable=False, public_route=False,
                                 confidence=0.0, sanitizer_present=True)
    assert lo == 1.5 and factors["sanitizer_present"] == -2.0
    floor, _ = severity.score("CWE-unknown", reachable=False, public_route=False,
                              confidence=0.0, sanitizer_present=True)
    assert floor == 1.0


def test_severity_labels():
    assert [severity.label(s) for s in (9.5, 7.0, 4.0, 0.1, 0)] == \
        ["critical", "high", "medium", "low", "info"]


def test_every_bug_class_is_tagged():
    assert owasp.owasp_for("CWE-78") == "A03:2021 Injection"
    assert owasp.owasp_for("CWE-89") == "A03:2021 Injection"
    assert owasp.owasp_for("CWE-22") == "A01:2021 Broken Access Control"
    assert owasp.owasp_for("CWE-999999") == owasp.UNMAPPED
    assert "parameterized" in owasp.remediation_for("CWE-89")


def _cand(**kw):
    return Candidate(**{"file": "a.py", "line": 3, "cwe": "CWE-89", "detector": "bandit", **kw})


def test_dedup_merges_detectors_and_keeps_strongest_evidence():
    merged = deduplicate([
        _cand(confidence=0.3),
        _cand(detector="semgrep", confidence=0.9, confidence_tier=ConfidenceTier.REACHABLE),
        _cand(line=9),
    ])
    assert len(merged) == 2
    assert merged[0].detector == "bandit+semgrep"
    assert merged[0].confidence_tier is ConfidenceTier.REACHABLE


def test_build_findings_scores_tags_and_sorts():
    findings = build_findings("S-0000abcd", [_cand(line=1, cwe="CWE-22"),
                                              _cand(line=2, reachable=True, public_route=True)],
                              started=0)
    assert [f.cwe for f in findings] == ["CWE-89", "CWE-22"]
    top = findings[0]
    assert top.id.startswith("F-0000abcd-")
    assert top.owasp == "A03:2021 Injection"
    assert top.fix_suggestion
    assert top.severity == round(sum(top.severity_factors.values()), 1)
