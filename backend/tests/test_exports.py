import json

from app.detect.base import Candidate
from app.models import Scan
from app.pipeline import build_findings
from app.report import sarif
from app.report.export import json_report, pdf_report
from app.schema import ConfidenceTier, Status


def _findings():
    cands = [
        Candidate(file="app/routes.py", line=6, cwe="CWE-78", detector="marker",
                  source="request.args['q']", sink="fixture_sink",
                  path=["route()", "helper()", "fixture_sink"], reachable=True,
                  public_route=True, confidence=0.9,
                  confidence_tier=ConfidenceTier.REACHABLE),
        Candidate(file="app/db.py", line=3, cwe="CWE-89", detector="marker"),
        Candidate(file="app/db.py", line=8, cwe="CWE-89", detector="marker"),
        Candidate(file="app/x.py", line=1, cwe="CWE-unknown", detector="marker", confidence=0.1),
    ]
    return build_findings("S-0000beef", cands, started=0)


def _scan():
    return Scan(id="S-0000beef", source_kind="cli", source_ref="demo", files_scanned=3)


def test_sarif_is_structurally_valid_and_github_ready():
    doc = sarif.to_sarif(_scan(), _findings())
    assert sarif.validate(doc) == []
    run = doc["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["CWE-78", "CWE-89", "CWE-unknown"]
    first = run["results"][0]
    assert first["level"] == "error"
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] == 6
    assert len(first["codeFlows"][0]["threadFlows"][0]["locations"]) == 3
    assert float(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]) >= 7
    json.dumps(doc)  # serializable


def test_sarif_fingerprints_are_stable_across_scans():
    a = sarif.to_sarif(None, _findings())["runs"][0]["results"]
    b = sarif.to_sarif(None, _findings())["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]


def test_sarif_suppresses_accepted_and_drops_fixed():
    findings = _findings()
    findings[0] = findings[0].model_copy(update={"status": Status.ACCEPTED})
    findings[1] = findings[1].model_copy(update={"status": Status.FIXED})
    results = sarif.to_sarif(None, findings)["runs"][0]["results"]
    assert len(results) == len(findings) - 1
    assert results[0]["suppressions"][0]["status"] == "accepted"


def test_sarif_validator_catches_errors():
    assert sarif.validate({"version": "1.0", "runs": []})
    bad = sarif.to_sarif(None, _findings())
    bad["runs"][0]["results"][0]["ruleIndex"] = 99
    assert any("ruleIndex" in e for e in sarif.validate(bad))


def test_json_and_pdf_reports():
    findings = _findings()
    report = json_report(_scan(), findings)
    assert report["summary"]["total"] == 4 and report["summary"]["by_cwe"]["CWE-89"] == 2
    pdf = pdf_report(_scan().model_copy(update={"notes": ["Skipped 3 files → ok"]}), findings)
    assert pdf.startswith(b"%PDF") and len(pdf) > 1000
