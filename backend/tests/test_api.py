import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.report.sarif import validate
from tests.conftest import APP_SOURCE, BrokenDetector, MarkerDetector, signed_in_client
from app.detect.registry import use_detectors


@pytest.fixture
def client():
    return signed_in_client()


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/app/routes.py", APP_SOURCE)
        zf.writestr("demo/tests/test_routes.py", "# sentinel-fixture: CWE-78\n")
        zf.writestr("demo/static/site.css", "body{}")
    return buf.getvalue()


def _upload(client) -> dict:
    res = client.post("/scans", files={"file": ("demo.zip", _zip_bytes(), "application/zip")})
    assert res.status_code == 202, res.text
    return res.json()


def test_zip_scan_end_to_end(client, marker):
    scan = _upload(client)
    done = client.get(f"/scans/{scan['id']}").json()
    assert done["status"] == "done"
    assert done["files_scanned"] == 1
    assert done["detectors"] == ["marker"]
    assert done["finding_count"] == 2

    findings = client.get(f"/scans/{scan['id']}/findings").json()
    assert [f["cwe"] for f in findings] == ["CWE-89", "CWE-22"]
    top = findings[0]
    assert top["file"] == "app/routes.py" and top["line"] == 6
    assert top["owasp"] == "A03:2021 Injection"
    assert top["severity"] == 9.4 and top["confidence_tier"] == "reachable"
    assert top["path"][-1] == "fixture_sink"


def test_findings_filters_and_status_workflow(client, marker):
    scan_id = _upload(client)["id"]
    high = client.get(f"/scans/{scan_id}/findings", params={"min_severity": 7}).json()
    assert len(high) == 1
    fid = high[0]["id"]

    res = client.patch(f"/findings/{fid}", json={"status": "accepted"})
    assert res.status_code == 200 and res.json()["status"] == "accepted"
    assert client.get(f"/findings/{fid}").json()["status"] == "accepted"
    assert len(client.get(f"/scans/{scan_id}/findings", params={"status": "open"}).json()) == 1
    assert client.patch(f"/findings/{fid}", json={"status": "bogus"}).status_code == 422


def test_exports(client, marker):
    scan_id = _upload(client)["id"]
    report = client.get(f"/scans/{scan_id}/report").json()
    assert report["summary"]["total"] == 2

    pdf = client.get(f"/scans/{scan_id}/report", params={"format": "pdf"})
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")

    sarif = client.get(f"/scans/{scan_id}/sarif")
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    assert validate(sarif.json()) == []


def test_source_endpoint_is_confined_to_workspace(client, marker):
    scan_id = _upload(client)["id"]
    ok = client.get(f"/scans/{scan_id}/source", params={"path": "app/routes.py"})
    assert ok.status_code == 200 and "def search" in ok.text
    for bad in ["../../../etc/passwd", "/etc/passwd", "static/site.css"]:
        assert client.get(f"/scans/{scan_id}/source", params={"path": bad}).status_code == 404


def test_snippet_endpoint(client, marker):
    res = client.post("/snippet", json={"code": "    x = 1  # sentinel-fixture: CWE-78 reachable"})
    assert res.status_code == 200
    body = res.json()
    assert body["scan"]["status"] == "done"
    assert body["findings"][0]["cwe"] == "CWE-78"


def test_rejects_bad_requests(client, marker):
    assert client.post("/scans").status_code == 422
    assert client.post("/scans", data={"github_url": "https://evil.example/x/y"}).status_code == 400
    res = client.post("/scans", files={"file": ("x.tar", b"data", "application/x-tar")})
    assert res.status_code == 400
    assert client.get("/scans/S-deadbeef").status_code == 404
    assert client.get("/scans/../../etc").status_code == 404
    assert client.get("/findings/not-an-id").status_code == 422


def test_bad_zip_marks_scan_failed(client, marker):
    res = client.post("/scans", files={"file": ("x.zip", b"garbage", "application/zip")})
    scan = client.get(f"/scans/{res.json()['id']}").json()
    assert scan["status"] == "failed" and "valid zip" in scan["error"]


def test_failing_detector_is_reported_not_fatal(client):
    with use_detectors([BrokenDetector(), MarkerDetector()]):
        scan = client.get(f"/scans/{_upload(client)['id']}").json()
    assert scan["status"] == "done" and scan["finding_count"] == 2
    assert any("broken failed" in n for n in scan["notes"])


def test_no_detectors_is_explained(client, no_detectors):
    scan = client.get(f"/scans/{_upload(client)['id']}").json()
    assert scan["finding_count"] == 0
    assert any("No detectors" in n for n in scan["notes"])


def test_list_scans_and_detectors(client, marker):
    _upload(client)
    assert len(client.get("/scans").json()) == 1
    assert client.get("/detectors").json() == [
        {"name": "marker", "version": "test-1", "available": True}]


def test_cwe_catalog(client):
    catalog = client.get("/cwe").json()
    assert catalog["CWE-89"] == {"title": "SQL injection", "owasp": "A03:2021 Injection"}
