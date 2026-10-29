"""Fix-watcher: dependency pins, advisory lookups (offline file or faked OSV), import matching.

Advisory records here are made up in OSV's format; no test reaches the network.
"""

import io
import json
import zipfile
from pathlib import Path

import pytest

from app.detect.base import Candidate
from app.detect.registry import active_detectors, use_detectors
from app.fixwatch import advisories
from app.fixwatch.advisories import AdvisoryError, lookup_offline, lookup_online, parse_vuln, version_key
from app.fixwatch.deps import find_dependencies, parse_pyproject, parse_requirements
from app.fixwatch.detector import FixWatchDetector, upgrade_to
from app.fixwatch.usage import find_uses, import_name
from app.pipeline import build_findings
from app.report import owasp
from app.report.severity import BASE_SCORE
from app.schema import DetectedAt
from tests.conftest import signed_in_client, write

VULN_FLASK = {"id": "GHSA-test-0001", "summary": "Example flaw in an old Flask",
              "database_specific": {"cwe_ids": ["CWE-400"]},
              "affected": [{"package": {"name": "Flask", "ecosystem": "PyPI"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}]}
VULN_YAML = {"id": "PYSEC-test-0002", "details": "Example flaw in PyYAML.\nMore text.",
             "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"}, "versions": ["5.3", "5.3.1"],
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}


@pytest.fixture
def project(tmp_path):
    write(tmp_path, "requirements.txt", "Flask==0.12.2\nPyYAML==5.3  # config\nrequests==2.19.0\nclick>=7.0\n")
    write(tmp_path, "app.py", "from flask import Flask\nimport yaml\n\napp = Flask(__name__)\n")
    return tmp_path


@pytest.fixture
def offline(tmp_path, monkeypatch):
    path = tmp_path / "vulns.json"
    path.write_text(json.dumps([VULN_FLASK, VULN_YAML]))
    monkeypatch.setenv("SENTINEL_FIXWATCH", str(path))
    return path


# dependencies ------------------------------------------------------------------

def test_requirements_keep_exact_pins_only():
    deps = parse_requirements("Flask==0.12.2\n# note\n-r other.txt\nrequests[socks]==2.19.0 ; python_version>'3'\n"
                              "click>=7.0\nJinja2 == 2.10  # pinned\n", "requirements.txt")
    assert [(d.name, d.version, d.line) for d in deps] == [
        ("flask", "0.12.2", 1), ("requests", "2.19.0", 4), ("jinja2", "2.10", 6)]


def test_pyproject_dependencies():
    text = '[project]\nname = "x"\ndependencies = [\n  "Werkzeug==2.0.0",\n  "click>=8",\n]\n'
    assert [(d.name, d.version, d.line) for d in parse_pyproject(text, "pyproject.toml")] == [("werkzeug", "2.0.0", 4)]


def test_dependency_files_in_virtualenvs_are_ignored(tmp_path):
    write(tmp_path, "requirements.txt", "flask==1.0\n")
    write(tmp_path, ".venv/lib/requirements.txt", "evil==1.0\n")
    write(tmp_path, "requirements-dev.txt", "flask==9.9\npytest==8.0\n")
    deps = {d.name: d.version for d in find_dependencies(tmp_path)}
    assert deps == {"flask": "1.0", "pytest": "8.0"}  # first mention of flask wins


# advisories ---------------------------------------------------------------------

def test_version_ordering():
    assert version_key("2.10.0") > version_key("2.9.9") > version_key("2.9")
    assert sorted(["1.0", "0.12.2", "2.2.5"], key=version_key) == ["0.12.2", "1.0", "2.2.5"]


def test_parse_vuln_reads_fixes_cwes_and_summary():
    a = parse_vuln(VULN_YAML, "pyyaml")
    assert (a.id, a.summary, a.fixed, a.url) == ("PYSEC-test-0002", "Example flaw in PyYAML.", ["5.4"],
                                                  "https://osv.dev/vulnerability/PYSEC-test-0002")
    assert parse_vuln(VULN_FLASK, "flask").cwes == ["CWE-400"]


def test_offline_lookup_matches_versions_and_ranges(project, offline):
    found = lookup_offline(find_dependencies(project), offline)
    assert {name: [a.id for a in hits] for name, hits in found.items()} == {
        "flask": ["GHSA-test-0001"], "pyyaml": ["PYSEC-test-0002"]}


def test_a_fixed_version_is_not_reported(tmp_path, offline):
    write(tmp_path, "requirements.txt", "Flask==2.2.5\n")
    assert lookup_offline(find_dependencies(tmp_path), offline) == {}


def test_unreadable_offline_file_is_a_clear_error(tmp_path):
    with pytest.raises(AdvisoryError, match="could not read"):
        lookup_offline([], tmp_path / "missing.json")


def test_online_lookup_batches_then_caches(project, monkeypatch):
    calls = []
    monkeypatch.setattr(advisories, "_cache", {})
    monkeypatch.setattr(advisories, "_post", lambda url, body: calls.append(url) or {"results": [
        {"vulns": [{"id": "GHSA-test-0001"}]}, {"vulns": [{"id": "PYSEC-test-0002"}]}, {}]})
    monkeypatch.setattr(advisories, "_get", lambda url: calls.append(url) or (
        VULN_FLASK if url.endswith("GHSA-test-0001") else VULN_YAML))
    deps = find_dependencies(project)
    first = lookup_online(deps)
    assert sorted(first) == ["flask", "pyyaml"] and len(calls) == 3  # one batch + two details
    assert lookup_online(deps) == first and len(calls) == 3           # cached: no new requests


def test_online_failure_is_a_clear_error(project, monkeypatch):
    monkeypatch.setattr(advisories, "_cache", {})
    def down(url, body):
        raise OSError("network unreachable")
    monkeypatch.setattr(advisories, "_post", down)
    with pytest.raises(AdvisoryError, match="could not reach the OSV"):
        lookup_online(find_dependencies(project))


# usage and the detector -----------------------------------------------------------

def test_import_names_and_uses(project):
    assert import_name("pyyaml") == "yaml" and import_name("flask-login") == "flask_login"
    assert [(u.file, u.line, u.module) for u in find_uses(project, ["app.py"], "flask")] == [("app.py", 1, "flask")]
    assert find_uses(project, ["app.py"], "requests") == []


def test_detector_is_off_by_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_FIXWATCH", raising=False)
    assert not FixWatchDetector().available()
    assert "fixwatch" not in [d.name for d in active_detectors()]


def test_detector_reports_used_vulnerable_packages_only(project, offline):
    found = FixWatchDetector().scan(project, ["app.py"], 30)
    assert [(c.file, c.line, c.cwe, c.path) for c in found] == [
        ("app.py", 1, "CWE-1395", ["import flask"]), ("app.py", 2, "CWE-1395", ["import yaml"])]
    flask = found[0]
    assert flask.source == "requirements.txt:1 Flask==0.12.2"
    assert flask.fix_suggestion.startswith("Upgrade flask from 0.12.2 to 2.2.5 or later in requirements.txt (line 1)")
    assert "https://osv.dev/vulnerability/GHSA-test-0001" in flask.fix_suggestion  # requests is never imported


def test_upgrade_target_needs_every_fix():
    hi, lo = parse_vuln(VULN_FLASK, "flask"), parse_vuln(VULN_FLASK, "flask")
    lo.fixed = ["1.0"]
    assert upgrade_to([hi, lo]) == "2.2.5"
    lo.fixed = []
    assert upgrade_to([hi, lo]) is None


def test_findings_are_marked_as_fix_watcher_leads():
    cand = Candidate(file="app.py", line=1, cwe="CWE-1395", detector="fixwatch", confidence=0.7)
    [finding] = build_findings("S-00000001", [cand], started=0.0)
    assert finding.detected_at == DetectedAt.WATCH
    assert finding.owasp == "A06:2021 Vulnerable and Outdated Components" and BASE_SCORE["CWE-1395"] == 5.0
    assert owasp.title_for("CWE-1395") == "Vulnerable dependency"


def test_scan_through_the_api(project, offline):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in project.glob("*.*"):
            zf.writestr(f"shop/{p.name}", p.read_text())
    client = signed_in_client()
    with use_detectors([FixWatchDetector()]):
        scan = client.post("/scans", files={"file": ("shop.zip", buf.getvalue(), "application/zip")}).json()
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    assert {f["detected_at"] for f in findings} == {"watch"} and len(findings) == 2
    patch = client.get(f"/findings/{findings[0]['id']}/patch").json()
    assert not patch["available"] and "upgrading the package" in patch["reason"]
