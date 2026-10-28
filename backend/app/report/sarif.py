"""SARIF 2.1.0 export, compatible with GitHub code scanning upload."""

import hashlib

from app import __version__
from app.models import Scan
from app.report import owasp, severity
from app.schema import Finding, Status

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "ZeroDay Sentinel"


def _level(sev: float) -> str:
    if sev >= 7.0:
        return "error"
    if sev >= 4.0:
        return "warning"
    return "note"


def _fingerprint(f: Finding) -> str:
    return hashlib.sha256(f"{f.file}|{f.cwe}|{f.sink}|{f.source}".encode()).hexdigest()[:32]


def _message(f: Finding) -> str:
    text = owasp.title_for(f.cwe)
    if f.source and f.sink:
        text += f": untrusted data from {f.source} reaches {f.sink}"
    elif f.sink:
        text += f" ({f.sink})"
    return f"{text}. Severity {f.severity}/10, confidence: {f.confidence_tier.value}."


def _rule(cwe: str, findings: list[Finding]) -> dict:
    top = max(f.severity for f in findings)
    return {
        "id": cwe,
        "name": owasp.title_for(cwe).title().replace(" ", ""),
        "shortDescription": {"text": owasp.title_for(cwe)},
        "help": {"text": owasp.remediation_for(cwe)},
        "properties": {
            "tags": ["security", cwe, owasp.owasp_for(cwe)],
            "security-severity": f"{top:.1f}",
        },
    }


def _code_flow(f: Finding) -> list[dict]:
    if not f.path:
        return []
    steps = [{"location": {"message": {"text": step}}} for step in f.path]
    return [{"threadFlows": [{"locations": steps}]}]


def _result(f: Finding, rule_index: int) -> dict:
    result = {
        "ruleId": f.cwe,
        "ruleIndex": rule_index,
        "level": _level(f.severity),
        "message": {"text": _message(f)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": f.line},
            }
        }],
        "partialFingerprints": {"sentinelFinding/v1": _fingerprint(f)},
        "properties": {
            "findingId": f.id,
            "severity": f.severity,
            "severityLabel": severity.label(f.severity),
            "severityFactors": f.severity_factors,
            "confidenceTier": f.confidence_tier.value,
            "mlRank": f.ml_rank,
            "detector": f.detector,
            "status": f.status.value,
        },
    }
    if flows := _code_flow(f):
        result["codeFlows"] = flows
    if f.status == Status.ACCEPTED:
        result["suppressions"] = [{"kind": "external", "status": "accepted",
                                   "justification": "Risk accepted in ZeroDay Sentinel"}]
    return result


def to_sarif(scan: Scan | None, findings: list[Finding]) -> dict:
    live = [f for f in findings if f.status != Status.FIXED]
    by_rule: dict[str, list[Finding]] = {}
    for f in live:
        by_rule.setdefault(f.cwe, []).append(f)
    rule_ids = sorted(by_rule)
    index = {rid: i for i, rid in enumerate(rule_ids)}
    run: dict = {
        "tool": {"driver": {
            "name": TOOL_NAME,
            "version": __version__,
            "semanticVersion": __version__,
            "rules": [_rule(rid, by_rule[rid]) for rid in rule_ids],
        }},
        "results": [_result(f, index[f.cwe]) for f in live],
        "columnKind": "utf16CodeUnits",
    }
    if scan is not None:
        run["automationDetails"] = {"id": f"zeroday-sentinel/{scan.id}"}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def validate(doc: dict) -> list[str]:
    """Structural checks for the parts of SARIF 2.1.0 we emit. Empty list means valid."""
    errors: list[str] = []
    if doc.get("version") != SARIF_VERSION:
        errors.append("version must be 2.1.0")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return errors + ["runs must be a non-empty array"]
    for r_i, run in enumerate(runs):
        driver = run.get("tool", {}).get("driver", {})
        if not driver.get("name"):
            errors.append(f"runs[{r_i}].tool.driver.name is required")
        rules = driver.get("rules", [])
        for res_i, res in enumerate(run.get("results", [])):
            where = f"runs[{r_i}].results[{res_i}]"
            if not res.get("message", {}).get("text"):
                errors.append(f"{where}.message.text is required")
            if res.get("level") not in {"none", "note", "warning", "error"}:
                errors.append(f"{where}.level is invalid")
            idx = res.get("ruleIndex")
            if idx is not None and (idx >= len(rules) or rules[idx]["id"] != res.get("ruleId")):
                errors.append(f"{where}.ruleIndex does not match ruleId")
            for loc in res.get("locations", []):
                region = loc.get("physicalLocation", {}).get("region", {})
                if region.get("startLine", 1) < 1:
                    errors.append(f"{where} startLine must be >= 1")
    return errors
