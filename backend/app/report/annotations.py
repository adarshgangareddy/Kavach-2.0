"""SARIF -> GitHub Actions workflow annotations.

Annotations show on the pull request's changed lines without GitHub Advanced
Security, which private repositories need for code-scanning uploads.
"""

_COMMAND = {"error": "error", "warning": "warning", "note": "notice", "none": "notice"}
MAX_ANNOTATIONS = 50  # GitHub shows at most 10 per step per type; keep the log readable


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def annotations(doc: dict) -> list[str]:
    """Workflow command lines, most severe first."""
    lines: list[tuple[float, str]] = []
    for run in doc.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for res in run.get("results", []):
            if res.get("suppressions"):
                continue
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri")
            if not path:
                continue
            line = loc.get("region", {}).get("startLine", 1)
            idx = res.get("ruleIndex")
            rule = rules[idx] if isinstance(idx, int) and idx < len(rules) else {}
            title = rule.get("shortDescription", {}).get("text", "")
            message = res.get("message", {}).get("text", "")
            if help_text := rule.get("help", {}).get("text"):
                message += f"\nFix: {help_text}"
            command = _COMMAND.get(res.get("level", "warning"), "warning")
            props = ",".join([f"file={_escape_property(path)}", f"line={int(line)}",
                              f"title={_escape_property(f'{res.get('ruleId', '')} {title}'.strip())}"])
            severity = float(res.get("properties", {}).get("severity", 0))
            lines.append((severity, f"::{command} {props}::{_escape_data(message)}"))
    lines.sort(key=lambda item: -item[0])
    return [text for _, text in lines[:MAX_ANNOTATIONS]]
