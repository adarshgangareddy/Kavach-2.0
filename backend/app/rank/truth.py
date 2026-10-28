"""Load and check a seeded target's ground truth (targets/<app>/truth.json).

    python -m app.rank.truth ../targets/app1 [../targets/app2 ...]

The format is documented in targets/README.md.
"""

import json
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

CWES = ("CWE-78", "CWE-89", "CWE-22", "CWE-502")
KINDS = ("wrapper", "direct")


class TruthError(ValueError):
    pass


def _check_entry(app_dir: Path, i: int, entry) -> list[str]:
    where = f"entry #{i + 1}"
    if not isinstance(entry, dict):
        return [f"{where}: must be an object"]
    errors = []
    rel = entry.get("file")
    line = entry.get("line")
    if not isinstance(rel, str) or not rel.endswith(".py"):
        errors.append(f"{where}: 'file' must be a .py path")
    elif PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts or "\\" in rel:
        errors.append(f"{where}: 'file' must be relative to the app folder, with forward slashes")
    elif not (app_dir / rel).is_file():
        errors.append(f"{where}: file not found: {rel}")
    elif isinstance(line, int) and not isinstance(line, bool):
        count = len((app_dir / rel).read_text(errors="replace").splitlines())
        if not 1 <= line <= count:
            errors.append(f"{where}: line {line} is outside {rel} (1-{count})")
    if not isinstance(line, int) or isinstance(line, bool):
        errors.append(f"{where}: 'line' must be a whole number")
    if entry.get("cwe") not in CWES:
        errors.append(f"{where}: 'cwe' must be one of {', '.join(CWES)}")
    if "kind" in entry and entry["kind"] not in KINDS:
        errors.append(f"{where}: 'kind' must be 'wrapper' or 'direct'")
    unknown = set(entry) - {"file", "line", "cwe", "kind", "note"}
    if unknown:
        errors.append(f"{where}: unknown fields {sorted(unknown)}")
    return errors


def check(app_dir: Path) -> tuple[list[dict], list[str]]:
    """(entries, problems). Problems are empty when truth.json is valid."""
    path = app_dir / "truth.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return [], [f"missing {path}"]
    except json.JSONDecodeError as exc:
        return [], [f"{path}: not valid JSON ({exc})"]
    if not isinstance(data, list) or not data:
        return [], [f"{path}: must be a non-empty JSON list"]
    problems = [p for i, e in enumerate(data) for p in _check_entry(app_dir, i, e)]
    keys = Counter((e.get("file"), e.get("line"), e.get("cwe")) for e in data if isinstance(e, dict))
    problems += [f"duplicate entry: {f}:{ln} {c}" for (f, ln, c), n in keys.items() if n > 1]
    return data, problems


def load_truth(app_dir: Path) -> list[dict]:
    entries, problems = check(app_dir)
    if problems:
        raise TruthError(f"{app_dir}: " + "; ".join(problems))
    return entries


def main(argv: list[str] | None = None) -> int:
    dirs = [Path(a) for a in (argv if argv is not None else sys.argv[1:])]
    if not dirs:
        print("usage: python -m app.rank.truth TARGET_DIR [TARGET_DIR ...]", file=sys.stderr)
        return 2
    failed = 0
    for app_dir in dirs:
        entries, problems = check(app_dir)
        if problems:
            failed += 1
            print(f"{app_dir}: {len(problems)} problems")
            for p in problems:
                print(f"  - {p}")
            continue
        by_cwe = Counter(e["cwe"] for e in entries)
        by_kind = Counter(e.get("kind", "unspecified") for e in entries)
        print(f"{app_dir}: ok, {len(entries)} seeded bugs  "
              f"({', '.join(f'{c}: {n}' for c, n in sorted(by_cwe.items()))}; "
              f"{', '.join(f'{k}: {n}' for k, n in sorted(by_kind.items()))})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
