"""Command-line scanner used by CI and the GitHub Action.

    sentinel scan PATH [--diff-base REF] [--format text|json|sarif] [--out FILE] [--fail-on N]
    sentinel validate-sarif FILE
"""

import argparse
import json
import sys
import time
from pathlib import Path

from app.config import get_settings
from app.detect.registry import active_detectors
from app.early.scope import in_changed_code
from app.ingest.diff import diff_against
from app.ingest.filter import filter_project
from app.models import Scan, ScanStatus
from app.pipeline import build_findings, run_detectors, severity_counts
from app.report import sarif
from app.report.annotations import annotations
from app.report.export import json_report
from app.report.text import render
from app.schema import DetectedAt


def _scan(args: argparse.Namespace) -> int:
    settings = get_settings()
    started = time.monotonic()
    root = args.path.resolve()
    filtered = filter_project(root, settings.max_file_bytes)
    excluded = [p.strip("/") for p in args.exclude]
    if excluded:
        kept = [f for f in filtered.files
                if not any(f == p or f.startswith(p + "/") for p in excluded)]
        filtered.notes.append(f"Excluded {len(filtered.files) - len(kept)} files under "
                              f"{', '.join(excluded)}.")
        filtered.files = kept
    files = filtered.files
    changed = None
    if args.diff_base:
        changed = diff_against(root, args.diff_base)
        files = [f for f in files if f in changed]

    detectors = active_detectors()
    candidates, notes = run_detectors(root, files, detectors, settings.detector_timeout_s,
                                      context_files=filtered.files)
    scan = Scan(source_kind="cli", source_ref=str(args.path), status=ScanStatus.DONE,
                files_scanned=len(files), detectors=[d.name for d in detectors],
                notes=filtered.notes + notes, finished_at=time.time())
    findings = build_findings(scan.id, candidates, started=started,
                              detected_at=DetectedAt.REVIEW if changed is not None else DetectedAt.WRITE)
    if changed is not None:
        findings = in_changed_code(findings, changed,
                                   lambda rel: (root / rel).read_text(errors="replace"))
    scan.finding_count = len(findings)
    scan.severity_counts = severity_counts(findings)

    for note in scan.notes:
        print(f"sentinel: {note}", file=sys.stderr)
    if not detectors:
        print("sentinel: warning - no detectors available", file=sys.stderr)

    if args.format == "sarif":
        output = json.dumps(sarif.to_sarif(scan, findings), indent=2)
    elif args.format == "json":
        output = json.dumps(json_report(scan, findings), indent=2)
    else:
        output = render(findings, threshold=args.fail_on)
    if args.out:
        args.out.write_text(output + "\n")
    else:
        print(output)

    print(f"sentinel: {len(files)} files, {len(findings)} findings, "
          f"{time.monotonic() - started:.2f}s", file=sys.stderr)
    return 1 if any(f.severity >= args.fail_on for f in findings) else 0


def _validate(args: argparse.Namespace) -> int:
    errors = sarif.validate(json.loads(args.file.read_text()))
    for err in errors:
        print(err, file=sys.stderr)
    print("valid" if not errors else f"{len(errors)} errors")
    return 1 if errors else 0


def _annotate(args: argparse.Namespace) -> int:
    lines = annotations(json.loads(args.file.read_text()))
    for line in lines:
        print(line)
    print(f"sentinel: {len(lines)} annotations", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a project directory")
    scan.add_argument("path", type=Path, nargs="?", default=Path("."))
    scan.add_argument("--diff-base", help="only report findings in code changed since this ref")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--out", type=Path)
    scan.add_argument("--exclude", action="append", default=[], metavar="DIR",
                      help="skip files under this project-relative folder (repeatable)")
    scan.add_argument("--fail-on", type=float, default=11.0,
                      help="exit 1 if any finding has at least this severity (default: never)")
    scan.set_defaults(func=_scan)
    val = sub.add_parser("validate-sarif", help="check a SARIF file's structure")
    val.add_argument("file", type=Path)
    val.set_defaults(func=_validate)
    ann = sub.add_parser("annotate", help="print GitHub Actions annotations for a SARIF file")
    ann.add_argument("file", type=Path)
    ann.set_defaults(func=_annotate)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
