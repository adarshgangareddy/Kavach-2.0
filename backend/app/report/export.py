"""JSON and PDF reports for a scan."""

import time

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from app import __version__
from app.models import Scan
from app.report import owasp, severity
from app.schema import Finding
from app.store import summary

_COLOURS = {
    "critical": (153, 27, 27), "high": (194, 65, 12), "medium": (161, 98, 7),
    "low": (37, 99, 235), "info": (75, 85, 99),
}
_DISCLAIMER = ("Static analysis results. Confidence tiers state how much evidence backs each "
               "finding; pattern-match findings have not been confirmed reachable.")


def json_report(scan: Scan, findings: list[Finding]) -> dict:
    return {
        "tool": {"name": "Kavach", "version": __version__},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan": scan.model_dump(mode="json"),
        "summary": summary(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def _latin1(text: str) -> str:
    """Core PDF fonts are Latin-1 only; replace anything else."""
    return text.replace("→", "->").encode("latin-1", "replace").decode("latin-1")


class _Report(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "Kavach - security scan report", align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, f"Page {self.page_no()}/{{nb}}", align="C")


def _text(pdf: FPDF, text: str, size: int = 10, style: str = "", colour=(20, 20, 20)) -> None:
    pdf.set_font("Helvetica", style, size)
    pdf.set_text_color(*colour)
    pdf.multi_cell(0, size * 0.5 + 1.5, _latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _finding_block(pdf: FPDF, f: Finding) -> None:
    sev_label = severity.label(f.severity)
    _text(pdf, f"{f.id}  [{sev_label.upper()} {f.severity}]  {owasp.title_for(f.cwe)}",
          11, "B", _COLOURS[sev_label])
    _text(pdf, f"{f.file}:{f.line}   {f.cwe}   {f.owasp}", 9)
    _text(pdf, f"Detector: {f.detector}   Confidence: {f.confidence_tier.value}   "
               f"Status: {f.status.value}", 9, colour=(80, 80, 80))
    if f.source or f.sink:
        _text(pdf, f"Source: {f.source or '-'}   Sink: {f.sink or '-'}", 9)
    if f.path:
        _text(pdf, "Path: " + " -> ".join(f.path), 9)
    factors = ", ".join(f"{k} {v:+g}" for k, v in f.severity_factors.items())
    _text(pdf, f"Score breakdown: {factors}", 9, colour=(80, 80, 80))
    _text(pdf, f"Suggested fix: {f.fix_suggestion}", 9)
    pdf.ln(3)


def pdf_report(scan: Scan, findings: list[Finding]) -> bytes:
    pdf = _Report()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    _text(pdf, "Security scan report", 18, "B")
    _text(pdf, f"Scan {scan.id} - {scan.source_kind}: {scan.source_ref}", 10)
    _text(pdf, time.strftime("Generated %Y-%m-%d %H:%M UTC", time.gmtime()), 9, colour=(90, 90, 90))
    pdf.ln(2)
    counts = {lbl: 0 for lbl in _COLOURS}
    for f in findings:
        counts[severity.label(f.severity)] += 1
    _text(pdf, f"{len(findings)} findings in {scan.files_scanned} files  |  " +
          "  ".join(f"{k}: {v}" for k, v in counts.items()), 10, "B")
    _text(pdf, f"Detectors: {', '.join(scan.detectors) or 'none'}", 9)
    for note in scan.notes:
        _text(pdf, f"Note: {note}", 8, colour=(110, 110, 110))
    _text(pdf, _DISCLAIMER, 8, "I", (110, 110, 110))
    pdf.ln(4)
    for f in findings:
        _finding_block(pdf, f)
    return bytes(pdf.output())
