"""Server-side PDF report generation.

The renderer consumes an already validated ``ScanReport``.  It never performs a
scan and never accepts HTML.  Every report value is treated as plain text,
escaped for ReportLab's mini-markup, and length-limited defensively.
"""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    HRFlowable,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .models import CheckStatus, ScanReport, Severity

CREATOR_NAME = "Biniyam Shambel"
CREATOR_TITLE = "Ethical Hacker | ID-CTC_721"

MAX_FINDINGS = 100
MAX_CHECKS = 100
MAX_LIMITATIONS = 50
MAX_REDIRECTS = 20
MAX_TEXT_LENGTH = 5000

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN_X = 18 * mm
MARGIN_TOP = 25 * mm
MARGIN_BOTTOM = 21 * mm

COFFEE = colors.HexColor("#6F4E37")
ESPRESSO = colors.HexColor("#3B2A20")
LATTE = colors.HexColor("#E9DED2")
BEIGE = colors.HexColor("#F0E8DF")
WARM_WHITE = colors.HexColor("#FAF8F5")
TEXT = colors.HexColor("#292522")
MUTED = colors.HexColor("#716961")
GREEN = colors.HexColor("#2F6B4F")
AMBER = colors.HexColor("#8A5A12")
RED = colors.HexColor("#A33B3B")

SEVERITY_ORDER = (
    Severity.critical,
    Severity.high,
    Severity.medium,
    Severity.low,
    Severity.info,
)
SEVERITY_LABELS = {
    Severity.critical: "Critical",
    Severity.high: "High",
    Severity.medium: "Medium",
    Severity.low: "Low",
    Severity.info: "Info",
}
SEVERITY_COLORS = {
    Severity.critical: RED,
    Severity.high: colors.HexColor("#8C3F2D"),
    Severity.medium: AMBER,
    Severity.low: colors.HexColor("#5A6B44"),
    Severity.info: MUTED,
}
CHECK_LABELS = {
    CheckStatus.passed: "PASS",
    CheckStatus.warning: "WARN",
    CheckStatus.failed: "FAIL",
    CheckStatus.not_applicable: "NOT APPLICABLE",
    CheckStatus.unknown: "UNKNOWN",
}
CHECK_COLORS = {
    CheckStatus.passed: GREEN,
    CheckStatus.warning: AMBER,
    CheckStatus.failed: RED,
    CheckStatus.not_applicable: MUTED,
    CheckStatus.unknown: MUTED,
}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _find_font(name: str) -> str | None:
    candidates = (
        Path("/usr/share/fonts/truetype/dejavu") / name,
        Path("/usr/share/fonts/truetype/liberation") / name,
        Path("/usr/share/fonts/TTF") / name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    # Font locations vary across distributions. Search common roots once at
    # import time so PDF export remains Unicode-capable where the files exist.
    for root in (
        Path("/usr/share/fonts"),
        Path("/usr/local/share/fonts"),
        Path.home() / ".fonts",
        Path.home() / ".local/share/fonts",
    ):
        if not root.is_dir():
            continue
        try:
            match = next(root.rglob(name), None)
        except OSError:
            match = None
        if match and match.is_file():
            return str(match)
    return None


def _register_fonts() -> tuple[str, str, str]:
    """Register a Unicode-capable family, falling back to built-in PDF fonts."""

    regular = _find_font("DejaVuSans.ttf") or _find_font("LiberationSans-Regular.ttf")
    bold = _find_font("DejaVuSans-Bold.ttf") or _find_font("LiberationSans-Bold.ttf")
    mono = _find_font("DejaVuSansMono.ttf") or _find_font("LiberationMono-Regular.ttf")

    registered = set(pdfmetrics.getRegisteredFontNames())
    if regular and bold and mono:
        if "APISentinelSans" not in registered:
            pdfmetrics.registerFont(TTFont("APISentinelSans", regular))
        if "APISentinelSansBold" not in registered:
            pdfmetrics.registerFont(TTFont("APISentinelSansBold", bold))
        if "APISentinelMono" not in registered:
            pdfmetrics.registerFont(TTFont("APISentinelMono", mono))
        return "APISentinelSans", "APISentinelSansBold", "APISentinelMono"

    # Built-in fonts keep the endpoint working on minimal systems.  They cover
    # Latin text; Unicode glyph coverage depends on the installed font files.
    return "Helvetica", "Helvetica-Bold", "Courier"


FONT_REGULAR, FONT_BOLD, FONT_MONO = _register_fonts()


def _clean(value: object, limit: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    text = str(value).encode("utf-8", "replace").decode("utf-8")
    text = _CONTROL_CHARS.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


def _p(value: object, style: ParagraphStyle, limit: int = MAX_TEXT_LENGTH) -> Paragraph:
    """Escape untrusted text and return a Paragraph."""

    text = escape(_redact_urls(_clean(value, limit)))
    # The escaped text is safe; newlines become ReportLab line breaks.
    text = text.replace("\n", "<br/>")
    return Paragraph(text, style)


def redact_url(raw_url: object) -> str:
    """Remove credentials and query values from a URL for display/export."""

    raw = _clean(raw_url, 2048)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw.split("?", 1)[0]

    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    query = ""
    if parts.query:
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            query = urlencode([(key, "REDACTED") for key, _value in pairs], doseq=True)
        except ValueError:
            query = "REDACTED"

    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def _redact_urls(text: str) -> str:
    """Redact query values and credentials in any URLs embedded in report text."""

    return _URL_PATTERN.sub(lambda match: redact_url(match.group(0)), text)


def _report_date(report: ScanReport) -> str:
    value = _clean(report.scanned_at, 64)
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", value)
    if match:
        return match.group(1)
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _generated_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _display_time(value: object) -> str:
    text = _clean(value, 64)
    if not text:
        return "Unavailable"
    return text.replace("T", " ").replace("Z", " UTC")


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle(
        "body",
        fontName=FONT_REGULAR,
        fontSize=9.4,
        leading=13.6,
        textColor=TEXT,
        alignment=TA_LEFT,
        spaceAfter=5,
        splitLongWords=1,
    )
    return {
        "brand": ParagraphStyle(
            "brand",
            fontName=FONT_BOLD,
            fontSize=9,
            leading=12,
            textColor=COFFEE,
            charSpace=1.2,
        ),
        "title": ParagraphStyle(
            "title",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=23,
            leading=27,
            textColor=ESPRESSO,
            spaceAfter=5,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base,
            fontSize=10.5,
            leading=15,
            textColor=MUTED,
            spaceAfter=10,
        ),
        "section": ParagraphStyle(
            "section",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=13.5,
            leading=17,
            textColor=COFFEE,
            spaceBefore=12,
            spaceAfter=7,
        ),
        "subheading": ParagraphStyle(
            "subheading",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=10.4,
            leading=14,
            textColor=ESPRESSO,
            spaceBefore=5,
            spaceAfter=4,
        ),
        "body": base,
        "small": ParagraphStyle(
            "small",
            parent=base,
            fontSize=8.2,
            leading=11.4,
            textColor=MUTED,
        ),
        "label": ParagraphStyle(
            "label",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=7.6,
            leading=10,
            textColor=MUTED,
            charSpace=0.7,
            spaceAfter=2,
        ),
        "evidence": ParagraphStyle(
            "evidence",
            parent=base,
            fontSize=8.3,
            leading=11.8,
            textColor=ESPRESSO,
            backColor=BEIGE,
            borderColor=LATTE,
            borderWidth=0.6,
            borderPadding=7,
            spaceBefore=3,
            spaceAfter=8,
            splitLongWords=1,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base,
            leftIndent=12,
            firstLineIndent=-8,
            spaceAfter=3,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base,
            fontSize=8.2,
            leading=11,
            textColor=MUTED,
            spaceAfter=4,
        ),
        "cell": ParagraphStyle(
            "cell",
            parent=base,
            fontSize=8.2,
            leading=11,
            spaceAfter=0,
        ),
        "cell_head": ParagraphStyle(
            "cell_head",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=7.6,
            leading=10,
            textColor=ESPRESSO,
            spaceAfter=0,
        ),
        "cell_muted": ParagraphStyle(
            "cell_muted",
            parent=base,
            fontSize=8,
            leading=10.8,
            textColor=MUTED,
            spaceAfter=0,
        ),
        "attribution": ParagraphStyle(
            "attribution",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=10,
            leading=14,
            textColor=ESPRESSO,
            spaceAfter=1,
        ),
        "attribution_sub": ParagraphStyle(
            "attribution_sub",
            parent=base,
            fontSize=8.6,
            leading=12,
            textColor=MUTED,
            spaceAfter=0,
        ),
    }


def _page_header(canv: canvas.Canvas, _doc: BaseDocTemplate) -> None:
    canv.saveState()
    canv.setFillColor(WARM_WHITE)
    canv.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, stroke=0, fill=1)
    canv.setFillColor(COFFEE)
    canv.setFont(FONT_BOLD, 8.5)
    canv.drawString(MARGIN_X, PAGE_HEIGHT - 13 * mm, "API SENTINEL")
    canv.setFillColor(MUTED)
    canv.setFont(FONT_REGULAR, 7.8)
    canv.drawRightString(
        PAGE_WIDTH - MARGIN_X,
        PAGE_HEIGHT - 13 * mm,
        "API Security Assessment Report",
    )
    canv.setStrokeColor(LATTE)
    canv.setLineWidth(0.7)
    canv.line(MARGIN_X, PAGE_HEIGHT - 16 * mm, PAGE_WIDTH - MARGIN_X, PAGE_HEIGHT - 16 * mm)
    canv.restoreState()


class _NumberedCanvas(canvas.Canvas):
    """Canvas that records pages so the footer can show "Page X of Y"."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, object]] = []

    def showPage(self) -> None:  # noqa: N802 - ReportLab API
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _draw_footer(self, total: int) -> None:
        self.saveState()
        self.setStrokeColor(LATTE)
        self.setLineWidth(0.6)
        self.line(MARGIN_X, 15 * mm, PAGE_WIDTH - MARGIN_X, 15 * mm)
        self.setFont(FONT_REGULAR, 7.2)
        self.setFillColor(MUTED)
        self.drawString(
            MARGIN_X,
            10.5 * mm,
            f"API Sentinel  ·  Created by {CREATOR_NAME}  ·  {CREATOR_TITLE}",
        )
        self.drawRightString(
            PAGE_WIDTH - MARGIN_X,
            10.5 * mm,
            f"Page {self._pageNumber} of {total}",
        )
        self.restoreState()


def _summary_text(report: ScanReport) -> str:
    if not report.reachable:
        code = report.error.code if report.error else "no_response"
        message = report.error.message if report.error else "No HTTP response was received."
        return (
            "API Sentinel could not obtain an HTTP response from the target. "
            f"The recorded reason was {_clean(code, 80)} — "
            f"{_clean(message, 500)} No security-header checks could be performed."
        )

    transport = (
        "HTTPS"
        if str(report.final_url or report.target_url).lower().startswith("https://")
        else "plain HTTP"
    )
    status = report.http_status if report.http_status is not None else "no status"
    latency = (
        f"{report.response_time_ms:.1f} ms"
        if report.response_time_ms is not None
        else "unavailable"
    )
    application = (
        "the application response was a 2xx success"
        if report.application_ok is True
        else "the application did not return a 2xx success response"
    )
    finding_word = "finding" if len(report.findings) == 1 else "findings"
    return (
        f"The target responded with HTTP {status} over {transport}; {application}. "
        f"The measured response time was {latency}. The rule set recorded "
        f"{len(report.findings)} {finding_word}, producing a configuration risk score of "
        f"{report.risk_score}/100 ({report.risk_level.value.title()})."
    )


def _severity_table(report: ScanReport, styles: dict[str, ParagraphStyle]) -> Table:
    rows: list[list[Paragraph]] = [
        [
            _p("Severity", styles["cell_head"]),
            _p("Findings", styles["cell_head"]),
            _p("Points", styles["cell_head"]),
        ]
    ]
    style_commands: list[tuple] = [
        ("BACKGROUND", (0, 0), (-1, 0), BEIGE),
        ("BOX", (0, 0), (-1, -1), 0.6, LATTE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, LATTE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    for severity in SEVERITY_ORDER:
        items = [f for f in report.findings if f.severity == severity]
        points = sum(item.weight for item in items)
        rows.append(
            [
                _p(SEVERITY_LABELS[severity], styles["cell"]),
                _p(str(len(items)), styles["cell"]),
                _p(str(points), styles["cell"]),
            ]
        )
        style_commands.append(
            ("TEXTCOLOR", (0, len(rows) - 1), (0, len(rows) - 1), SEVERITY_COLORS[severity])
        )

    table = Table(rows, colWidths=[52 * mm, 30 * mm, 30 * mm], hAlign="LEFT")
    table.setStyle(TableStyle(style_commands))
    return table


def _finding_flowables(
    report: ScanReport,
    styles: dict[str, ParagraphStyle],
) -> list[object]:
    flowables: list[object] = []
    ordered = sorted(
        report.findings,
        key=lambda item: (
            SEVERITY_ORDER.index(item.severity)
            if item.severity in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
            -item.weight,
            item.title,
        ),
    )

    if not ordered:
        flowables.append(
            _p(
                "No findings were recorded by the performed checks. "
                "This does not prove that the API is free of vulnerabilities.",
                styles["body"],
            )
        )
        return flowables

    for index, finding in enumerate(ordered, start=1):
        label = SEVERITY_LABELS.get(finding.severity, "Info")
        flowables.append(CondPageBreak(33 * mm))
        heading = f"{index}. {_clean(finding.title, 300)}"
        flowables.append(_p(heading, styles["subheading"]))
        meta = (
            f"{label}  ·  {_clean(finding.category, 120)}  ·  "
            f"{finding.weight} points"
        )
        flowables.append(_p(meta, styles["meta"]))
        flowables.append(_p(finding.description, styles["body"]))
        if _clean(finding.evidence):
            flowables.append(_p("EVIDENCE", styles["label"]))
            flowables.append(_p(finding.evidence, styles["evidence"]))
        if _clean(finding.recommendation):
            flowables.append(_p("RECOMMENDED REMEDIATION", styles["label"]))
            flowables.append(_p(finding.recommendation, styles["body"]))
        flowables.append(
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=LATTE,
                spaceBefore=6,
                spaceAfter=8,
            )
        )
    return flowables


def _checks_table(report: ScanReport, styles: dict[str, ParagraphStyle]) -> object:
    if not report.checks:
        return _p(
            "No check details were returned with this report.",
            styles["body"],
        )

    rows: list[list[Paragraph]] = [
        [
            _p("Check", styles["cell_head"]),
            _p("Result", styles["cell_head"]),
            _p("Detail", styles["cell_head"]),
        ]
    ]
    commands: list[tuple] = [
        ("BACKGROUND", (0, 0), (-1, 0), BEIGE),
        ("BOX", (0, 0), (-1, -1), 0.6, LATTE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, LATTE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    for check in report.checks:
        status = check.status if check.status in CHECK_LABELS else CheckStatus.unknown
        rows.append(
            [
                _p(check.label, styles["cell"]),
                _p(CHECK_LABELS[status], styles["cell"]),
                _p(check.detail, styles["cell_muted"]),
            ]
        )
        commands.append(
            ("TEXTCOLOR", (1, len(rows) - 1), (1, len(rows) - 1), CHECK_COLORS[status])
        )

    table = Table(
        rows,
        colWidths=[43 * mm, 26 * mm, 87 * mm],
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    table.setStyle(TableStyle(commands))
    return table


def _info_table(report: ScanReport, styles: dict[str, ParagraphStyle]) -> Table:
    rows = [
        [
            _p("SCAN TIME", styles["label"]),
            _p("SECURITY SCORE", styles["label"]),
            _p("FINDINGS", styles["label"]),
        ],
        [
            _p(_display_time(report.scanned_at), styles["cell"]),
            _p(
                f"{report.risk_score}/100 · {report.risk_level.value.title()}",
                styles["cell"],
            ),
            _p(str(len(report.findings)), styles["cell"]),
        ],
    ]
    table = Table(rows, colWidths=[72 * mm, 52 * mm, 32 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BEIGE),
                ("BOX", (0, 0), (-1, -1), 0.6, LATTE),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, LATTE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def build_pdf(report: ScanReport, *, compress: bool = True) -> bytes:
    """Render a complete, paginated PDF report from a validated ScanReport."""

    styles = _styles()
    buffer = io.BytesIO()
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
        title="API Security Assessment Report",
        author=CREATOR_NAME,
        subject="API health and HTTP security-configuration assessment",
        creator="API Sentinel",
        pageCompression=1 if compress else 0,
    )
    frame = Frame(
        MARGIN_X,
        MARGIN_BOTTOM,
        PAGE_WIDTH - 2 * MARGIN_X,
        PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM,
        id="report-body",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    doc.addPageTemplates([PageTemplate(id="report", frames=[frame], onPage=_page_header)])

    story: list[object] = [
        Spacer(1, 4 * mm),
        _p("API SECURITY ASSESSMENT", styles["brand"]),
        Spacer(1, 2 * mm),
        _p("API Security Assessment Report", styles["title"]),
        _p(
            f"Generated {_generated_at()}  ·  API Sentinel report {_clean(report.report_id, 100)}",
            styles["subtitle"],
        ),
        _p("TARGET", styles["label"]),
        _p(redact_url(report.target_url), styles["subheading"]),
    ]

    if report.final_url and redact_url(report.final_url) != redact_url(report.target_url):
        story.append(_p("FINAL URL", styles["label"]))
        story.append(_p(redact_url(report.final_url), styles["body"]))

    story.extend(
        [
            Spacer(1, 3 * mm),
            _info_table(report, styles),
            Spacer(1, 2 * mm),
            _p("API Security Assessment Report  ·  rule version " + _clean(report.rule_version, 40), styles["small"]),
            HRFlowable(width="100%", thickness=0.8, color=LATTE, spaceBefore=10, spaceAfter=4),
        ]
    )

    story.append(_p("Executive summary", styles["section"]))
    story.append(_p(_summary_text(report), styles["body"]))
    if report.reachable:
        story.append(_severity_table(report, styles))
    else:
        story.append(
            _p(
                "Header, status-class, and latency findings are limited because no "
                "HTTP response was available. The report records the availability "
                "observation and the safe error code instead of inventing results.",
                styles["small"],
            )
        )

    story.append(_p("Detailed findings", styles["section"]))
    story.extend(_finding_flowables(report, styles))

    story.append(_p("Security check results", styles["section"]))
    story.append(
        _p(
            "Results below are the checks that were actually returned with this report. "
            "Not-applicable checks are labelled explicitly.",
            styles["small"],
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(_checks_table(report, styles))

    story.append(_p("Methodology and limitations", styles["section"]))
    story.append(
        _p(
            "API Sentinel performs a bounded, non-destructive HTTP GET request and applies "
            "explicit rule-based checks to the response status, timing, and selected "
            "security-related headers. It does not authenticate, fuzz, exploit, enumerate "
            "routes, or test business logic.",
            styles["body"],
        )
    )
    if report.risk_model:
        story.append(_p(report.risk_model.method, styles["body"]))
        weights = ", ".join(
            f"{label.title()} {report.risk_model.weights.get(label.value, 0)}"
            for label in SEVERITY_ORDER
            if label.value in report.risk_model.weights
        )
        bands = ", ".join(
            f"{level.title()} {band}"
            for level, band in report.risk_model.bands.items()
        )
        if weights:
            story.append(_p(f"Rule weights: {weights} points.", styles["small"]))
        if bands:
            story.append(_p(f"Risk bands: {bands}.", styles["small"]))
        story.append(_p(report.risk_model.disclaimer, styles["small"]))

    story.append(
        _p(
            "Missing headers may indicate a hardening opportunity but do not automatically "
            "prove an exploitable vulnerability. The security score is a heuristic based on "
            "the project's additive rule model; higher scores indicate more configuration "
            "risk. This report is not a penetration-test certificate or a guarantee of "
            "security, and it reflects only the checks performed at the reported time.",
            styles["body"],
        )
    )

    if report.limitations:
        story.append(_p("Reported limitations", styles["subheading"]))
        for limitation in report.limitations[:MAX_LIMITATIONS]:
            story.append(_p("• " + _clean(limitation), styles["bullet"]))

    story.append(_p("Responsible use", styles["section"]))
    story.append(
        _p(
            "API Sentinel should be used only against systems that the user owns or has "
            "explicit permission to assess. The report is intended to support learning, "
            "review, and remediation planning, not unauthorized testing.",
            styles["body"],
        )
    )

    story.append(Spacer(1, 4 * mm))
    attribution = Table(
        [
            [_p("Created by Biniyam Shambel", styles["attribution"])],
            [_p("Ethical Hacker | ID-CTC_721", styles["attribution_sub"])],
        ],
        colWidths=[PAGE_WIDTH - 2 * MARGIN_X - 2 * mm],
        hAlign="LEFT",
    )
    attribution.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BEIGE),
                ("BOX", (0, 0), (-1, -1), 0.7, LATTE),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (0, 0), 7),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
            ]
        )
    )
    story.append(attribution)
    story.append(Spacer(1, 3 * mm))
    story.append(
        _p(
            "API Sentinel is an API health monitoring and security configuration assessment "
            "tool designed to help users understand API availability, response performance, "
            "and HTTP security-header configuration.",
            styles["small"],
        )
    )

    doc.build(story, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()


def pdf_filename(report: ScanReport) -> str:
    return f"api-sentinel-report-{_report_date(report)}.pdf"


def validate_pdf_report_limits(report: ScanReport) -> None:
    """Reject reports that would create unbounded PDF work."""

    if len(report.findings) > MAX_FINDINGS:
        raise ValueError(f"Reports are limited to {MAX_FINDINGS} findings.")
    if len(report.checks) > MAX_CHECKS:
        raise ValueError(f"Reports are limited to {MAX_CHECKS} checks.")
    if len(report.limitations) > MAX_LIMITATIONS:
        raise ValueError(f"Reports are limited to {MAX_LIMITATIONS} limitations.")
    if len(report.redirect_chain) > MAX_REDIRECTS:
        raise ValueError(f"Reports are limited to {MAX_REDIRECTS} redirect entries.")
