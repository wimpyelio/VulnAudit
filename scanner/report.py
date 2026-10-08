from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF

from .models import Finding, ScanResult


# ---------------------------------------------------------------------------
# JSON REPORT
# ---------------------------------------------------------------------------


def result_json(result: ScanResult) -> dict:
    return {
        "target_url": result.target_url,
        "scanner_version": result.scanner_version,
        "duration_ms": result.duration_ms,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in result.findings],
    }


def write_json(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(result_json(result), indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# REPORT HELPERS
# ---------------------------------------------------------------------------


def _clean(text: str) -> str:
    """Normalize text for predictable cross-platform PDF rendering."""
    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
        "\u2022": "-",
        "\u2192": "->",
    }

    value = str(text)

    for source, target in replacements.items():
        value = value.replace(source, target)

    return value


def _risk_for(finding: Finding) -> str:
    if finding.id == "VA-001":
        return (
            "An unauthenticated attacker can alter the login query and obtain "
            "an authenticated session."
        )

    if finding.id == "VA-002":
        return (
            "An attacker can execute script in a victim's browser under the "
            "application's origin when the crafted link is visited."
        )

    if finding.id == "VA-003":
        return (
            "A caller can retrieve records belonging to other users by changing "
            "the object identifier."
        )

    if finding.id == "VA-004":
        return (
            "Predictable session material and weak credential controls reduce "
            "resistance to account takeover."
        )

    if finding.id == "VA-006":
        return (
            "A cross-site request can trigger a balance-changing operation in a "
            "victim's authenticated context."
        )

    if finding.owasp_category == "A05 Security Misconfiguration":
        return (
            "Missing defensive controls or verbose responses expose implementation "
            "details or reduce browser-side protection."
        )

    return "The observed behavior can weaken the security boundary described by the finding."


def _font_candidates() -> dict[str, list[str]]:
    return {
        "regular": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "C:/Windows/Fonts/segoeui.ttf",
            "C:/Windows/Fonts/arial.ttf",
        ],
        "bold": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "C:/Windows/Fonts/segoeuib.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
        ],
        "mono": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "C:/Windows/Fonts/consola.ttf",
            "C:/Windows/Fonts/cour.ttf",
        ],
    }


# ---------------------------------------------------------------------------
# LANDSCAPE PDF
# ---------------------------------------------------------------------------


class _VulnAuditPDF(FPDF):
    def __init__(self) -> None:
        # A4 landscape: 297 x 210 mm
        super().__init__(orientation="L", unit="mm", format="A4")

        self.section = ""
        self.font_main = "Helvetica"
        self.font_mono = "Courier"

    def header(self) -> None:
        if self.page_no() <= 1:
            return

        self.set_y(7)

        self.set_draw_color(226, 232, 240)
        self.set_line_width(0.25)
        self.line(
            self.l_margin,
            14,
            self.w - self.r_margin,
            14,
        )

        self.set_text_color(15, 23, 42)
        self.set_font(self.font_main, "B", 7.4)
        self.cell(38, 4.5, "VULNAUDIT")

        self.set_text_color(100, 116, 139)
        self.set_font(self.font_main, size=7.0)
        self.cell(
            self.epw - 38,
            4.5,
            _clean(self.section),
            align="R",
        )

        self.set_y(18)

    def footer(self) -> None:
        if self.page_no() <= 1:
            return

        self.set_y(-10)

        self.set_draw_color(226, 232, 240)
        self.set_line_width(0.25)
        self.line(
            self.l_margin,
            self.get_y(),
            self.w - self.r_margin,
            self.get_y(),
        )

        self.set_y(-7.7)
        self.set_text_color(100, 116, 139)
        self.set_font(self.font_main, size=6.6)

        self.cell(
            150,
            3.5,
            "VulnAudit - Vulnerability Assessment & Penetration Testing",
        )

        self.cell(
            self.epw - 150,
            3.5,
            f"Page {self.page_no()}",
            align="R",
        )


def _register_fonts(pdf: _VulnAuditPDF) -> None:
    paths = _font_candidates()

    regular = next(
        (p for p in paths["regular"] if os.path.exists(p)),
        None,
    )

    bold = next(
        (p for p in paths["bold"] if os.path.exists(p)),
        None,
    )

    mono = next(
        (p for p in paths["mono"] if os.path.exists(p)),
        None,
    )

    if regular and bold:
        pdf.add_font("VA", "", regular)
        pdf.add_font("VA", "B", bold)
        pdf.font_main = "VA"

    if mono:
        pdf.add_font("VAMono", "", mono)
        pdf.font_mono = "VAMono"


def write_pdf(result: ScanResult, path: str | Path) -> None:
    pdf = _VulnAuditPDF()

    # Landscape page with compact professional margins.
    pdf.set_auto_page_break(
        auto=True,
        margin=13,
    )

    pdf.set_margins(
        12,
        18,
        12,
    )

    _register_fonts(pdf)

    pdf.set_title("VulnAudit - VAPT Report")
    pdf.set_author("VulnAudit")
    pdf.set_subject(
        "Vulnerability Assessment and Penetration Testing Report"
    )

    # -----------------------------------------------------------------------
    # Palette
    # -----------------------------------------------------------------------

    NAVY = (15, 23, 42)
    SLATE = (51, 65, 85)
    MUTED = (100, 116, 139)
    LIGHT = (248, 250, 252)
    LINE = (226, 232, 240)
    WHITE = (255, 255, 255)

    BLUE = (37, 99, 235)
    BLUE_SOFT = (239, 246, 255)

    CRITICAL = (185, 28, 28)
    HIGH = (194, 65, 12)
    MEDIUM = (180, 83, 9)
    LOW = (21, 128, 61)
    INFO = (30, 64, 175)

    severity_colors = {
        "Critical": CRITICAL,
        "High": HIGH,
        "Medium": MEDIUM,
        "Low": LOW,
        "Informational": INFO,
    }

    counts = Counter(
        finding.severity
        for finding in result.findings
    )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def set_font(
        style: str = "",
        size: float = 9.0,
        mono: bool = False,
    ) -> None:
        pdf.set_font(
            pdf.font_mono if mono else pdf.font_main,
            style,
            size,
        )

    def wrap_lines(
        text: str,
        width: float,
        size: float,
        mono: bool = False,
    ) -> list[str]:
        clean = _clean(text).replace("\r", "")

        set_font(
            size=size,
            mono=mono,
        )

        out: list[str] = []

        for paragraph in (clean.split("\n") or [""]):
            if paragraph == "":
                out.append("")
                continue

            current = ""

            for word in paragraph.split(" "):
                candidate = (
                    word
                    if not current
                    else f"{current} {word}"
                )

                if pdf.get_string_width(candidate) <= width:
                    current = candidate
                    continue

                if current:
                    out.append(current)
                    current = ""

                if pdf.get_string_width(word) <= width:
                    current = word
                    continue

                # Long unbroken token fallback for URLs/payloads.
                chunk = ""

                for char in word:
                    candidate = chunk + char

                    if pdf.get_string_width(candidate) <= width:
                        chunk = candidate
                    else:
                        if chunk:
                            out.append(chunk)

                        chunk = char

                current = chunk

            if current:
                out.append(current)

        return out or [""]

    def section(
        number: str,
        title: str,
    ) -> None:
        pdf.section = f"{number}. {title}"

        pdf.add_page()

        pdf.set_text_color(*NAVY)
        set_font("B", 15)

        pdf.cell(
            0,
            7,
            _clean(f"{number}. {title}"),
            ln=1,
        )

        pdf.set_text_color(*MUTED)
        set_font(size=7.2)

        pdf.cell(
            0,
            4,
            "VulnAudit assessment report",
            ln=1,
        )

        pdf.set_draw_color(*LINE)
        pdf.set_line_width(0.35)

        pdf.line(
            pdf.l_margin,
            pdf.get_y() + 2,
            pdf.w - pdf.r_margin,
            pdf.get_y() + 2,
        )

        pdf.ln(7)

    def note(text: str) -> None:
        y = pdf.get_y()

        lines = wrap_lines(
            text,
            pdf.epw - 8,
            7.3,
        )

        h = max(
            10,
            5 + len(lines) * 3.6,
        )

        pdf.set_fill_color(*BLUE_SOFT)
        pdf.set_draw_color(
            191,
            219,
            254,
        )

        pdf.rect(
            pdf.l_margin,
            y,
            pdf.epw,
            h,
            style="DF",
        )

        pdf.set_xy(
            pdf.l_margin + 4,
            y + 3,
        )

        pdf.set_text_color(*SLATE)
        set_font(size=7.3)

        pdf.multi_cell(
            pdf.epw - 8,
            3.6,
            "\n".join(lines),
            align="L",
        )

        pdf.set_y(
            y + h + 5,
        )

    def box(
        x: float,
        y: float,
        w: float,
        h: float,
        *,
        fill=WHITE,
        border=LINE,
    ) -> None:
        pdf.set_fill_color(*fill)
        pdf.set_draw_color(*border)

        pdf.rect(
            x,
            y,
            w,
            h,
            style="DF",
        )

    def text_box(
        x: float,
        y: float,
        w: float,
        title: str,
        text: str,
        *,
        h: float | None = None,
        mono: bool = False,
        fill=WHITE,
        title_color=NAVY,
        body_color=SLATE,
        title_size=7.0,
        body_size=7.0,
        line_h=3.5,
    ) -> float:
        lines = wrap_lines(
            text or "(None supplied.)",
            w - 8,
            body_size,
            mono=mono,
        )

        needed = (
            7
            + len(lines) * line_h
            + 4
        )

        height = max(
            h or 0,
            needed,
            17,
        )

        box(
            x,
            y,
            w,
            height,
            fill=fill,
        )

        pdf.set_xy(
            x + 4,
            y + 2.5,
        )

        pdf.set_text_color(*title_color)

        set_font(
            "B",
            title_size,
        )

        pdf.cell(
            w - 8,
            4,
            _clean(title),
            ln=1,
        )

        pdf.set_x(x + 4)
        pdf.set_text_color(*body_color)

        set_font(
            size=body_size,
            mono=mono,
        )

        pdf.multi_cell(
            w - 8,
            line_h,
            "\n".join(lines),
            align="L",
        )

        return height

    def pill(
        text: str,
        color: tuple[int, int, int],
        x: float,
        y: float,
        w: float = 27,
    ) -> None:
        pdf.set_fill_color(*color)

        pdf.rect(
            x,
            y,
            w,
            6.5,
            style="F",
        )

        pdf.set_xy(
            x,
            y + 1.5,
        )

        pdf.set_text_color(*WHITE)

        set_font(
            "B",
            5.7,
        )

        pdf.cell(
            w,
            3,
            _clean(text.upper()),
            align="C",
        )

    def severity_cell(
        x: float,
        y: float,
        w: float,
        h: float,
        severity: str,
    ) -> None:
        color = severity_colors.get(
            severity,
            INFO,
        )

        pdf.set_fill_color(*color)

        pdf.rect(
            x + 3,
            y + 2.6,
            w - 6,
            h - 5.2,
            style="F",
        )

        pdf.set_xy(
            x + 2,
            y + (h / 2) - 1.6,
        )

        pdf.set_text_color(*WHITE)

        set_font(
            "B",
            5.6,
        )

        pdf.cell(
            w - 4,
            3.2,
            _clean(severity.upper()),
            align="C",
        )

    def table_header(
        headers: list[str],
        widths: list[float],
        y: float,
        x: float | None = None,
    ) -> None:
        x0 = (
            pdf.l_margin
            if x is None
            else x
        )

        pdf.set_fill_color(*NAVY)
        pdf.set_draw_color(*NAVY)
        pdf.set_text_color(*WHITE)

        set_font(
            "B",
            6.7,
        )

        for header, width in zip(headers, widths):
            pdf.rect(
                x0,
                y,
                width,
                8,
                style="F",
            )

            pdf.set_xy(
                x0 + 2,
                y + 2.2,
            )

            pdf.cell(
                width - 4,
                3.4,
                _clean(header),
            )

            x0 += width

        pdf.set_y(y + 8)

    # -----------------------------------------------------------------------
    # Finding summary table
    # -----------------------------------------------------------------------

    def summary_table(
        findings: list[Finding],
    ) -> None:
        widths = [
            42,
            32,
            72,
            pdf.epw - 42 - 32 - 72,
        ]

        headers = [
            "ID",
            "SEVERITY",
            "FINDING",
            "OWASP CATEGORY",
        ]

        table_header(
            headers,
            widths,
            pdf.get_y(),
        )

        for idx, finding in enumerate(findings):
            title_lines = wrap_lines(
                finding.title,
                widths[2] - 6,
                6.8,
            )

            owasp_lines = wrap_lines(
                finding.owasp_category,
                widths[3] - 6,
                6.6,
            )

            row_h = max(
                9.5,
                2.5
                + max(
                    len(title_lines) * 3.4,
                    len(owasp_lines) * 3.2,
                ),
            )

            if (
                pdf.get_y() + row_h
                > pdf.h - 18
            ):
                pdf.add_page()

                pdf.section = (
                    "4. Finding Summary"
                )

                y = pdf.get_y()

                pdf.set_text_color(*NAVY)
                set_font("B", 11.5)

                pdf.cell(
                    0,
                    6,
                    "4. Finding Summary - continued",
                    ln=1,
                )

                pdf.ln(2)

                table_header(
                    headers,
                    widths,
                    pdf.get_y(),
                )

            y = pdf.get_y()

            fill = (
                WHITE
                if idx % 2
                else LIGHT
            )

            x = pdf.l_margin

            for width in widths:
                box(
                    x,
                    y,
                    width,
                    row_h,
                    fill=fill,
                )

                x += width

            x = pdf.l_margin

            pdf.set_text_color(*NAVY)

            set_font(
                "B",
                6.5,
            )

            pdf.set_xy(
                x + 2,
                y + (row_h - 3.5) / 2,
            )

            pdf.cell(
                widths[0] - 4,
                3.5,
                _clean(finding.id),
            )

            x += widths[0]

            severity_cell(
                x,
                y,
                widths[1],
                row_h,
                finding.severity,
            )

            x += widths[1]

            pdf.set_xy(
                x + 3,
                y + 2.4,
            )

            pdf.set_text_color(*SLATE)

            set_font(
                size=6.8,
            )

            pdf.multi_cell(
                widths[2] - 6,
                3.4,
                "\n".join(title_lines),
                align="L",
            )

            x += widths[2]

            pdf.set_xy(
                x + 3,
                y + 2.4,
            )

            pdf.set_text_color(*SLATE)

            set_font(
                size=6.6,
            )

            pdf.multi_cell(
                widths[3] - 6,
                3.2,
                "\n".join(owasp_lines),
                align="L",
            )

            pdf.set_y(
                y + row_h,
            )

    # -----------------------------------------------------------------------
    # Detailed finding block
    # -----------------------------------------------------------------------

    def finding_block(
        finding: Finding,
        y: float,
    ) -> float:
        color = severity_colors.get(
            finding.severity,
            INFO,
        )

        # Header row.
        #
        # A fixed ID column keeps long VA-005 identifiers completely
        # separated from the finding title.
        header_h = 12

        box(
            pdf.l_margin,
            y,
            pdf.epw,
            header_h,
            fill=LIGHT,
        )

        id_w = 44

        pdf.set_xy(
            pdf.l_margin + 4,
            y + 2.3,
        )

        pdf.set_text_color(*MUTED)

        set_font(
            "B",
            5.45,
        )

        pdf.cell(
            id_w - 4,
            3.2,
            _clean(finding.id),
        )

        title_x = (
            pdf.l_margin
            + id_w
            + 4
        )

        severity_x = (
            pdf.w
            - pdf.r_margin
            - 31
        )

        title_w = (
            severity_x
            - title_x
            - 4
        )

        pdf.set_xy(
            title_x,
            y + 1.9,
        )

        pdf.set_text_color(*NAVY)

        set_font(
            "B",
            9.7,
        )

        pdf.cell(
            title_w,
            4.7,
            _clean(finding.title),
        )

        pill(
            finding.severity,
            color,
            severity_x,
            y + 2.3,
            27,
        )

        pdf.set_xy(
            title_x,
            y + 7.1,
        )

        pdf.set_text_color(*MUTED)

        set_font(
            size=5.9,
        )

        pdf.cell(
            title_w,
            2.8,
            _clean(finding.owasp_category),
        )

        # -------------------------------------------------------------------
        # Description
        # -------------------------------------------------------------------

        desc_y = (
            y
            + header_h
            + 3
        )

        desc_h = text_box(
            pdf.l_margin,
            desc_y,
            pdf.epw,
            "Description",
            finding.description,
            fill=WHITE,
            body_size=6.9,
            line_h=3.4,
        )

        # -------------------------------------------------------------------
        # Evidence
        # -------------------------------------------------------------------

        gap = 4

        half = (
            pdf.epw - gap
        ) / 2

        ev_y = (
            desc_y
            + desc_h
            + 3
        )

        request = (
            finding.evidence.get(
                "request",
                "",
            )
            if finding.evidence
            else ""
        )

        response = (
            finding.evidence.get(
                "response_snippet",
                "",
            )
            if finding.evidence
            else ""
        )

        req_h = text_box(
            pdf.l_margin,
            ev_y,
            half,
            "Request",
            request,
            fill=LIGHT,
            mono=True,
            body_size=6.25,
            line_h=3.05,
        )

        resp_h = text_box(
            pdf.l_margin
            + half
            + gap,
            ev_y,
            half,
            "Response",
            response,
            fill=LIGHT,
            mono=True,
            body_size=6.25,
            line_h=3.05,
        )

        evidence_h = max(
            req_h,
            resp_h,
        )

        # -------------------------------------------------------------------
        # Risk + remediation
        # -------------------------------------------------------------------

        bottom_y = (
            ev_y
            + evidence_h
            + 3
        )

        remaining = (
            pdf.h
            - pdf.get_y()
            - 17
        )

        risk_text = _risk_for(
            finding,
        )

        rem_text = finding.remediation

        risk_h = max(
            24,
            min(
                35,
                7
                + len(
                    wrap_lines(
                        risk_text,
                        half - 8,
                        6.7,
                    )
                )
                * 3.2,
                + 4,
            ),
        )

        remediation_h = max(
            24,
            min(
                35,
                7
                + len(
                    wrap_lines(
                        rem_text,
                        half - 8,
                        6.7,
                    )
                )
                * 3.2,
                + 4,
            ),
        )

        content_h = max(
            risk_h,
            remediation_h,
        )

        # Keep the block conservative so two findings remain on a page.
        if (
            bottom_y
            + content_h
            > pdf.h - 16
        ):
            content_h = max(
                24,
                remaining,
            )

        text_box(
            pdf.l_margin,
            bottom_y,
            half,
            "Security impact",
            risk_text,
            h=content_h,
            fill=WHITE,
            body_size=6.7,
            line_h=3.2,
        )

        text_box(
            pdf.l_margin
            + half
            + gap,
            bottom_y,
            half,
            "Recommended remediation",
            rem_text,
            h=content_h,
            fill=WHITE,
            body_size=6.7,
            line_h=3.2,
        )

        return (
            bottom_y
            + content_h
            - y
        )

    # -----------------------------------------------------------------------
    # Cover
    # -----------------------------------------------------------------------

    pdf.add_page()
    pdf.section = "VulnAudit"

    pdf.set_fill_color(*NAVY)

    pdf.rect(
        0,
        0,
        pdf.w,
        pdf.h,
        style="F",
    )

    pdf.set_text_color(*WHITE)

    set_font(
        "B",
        25,
    )

    pdf.set_xy(
        pdf.l_margin,
        28,
    )

    pdf.cell(
        0,
        10,
        "VULNAUDIT",
    )

    pdf.set_text_color(
        191,
        219,
        254,
    )

    set_font(
        "B",
        9,
    )

    pdf.set_xy(
        pdf.l_margin,
        41,
    )

    pdf.cell(
        0,
        5,
        "VULNERABILITY ASSESSMENT & PENETRATION TESTING",
    )

    # Target block.
    card_y = 70
    card_h = 43

    pdf.set_fill_color(
        30,
        41,
        59,
    )

    pdf.set_draw_color(
        71,
        85,
        105,
    )

    pdf.rect(
        pdf.l_margin,
        card_y,
        pdf.epw,
        card_h,
        style="DF",
    )

    pdf.set_text_color(
        148,
        163,
        184,
    )

    set_font(
        "B",
        6.8,
    )

    pdf.set_xy(
        pdf.l_margin + 6,
        card_y + 7,
    )

    pdf.cell(
        36,
        4,
        "ASSESSMENT TARGET",
    )

    pdf.set_text_color(*WHITE)

    set_font(
        "B",
        13,
    )

    pdf.set_xy(
        pdf.l_margin + 6,
        card_y + 15,
    )

    target_lines = wrap_lines(
        result.target_url,
        pdf.epw - 12,
        13,
    )

    pdf.multi_cell(
        pdf.epw - 12,
        6,
        "\n".join(target_lines),
        align="L",
    )

    pdf.set_text_color(
        148,
        163,
        184,
    )

    set_font(
        size=6.8,
    )

    pdf.set_xy(
        pdf.l_margin + 6,
        card_y + 31,
    )

    pdf.cell(
        pdf.epw - 12,
        4,
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"· Scanner {result.scanner_version}",
    )

    # Compact summary strip.
    strip_y = 130
    strip_h = 30

    values = [
        ("FINDINGS", str(len(result.findings))),
        ("CRITICAL", str(counts.get("Critical", 0))),
        ("HIGH", str(counts.get("High", 0))),
        ("MEDIUM", str(counts.get("Medium", 0))),
        ("LOW", str(counts.get("Low", 0))),
    ]

    gap = 4

    strip_w = (
        pdf.epw
        - gap * (len(values) - 1)
    ) / len(values)

    for index, (label, value) in enumerate(values):
        x = (
            pdf.l_margin
            + index * (strip_w + gap)
        )

        pdf.set_fill_color(
            30,
            41,
            59,
        )

        pdf.rect(
            x,
            strip_y,
            strip_w,
            strip_h,
            style="F",
        )

        pdf.set_text_color(
            148,
            163,
            184,
        )

        set_font(
            "B",
            6.1,
        )

        pdf.set_xy(
            x,
            strip_y + 5,
        )

        pdf.cell(
            strip_w,
            4,
            label,
            align="C",
        )

        pdf.set_text_color(*WHITE)

        set_font(
            "B",
            15,
        )

        pdf.set_xy(
            x,
            strip_y + 11,
        )

        pdf.cell(
            strip_w,
            7,
            value,
            align="C",
        )

    pdf.set_text_color(
        148,
        163,
        184,
    )

    set_font(
        size=6.8,
    )

    pdf.set_xy(
        pdf.l_margin,
        pdf.h - 21,
    )

    pdf.cell(
        0,
        4,
        "Prepared by VulnAudit",
    )

    # -----------------------------------------------------------------------
    # Executive summary
    # -----------------------------------------------------------------------

    section(
        "1",
        "Executive Summary",
    )

    note(
        "This report records the deterministic vulnerability assessment performed against the configured local target. The findings below are the results emitted by the existing scanner."
    )

    severity_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ]

    gap = 4

    card_w = (
        pdf.epw
        - gap * 4
    ) / 5

    y = pdf.get_y()

    for idx, severity in enumerate(
        severity_order
    ):
        x = (
            pdf.l_margin
            + idx * (
                card_w
                + gap
            )
        )

        color = severity_colors[
            severity
        ]

        pdf.set_fill_color(*color)

        pdf.rect(
            x,
            y,
            card_w,
            18,
            style="F",
        )

        pdf.set_xy(
            x,
            y + 2.5,
        )

        pdf.set_text_color(*WHITE)

        set_font(
            "B",
            6.3,
        )

        pdf.cell(
            card_w,
            3.5,
            severity.upper(),
            align="C",
        )

        pdf.set_xy(
            x,
            y + 8,
        )

        set_font(
            "B",
            13,
        )

        pdf.cell(
            card_w,
            6,
            str(
                counts.get(
                    severity,
                    0,
                )
            ),
            align="C",
        )

    pdf.set_y(
        y + 24,
    )

    pdf.set_text_color(*NAVY)

    set_font(
        "B",
        10.5,
    )

    pdf.cell(
        0,
        5,
        "Priority findings",
    )

    pdf.ln(4)

    headers = [
        "ID",
        "SEVERITY",
        "FINDING",
    ]

    widths = [
        31,
        32,
        pdf.epw - 31 - 32,
    ]

    table_header(
        headers,
        widths,
        pdf.get_y(),
    )

    priority = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }

    top = sorted(
        result.findings,
        key=lambda f: priority.get(
            f.severity,
            5,
        ),
    )[:4]

    for idx, finding in enumerate(top):
        h = 10

        y = pdf.get_y()

        fill = (
            WHITE
            if idx % 2
            else LIGHT
        )

        x = pdf.l_margin

        for width in widths:
            box(
                x,
                y,
                width,
                h,
                fill=fill,
            )

            x += width

        x = pdf.l_margin

        pdf.set_xy(
            x + 2,
            y + 3.2,
        )

        pdf.set_text_color(*NAVY)

        set_font(
            "B",
            6.6,
        )

        pdf.cell(
            widths[0] - 4,
            3.5,
            _clean(finding.id),
        )

        x += widths[0]

        severity_cell(
            x,
            y,
            widths[1],
            h,
            finding.severity,
        )

        x += widths[1]

        pdf.set_xy(
            x + 3,
            y + 3.2,
        )

        pdf.set_text_color(*SLATE)

        set_font(
            size=6.8,
        )

        pdf.cell(
            widths[2] - 6,
            3.5,
            _clean(finding.title),
        )

        pdf.set_y(
            y + h,
        )

    y = pdf.get_y() + 7

    conclusion_h = 26

    box(
        pdf.l_margin,
        y,
        pdf.epw,
        conclusion_h,
        fill=LIGHT,
    )

    pdf.set_xy(
        pdf.l_margin + 5,
        y + 4,
    )

    pdf.set_text_color(*NAVY)

    set_font(
        "B",
        7.4,
    )

    pdf.cell(
        42,
        4,
        "ASSESSMENT CONCLUSION",
    )

    pdf.set_xy(
        pdf.l_margin + 54,
        y + 4,
    )

    pdf.set_text_color(*SLATE)

    set_font(
        size=7.3,
    )

    pdf.multi_cell(
        pdf.epw - 59,
        3.7,
        "The highest-impact observed issue is SQL injection in the login functionality. Additional high-severity observations include reflected cross-site scripting, weak authentication controls, and missing CSRF protection.",
        align="L",
    )

    # -----------------------------------------------------------------------
    # Scope
    # -----------------------------------------------------------------------

    section(
        "2",
        "Scope",
    )

    note(
        "The assessment is scoped to the configured local target and the application paths exercised by the deterministic probes."
    )

    gap = 5

    half = (
        pdf.epw - gap
    ) / 2

    y = pdf.get_y()

    left_h = text_box(
        pdf.l_margin,
        y,
        half,
        "Assessment target",
        result.target_url,
        h=31,
        body_size=8.2,
        line_h=4.0,
    )

    right_h = text_box(
        pdf.l_margin + half + gap,
        y,
        half,
        "Scan configuration",
        (
            f"Scanner version: {result.scanner_version}\n"
            f"Scan duration: {result.duration_ms} ms\n"
            f"Finding count: {len(result.findings)}"
        ),
        h=31,
        body_size=7.6,
        line_h=4.0,
    )

    pdf.set_y(
        y + max(
            left_h,
            right_h,
        ) + 7,
    )

    pdf.set_text_color(*NAVY)

    set_font(
        "B",
        10.5,
    )

    pdf.cell(
        0,
        5,
        "URLs tested",
    )

    pdf.ln(4)

    endpoints = [
        f"{result.target_url}/login",
        f"{result.target_url}/search",
        f"{result.target_url}/user/1-20",
        f"{result.target_url}/admin/debug",
        f"{result.target_url}/static/",
        f"{result.target_url}/transfer",
    ]

    headers = [
        "METHOD",
        "ENDPOINT",
    ]

    widths = [
        26,
        pdf.epw - 26,
    ]

    table_header(
        headers,
        widths,
        pdf.get_y(),
    )

    for idx, endpoint in enumerate(endpoints):
        y = pdf.get_y()

        h = 8

        fill = (
            WHITE
            if idx % 2
            else LIGHT
        )

        box(
            pdf.l_margin,
            y,
            widths[0],
            h,
            fill=fill,
        )

        box(
            pdf.l_margin + widths[0],
            y,
            widths[1],
            h,
            fill=fill,
        )

        pdf.set_xy(
            pdf.l_margin + 2,
            y + 2.4,
        )

        pdf.set_text_color(*BLUE)

        set_font(
            "B",
            6.5,
        )

        pdf.cell(
            widths[0] - 4,
            3.5,
            "HTTP",
        )

        pdf.set_xy(
            pdf.l_margin
            + widths[0]
            + 3,
            y + 2.4,
        )

        pdf.set_text_color(*SLATE)

        set_font(
            size=7.0,
            mono=True,
        )

        pdf.cell(
            widths[1] - 6,
            3.5,
            _clean(endpoint),
        )

        pdf.set_y(
            y + h,
        )

    y = pdf.get_y() + 7

    text_box(
        pdf.l_margin,
        y,
        pdf.epw,
        "Exclusions",
        "External hosts and non-PRD application paths were excluded from the assessment.",
        h=21,
        body_size=7.2,
        line_h=3.7,
    )

    # -----------------------------------------------------------------------
    # Methodology
    # -----------------------------------------------------------------------

    section(
        "3",
        "Methodology",
    )

    note(
        "VulnAudit uses deterministic HTTP probes designed around the configured acceptance conditions. A finding is emitted only when the corresponding observed behavior satisfies the probe condition."
    )

    methodology_items = [
        (
            "SQL Injection",
            "SQL error detection and boolean login injection.",
        ),
        (
            "Reflected XSS",
            "Unique-marker reflected XSS testing.",
        ),
        (
            "IDOR",
            "Sequential object identifier walk.",
        ),
        (
            "Authentication",
            "Common-credential attempt, token-entropy calculation, and failed-login lockout testing.",
        ),
        (
            "Security Headers",
            "Exact security-header checks, verbose error testing, and directory-listing checks.",
        ),
        (
            "CSRF",
            "State-changing transfer request without a CSRF token.",
        ),
    ]

    headers = [
        "#",
        "METHOD",
        "PROBE DESCRIPTION",
    ]

    widths = [
        12,
        48,
        pdf.epw - 60,
    ]

    table_header(
        headers,
        widths,
        pdf.get_y(),
    )

    for index, (
        title,
        description,
    ) in enumerate(
        methodology_items,
        start=1,
    ):
        y = pdf.get_y()

        h = 15

        fill = (
            WHITE
            if index % 2
            else LIGHT
        )

        box(
            pdf.l_margin,
            y,
            widths[0],
            h,
            fill=fill,
        )

        box(
            pdf.l_margin + widths[0],
            y,
            widths[1],
            h,
            fill=fill,
        )

        box(
            pdf.l_margin + widths[0] + widths[1],
            y,
            widths[2],
            h,
            fill=fill,
        )

        pdf.set_xy(
            pdf.l_margin + 2,
            y + 5,
        )

        pdf.set_text_color(*BLUE)

        set_font(
            "B",
            7.0,
        )

        pdf.cell(
            widths[0] - 4,
            4,
            f"{index:02d}",
        )

        pdf.set_xy(
            pdf.l_margin
            + widths[0]
            + 3,
            y + 5,
        )

        pdf.set_text_color(*NAVY)

        set_font(
            "B",
            7.0,
        )

        pdf.cell(
            widths[1] - 6,
            4,
            _clean(title),
        )

        pdf.set_xy(
            pdf.l_margin
            + widths[0]
            + widths[1]
            + 3,
            y + 4,
        )

        pdf.set_text_color(*SLATE)

        set_font(
            size=6.9,
        )

        pdf.multi_cell(
            widths[2] - 6,
            3.6,
            _clean(description),
            align="L",
        )

        pdf.set_y(
            y + h,
        )

    y = pdf.get_y() + 7

    text_box(
        pdf.l_margin,
        y,
        half,
        "Tools and implementation",
        "requests, BeautifulSoup, and deterministic local HTTP probes.",
        h=24,
        body_size=7.0,
        line_h=3.5,
    )

    text_box(
        pdf.l_margin + half + gap,
        y,
        half,
        "False-positive controls",
        "A finding is emitted only when its PRD acceptance condition is observed. Security-header findings use exact header names.",
        h=24,
        body_size=7.0,
        line_h=3.5,
    )

    # -----------------------------------------------------------------------
    # Finding Summary
    # -----------------------------------------------------------------------

    section(
        "4",
        "Finding Summary",
    )

    note(
        "The table below is the complete finding inventory for this scan, preserving the stored ID, severity, title, and OWASP mapping."
    )

    summary_table(
        result.findings,
    )

    # -----------------------------------------------------------------------
    # Detailed Findings
    #
    # Landscape gives enough horizontal space to keep two findings together
    # on most pages while retaining readable request/response blocks.
    # -----------------------------------------------------------------------

    pdf.section = "5. Detailed Findings"

    for index in range(
        0,
        len(result.findings),
        2,
    ):
        pdf.add_page()

        pdf.section = "5. Detailed Findings"

        first = result.findings[index]

        second = (
            result.findings[index + 1]
            if index + 1 < len(result.findings)
            else None
        )

        y = pdf.get_y()

        used = finding_block(
            first,
            y,
        )

        if second is not None:
            y2 = (
                y
                + used
                + 5
            )

            finding_block(
                second,
                y2,
            )

    # -----------------------------------------------------------------------
    # Appendix
    # -----------------------------------------------------------------------

    section(
        "6",
        "Appendix",
    )

    note(
        "Report configuration and evidence-handling notes for reproducibility."
    )

    y = pdf.get_y()

    left_h = text_box(
        pdf.l_margin,
        y,
        half,
        "Report configuration",
        (
            f"Target: {result.target_url}\n"
            f"Scanner version: {result.scanner_version}\n"
            "HTTP timeout: 5 seconds\n"
            "Probe model: Deterministic local HTTP probes"
        ),
        h=38,
        body_size=7.2,
        line_h=3.7,
    )

    right_h = text_box(
        pdf.l_margin + half + gap,
        y,
        half,
        "Evidence handling",
        "Raw response samples are limited to 2 KB per response snippet in accordance with the report configuration.",
        h=38,
        body_size=7.2,
        line_h=3.7,
    )

    pdf.set_y(
        y
        + max(
            left_h,
            right_h,
        )
        + 7,
    )

    text_box(
        pdf.l_margin,
        pdf.get_y(),
        pdf.epw,
        "Finding count",
        (
            f"The completed assessment contains "
            f"{len(result.findings)} findings: "
            f"{counts.get('Critical', 0)} Critical, "
            f"{counts.get('High', 0)} High, "
            f"{counts.get('Medium', 0)} Medium, "
            f"{counts.get('Low', 0)} Low, and "
            f"{counts.get('Informational', 0)} Informational."
        ),
        h=23,
        body_size=7.2,
        line_h=3.7,
        fill=LIGHT,
    )

    Path(path).parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    pdf.output(
        str(path),
    )