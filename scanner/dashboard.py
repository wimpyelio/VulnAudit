"""VulnAudit Streamlit dashboard.

The dashboard owns presentation and Streamlit orchestration only. Scanner,
report, model, database, and CLI behavior remain in their existing modules.
"""

from __future__ import annotations

import html
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from .cli import save_history
from .database import connect
from .models import SEVERITIES, ScanResult
from .probes import VERSION, run_probe_stream
from .report import write_json, write_pdf


PAGE_TITLE = "VulnAudit"
DEFAULT_TARGET = "http://127.0.0.1:5000"
SEVERITY_ORDER = list(SEVERITIES)
SEVERITY_CLASS = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --va-ink: #111827;
            --va-muted: #667085;
            --va-subtle: #98a2b3;
            --va-line: #e4e7ec;
            --va-surface: #ffffff;
            --va-surface-2: #f8fafc;
            --va-accent: #155eef;
            --va-accent-dark: #0b4bc4;
            --va-critical: #b42318;
            --va-critical-bg: #fef3f2;
            --va-high: #c4320a;
            --va-high-bg: #fff6ed;
            --va-medium: #b54708;
            --va-medium-bg: #fffaeb;
            --va-low: #027a48;
            --va-low-bg: #ecfdf3;
            --va-info: #175cd3;
            --va-info-bg: #eff8ff;
        }

        .stApp {
            background: #f5f7fa;
        }

        [data-testid="stHeader"] {
            background: rgba(245, 247, 250, 0.86);
        }

        .block-container {
            max-width: 1320px;
            padding-top: 2rem;
            padding-bottom: 4rem;
        }

        [data-testid="stSidebar"] {
            background: #ffffff;
            border-right: 1px solid var(--va-line);
        }

        [data-testid="stSidebar"] .block-container {
            padding: 1.5rem 1.15rem;
        }

        .va-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 1.5rem;
        }

        .va-mark {
            width: 38px;
            height: 38px;
            display: grid;
            place-items: center;
            border-radius: 11px;
            background: #111827;
            color: #ffffff;
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.03em;
        }

        .va-brand-name {
            color: var(--va-ink);
            font-size: 16px;
            line-height: 1.1;
            font-weight: 750;
            letter-spacing: -0.02em;
        }

        .va-brand-meta {
            color: var(--va-muted);
            font-size: 11px;
            margin-top: 3px;
        }

        .va-hero {
            background: linear-gradient(135deg, #101828 0%, #182230 64%, #1d2939 100%);
            border: 1px solid #253244;
            border-radius: 18px;
            padding: 28px 30px;
            margin: 0 0 22px;
            box-shadow: 0 10px 30px rgba(16, 24, 40, 0.12);
        }

        .va-eyebrow {
            color: #b7c4d6;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: .12em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        .va-hero h1 {
            color: #ffffff;
            font-size: clamp(28px, 4vw, 42px);
            line-height: 1.05;
            letter-spacing: -0.04em;
            margin: 0 0 10px;
        }

        .va-hero p {
            color: #c7d1df;
            max-width: 760px;
            margin: 0;
            font-size: 14px;
            line-height: 1.6;
        }

        .va-status {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            margin-top: 18px;
            padding: 6px 10px;
            border: 1px solid rgba(255,255,255,.14);
            border-radius: 999px;
            color: #d0d5dd;
            background: rgba(255,255,255,.06);
            font-size: 12px;
        }

        .va-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #32d583;
        }

        .va-section {
            margin: 30px 0 12px;
        }

        .va-section-title {
            color: var(--va-ink);
            font-size: 18px;
            font-weight: 750;
            letter-spacing: -0.02em;
            margin: 0;
        }

        .va-section-copy {
            color: var(--va-muted);
            font-size: 13px;
            margin: 4px 0 14px;
        }

        .va-card {
            background: var(--va-surface);
            border: 1px solid var(--va-line);
            border-radius: 14px;
            padding: 16px 17px;
            min-height: 94px;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.03);
        }

        .va-card-label {
            color: var(--va-muted);
            font-size: 11px;
            font-weight: 650;
            letter-spacing: .06em;
            text-transform: uppercase;
        }

        .va-card-value {
            color: var(--va-ink);
            font-size: 27px;
            line-height: 1.1;
            font-weight: 760;
            margin-top: 8px;
            letter-spacing: -0.04em;
        }

        .va-card-note {
            color: var(--va-subtle);
            font-size: 11px;
            margin-top: 5px;
        }

        .va-card.critical { border-top: 3px solid var(--va-critical); }
        .va-card.high { border-top: 3px solid var(--va-high); }
        .va-card.medium { border-top: 3px solid var(--va-medium); }
        .va-card.low { border-top: 3px solid var(--va-low); }
        .va-card.info { border-top: 3px solid var(--va-info); }

        .va-finding {
            background: #ffffff;
            border: 1px solid var(--va-line);
            border-radius: 14px;
            padding: 16px 18px;
            margin: 0 0 10px;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.025);
        }

        .va-finding-top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
        }

        .va-finding-id {
            color: var(--va-subtle);
            font: 650 11px/1.2 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            letter-spacing: .04em;
            margin-bottom: 5px;
        }

        .va-finding-title {
            color: var(--va-ink);
            font-size: 15px;
            font-weight: 720;
            line-height: 1.35;
        }

        .va-badge {
            flex: 0 0 auto;
            border-radius: 999px;
            padding: 5px 9px;
            font-size: 11px;
            line-height: 1;
            font-weight: 750;
            border: 1px solid transparent;
        }

        .va-badge.critical { color: var(--va-critical); background: var(--va-critical-bg); border-color: #fecdca; }
        .va-badge.high { color: var(--va-high); background: var(--va-high-bg); border-color: #fedf89; }
        .va-badge.medium { color: var(--va-medium); background: var(--va-medium-bg); border-color: #fedf89; }
        .va-badge.low { color: var(--va-low); background: var(--va-low-bg); border-color: #abefc6; }
        .va-badge.info { color: var(--va-info); background: var(--va-info-bg); border-color: #b2ddff; }

        .va-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 12px;
        }

        .va-chip {
            display: inline-flex;
            align-items: center;
            border: 1px solid var(--va-line);
            border-radius: 7px;
            padding: 4px 7px;
            color: var(--va-muted);
            background: var(--va-surface-2);
            font-size: 11px;
        }

        .va-empty {
            background: #ffffff;
            border: 1px dashed #cfd5dd;
            border-radius: 14px;
            padding: 34px 24px;
            text-align: center;
        }

        .va-empty-title {
            color: var(--va-ink);
            font-weight: 720;
            font-size: 15px;
        }

        .va-empty-copy {
            color: var(--va-muted);
            font-size: 13px;
            margin-top: 5px;
        }

        .va-footer {
            color: var(--va-subtle);
            font-size: 11px;
            border-top: 1px solid var(--va-line);
            margin-top: 42px;
            padding-top: 16px;
        }

        div[data-testid="stButton"] > button,
        div[data-testid="stDownloadButton"] > button {
            border-radius: 9px;
            min-height: 42px;
            font-weight: 700;
        }

        div[data-testid="stButton"] > button[kind="primary"] {
            box-shadow: 0 5px 14px rgba(21, 94, 239, 0.18);
        }

        @media (max-width: 760px) {
            .block-container { padding: 1rem 0.85rem 3rem; }
            .va-hero { padding: 22px; border-radius: 14px; }
            .va-finding-top { gap: 10px; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _section(title: str, copy: str | None = None) -> None:
    st.markdown(f'<div class="va-section"><div class="va-section-title">{html.escape(title)}</div></div>', unsafe_allow_html=True)
    if copy:
        st.markdown(f'<div class="va-section-copy">{html.escape(copy)}</div>', unsafe_allow_html=True)


def _severity_counts(result: ScanResult) -> Counter[str]:
    counts: Counter[str] = Counter(f.severity for f in result.findings)
    return counts


def _render_summary(result: ScanResult) -> None:
    counts = _severity_counts(result)
    total = len(result.findings)
    highest = next((severity for severity in SEVERITY_ORDER if counts.get(severity, 0)), "None")

    cols = st.columns(5, gap="small")
    cards = [
        ("Findings", total, f"Scanner {VERSION}", ""),
        ("Critical", counts.get("Critical", 0), "Immediate attention", "critical"),
        ("High", counts.get("High", 0), "High-priority exposure", "high"),
        ("Medium", counts.get("Medium", 0), "Action recommended", "medium"),
        ("Low", counts.get("Low", 0), f"Highest severity: {highest}", "low"),
    ]
    for col, (label, value, note, cls) in zip(cols, cards):
        with col:
            st.markdown(
                f'<div class="va-card {cls}">'
                f'<div class="va-card-label">{html.escape(label)}</div>'
                f'<div class="va-card-value">{value}</div>'
                f'<div class="va-card-note">{html.escape(note)}</div>'
                '</div>',
                unsafe_allow_html=True,
            )


def _render_finding(finding) -> None:
    cls = SEVERITY_CLASS.get(finding.severity, "info")
    category = finding.owasp_category
    st.markdown(
        f'<div class="va-finding">'
        f'<div class="va-finding-top">'
        f'<div><div class="va-finding-id">{html.escape(finding.id)}</div>'
        f'<div class="va-finding-title">{html.escape(finding.title)}</div></div>'
        f'<span class="va-badge {cls}">{html.escape(finding.severity)}</span>'
        f'</div>'
        f'<div class="va-meta">'
        f'<span class="va-chip">{html.escape(category)}</span>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    with st.expander("View finding details", expanded=False):
        st.markdown("**Description**")
        st.write(finding.description)

        st.markdown("**Evidence**")
        evidence = finding.evidence or {}
        if evidence:
            for key, value in evidence.items():
                st.caption(str(key).replace("_", " ").title())
                st.code(str(value), language="text")
        else:
            st.caption("No evidence payload was returned for this finding.")

        st.markdown("**Remediation**")
        st.write(finding.remediation)


def _state_get(key: str, default=None):
    try:
        return st.session_state[key]
    except KeyError:
        return default


def _history_rows() -> list[tuple]:
    with connect() as db:
        return db.execute(
            "SELECT id, timestamp, target_url, duration_ms "
            "FROM scans ORDER BY id DESC LIMIT 20"
        ).fetchall()


def _finding_titles(scan_id: int) -> set[str]:
    with connect() as db:
        return {
            row[0]
            for row in db.execute(
                "SELECT title FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()
        }


def _render_history() -> None:
    rows = _history_rows()
    if not rows:
        st.markdown(
            '<div class="va-empty"><div class="va-empty-title">No scans recorded yet</div>'
            '<div class="va-empty-copy">Completed scans will appear here with timing and target details.</div></div>',
            unsafe_allow_html=True,
        )
        return

    history_records = [
        {
            "Scan ID": int(row[0]),
            "Timestamp": str(row[1]),
            "Target URL": str(row[2]),
            "Duration (ms)": int(row[3]),
        }
        for row in rows
    ]

    st.dataframe(
        history_records,
        hide_index=True,
        use_container_width=True,
        height=min(560, 48 + (len(history_records) * 35)),
        column_config={
            "Scan ID": st.column_config.NumberColumn(
                "Scan ID",
                width="small",
                format="%d",
            ),
            "Timestamp": st.column_config.TextColumn(
                "Timestamp",
                width="medium",
            ),
            "Target URL": st.column_config.TextColumn(
                "Target URL",
                width="large",
            ),
            "Duration (ms)": st.column_config.NumberColumn(
                "Duration",
                width="small",
                format="%d ms",
            ),
        },
        column_order=["Scan ID", "Timestamp", "Target URL", "Duration (ms)"],
    )
    st.caption(f"{len(rows)} most recent scans · newest first")

    if len(rows) < 2:
        st.caption("Run one more scan to compare the latest result with its predecessor.")
        return

    current_id = int(rows[0][0])
    previous_id = int(rows[1][0])
    current = _finding_titles(current_id)
    previous = _finding_titles(previous_id)
    new = sorted(current - previous)
    fixed = sorted(previous - current)
    unchanged = sorted(current & previous)

    _section("Latest delta", "Comparison of finding titles between the two most recent scans.")
    delta_cols = st.columns(3, gap="small")
    for col, label, values in zip(
        delta_cols,
        ("New", "Fixed", "Unchanged"),
        (new, fixed, unchanged),
    ):
        with col:
            st.markdown(
                f'<div class="va-card"><div class="va-card-label">{label}</div>'
                f'<div class="va-card-value">{len(values)}</div></div>',
                unsafe_allow_html=True,
            )
            if values:
                for value in values:
                    st.caption(value)
            else:
                st.caption("None")


def _run_scan(base_url: str) -> None:
    started = time.perf_counter()
    findings = []
    progress_placeholder = None

    try:
        with st.status("Scanning target", expanded=True) as status:
            st.write(f"Target: `{base_url.rstrip('/')}`")
            st.write("Running deterministic probes…")
            progress_placeholder = st.empty()

            for index, finding in enumerate(run_probe_stream(base_url), start=1):
                findings.append(finding)
                progress_placeholder.markdown(
                    f"**Probe {index} complete** · {finding.severity} · {finding.title}"
                )

            duration_ms = int((time.perf_counter() - started) * 1000)
            result = ScanResult(
                base_url.rstrip("/"),
                VERSION,
                duration_ms,
                findings,
            )

            Path("reports").mkdir(exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            json_path = Path("reports") / f"vulnaudit-{stamp}.json"
            pdf_path = Path("reports") / f"vulnaudit-{stamp}.pdf"

            write_json(result, json_path)
            write_pdf(result, pdf_path)
            scan_id = save_history(result, "scans.db")

            st.session_state["last_result"] = result
            st.session_state["last_json_path"] = str(json_path)
            st.session_state["last_pdf_path"] = str(pdf_path)
            st.session_state["last_scan_id"] = scan_id

            status.update(
                label=f"Scan complete · {len(findings)} findings · {duration_ms} ms",
                state="complete",
                expanded=False,
            )
    except Exception as exc:
        st.error("The scan could not be completed.")
        st.exception(exc)


def _render_exports(result: ScanResult) -> None:
    json_payload = json.dumps(
        {"findings": [f.to_dict() for f in result.findings]}, indent=2
    )
    pdf_path = Path(_state_get("last_pdf_path", ""))
    json_path = Path(_state_get("last_json_path", ""))

    cols = st.columns(2, gap="small")
    with cols[0]:
        st.download_button(
            "Download JSON",
            json_payload,
            file_name=json_path.name if json_path.name else "vulnaudit.json",
            mime="application/json",
            use_container_width=True,
        )
    with cols[1]:
        if pdf_path.exists():
            st.download_button(
                "Download PDF",
                pdf_path.read_bytes(),
                file_name=pdf_path.name,
                mime="application/pdf",
                use_container_width=True,
            )
        else:
            st.button("PDF unavailable", disabled=True, use_container_width=True)


def main() -> None:
    st.set_page_config(
        page_title=PAGE_TITLE,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_styles()

    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None

    with st.sidebar:
        st.markdown(
            '<div class="va-brand"><div class="va-mark">VA</div>'
            '<div><div class="va-brand-name">VulnAudit</div>'
            '<div class="va-brand-meta">Local VAPT dashboard</div></div></div>',
            unsafe_allow_html=True,
        )
        page = st.radio("Workspace", ["Overview", "Findings", "History"], label_visibility="collapsed")
        st.divider()
        st.caption("SCAN TARGET")
        base_url = st.text_input("Base URL", DEFAULT_TARGET, label_visibility="collapsed")
        scan_clicked = st.button("Run scan", type="primary", use_container_width=True)
        st.caption(f"Scanner version {VERSION}")
        st.caption("Local targets only")

    result = _state_get("last_result")

    if scan_clicked:
        _run_scan(base_url)
        result = _state_get("last_result")

    st.markdown(
        '<div class="va-hero">'
        '<div class="va-eyebrow">Security assessment workspace</div>'
        '<h1>VulnAudit</h1>'
        '<p>Inspect the local lab, review evidence by severity, and compare findings across scans without leaving the assessment workspace.</p>'
        '<div class="va-status"><span class="va-dot"></span> Scanner ready</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if page == "Overview":
        _section("Assessment overview", "The latest completed scan is the source for the dashboard metrics below.")
        if result:
            _render_summary(result)
            st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
            top_findings = sorted(
                result.findings,
                key=lambda item: SEVERITY_ORDER.index(item.severity),
            )[:5]
            _section("Priority findings", "The five highest-severity findings from the latest scan.")
            for finding in top_findings:
                _render_finding(finding)
            _section("Exports", "Download the latest assessment artifacts generated by the existing report pipeline.")
            _render_exports(result)
        else:
            st.markdown(
                '<div class="va-empty"><div class="va-empty-title">Ready for the first assessment</div>'
                '<div class="va-empty-copy">Set the local target in the sidebar and run a scan to populate findings, evidence, exports, and history.</div></div>',
                unsafe_allow_html=True,
            )

    elif page == "Findings":
        _section("Findings", "Filter the latest scan by severity and open any finding for evidence and remediation.")
        if result:
            counts = _severity_counts(result)
            filter_options = ["All"] + SEVERITY_ORDER
            selected = st.selectbox(
                "Severity",
                filter_options,
                format_func=lambda value: f"{value} · {len(result.findings) if value == 'All' else counts.get(value, 0)}",
            )
            filtered = [
                finding
                for finding in result.findings
                if selected == "All" or finding.severity == selected
            ]
            st.caption(f"Showing {len(filtered)} of {len(result.findings)} findings")
            if filtered:
                for finding in filtered:
                    _render_finding(finding)
            else:
                st.info("No findings match this severity filter.")
            _section("Exports", "Artifacts from the latest completed scan.")
            _render_exports(result)
        else:
            st.markdown(
                '<div class="va-empty"><div class="va-empty-title">No finding set loaded</div>'
                '<div class="va-empty-copy">Run a scan to inspect findings and evidence.</div></div>',
                unsafe_allow_html=True,
            )

    else:
        _section("Scan history", "The latest 20 persisted scans are shown from the existing SQLite history store.")
        _render_history()

    if result:
        scan_id = _state_get("last_scan_id")
        suffix = f" · saved as scan #{scan_id}" if scan_id is not None else ""
        st.markdown(
            f'<div class="va-footer">Latest assessment: {html.escape(result.target_url)} · '
            f'{len(result.findings)} findings · {result.duration_ms} ms{html.escape(suffix)}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown('<div class="va-footer">No scan has been run in this session.</div>', unsafe_allow_html=True)
