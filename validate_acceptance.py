#!/usr/bin/env python3
"""VulnAudit PRD acceptance validator.

Validates the artifacts the scanner produces -- JSON report, PDF report, and
SQLite persistence -- against the 11-finding baseline recorded in the project
master context. This script never modifies the lab, the scanner, or their
databases; SQLite is opened read-only.

Baseline under test:
    VA-001                            Critical  A03
    VA-002                            High      A03
    VA-003                            Medium    A01
    VA-004                            High      A07
    VA-005-x-content-type-options     Medium    A05
    VA-005-x-frame-options            Medium    A05
    VA-005-content-security-policy    Medium    A05
    VA-005-strict-transport-security  Medium    A05
    VA-005-debug                      Medium    A05
    VA-005-static                     Low       A05
    VA-006                            High      A01

Severity note: VA-003 is Medium because the PRD's fixed severity rule puts a
non-sensitive IDOR at Medium; the PRD's OWASP mapping table lists IDOR as High.
That PRD inconsistency is recorded by this script, not "corrected".

Usage, from the project root with .venv activated:

    python validate_acceptance.py
    python validate_acceptance.py --json report.json --pdf report.pdf --db scans.db
    python validate_acceptance.py --max-snippet 200

Omitted paths are auto-discovered under --root (default: current directory):
the newest parseable JSON that contains VA- findings, the newest non-empty
PDF, and the newest .db that has a scan table. Every discovery decision is
printed, not guessed.

Optional dependency for stronger PDF checks (used only by this validator):
    python -m pip install pypdf

Exit codes: 0 = no FAIL. 1 = at least one FAIL. WARN does not fail the run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import zlib
from collections import Counter
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Baseline data (from the recorded 11-finding scanner baseline)
# --------------------------------------------------------------------------

EXPECTED_EXACT: dict[str, tuple[str, str]] = {
    "VA-001": ("Critical", "A03"),
    "VA-002": ("High", "A03"),
    "VA-003": ("Medium", "A01"),
    "VA-004": ("High", "A07"),
    "VA-005-x-content-type-options": ("Medium", "A05"),
    "VA-005-x-frame-options": ("Medium", "A05"),
    "VA-005-content-security-policy": ("Medium", "A05"),
    "VA-005-strict-transport-security": ("Medium", "A05"),
    "VA-005-debug": ("Medium", "A05"),
    "VA-005-static": ("Low", "A05"),
    "VA-006": ("High", "A01"),
}

# base id -> (expected count, expected severity multiset, expected OWASP code)
EXPECTED_GROUPS: dict[str, tuple[int, Counter, str]] = {
    "VA-001": (1, Counter({"critical": 1}), "A03"),
    "VA-002": (1, Counter({"high": 1}), "A03"),
    "VA-003": (1, Counter({"medium": 1}), "A01"),
    "VA-004": (1, Counter({"high": 1}), "A07"),
    "VA-005": (6, Counter({"medium": 5, "low": 1}), "A05"),
    "VA-006": (1, Counter({"high": 1}), "A01"),
}

PDF_SECTIONS: list[tuple[str, tuple[str, ...]]] = [
    ("executive summary", ("executive summary",)),
    ("scope", ("scope",)),
    ("methodology", ("methodology",)),
    (
        "finding summary",
        (
            "finding summary",
            "finding summary table",
            "summary of findings",
            "summary of findings table",
            "findings summary",
        ),
    ),
    (
        "detailed findings",
        ("detailed findings", "detailed finding", "finding details", "findings detail"),
    ),
    ("appendix", ("appendix",)),
]

FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "id": ("id", "finding_id", "fid", "vid", "code"),
    "title": ("title", "name", "finding", "finding_name", "summary", "check", "vulnerability"),
    "severity": ("severity", "risk", "impact"),
    "category": ("category", "owasp", "owasp_category", "owasp_mapping", "mapping"),
    "evidence": ("evidence", "proof", "evidence_data"),
    "remediation": ("remediation", "fix", "recommendation", "mitigation", "remedy"),
}

EXCLUDE_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", ".vscode"}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


class Results:
    """Accumulates PASS / WARN / FAIL / INFO lines with concrete evidence."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str, str]] = []

    def ok(self, name: str, evidence: str) -> None:
        self.items.append(("PASS", name, evidence))

    def warn(self, name: str, evidence: str) -> None:
        self.items.append(("WARN", name, evidence))

    def fail(self, name: str, evidence: str) -> None:
        self.items.append(("FAIL", name, evidence))

    def info(self, name: str, evidence: str) -> None:
        self.items.append(("INFO", name, evidence))

    @property
    def fail_count(self) -> int:
        return sum(1 for status, _, _ in self.items if status == "FAIL")

    def dump(self) -> None:
        width = max((len(name) for _, name, _ in self.items), default=0)
        for status, name, evidence in self.items:
            print(f"[{status}] {name:<{width}} | {evidence}")

    def summary(self) -> None:
        counts = Counter(status for status, _, _ in self.items)
        print()
        print(
            f"Summary: {len(self.items)} checks -- PASS {counts.get('PASS', 0)}, "
            f"WARN {counts.get('WARN', 0)}, FAIL {counts.get('FAIL', 0)}, "
            f"INFO {counts.get('INFO', 0)}"
        )


def iso(mtime: float) -> str:
    return datetime.fromtimestamp(mtime).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Finding normalization (tolerant of unknown report key names)
# --------------------------------------------------------------------------


def pick_field(finding: dict, field: str):
    lowered = {str(k).strip().lower(): k for k in finding}
    for candidate in FIELD_CANDIDATES[field]:
        key = lowered.get(candidate)
        if key is not None:
            return finding[key]
    return None


def finding_id(finding: dict):
    value = pick_field(finding, "id")
    if isinstance(value, str) and re.match(r"VA-\d{3}", value):
        return value
    return None


def base_of(raw_id: str) -> str:
    return raw_id[:6] if re.match(r"VA-\d{3}", raw_id) else raw_id


def find_findings(node) -> list[dict]:
    """Depth-first search for the list of finding dicts (ids matching VA-nnn)."""
    if isinstance(node, list):
        dicts = [x for x in node if isinstance(x, dict)]
        if len(dicts) >= 3:
            hits = sum(1 for d in dicts if finding_id(d) is not None)
            if hits >= max(3, int(len(dicts) * 0.6)):
                return dicts
        for x in node:
            found = find_findings(x)
            if found:
                return found
    elif isinstance(node, dict):
        for value in node.values():
            found = find_findings(value)
            if found:
                return found
    return []


# --------------------------------------------------------------------------
# JSON report validation
# --------------------------------------------------------------------------


def validate_json(path: Path, res: Results, max_snippet: int | None) -> list[dict]:
    """Returns the normalized finding dicts so the PDF validator can cross-check."""
    stat = path.stat()
    res.info("json.path", f"{path} ({stat.st_size} bytes, mtime {iso(stat.st_mtime)})")
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        res.fail("json.valid", f"not parseable as JSON: {exc}")
        return []
    res.ok("json.valid", "file parses as JSON")

    findings = find_findings(data)
    if not findings:
        res.fail("json.findings_present", "no list of dicts with VA-xxx ids found anywhere in the JSON")
        return []
    res.ok("json.findings_present", f"{len(findings)} finding objects located")

    raw_ids = []
    for f in findings:
        raw_ids.append(finding_id(f) or "<missing id>")

    # Per-group counts: scheme-agnostic (full ids or repeated base ids).
    group_counts: Counter = Counter()
    severity_by_group: dict[str, Counter] = {}
    for f, rid in zip(findings, raw_ids):
        base = base_of(rid)
        group_counts[base] += 1
        sev = pick_field(f, "severity")
        key = str(sev).strip().lower() if sev is not None else "<missing>"
        severity_by_group.setdefault(base, Counter())[key] += 1

    counts_ok = True
    for base in sorted(EXPECTED_GROUPS):
        expected_count = EXPECTED_GROUPS[base][0]
        actual = group_counts.get(base, 0)
        if actual != expected_count:
            counts_ok = False
            detail = f"expected {expected_count} finding(s), found {actual}"
            if actual == 0:
                detail += "; ids seen: " + ", ".join(sorted(set(raw_ids)))
            res.fail(f"json.count[{base}]", detail)
        else:
            res.ok(f"json.count[{base}]", f"{actual} finding(s)")
    unexpected = sorted(b for b in group_counts if b not in EXPECTED_GROUPS)
    if unexpected:
        counts_ok = False
        res.fail("json.count[unexpected]", f"unexpected id groups: {', '.join(unexpected)}")
    if counts_ok:
        res.ok("json.count_total", f"{sum(group_counts.values())} findings, matches the 11-finding baseline")

    # Exact-id scheme (informational: the report may legitimately use base ids only).
    exact = Counter(raw_ids)
    if exact == Counter({key: 1 for key in EXPECTED_EXACT}):
        res.ok("json.ids_exact", "all 11 exact baseline ids present (VA-001 ... VA-006)")
    else:
        missing = sorted(set(EXPECTED_EXACT) - set(raw_ids))
        extra = sorted(set(raw_ids) - set(EXPECTED_EXACT))
        res.warn(
            "json.ids_exact",
            f"exact ids differ from baseline (missing: {missing or 'none'}; unmapped: {extra or 'none'}); "
            "group counts above still hold -- adjudicate against your report.py id scheme",
        )

    # Severity per group.
    for base in sorted(EXPECTED_GROUPS):
        expected_sevs = EXPECTED_GROUPS[base][1]
        actual = severity_by_group.get(base, Counter())
        if actual == expected_sevs:
            res.ok(f"json.severity[{base}]", f"{dict(actual)}")
        else:
            res.fail(f"json.severity[{base}]", f"expected {dict(expected_sevs)}, found {dict(actual)}")
    res.info(
        "json.severity[VA-003 note]",
        "Medium is the baseline: the PRD fixed rule puts a non-sensitive IDOR at Medium while the PRD OWASP table "
        "lists IDOR as High -- known PRD inconsistency, kept as-is",
    )

    # OWASP category per group.
    for base in sorted(EXPECTED_GROUPS):
        expected_code = EXPECTED_GROUPS[base][2]
        problems = []
        for f, rid in zip(findings, raw_ids):
            if base_of(rid) != base:
                continue
            cat = pick_field(f, "category")
            if not isinstance(cat, str) or expected_code.lower() not in cat.lower():
                problems.append(f"{rid}: {cat!r}")
        if problems:
            res.fail(f"json.category[{base}]", f"expected OWASP {expected_code}; problems: {'; '.join(problems)}")
        else:
            res.ok(f"json.category[{base}]", f"every finding in this group carries {expected_code}")

    # Evidence and remediation per finding.
    missing_evidence: list[str] = []
    missing_remediation: list[str] = []
    no_req_resp: list[str] = []
    for f, rid in zip(findings, raw_ids):
        evidence = pick_field(f, "evidence")
        if evidence in (None, "", {}, []):
            missing_evidence.append(rid)
        elif isinstance(evidence, dict):
            keys = [str(k).lower() for k in evidence]
            has_request = any("request" in k for k in keys)
            has_response = any("response" in k or "resp" in k for k in keys)
            if not (has_request and has_response):
                no_req_resp.append(f"{rid} (keys={list(evidence)})")
        remediation = pick_field(f, "remediation")
        if remediation in (None, "", {}, []):
            missing_remediation.append(rid)

    if missing_evidence:
        res.fail("json.evidence", f"findings with empty/missing evidence: {', '.join(missing_evidence)}")
    else:
        res.ok("json.evidence", f"all {len(findings)} findings carry evidence")
    if no_req_resp:
        res.warn("json.evidence[req+resp]", f"evidence lacks request/response keys: {'; '.join(no_req_resp)}")
    else:
        res.ok("json.evidence[req+resp]", "every evidence object has request and response data")
    if missing_remediation:
        res.fail("json.remediation", f"findings with empty/missing remediation: {', '.join(missing_remediation)}")
    else:
        res.ok("json.remediation", f"all {len(findings)} findings carry remediation")

    # Evidence snippet size. The PRD's numeric limit lives in the uploaded PRD,
    # so it is enforced only when supplied via --max-snippet.
    longest = 0
    longest_at = "-"
    for f, rid in zip(findings, raw_ids):
        evidence = pick_field(f, "evidence")
        if isinstance(evidence, dict):
            values = list(evidence.values())
        elif isinstance(evidence, str):
            values = [evidence]
        else:
            values = []
        for v in values:
            if isinstance(v, str) and len(v) > longest:
                longest, longest_at = len(v), rid
    if max_snippet is not None:
        if longest > max_snippet:
            res.fail(
                "json.snippet_limit",
                f"longest evidence value is {longest} chars (at {longest_at}), exceeds --max-snippet {max_snippet}",
            )
        else:
            res.ok(
                "json.snippet_limit",
                f"longest evidence value is {longest} chars (at {longest_at}), within {max_snippet}",
            )
    else:
        res.info(
            "json.snippet_limit",
            f"longest evidence value is {longest} chars (at {longest_at}); "
            "rerun with --max-snippet <PRD limit> to enforce the PRD limit",
        )

    return findings


# --------------------------------------------------------------------------
# PDF report validation
# --------------------------------------------------------------------------


def _pdf_unescape(raw: bytes) -> str:
    raw = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), raw)
    for esc, real in (
        (rb"\(", b"("),
        (rb"\)", b")"),
        (rb"\\", b"\\"),
        (rb"\r", b"\r"),
        (rb"\n", b"\n"),
        (rb"\t", b"\t"),
    ):
        raw = raw.replace(esc, real)
    return raw.decode("latin-1", "replace")


def pdf_text_manual(path: Path) -> str:
    """Fallback: decompress content streams and read Tj / TJ text operators."""
    data = path.read_bytes()
    parts: list[str] = []
    for stream in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        chunk = stream.group(1)
        try:
            chunk = zlib.decompress(chunk)
        except zlib.error:
            pass  # uncompressed streams are fine
        for arr in re.finditer(rb"\[(.*?)\]\s*TJ", chunk, re.S):
            for s in re.finditer(rb"\(((?:[^()\\]|\\.)*)\)", arr.group(1)):
                parts.append(_pdf_unescape(s.group(1)))
        for s in re.finditer(rb"\(((?:[^()\\]|\\.)*)\)\s*(?:Tj|'|\")", chunk, re.S):
            parts.append(_pdf_unescape(s.group(1)))
    return " ".join(parts)


def pdf_text_pypdf(path: Path):
    """Returns (text, pages). None if pypdf is not installed; raises if broken."""
    reader_cls = None
    try:
        from pypdf import PdfReader as reader_cls  # type: ignore
    except ImportError:
        try:
            from PyPDF2 import PdfReader as reader_cls  # type: ignore
        except ImportError:
            return None
    try:
        reader = reader_cls(str(path))
        pages = len(reader.pages)
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        return text, pages
    except Exception as exc:
        raise ValueError(f"pypdf could not read the file: {exc}") from exc


def pdf_text_pdfminer(path: Path):
    try:
        # Optional fallback reader; guarded below, so a missing package is fine.
        from pdfminer.high_level import extract_text  # type: ignore
    except ImportError:
        return None
    return extract_text(str(path))


def phrase_in(text: str, phrase: str) -> bool:
    return re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text, re.IGNORECASE) is not None


def validate_pdf(path: Path, res: Results, json_findings: list[dict]) -> None:
    stat = path.stat()
    res.info("pdf.path", f"{path} ({stat.st_size} bytes, mtime {iso(stat.st_mtime)})")
    if stat.st_size == 0:
        res.fail("pdf.nonempty", "file is 0 bytes")
        return
    res.ok("pdf.nonempty", f"{stat.st_size} bytes")

    text = ""
    method = ""
    pypdf_result = None
    try:
        pypdf_result = pdf_text_pypdf(path)
    except ValueError as exc:
        res.fail("pdf.openable", str(exc))
        return
    if pypdf_result is not None:
        text, pages = pypdf_result
        method = f"pypdf ({pages} pages)"
        res.ok("pdf.openable", f"opened with pypdf, {pages} pages")
    else:
        try:
            mined = pdf_text_pdfminer(path)
        except Exception as exc:
            res.warn("pdf.openable", f"pdfminer present but failed: {exc}; falling back to stream decompression")
            mined = None
        if mined:
            text = mined
            method = "pdfminer"
            res.warn("pdf.openable", "extracted with pdfminer; install pypdf for page count and a stronger open check")
        else:
            text = pdf_text_manual(path)
            method = "manual zlib stream decompression"
            res.warn(
                "pdf.openable",
                "pypdf/pdfminer absent; openability verified only via zlib stream decompression -- "
                "run: python -m pip install pypdf",
            )

    if not text.strip():
        if method.startswith("pypdf"):
            res.fail(
                "pdf.text_extractable",
                "pypdf opened the file but extracted no text; open the PDF in a viewer to confirm it renders",
            )
        else:
            res.fail(
                "pdf.text_extractable",
                f"no text extracted via {method}; run: python -m pip install pypdf, then rerun",
            )
        return
    res.ok("pdf.text_extractable", f"{len(text)} chars extracted via {method}")

    # Required section headings.
    for section, phrases in PDF_SECTIONS:
        hit = next((p for p in phrases if phrase_in(text, p)), None)
        if hit:
            res.ok(f"pdf.section[{section}]", f"heading '{hit}' found")
        else:
            res.fail(f"pdf.section[{section}]", f"none of {list(phrases)} found in extracted text")

    head = text[:3000]
    if phrase_in(head, "VulnAudit") or phrase_in(head, "cover"):
        res.ok("pdf.section[cover]", "page-1 area contains 'VulnAudit' or 'cover'")
    else:
        res.warn("pdf.section[cover]", "no 'VulnAudit'/'cover' text in the first 3000 chars -- check the cover page by eye")

    # All 11 findings appear (group counts tolerate both id schemes).
    for base in sorted(EXPECTED_GROUPS):
        expected_count = EXPECTED_GROUPS[base][0]
        found = len(re.findall(re.escape(base), text, re.IGNORECASE))
        if found >= expected_count:
            res.ok(f"pdf.findings[{base}]", f"{found} occurrence(s), expected >= {expected_count}")
        else:
            res.fail(f"pdf.findings[{base}]", f"only {found} occurrence(s), expected >= {expected_count}")

    # Cross-check: evidence strings from the JSON should appear in the PDF.
    checked = 0
    missing: list[str] = []
    normalized_text = re.sub(r"\s+", " ", text)
    for f in json_findings:
        rid = finding_id(f)
        if rid is None:
            continue
        evidence = pick_field(f, "evidence")
        if isinstance(evidence, dict):
            values = list(evidence.values())
        elif isinstance(evidence, str):
            values = [evidence]
        else:
            values = []
        probe = next((v for v in values if isinstance(v, str) and len(v) >= 20), "")
        if not probe:
            continue
        checked += 1
        fragment = re.sub(r"\s+", " ", probe[:24]).strip()
        if fragment.lower() in normalized_text.lower():
            res.ok(f"pdf.evidence[{rid}]", f"evidence fragment '{fragment}' present")
        else:
            missing.append(f"{rid}: '{fragment}'")
    if checked == 0:
        res.warn("pdf.evidence", "no >=20-char evidence string in the JSON to cross-check against the PDF")
    elif missing:
        res.warn(
            "pdf.evidence",
            f"evidence fragments not found in PDF text (may be PRD-truncated or reformatted): {'; '.join(missing)}",
        )
    else:
        res.ok("pdf.evidence", f"all {checked} sampled evidence fragments appear in the PDF")
    res.info(
        "pdf.snippet_limit",
        "PDF snippet sizes derive from the same evidence strings measured by json.snippet_limit",
    )


# --------------------------------------------------------------------------
# SQLite persistence validation (read-only)
# --------------------------------------------------------------------------


def open_ro(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only=ON")
    return conn


def validate_db(path: Path, res: Results, json_findings: list[dict]) -> None:
    stat = path.stat()
    res.info("db.path", f"{path} ({stat.st_size} bytes, mtime {iso(stat.st_mtime)})")
    try:
        conn = open_ro(path)
    except sqlite3.Error as exc:
        res.fail("db.open", f"cannot open read-only: {exc}")
        return

    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        res.info("db.tables", ", ".join(tables) or "(none)")
        for name, sql in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"):
            res.info(f"db.schema[{name}]", (sql or "(no schema recorded)").replace("\n", " "))

        scan_tables = [t for t in tables if "scan" in t.lower() and "finding" not in t.lower()]
        finding_tables = [t for t in tables if "finding" in t.lower()]
        if not scan_tables:
            res.fail("db.scans_table", f"no table with 'scan' in its name; tables: {', '.join(tables) or 'none'}")
            return
        if not finding_tables:
            res.fail("db.findings_table", f"no table with 'finding' in its name; tables: {', '.join(tables) or 'none'}")
            return
        scan_table = scan_tables[0]
        finding_table = finding_tables[0]
        if len(scan_tables) > 1 or len(finding_tables) > 1:
            res.warn(
                "db.table_choice",
                f"multiple candidates; using '{scan_table}' and '{finding_table}' "
                f"(others: {scan_tables[1:] + finding_tables[1:]})",
            )

        scan_cols = list(conn.execute(f'PRAGMA table_info("{scan_table}")'))
        finding_cols = list(conn.execute(f'PRAGMA table_info("{finding_table}")'))
        res.info(
            "db.columns",
            f"{scan_table}: {[c[1] for c in scan_cols]}; {finding_table}: {[c[1] for c in finding_cols]}",
        )
        res.info(
            "db.schema_vs_prd",
            "compare the printed CREATE statements above against the PRD scans/findings schemas by hand "
            "(the PRD schema text is not embedded in this validator)",
        )

        def pk_col(cols):
            pks = [c for c in cols if c[5] > 0]
            return pks[0][1] if pks else None

        scan_pk = pk_col(scan_cols) or "rowid"

        scan_rows = conn.execute(f'SELECT COUNT(*) FROM "{scan_table}"').fetchone()[0]
        if scan_rows >= 1:
            res.ok("db.scans_inserted", f"{scan_rows} scan row(s) in {scan_table}")
        else:
            res.fail("db.scans_inserted", f"0 rows in {scan_table}")
        if scan_rows >= 2:
            res.ok("db.multiple_scans", f"{scan_rows} scans accumulated in {scan_table}")
        else:
            res.warn("db.multiple_scans", f"only {scan_rows} scan stored; run the scanner again to confirm scans accumulate")

        total_findings = conn.execute(f'SELECT COUNT(*) FROM "{finding_table}"').fetchone()[0]
        if total_findings >= 1:
            res.ok("db.findings_inserted", f"{total_findings} finding row(s) in {finding_table}")
        else:
            res.fail("db.findings_inserted", f"0 rows in {finding_table}")

        link = next((c[1] for c in finding_cols if "scan" in c[1].lower()), None)
        if link is None:
            res.fail(
                "db.relationship",
                f"no scan-link column in {finding_table}; columns: {[c[1] for c in finding_cols]}",
            )
        else:
            orphans = conn.execute(
                f'SELECT COUNT(*) FROM "{finding_table}" f '
                f'WHERE f."{link}" NOT IN (SELECT "{scan_pk}" FROM "{scan_table}")'
            ).fetchone()[0]
            if orphans == 0:
                res.ok("db.relationship", f"all {finding_table}.{link} values resolve to {scan_table}.{scan_pk}")
            else:
                res.fail("db.relationship", f"{orphans} finding row(s) with dangling {link}")

        if scan_rows < 1 or link is None:
            return
        scan_ids = [
            r[0] for r in conn.execute(f'SELECT "{scan_pk}" FROM "{scan_table}" ORDER BY "{scan_pk}" DESC LIMIT 2')
        ]
        latest = scan_ids[0]
        id_col = next(
            (c[1] for c in finding_cols if c[1].lower() in ("id", "finding_id", "fid", "vid", "code")),
            pk_col(finding_cols) or finding_cols[0][1],
        )
        title_col = next(
            (
                c[1]
                for c in finding_cols
                if c[1].lower() in ("title", "name", "finding", "finding_name", "summary", "check")
            ),
            None,
        )
        sev_col = next(
            (c[1] for c in finding_cols if "sever" in c[1].lower() or "risk" in c[1].lower()),
            None,
        )
        res.info("db.id_column", f"id column '{id_col}'; title column '{title_col}'; severity column '{sev_col}'")

        latest_ids = [
            str(r[0])
            for r in conn.execute(f'SELECT "{id_col}" FROM "{finding_table}" WHERE "{link}" = ?', (latest,))
        ]
        uses_va_ids = any(re.match(r"VA-\d{3}", i) for i in latest_ids)
        curr_keys: set = set()

        if uses_va_ids:
            res.info("db.identity", f"finding identity: VA-xxx codes from column '{id_col}'")
            expected_counts = Counter({base: EXPECTED_GROUPS[base][0] for base in EXPECTED_GROUPS})
            actual_counts = Counter(base_of(i) for i in latest_ids)
            if actual_counts == expected_counts:
                res.ok("db.latest_findings", f"latest scan {latest} has all 11 baseline findings: {sorted(latest_ids)}")
            else:
                res.fail(
                    "db.latest_findings",
                    f"scan {latest} ids {sorted(latest_ids)} do not match the 11-finding baseline",
                )
            if sev_col is None:
                res.warn("db.severity", f"no severity column detected in {finding_table}")
            else:
                rows = conn.execute(
                    f'SELECT "{id_col}", "{sev_col}" FROM "{finding_table}" WHERE "{link}" = ?', (latest,)
                ).fetchall()
                problems = []
                for rid, sev in rows:
                    group = EXPECTED_GROUPS.get(base_of(str(rid)))
                    if group and str(sev).strip().lower() not in group[1]:
                        problems.append(f"{rid}={sev}")
                if problems:
                    res.fail("db.severity", f"severity mismatches against baseline: {', '.join(problems)}")
                else:
                    res.ok("db.severity", f"all {len(rows)} finding rows match baseline severities")
            curr_keys = set(latest_ids)
        elif title_col is not None:
            res.info(
                "db.identity",
                f"column '{id_col}' holds row ids, not VA-xxx codes; using title column '{title_col}' as finding identity",
            )
            actual_titles = [
                str(r[0]).strip().lower()
                for r in conn.execute(
                    f'SELECT "{title_col}" FROM "{finding_table}" WHERE "{link}" = ?', (latest,)
                )
            ]
            curr_keys = set(actual_titles)
            if not json_findings:
                res.warn(
                    "db.latest_findings",
                    "no JSON report available for title comparison; checking title count and severities only",
                )
                if len(actual_titles) != 11:
                    res.fail("db.latest_findings", f"latest scan {latest} has {len(actual_titles)} finding rows, expected 11")
                else:
                    res.ok("db.latest_findings", f"latest scan {latest} has 11 finding rows")
                if sev_col is None:
                    res.warn("db.severity", "no severity column detected")
                else:
                    expected_sevs: Counter = Counter()
                    for _, sevs, _ in EXPECTED_GROUPS.values():
                        expected_sevs += sevs
                    actual_sevs = Counter(
                        str(r[0]).strip().lower()
                        for r in conn.execute(
                            f'SELECT "{sev_col}" FROM "{finding_table}" WHERE "{link}" = ?', (latest,)
                        )
                    )
                    if actual_sevs == expected_sevs:
                        res.ok("db.severity", f"severity multiset matches baseline: {dict(actual_sevs)}")
                    else:
                        res.fail("db.severity", f"expected {dict(expected_sevs)}, found {dict(actual_sevs)}")
            elif sev_col is None:
                expected_titles = {
                    str(pick_field(f, "title") or "").strip().lower() for f in json_findings
                }
                expected_titles.discard("")
                if Counter(actual_titles) == Counter(sorted(expected_titles)):
                    res.ok("db.latest_findings", f"latest scan {latest} titles match the JSON report")
                else:
                    res.fail(
                        "db.latest_findings",
                        f"scan {latest} titles {sorted(set(actual_titles))} differ from the JSON report "
                        f"{sorted(expected_titles)}",
                    )
                res.warn("db.severity", "no severity column detected; severities not checked in the DB")
            else:
                expected_pairs: Counter = Counter()
                for f in json_findings:
                    t = pick_field(f, "title")
                    s = pick_field(f, "severity")
                    if isinstance(t, str):
                        sev = str(s).strip().lower() if s is not None else "<missing>"
                        expected_pairs[(t.strip().lower(), sev)] += 1
                actual_pairs: Counter = Counter()
                for t, s in conn.execute(
                    f'SELECT "{title_col}", "{sev_col}" FROM "{finding_table}" WHERE "{link}" = ?', (latest,)
                ):
                    actual_pairs[(str(t).strip().lower(), str(s).strip().lower())] += 1
                if actual_pairs == expected_pairs:
                    res.ok(
                        "db.latest_findings",
                        f"latest scan {latest} matches the JSON report's findings by title+severity "
                        f"({len(actual_titles)} rows)",
                    )
                    res.ok("db.severity", "severities verified jointly with titles against the JSON report")
                else:
                    missing_pairs = sorted(f"{t} [{s}]" for t, s in (expected_pairs - actual_pairs).elements())
                    extra_pairs = sorted(f"{t} [{s}]" for t, s in (actual_pairs - expected_pairs).elements())
                    res.fail(
                        "db.latest_findings",
                        f"scan {latest} differs from the JSON report; missing: {missing_pairs or '[]'}; "
                        f"unexpected: {extra_pairs or '[]'}",
                    )
                    exp_by_title = {t: s for t, s in expected_pairs}
                    act_by_title = {t: s for t, s in actual_pairs}
                    sev_problems = sorted(
                        f"{t}: db={act_by_title[t]}, report={exp_by_title[t]}"
                        for t in exp_by_title
                        if t in act_by_title and act_by_title[t] != exp_by_title[t]
                    )
                    if sev_problems:
                        res.fail("db.severity", f"severity mismatches: {'; '.join(sev_problems)}")
                    else:
                        res.ok(
                            "db.severity",
                            "shared titles carry matching severities; row differences reported in db.latest_findings",
                        )
        else:
            res.fail(
                "db.identity",
                f"finding table has neither VA-xxx codes (column '{id_col}') nor a title column; "
                f"columns: {[c[1] for c in finding_cols]}",
            )

        if len(scan_ids) >= 2:
            prev = scan_ids[1]
            if uses_va_ids:
                prev_keys = {
                    str(r[0])
                    for r in conn.execute(f'SELECT "{id_col}" FROM "{finding_table}" WHERE "{link}" = ?', (prev,))
                }
            elif title_col is not None:
                prev_keys = {
                    str(r[0]).strip().lower()
                    for r in conn.execute(f'SELECT "{title_col}" FROM "{finding_table}" WHERE "{link}" = ?', (prev,))
                }
            else:
                prev_keys = set()
            new_keys = sorted(curr_keys - prev_keys)
            gone_keys = sorted(prev_keys - curr_keys)
            delta = (
                "; identical finding sets (expected for a stable lab)"
                if curr_keys and prev_keys and not new_keys and not gone_keys
                else ""
            )
            res.ok(
                "db.history",
                f"scan {prev} -> {latest}: new={new_keys or '[]'}, resolved={gone_keys or '[]'}{delta}",
            )
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Artifact discovery
# --------------------------------------------------------------------------


def discover_files(root: Path) -> tuple[list[Path], list[Path], list[Path]]:
    jsons: list[Path] = []
    pdfs: list[Path] = []
    dbs: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            suffix = p.suffix.lower()
            if suffix == ".json":
                jsons.append(p)
            elif suffix == ".pdf":
                pdfs.append(p)
            elif suffix in (".db", ".sqlite", ".sqlite3"):
                dbs.append(p)
    return jsons, pdfs, dbs


def pick_json(candidates: list[Path]) -> tuple[Path | None, str]:
    newest_first = sorted(candidates, key=lambda q: q.stat().st_mtime, reverse=True)
    for p in newest_first[:25]:
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if find_findings(data):
            return p, f"newest JSON containing VA- findings (checked {min(len(newest_first), 25)} of {len(candidates)} .json files)"
    return None, f"no JSON with VA- findings among {len(candidates)} .json files"


def pick_pdf(candidates: list[Path]) -> tuple[Path | None, str]:
    nonzero = [p for p in candidates if p.stat().st_size > 0]
    if not nonzero:
        return None, f"no non-empty .pdf among {len(candidates)} files"
    newest = max(nonzero, key=lambda p: p.stat().st_mtime)
    return newest, f"newest non-empty PDF of {len(candidates)}"


def pick_db(candidates: list[Path]) -> tuple[Path | None, str]:
    for p in sorted(candidates, key=lambda q: q.stat().st_mtime, reverse=True):
        try:
            conn = open_ro(p)
        except sqlite3.Error:
            continue
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        except sqlite3.Error:
            tables = []
        finally:
            conn.close()
        if any("scan" in t.lower() and "finding" not in t.lower() for t in tables):
            return p, f"has a scans table (checked {len(candidates)} .db files by newest first)"
    return None, f"no .db with a scans table among {[str(p) for p in candidates] or 'no .db files found'}"


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VulnAudit PRD acceptance validator (JSON report, PDF report, SQLite persistence)."
    )
    parser.add_argument("--json", type=Path, default=None, help="path to the generated JSON report")
    parser.add_argument("--pdf", type=Path, default=None, help="path to the generated PDF report")
    parser.add_argument("--db", type=Path, default=None, help="path to the scanner SQLite database")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="root for auto-discovery when a path is omitted (default: current directory)",
    )
    parser.add_argument(
        "--max-snippet",
        type=int,
        default=None,
        help="PRD evidence-snippet character limit; FAIL if any JSON evidence value is longer",
    )
    parser.add_argument("--skip-db", action="store_true", help="do not validate the database")
    args = parser.parse_args()

    res = Results()

    json_path: Path | None = args.json
    pdf_path: Path | None = args.pdf
    db_path: Path | None = args.db

    if json_path is None or pdf_path is None or (db_path is None and not args.skip_db):
        res.info("discovery.root", str(args.root.resolve()))
        jsons, pdfs, dbs = discover_files(args.root)
        if json_path is None:
            json_path, why = pick_json(jsons)
            res.info("discovery.json", f"{json_path or 'NOT FOUND'} -- {why}")
        if pdf_path is None:
            pdf_path, why = pick_pdf(pdfs)
            res.info("discovery.pdf", f"{pdf_path or 'NOT FOUND'} -- {why}")
        if db_path is None and not args.skip_db:
            db_path, why = pick_db(dbs)
            res.info("discovery.db", f"{db_path or 'NOT FOUND'} -- {why}")

    json_findings: list[dict] = []
    if json_path is None:
        res.fail("json.exists", "no JSON report found; pass --json")
    elif not json_path.is_file():
        res.fail("json.exists", f"{json_path} is not a file")
    else:
        json_findings = validate_json(json_path, res, args.max_snippet)

    if pdf_path is None:
        res.fail("pdf.exists", "no PDF report found; pass --pdf")
    elif not pdf_path.is_file():
        res.fail("pdf.exists", f"{pdf_path} is not a file")
    else:
        validate_pdf(pdf_path, res, json_findings)

    if args.skip_db:
        res.info("db.skipped", "--skip-db given")
    elif db_path is None:
        res.fail("db.exists", "no scanner database found; pass --db")
    elif not db_path.is_file():
        res.fail("db.exists", f"{db_path} is not a file")
    else:
        validate_db(db_path, res, json_findings)

    print()
    print("=" * 78)
    res.dump()
    res.summary()
    print()
    if res.fail_count:
        print(f"RESULT: FAIL ({res.fail_count} check(s) failed)")
        return 1
    print("RESULT: PASS (no failed checks; review WARN lines before sign-off)")
    return 0


if __name__ == "__main__":
    sys.exit(main())