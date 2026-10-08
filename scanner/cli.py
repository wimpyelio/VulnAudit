from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .database import connect
from .models import ScanResult
from .probes import VERSION, run_probe_stream
from .report import write_json, write_pdf


def save_history(result: ScanResult, db_path: str) -> int:
    with connect(db_path) as db:
        cur = db.execute("INSERT INTO scans(timestamp, target_url, duration_ms) VALUES (?, ?, ?)", (datetime.now(timezone.utc).isoformat(), result.target_url, result.duration_ms))
        scan_id = cur.lastrowid
        for f in result.findings:
            import json
            db.execute("INSERT INTO findings(scan_id, title, severity, owasp_category, evidence, remediation) VALUES (?, ?, ?, ?, ?, ?)", (scan_id, f.title, f.severity, f.owasp_category, json.dumps(f.evidence), f.remediation))
        db.commit()
        return int(scan_id)


def validate_target(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("VulnAudit only permits localhost targets by default; this lab is intended to remain local.")


def scan(base_url: str, db_path: str = "scans.db", report_dir: str = "reports") -> ScanResult:
    validate_target(base_url)
    started = time.perf_counter()
    findings = list(run_probe_stream(base_url))
    duration_ms = int((time.perf_counter() - started) * 1000)
    result = ScanResult(base_url.rstrip("/"), VERSION, duration_ms, findings)
    Path(report_dir).mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    write_json(result, Path(report_dir) / f"vulnaudit-{stamp}.json")
    write_pdf(result, Path(report_dir) / f"vulnaudit-{stamp}.pdf")
    save_history(result, db_path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnAudit local deterministic vulnerability scanner")
    parser.add_argument("base_url")
    parser.add_argument("--db", default="scans.db")
    parser.add_argument("--report-dir", default="reports")
    args = parser.parse_args()
    result = scan(args.base_url, args.db, args.report_dir)
    print(f"Scan completed in {result.duration_ms} ms; findings={len(result.findings)}")
    for f in result.findings:
        print(f"{f.id}\t{f.severity}\t{f.title}")

if __name__ == "__main__":
    main()
