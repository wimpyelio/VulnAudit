from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import requests
import pytest

from scanner.cli import scan


def test_target_validation_is_local_only():
    from scanner.cli import validate_target
    validate_target("http://127.0.0.1:5000")
    validate_target("http://localhost:5000")
    with pytest.raises(ValueError):
        validate_target("https://example.com")


def test_project_stays_local():
    source = Path("lab/app.py").read_text(encoding="utf-8")
    assert "host='127.0.0.1'" in source or 'host="127.0.0.1"' in source
    assert "0.0.0.0" not in source


@pytest.mark.skipif(__import__("importlib").util.find_spec("flask") is None, reason="Flask dependency not installed in this execution environment")
def test_scan_detects_all_six_classes(tmp_path):
    db = tmp_path / "scans.db"
    reports = tmp_path / "reports"
    proc = subprocess.Popen([sys.executable, "run_lab.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                if requests.get("http://127.0.0.1:5000/static/", timeout=0.2).status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.05)
        result = scan("http://127.0.0.1:5000", str(db), str(reports))
        titles = {f.title for f in result.findings}
        assert "SQL injection in login" in titles
        assert "Reflected cross-site scripting" in titles
        assert "Insecure direct object reference" in titles
        assert "Weak authentication controls" in titles
        assert sum(1 for f in result.findings if f.owasp_category == "A05 Security Misconfiguration") >= 1
        assert "Cross-site request forgery protection absent" in titles
        assert result.duration_ms < 30000
        pdfs = list(reports.glob("*.pdf")); jsons = list(reports.glob("*.json"))
        assert pdfs and pdfs[0].stat().st_size > 0
        payload = json.loads(jsons[0].read_text(encoding="utf-8"))
        assert payload["findings"]
    finally:
        proc.terminate(); proc.wait(timeout=3)


@pytest.mark.skipif(__import__("importlib").util.find_spec("flask") is None, reason="Flask dependency not installed in this execution environment")
def test_two_scans_have_same_finding_sets(tmp_path):
    db = tmp_path / "scans.db"; reports = tmp_path / "reports"
    proc = subprocess.Popen([sys.executable, "run_lab.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                requests.get("http://127.0.0.1:5000/static/", timeout=0.2); break
            except requests.RequestException:
                time.sleep(0.05)
        a = scan("http://127.0.0.1:5000", str(db), str(reports))
        b = scan("http://127.0.0.1:5000", str(db), str(reports))
        assert {(f.id, f.title, f.severity) for f in a.findings} == {(f.id, f.title, f.severity) for f in b.findings}
    finally:
        proc.terminate(); proc.wait(timeout=3)
