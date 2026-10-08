from __future__ import annotations

import math
import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .models import Finding

VERSION = "1.0.0"
SQL_ERROR_MARKERS = (
    "sql error",
    "sqlite",
    "syntax error",
    "unrecognized token",
    "no such column",
    "near ",
)
XSS_MARKER = "VULNAUDIT_XSS_7F3A"


def _url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _safe_text(response: requests.Response) -> str:
    return response.text[:2048]


def probe_sqli(session: requests.Session, base: str) -> list[Finding]:
    url = _url(base, "/login")

    # Error-based SQL injection probe.
    error_payload = "'"

    # Boolean-based SQL injection probes.
    true_payload = "' OR '1'='1' -- "
    false_payload = "' OR '1'='2' -- "

    error_response = session.post(
        url,
        data={
            "username": "alice",
            "password": error_payload,
        },
        timeout=5,
    )

    true_response = session.post(
        url,
        data={
            "username": "alice",
            "password": true_payload,
        },
        timeout=5,
    )

    false_response = session.post(
        url,
        data={
            "username": "alice",
            "password": false_payload,
        },
        timeout=5,
    )

    error_hit = any(
        marker in error_response.text.lower()
        for marker in SQL_ERROR_MARKERS
    )

    try:
        true_json = true_response.json()
    except ValueError:
        true_json = {}

    try:
        false_json = false_response.json()
    except ValueError:
        false_json = {}

    boolean_hit = (
        true_response.status_code == 200
        and true_json.get("authenticated") is True
        and (
            false_response.status_code != true_response.status_code
            or false_json.get("authenticated") != True
            or len(true_response.text) != len(false_response.text)
        )
    )

    if error_hit and boolean_hit:
        return [
            Finding(
                "VA-001",
                "SQL injection in login",
                "A03 Injection",
                "Critical",
                "The login query is injectable through concatenated user-controlled input; both error-based and boolean-based probes succeeded.",
                {
                    "request": (
                        f"POST {url} "
                        f"username='alice' "
                        f"password={true_payload!r}; "
                        f"false_probe={false_payload!r}"
                    ),
                    "response_snippet": (
                        f"true_status={true_response.status_code}; "
                        f"true_authenticated={true_json.get('authenticated')}; "
                        f"true_length={len(true_response.text)}; "
                        f"false_status={false_response.status_code}; "
                        f"false_authenticated={false_json.get('authenticated')}; "
                        f"false_length={len(false_response.text)}"
                    ),
                },
                "Use parameterized SQL queries and bind all user-controlled values. "
                "Do not concatenate request data into SQL statements.",
            )
        ]

    return []

def probe_xss(session: requests.Session, base: str) -> list[Finding]:
    url = _url(base, "/search")
    response = session.get(url, params={"q": f"<script>alert(1)</script>{XSS_MARKER}"}, timeout=5)
    soup = BeautifulSoup(response.text, "html.parser")
    marker_present = XSS_MARKER in response.text
    script_present = soup.find("script", string=lambda s: s and "alert(1)" in s) is not None
    if marker_present and script_present:
        return [Finding("VA-002", "Reflected cross-site scripting", "A03 Injection (XSS)", "High",
            "A unique marker and executable script payload are reflected without HTML encoding.",
            {"request": f"GET {url}?q=<script>alert(1)</script>{XSS_MARKER}", "response_snippet": _safe_text(response)},
            "Context-encode untrusted output and apply an appropriate Content-Security-Policy. Avoid rendering raw request parameters as HTML.")]
    return []


def probe_idor(session: requests.Session, base: str) -> list[Finding]:
    bodies = []
    samples = []
    for user_id in range(1, 21):
        response = session.get(_url(base, f"/user/{user_id}"), timeout=5)
        if response.status_code == 200:
            body = response.text
            bodies.append(body)
            samples.append(f"GET /user/{user_id} -> {body[:180]}")
    distinct = len(set(bodies))
    if distinct >= 3:
        return [Finding("VA-003", "Insecure direct object reference", "A01 Broken Access Control", "Medium",
            f"Sequential IDs 1–20 returned {distinct} distinct user records without an ownership check.",
            {"request": "GET /user/1 through /user/20", "response_snippet": "\n".join(samples[:6])},
            "Enforce authorization for each object access. Verify that the authenticated principal owns or is permitted to access the requested record.")]
    return []


def _shannon_entropy_bits(token: str) -> float:
    if not token:
        return 0.0
    counts = {c: token.count(c) for c in set(token)}
    entropy_per_char = -sum((n / len(token)) * math.log2(n / len(token)) for n in counts.values())
    return entropy_per_char * len(token)


def probe_auth(session: requests.Session, base: str) -> list[Finding]:
    url = _url(base, "/login")
    response = session.post(url, data={"username": "admin", "password": "admin"}, timeout=5)
    token = response.json().get("token", "") if response.headers.get("content-type", "").startswith("application/json") else ""
    entropy = _shannon_entropy_bits(token)
    weak = 0 < entropy < 32 or len(token) < 8
    failed = [session.post(url, data={"username": "admin", "password": f"wrong-{i}"}, timeout=5) for i in range(5)]
    no_lockout = all(r.status_code == 401 for r in failed)
    if weak or (response.status_code == 200 and no_lockout):
        return [Finding("VA-004", "Weak authentication controls", "A07 Identification & Authentication Failures", "High",
            f"A common credential succeeded and the observed session token measured {entropy:.1f} bits of entropy; five failed attempts did not lock the account.",
            {"request": f"POST {url} username=admin password=admin; then five invalid attempts", "response_snippet": f"token_length={len(token)}, estimated_entropy_bits={entropy:.1f}, failed_attempt_statuses={[r.status_code for r in failed]}"},
            "Use high-entropy, unpredictable session identifiers, reject common/default credentials, and apply rate limiting or account lockout controls.")]
    return []


def probe_headers_and_debug(session: requests.Session, base: str) -> list[Finding]:
    findings: list[Finding] = []
    url = _url(base, "/admin/debug")
    response = session.get(url, timeout=5)
    headers = {k.lower(): v for k, v in response.headers.items()}
    expected = {
        "x-content-type-options": "Medium",
        "x-frame-options": "Medium",
        "content-security-policy": "Medium",
        "strict-transport-security": "Medium",
    }
    for header, severity in expected.items():
        if header not in headers:
            findings.append(Finding(f"VA-005-{header}", f"Missing {header}", "A05 Security Misconfiguration", severity,
                f"The expected security response header {header} is absent.",
                {"request": f"GET {url}", "response_snippet": f"status={response.status_code}; headers={dict(response.headers)}"},
                f"Set the {header} header with a value appropriate for the deployed application."))
    if response.status_code == 500 and "Traceback" in response.text:
        findings.append(Finding("VA-005-debug", "Verbose error disclosure", "A05 Security Misconfiguration", "Medium",
            "The debug endpoint returns a server traceback in the HTTP response.",
            {"request": f"GET {url}", "response_snippet": _safe_text(response)},
            "Return a generic error response to clients and log detailed tracebacks only on the server."))
    static = session.get(_url(base, "/static/"), timeout=5)
    if "Index of /static/" in static.text:
        findings.append(Finding("VA-005-static", "Directory listing enabled", "A05 Security Misconfiguration", "Low",
            "The static directory is browsable and exposes file names.",
            {"request": "GET /static/", "response_snippet": _safe_text(static)},
            "Disable directory indexing and serve only intended static assets."))
    return findings


def probe_csrf(session: requests.Session, base: str) -> list[Finding]:
    url = _url(base, "/transfer")
    response = session.post(url, data={"username": "alice", "amount": "1"}, timeout=5)
    try:
        transfer_json = response.json()
    except ValueError:
        transfer_json = {}
    if response.status_code == 200 and transfer_json.get("success") is True:
        return [Finding("VA-006", "Cross-site request forgery protection absent", "A01 Broken Access Control (CSRF)", "High",
            "A state-changing transfer succeeds without a CSRF token field or header.",
            {"request": f"POST {url} username=alice&amount=1 without CSRF token", "response_snippet": _safe_text(response)},
            "Require a server-generated CSRF token for state-changing requests and validate it before applying the transfer.")]
    return []


def run_probe_stream(base_url: str):
    session = requests.Session()
    for probe in (probe_sqli, probe_xss, probe_idor, probe_auth, probe_headers_and_debug, probe_csrf):
        yield from probe(session, base_url)


def run_probes(base_url: str) -> list[Finding]:
    return list(run_probe_stream(base_url))
