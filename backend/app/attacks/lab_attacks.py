"""
Lab-mode active tests (restricted to localhost / *.local).
These are intentionally low-intensity and time-bounded.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from uuid import uuid4

import requests
from bs4 import BeautifulSoup

from app.models import Asset, Evidence, Finding, Severity


DEFAULT_SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"a\"=\"a",
    "admin' --",
]

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql",
    r"sqlite",
    r"psql",
    r"postgres",
    r"ora-\d{5}",
    r"syntax error",
]

COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("test", "test"),
    ("user", "password"),
    ("demo", "demo"),
]


def _make_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:8]}"


@dataclass
class FormSpec:
    action: str
    method: str
    inputs: list[dict[str, str]]


def _get_forms(target_url: str) -> tuple[list[FormSpec], bool]:
    try:
        response = requests.get(target_url, timeout=5)
    except requests.RequestException:
        return [], False

    soup = BeautifulSoup(response.text, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = (form.get("action") or "").strip()
        action_url = urljoin(response.url, action) if action else response.url

        inputs = []
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").strip()
            input_type = (inp.get("type") or "text").lower()
            if name:
                inputs.append({"name": name, "type": input_type})

        forms.append(FormSpec(action=action_url, method=method, inputs=inputs))

    return forms, True


def _sql_injection_findings(target_url: str, run_id: str) -> list[Finding]:
    findings: list[Finding] = []
    forms, fetched = _get_forms(target_url)
    forms = [f for f in forms if f.method == "post"]
    executed = fetched

    for form in forms[:3]:
        for payload in DEFAULT_SQL_PAYLOADS:
            data = {}
            for inp in form.inputs:
                if inp["type"] in {"text", "email"} or "user" in inp["name"].lower():
                    data[inp["name"]] = payload
                elif inp["type"] == "password":
                    data[inp["name"]] = "test"
                else:
                    data[inp["name"]] = "test"

            try:
                response = requests.post(form.action, data=data, timeout=5)
                executed = True
                body = response.text.lower()
                if response.status_code >= 500 or any(re.search(p, body) for p in SQL_ERROR_PATTERNS):
                    findings.append(
                        Finding(
                            id=_make_id("LAB-SQLI"),
                            asset=Asset(type="url", value=form.action),
                            category="OWASP A03",
                            check="lab_sql_injection",
                            severity=Severity.HIGH,
                            summary="Possible SQL injection behavior detected in form submission",
                            evidence=Evidence(
                                details=f"Payload triggered error-like response. Status: {response.status_code}. Payload: {payload}"
                            ),
                            remediation=[
                                "Use parameterized queries / ORM bindings",
                                "Validate and sanitize user input",
                                "Disable detailed SQL errors in production",
                            ],
                            source="lab_attack",
                            run_id=run_id,
                        )
                    )
                    return findings
            except requests.RequestException:
                continue

    if executed:
        details = "Heuristic payloads did not trigger SQL error patterns."
        if fetched and not forms:
            details = "No POST forms detected to test for SQL injection."
        findings.append(
            Finding(
                id=_make_id("LAB-SQLI"),
                asset=Asset(type="url", value=target_url),
                category="OWASP A03",
                check="lab_sql_injection",
                severity=Severity.INFO,
                summary="SQL injection test completed with no clear indicators",
                evidence=Evidence(details=details),
                remediation=[
                    "Continue using parameterized queries",
                    "Keep input validation and error handling in place",
                ],
                source="lab_attack",
                run_id=run_id,
            )
        )
    return findings


def _csrf_findings(target_url: str, run_id: str) -> list[Finding]:
    findings: list[Finding] = []
    forms, fetched = _get_forms(target_url)
    forms = [f for f in forms if f.method == "post"]
    executed = fetched

    for form in forms[:5]:
        has_csrf = False
        for inp in form.inputs:
            name = inp["name"].lower()
            if "csrf" in name or "xsrf" in name:
                has_csrf = True
                break

        if not has_csrf:
            findings.append(
                Finding(
                    id=_make_id("LAB-CSRF"),
                    asset=Asset(type="url", value=form.action),
                    category="OWASP A01",
                    check="lab_csrf_probe",
                    severity=Severity.MEDIUM,
                    summary="POST form appears to lack CSRF protection token",
                    evidence=Evidence(
                        details="No input field containing 'csrf' or 'xsrf' detected in the form."
                    ),
                    remediation=[
                        "Add CSRF tokens to state-changing POST forms",
                        "Validate CSRF tokens server-side",
                    ],
                    source="lab_attack",
                    run_id=run_id,
                )
            )

    if not findings and executed:
        details = "No POST forms without obvious CSRF tokens were detected."
        if fetched and not forms:
            details = "No POST forms detected to evaluate CSRF protections."
        findings.append(
            Finding(
                id=_make_id("LAB-CSRF"),
                asset=Asset(type="url", value=target_url),
                category="OWASP A01",
                check="lab_csrf_probe",
                severity=Severity.INFO,
                summary="CSRF probe completed with no missing-token indicators",
                evidence=Evidence(details=details),
                remediation=[
                    "Maintain CSRF protections on state-changing routes",
                    "Validate tokens server-side",
                ],
                source="lab_attack",
                run_id=run_id,
            )
        )

    return findings


def _credential_stuffing_findings(target_url: str, run_id: str) -> list[Finding]:
    findings: list[Finding] = []
    forms, fetched = _get_forms(target_url)
    executed = fetched
    has_login_form = any(
        any("pass" in inp["name"].lower() for inp in form.inputs) for form in forms
    )

    for form in forms[:3]:
        input_names = [i["name"].lower() for i in form.inputs]
        if not any("pass" in n for n in input_names):
            continue

        baseline = None
        try:
            baseline = requests.post(form.action, data={"username": "invalid", "password": "invalid"}, timeout=5)
            executed = True
        except requests.RequestException:
            baseline = None

        for username, password in COMMON_CREDENTIALS:
            data = {}
            for inp in form.inputs:
                name = inp["name"]
                lname = name.lower()
                if "user" in lname or "email" in lname or "login" in lname:
                    data[name] = username
                elif "pass" in lname:
                    data[name] = password
                else:
                    data[name] = "test"

            try:
                response = requests.post(form.action, data=data, timeout=5)
                executed = True
                if _looks_like_login_success(response, baseline):
                    findings.append(
                        Finding(
                            id=_make_id("LAB-CRED"),
                            asset=Asset(type="url", value=form.action),
                            category="OWASP A07",
                            check="lab_credential_stuffing",
                            severity=Severity.HIGH,
                            summary="Login form accepted common credential pair during lab test",
                            evidence=Evidence(
                                details=f"Credential pair '{username}:{password}' produced a success-like response. Status: {response.status_code}"
                            ),
                            remediation=[
                                "Enforce strong password policies",
                                "Enable multi-factor authentication",
                                "Implement rate limiting and account lockouts",
                            ],
                            source="lab_attack",
                            run_id=run_id,
                        )
                    )
                    return findings
            except requests.RequestException:
                continue

    if not findings and executed:
        details = "Common username/password pairs were rejected by the login form."
        if fetched and not has_login_form:
            details = "No login form detected to test credential stuffing."
        findings.append(
            Finding(
                id=_make_id("LAB-CRED"),
                asset=Asset(type="url", value=target_url),
                category="OWASP A07",
                check="lab_credential_stuffing",
                severity=Severity.INFO,
                summary="Credential stuffing test completed with no accepted common credentials",
                evidence=Evidence(details=details),
                remediation=[
                    "Keep enforcing strong authentication policies",
                    "Maintain rate limiting and lockout controls",
                ],
                source="lab_attack",
                run_id=run_id,
            )
        )
    return findings


def _looks_like_login_success(response: requests.Response, baseline: requests.Response | None) -> bool:
    if response.status_code in {401, 403}:
        return False

    body = response.text.lower()
    if any(token in body for token in ["logout", "dashboard", "welcome", "account"]):
        return True

    if baseline is None:
        return False

    delta = abs(len(response.text) - len(baseline.text))
    return response.status_code == 200 and delta > max(200, int(len(baseline.text) * 0.2))


def _least_privilege_findings(target_url: str, run_id: str) -> list[Finding]:
    findings: list[Finding] = []
    urls = _get_urls_from_sitemap(target_url)
    if not urls:
        urls = [target_url]
    executed = False

    for url in urls[:3]:
        forms, fetched = _get_forms(url)
        forms = [f for f in forms if f.method == "post"]
        executed = executed or fetched
        for form in forms[:3]:
            try:
                response = requests.post(form.action, data={"test": "value"}, timeout=5)
                executed = True
            except requests.RequestException:
                continue

            if response.status_code not in {401, 403} and response.status_code < 400:
                findings.append(
                    Finding(
                        id=_make_id("LAB-LEAST"),
                        asset=Asset(type="url", value=form.action),
                        category="OWASP A01",
                        check="lab_least_privilege",
                        severity=Severity.MEDIUM,
                        summary="POST endpoint responded without obvious authorization enforcement",
                        evidence=Evidence(
                            details=f"POST to {form.action} returned status {response.status_code} without authentication."
                        ),
                        remediation=[
                            "Require authentication for sensitive endpoints",
                            "Apply authorization checks per action",
                        ],
                        source="lab_attack",
                        run_id=run_id,
                    )
                )

    if not findings and executed:
        findings.append(
            Finding(
                id=_make_id("LAB-LEAST"),
                asset=Asset(type="url", value=target_url),
                category="OWASP A01",
                check="lab_least_privilege",
                severity=Severity.INFO,
                summary="Least-privilege probe completed with no unauthenticated POST successes",
                evidence=Evidence(details="No POST endpoints returned a successful response without auth."),
                remediation=[
                    "Continue enforcing authz checks on sensitive actions",
                    "Review endpoint access control regularly",
                ],
                source="lab_attack",
                run_id=run_id,
            )
        )

    return findings


def _get_urls_from_sitemap(target_url: str) -> list[str]:
    try:
        parsed = urlparse(target_url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        response = requests.get(sitemap_url, timeout=5)
    except requests.RequestException:
        return []

    if response.status_code != 200:
        return []

    try:
        root = ET.fromstring(response.content)
    except ET.ParseError:
        return []

    namespace = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = []
    for url in root.findall("ns:url", namespace):
        loc = url.find("ns:loc", namespace)
        if loc is not None and loc.text:
            urls.append(loc.text)
    return urls


def _dos_simulation_findings(target_url: str, run_id: str) -> list[Finding]:
    total_requests = 20
    concurrency = 4
    timeout_sec = 3

    start = time.time()
    errors = 0
    responses = 0

    def _hit() -> bool | None:
        nonlocal responses
        try:
            response = requests.get(target_url, timeout=timeout_sec)
            responses += 1
            return response.status_code < 500
        except requests.RequestException:
            return None

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_hit) for _ in range(total_requests)]
        for future in as_completed(futures):
            result = future.result()
            if result is False:
                errors += 1

    duration = time.time() - start
    error_rate = errors / max(total_requests, 1)

    if responses == 0:
        return []

    if error_rate >= 0.3:
        return [
            Finding(
                id=_make_id("LAB-DOS"),
                asset=Asset(type="url", value=target_url),
                category="Availability",
                check="lab_dos_simulation",
                severity=Severity.MEDIUM,
                summary="Service showed instability under a small burst of requests",
                evidence=Evidence(
                    details=f"Error rate: {error_rate:.0%} over {total_requests} requests in {duration:.2f}s."
                ),
                remediation=[
                    "Add request rate limiting",
                    "Use caching or queueing for expensive operations",
                    "Monitor and autoscale under load",
                ],
                source="lab_attack",
                run_id=run_id,
            )
        ]

    return [
        Finding(
            id=_make_id("LAB-DOS"),
            asset=Asset(type="url", value=target_url),
            category="Availability",
            check="lab_dos_simulation",
            severity=Severity.INFO,
            summary="DoS simulation completed with no significant errors",
            evidence=Evidence(
                details=f"Error rate: {error_rate:.0%} over {total_requests} requests in {duration:.2f}s."
            ),
            remediation=[
                "Continue monitoring traffic spikes",
                "Keep rate limiting policies updated",
            ],
            source="lab_attack",
            run_id=run_id,
        )
    ]


def run_lab_attacks(target_url: str, run_id: str) -> list[Finding]:
    findings: list[Finding] = []

    findings.extend(_sql_injection_findings(target_url, run_id))
    findings.extend(_csrf_findings(target_url, run_id))
    findings.extend(_least_privilege_findings(target_url, run_id))
    findings.extend(_credential_stuffing_findings(target_url, run_id))
    findings.extend(_dos_simulation_findings(target_url, run_id))

    return findings
