"""
SQL injection attack simulation.
"""

from attack_tools import get_forms, make_id, DEFAULT_SQL_PAYLOADS, SQL_ERROR_PATTERNS
from app.models import Asset, Evidence, Finding, Severity
import requests

def sql_injection_findings(target_url: str, run_id: str) -> list[Finding]:
    """Test for SQL injection vulnerabilities in forms.

    Args:
        target_url (str): The target URL to test.
        run_id (str): A unique identifier for the test run.

    Returns:
        list[Finding]: A list of findings related to SQL injection vulnerabilities.
    """
    findings: list[Finding] = []
    forms, fetched = get_forms(target_url)
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
                            id=make_id("LAB-SQLI"),
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
                id=make_id("LAB-SQLI"),
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
