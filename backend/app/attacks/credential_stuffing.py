"""
Credential stuffing attack simulation.
"""

from attack_tools import get_forms, make_id, COMMON_CREDENTIALS, looks_like_login_success
from app.models import Asset, Evidence, Finding, Severity
import requests

def credential_stuffing_findings(target_url: str, run_id: str) -> list[Finding]:
    """Test for credential stuffing vulnerabilities in login forms.

    Args:
        target_url (str): The target URL to test.
        run_id (str): A unique identifier for the test run.

    Returns:
        list[Finding]: A list of findings related to credential stuffing vulnerabilities.
    """
    findings: list[Finding] = []
    forms, fetched = get_forms(target_url)
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
                if looks_like_login_success(response, baseline):
                    findings.append(
                        Finding(
                            id=make_id("LAB-CRED"),
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
                id=make_id("LAB-CRED"),
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
