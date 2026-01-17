"""
CSRF attack simulation.
"""

from attack_tools import get_forms, make_id
from app.models import Asset, Evidence, Finding, Severity

def csrf_findings(target_url: str, run_id: str) -> list[Finding]:
    """Test for missing CSRF tokens in forms.

    Args:
        target_url (str): The target URL to test.
        run_id (str): A unique identifier for the test run.

    Returns:
        list[Finding]: A list of findings related to CSRF vulnerabilities.
    """
    findings: list[Finding] = []
    forms, fetched = get_forms(target_url)
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
                    id=make_id("LAB-CSRF"),
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
                id=make_id("LAB-CSRF"),
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
