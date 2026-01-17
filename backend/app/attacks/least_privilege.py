"""
Least privilege attack simulation.
"""

from attack_tools import get_forms, make_id, get_urls_from_sitemap
from app.models import Asset, Evidence, Finding, Severity
import requests

def least_privilege_findings(target_url: str, run_id: str) -> list[Finding]:
    """Test for least privilege violations in POST endpoints.

    Args:
        target_url (str): The target URL to test.
        run_id (str): A unique identifier for the test run.

    Returns:
        list[Finding]: A list of findings related to least privilege violations.
    """
    findings: list[Finding] = []
    urls = get_urls_from_sitemap(target_url)
    if not urls:
        urls = [target_url]
    executed = False

    for url in urls[:3]:
        forms, fetched = get_forms(url)
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
                        id=make_id("LAB-LEAST"),
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
                id=make_id("LAB-LEAST"),
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
