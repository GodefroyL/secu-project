"""
Run all security attack simulations.
"""

from sql_injection import sql_injection_findings
from csrf import csrf_findings
from least_privilege import least_privilege_findings
from credential_stuffing import credential_stuffing_findings
from dos_simulation import dos_simulation_findings
from app.models import Finding

def run_lab_attacks(target_url: str, run_id: str) -> list[Finding]:
    """Run all security attack simulations on the target URL.

    Args:
        target_url (str): The target URL to test.
        run_id (str): A unique identifier for the test run.

    Returns:
        list[Finding]: A list of findings from all attack simulations.
    """
    findings: list[Finding] = []

    findings.extend(sql_injection_findings(target_url, run_id))
    findings.extend(csrf_findings(target_url, run_id))
    findings.extend(least_privilege_findings(target_url, run_id))
    findings.extend(credential_stuffing_findings(target_url, run_id))
    findings.extend(dos_simulation_findings(target_url, run_id))

    return findings
