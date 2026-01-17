"""
Denial of Service (DoS) simulation.
"""

from attack_tools import make_id
from app.models import Asset, Evidence, Finding, Severity
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import requests

def dos_simulation_findings(target_url: str, run_id: str) -> list[Finding]:
    """Simulate a DoS attack by sending multiple concurrent requests.

    Args:
        target_url (str): The target URL to test.
        run_id (str): A unique identifier for the test run.

    Returns:
        list[Finding]: A list of findings related to DoS vulnerabilities.
    """
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
                id=make_id("LAB-DOS"),
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
            id=make_id("LAB-DOS"),
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
