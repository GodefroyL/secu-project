"""
OWASP ZAP Report Parser.
Converts ZAP JSON output to normalized Finding format.
"""
import json
import logging
from pathlib import Path
from typing import Optional

from app.models import Asset, Evidence, Finding, Severity

logger = logging.getLogger(__name__)


class ZAPParser:
    """Parses OWASP ZAP JSON reports into normalized findings."""

    # ZAP risk levels to our severity mapping
    RISK_MAP = {
        "0": Severity.INFO,      # Informational
        "1": Severity.LOW,       # Low
        "2": Severity.MEDIUM,    # Medium
        "3": Severity.HIGH,      # High
    }

    # ZAP alert to OWASP category mapping
    OWASP_CATEGORY_MAP = {
        # A01: Broken Access Control
        "10035": "OWASP A01",  # Strict-Transport-Security
        
        # A02: Cryptographic Failures
        "10040": "OWASP A02",  # Secure Pages Include Mixed Content
        
        # A03: Injection (XSS, etc.)
        "10015": "OWASP A03",  # Incomplete or No Cache-control and Pragma HTTP Header Set
        "10017": "OWASP A03",  # Cross-Domain JavaScript Source File Inclusion
        "10020": "OWASP A03",  # X-Frame-Options Header
        "10021": "OWASP A03",  # X-Content-Type-Options Header Missing
        "10038": "OWASP A03",  # Content Security Policy (CSP) Header Not Set
        "10055": "OWASP A03",  # CSP
        "10094": "OWASP A03",  # Base64 Disclosure
        "10096": "OWASP A03",  # Timestamp Disclosure
        "40012": "OWASP A03",  # Cross Site Scripting (Reflected)
        "40014": "OWASP A03",  # Cross Site Scripting (Persistent)
        "40016": "OWASP A03",  # Cross Site Scripting (Persistent) - Prime
        "40017": "OWASP A03",  # Cross Site Scripting (Persistent) - Spider
        
        # A04: Insecure Design
        "10010": "OWASP A04",  # Cookie No HttpOnly Flag
        "10011": "OWASP A04",  # Cookie Without Secure Flag
        "10029": "OWASP A04",  # Cookie Poisoning
        "10054": "OWASP A04",  # Cookie without SameSite Attribute
        
        # A05: Security Misconfiguration
        "10003": "OWASP A05",  # Vulnerable JS Library
        "10019": "OWASP A05",  # Content-Type Header Missing
        "10023": "OWASP A05",  # Information Disclosure - Debug Error Messages
        "10024": "OWASP A05",  # Information Disclosure - Sensitive Information in URL
        "10025": "OWASP A05",  # Information Disclosure - Sensitive Information in HTTP Referrer Header
        "10027": "OWASP A05",  # Information Disclosure - Suspicious Comments
        "10028": "OWASP A05",  # Open Redirect
        "10031": "OWASP A05",  # User Controllable HTML Element Attribute
        "10032": "OWASP A05",  # Viewstate
        "10036": "OWASP A05",  # Server Leaks Version Information via "Server" HTTP Response Header Field
        "10037": "OWASP A05",  # Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
        "10050": "OWASP A05",  # Retrieved from Cache
        "10052": "OWASP A05",  # X-ChromeLogger-Data (XCOLD) Header Information Leak
        "10056": "OWASP A05",  # X-Debug-Token Information Leak
        "10061": "OWASP A05",  # X-AspNet-Version Response Header
        "10062": "OWASP A05",  # PII Disclosure
        "10095": "OWASP A05",  # Backup File Disclosure
        "10098": "OWASP A05",  # Cross-Domain Misconfiguration
        "10105": "OWASP A05",  # Weak Authentication Method
        "10109": "OWASP A05",  # Modern Web Application
        "10110": "OWASP A05",  # Dangerous JS Functions
        "90003": "OWASP A05",  # Sub Resource Integrity Attribute Missing
        
        # A06: Vulnerable and Outdated Components
        "10099": "OWASP A06",  # Source Code Disclosure
        
        # A07: Identification and Authentication Failures
        "10012": "OWASP A07",  # Password Autocomplete in Browser
        "10057": "OWASP A07",  # Username Hash Found
        "10058": "OWASP A07",  # GET for POST
        
        # A08: Software and Data Integrity Failures
        "10063": "OWASP A08",  # Permissions Policy Header Not Set
        
        # A09: Security Logging and Monitoring Failures
        "10104": "OWASP A09",  # User Agent Fuzzer
        
        # A10: Server-Side Request Forgery
        "40046": "OWASP A10",  # Server Side Request Forgery
    }

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.finding_counter = 0

    def _generate_finding_id(self) -> str:
        self.finding_counter += 1
        return f"ZAP-{self.finding_counter:04d}"

    def parse_report(self, report_path: str) -> list[Finding]:
        """
        Parse a ZAP JSON report and return normalized findings.
        
        Args:
            report_path: Path to the ZAP JSON report file
            
        Returns:
            List of Finding objects
        """
        findings = []
        path = Path(report_path)
        
        if not path.exists():
            logger.warning(f"ZAP report not found: {report_path}")
            return findings
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse ZAP report: {e}")
            return findings
        
        # Handle different ZAP report formats
        alerts = self._extract_alerts(data)
        
        for alert in alerts:
            finding = self._convert_alert_to_finding(alert)
            if finding:
                findings.append(finding)
        
        logger.info(f"Parsed {len(findings)} findings from ZAP report")
        return findings

    def _extract_alerts(self, data: dict) -> list[dict]:
        """Extract alerts from different ZAP report formats."""
        # Standard baseline report format
        if "site" in data:
            alerts = []
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    alert["url"] = site.get("@name", "")
                    alerts.append(alert)
            return alerts
        
        # API format
        if "alerts" in data:
            return data["alerts"]
        
        # Direct alerts list
        if isinstance(data, list):
            return data
        
        return []

    def _convert_alert_to_finding(self, alert: dict) -> Optional[Finding]:
        """Convert a single ZAP alert to a Finding."""
        try:
            # Get basic info
            plugin_id = str(alert.get("pluginid", alert.get("pluginId", "")))
            risk = str(alert.get("riskcode", alert.get("risk", "0")))
            
            # Get URL from instances or direct field
            instances = alert.get("instances", [])
            if instances:
                url = instances[0].get("uri", alert.get("url", "unknown"))
            else:
                url = alert.get("url", alert.get("uri", "unknown"))
            
            # Build evidence details
            evidence_parts = []
            
            if alert.get("desc", alert.get("description")):
                evidence_parts.append(f"Description: {alert.get('desc', alert.get('description'))}")
            
            if instances:
                evidence_parts.append(f"\nAffected instances: {len(instances)}")
                for i, inst in enumerate(instances[:3]):  # Show first 3 instances
                    evidence_parts.append(f"  [{i+1}] {inst.get('uri', 'N/A')}")
                    if inst.get("evidence"):
                        evidence_parts.append(f"      Evidence: {inst.get('evidence')[:200]}")
            
            if alert.get("evidence"):
                evidence_parts.append(f"\nEvidence: {alert.get('evidence')[:500]}")
            
            if alert.get("attack"):
                evidence_parts.append(f"\nAttack: {alert.get('attack')[:200]}")
            
            # Build remediation
            remediation = []
            if alert.get("solution"):
                # Split solution into separate lines if it contains bullet points or newlines
                solution = alert.get("solution", "")
                for line in solution.split("\n"):
                    line = line.strip()
                    if line and len(line) > 2:
                        remediation.append(line)
            
            if alert.get("reference"):
                remediation.append(f"Reference: {alert.get('reference')[:200]}")
            
            if not remediation:
                remediation = ["Review the finding and implement appropriate security controls"]
            
            # Create finding
            finding = Finding(
                id=self._generate_finding_id(),
                asset=Asset(type="url", value=url),
                category=self.OWASP_CATEGORY_MAP.get(plugin_id, "OWASP A05"),
                check="zap_baseline",
                severity=self.RISK_MAP.get(risk, Severity.INFO),
                summary=alert.get("alert", alert.get("name", "Unknown Alert")),
                evidence=Evidence(
                    details="\n".join(evidence_parts),
                    headers={},
                    artifact_path=None,
                ),
                remediation=remediation[:5],  # Limit to 5 remediation items
                source="zap",
                run_id=self.run_id,
            )
            
            return finding
            
        except Exception as e:
            logger.error(f"Error converting ZAP alert: {e}")
            return None

    def parse_alerts_response(self, alerts_data: dict) -> list[Finding]:
        """
        Parse ZAP alerts API response (alternative format).
        """
        findings = []
        alerts = alerts_data.get("alerts", [])
        
        for alert in alerts:
            finding = self._convert_alert_to_finding(alert)
            if finding:
                findings.append(finding)
        
        return findings
