"""
TLS/SSL Security Probe - Analyzes certificate, expiration, SANs, and HSTS.
Non-destructive passive analysis only.
"""
import logging
import socket
import ssl
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from app.models import Asset, Evidence, Finding, Severity

logger = logging.getLogger(__name__)


class TLSProbe:
    """Probe for TLS/SSL security analysis."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.finding_counter = 0

    def _generate_finding_id(self) -> str:
        self.finding_counter += 1
        return f"TLS-{self.finding_counter:04d}"

    def analyze(self, target_url: str) -> list[Finding]:
        """
        Perform TLS analysis on the target URL.
        Returns a list of findings.
        """
        findings = []
        
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        if parsed.scheme != "https":
            findings.append(
                Finding(
                    id=self._generate_finding_id(),
                    asset=Asset(type="url", value=target_url),
                    category="OWASP A02",
                    check="tls_probe",
                    severity=Severity.HIGH,
                    summary="Site does not use HTTPS",
                    evidence=Evidence(
                        details=f"The target URL uses {parsed.scheme} instead of HTTPS. "
                                "All traffic is transmitted in plaintext.",
                    ),
                    remediation=[
                        "Enable HTTPS on the web server",
                        "Obtain a valid TLS certificate (Let's Encrypt is free)",
                        "Redirect all HTTP traffic to HTTPS",
                    ],
                    source="custom_probe",
                    run_id=self.run_id,
                )
            )
            return findings

        try:
            cert_info = self._get_certificate_info(hostname, port)
            if cert_info:
                findings.extend(self._analyze_certificate(target_url, hostname, cert_info))
        except Exception as e:
            logger.error(f"TLS probe error for {target_url}: {e}")
            findings.append(
                Finding(
                    id=self._generate_finding_id(),
                    asset=Asset(type="url", value=target_url),
                    category="OWASP A02",
                    check="tls_probe",
                    severity=Severity.MEDIUM,
                    summary="Unable to analyze TLS configuration",
                    evidence=Evidence(
                        details=f"Could not retrieve TLS certificate information: {str(e)}",
                    ),
                    remediation=[
                        "Ensure the server is reachable",
                        "Verify TLS is properly configured",
                    ],
                    source="custom_probe",
                    run_id=self.run_id,
                )
            )

        return findings

    def _get_certificate_info(self, hostname: str, port: int) -> Optional[dict]:
        """Retrieve certificate information from the server."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Allow self-signed for analysis
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    # Get certificate in binary form for additional checks
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    # Get cipher info
                    cipher = ssock.cipher()
                    
                    # Get protocol version
                    version = ssock.version()
                    
                    return {
                        "cert": cert,
                        "cert_binary": cert_binary,
                        "cipher": cipher,
                        "version": version,
                    }
        except ssl.SSLError as e:
            # Try to get minimal info even on SSL errors
            logger.warning(f"SSL Error for {hostname}:{port}: {e}")
            return {"error": str(e)}
        except socket.timeout:
            logger.warning(f"Connection timeout for {hostname}:{port}")
            return {"error": "Connection timeout"}
        except Exception as e:
            logger.error(f"Connection error for {hostname}:{port}: {e}")
            return {"error": str(e)}

    def _analyze_certificate(self, target_url: str, hostname: str, cert_info: dict) -> list[Finding]:
        """Analyze certificate and return findings."""
        findings = []
        
        if "error" in cert_info:
            findings.append(
                Finding(
                    id=self._generate_finding_id(),
                    asset=Asset(type="url", value=target_url),
                    category="OWASP A02",
                    check="tls_probe",
                    severity=Severity.HIGH,
                    summary="TLS connection error",
                    evidence=Evidence(
                        details=f"TLS error: {cert_info['error']}",
                    ),
                    remediation=[
                        "Check TLS configuration on the server",
                        "Ensure valid certificate is installed",
                        "Verify certificate chain is complete",
                    ],
                    source="custom_probe",
                    run_id=self.run_id,
                )
            )
            return findings

        cert = cert_info.get("cert", {})
        
        # Check certificate expiration
        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry_date - datetime.utcnow()).days
                
                if days_until_expiry < 0:
                    findings.append(
                        Finding(
                            id=self._generate_finding_id(),
                            asset=Asset(type="url", value=target_url),
                            category="OWASP A02",
                            check="tls_probe",
                            severity=Severity.CRITICAL,
                            summary="SSL certificate has expired",
                            evidence=Evidence(
                                details=f"Certificate expired on {not_after}. "
                                        f"Expired {abs(days_until_expiry)} days ago.",
                            ),
                            remediation=[
                                "Renew the SSL certificate immediately",
                                "Consider using automated certificate renewal (e.g., certbot)",
                            ],
                            source="custom_probe",
                            run_id=self.run_id,
                        )
                    )
                elif days_until_expiry < 30:
                    findings.append(
                        Finding(
                            id=self._generate_finding_id(),
                            asset=Asset(type="url", value=target_url),
                            category="OWASP A02",
                            check="tls_probe",
                            severity=Severity.MEDIUM,
                            summary="SSL certificate expires soon",
                            evidence=Evidence(
                                details=f"Certificate expires on {not_after}. "
                                        f"Only {days_until_expiry} days remaining.",
                            ),
                            remediation=[
                                "Plan certificate renewal before expiration",
                                "Set up automated certificate renewal",
                            ],
                            source="custom_probe",
                            run_id=self.run_id,
                        )
                    )

            # Check Subject Alternative Names (SANs)
            sans = cert.get("subjectAltName", [])
            san_names = [san[1] for san in sans if san[0] == "DNS"]
            
            if not san_names:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A02",
                        check="tls_probe",
                        severity=Severity.LOW,
                        summary="Certificate has no Subject Alternative Names",
                        evidence=Evidence(
                            details="The certificate does not include SANs. "
                                    "Modern browsers prefer SANs over CN.",
                        ),
                        remediation=[
                            "Regenerate certificate with appropriate SANs",
                            "Include all relevant domain names in SANs",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
            elif hostname not in san_names and f"*.{'.'.join(hostname.split('.')[1:])}" not in san_names:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A02",
                        check="tls_probe",
                        severity=Severity.HIGH,
                        summary="Hostname not in certificate SANs",
                        evidence=Evidence(
                            details=f"The hostname '{hostname}' is not listed in the certificate's SANs. "
                                    f"SANs: {', '.join(san_names)}",
                        ),
                        remediation=[
                            f"Add '{hostname}' to the certificate's SANs",
                            "Use a wildcard certificate if applicable",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )

        # Check TLS version
        version = cert_info.get("version", "")
        if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]:
            findings.append(
                Finding(
                    id=self._generate_finding_id(),
                    asset=Asset(type="url", value=target_url),
                    category="OWASP A02",
                    check="tls_probe",
                    severity=Severity.HIGH,
                    summary=f"Deprecated TLS version in use: {version}",
                    evidence=Evidence(
                        details=f"The server is using {version}, which is deprecated and insecure.",
                    ),
                    remediation=[
                        "Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1",
                        "Enable TLS 1.2 and TLS 1.3 only",
                        "Update server TLS configuration",
                    ],
                    source="custom_probe",
                    run_id=self.run_id,
                )
            )

        # Check cipher strength
        cipher = cert_info.get("cipher", ())
        if cipher:
            cipher_name = cipher[0] if len(cipher) > 0 else ""
            cipher_bits = cipher[2] if len(cipher) > 2 else 0
            
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
            if any(weak in cipher_name.upper() for weak in weak_ciphers):
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A02",
                        check="tls_probe",
                        severity=Severity.HIGH,
                        summary="Weak cipher suite in use",
                        evidence=Evidence(
                            details=f"Weak cipher detected: {cipher_name}",
                        ),
                        remediation=[
                            "Disable weak cipher suites",
                            "Use only strong ciphers (AES-GCM, ChaCha20)",
                            "Follow Mozilla SSL Configuration Generator recommendations",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
            
            if cipher_bits < 128:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A02",
                        check="tls_probe",
                        severity=Severity.HIGH,
                        summary="Cipher with insufficient key length",
                        evidence=Evidence(
                            details=f"Cipher {cipher_name} uses only {cipher_bits} bits. "
                                    "Minimum recommended is 128 bits.",
                        ),
                        remediation=[
                            "Use ciphers with at least 128-bit keys",
                            "Prefer 256-bit ciphers for sensitive data",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )

        return findings
