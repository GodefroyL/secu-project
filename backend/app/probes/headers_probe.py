"""
HTTP Security Headers Probe - Analyzes security headers and cookies.
Non-destructive passive analysis only.
"""
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.models import Asset, Evidence, Finding, Severity

logger = logging.getLogger(__name__)


class HeadersProbe:
    """Probe for HTTP security headers and cookie analysis."""

    # Security headers to check with their importance
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": Severity.HIGH,
            "category": "OWASP A05",
            "description": "HSTS header missing - vulnerable to protocol downgrade attacks",
            "remediation": [
                "Add Strict-Transport-Security header",
                "Recommended value: max-age=31536000; includeSubDomains; preload",
                "Consider HSTS preloading for maximum protection",
            ],
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "category": "OWASP A03",
            "description": "CSP header missing - vulnerable to XSS and data injection attacks",
            "remediation": [
                "Implement Content-Security-Policy header",
                "Start with report-only mode to test",
                "Gradually restrict sources to trusted domains",
            ],
        },
        "X-Content-Type-Options": {
            "severity": Severity.MEDIUM,
            "category": "OWASP A05",
            "description": "X-Content-Type-Options missing - vulnerable to MIME sniffing attacks",
            "remediation": [
                "Add X-Content-Type-Options: nosniff",
            ],
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "category": "OWASP A05",
            "description": "X-Frame-Options missing - vulnerable to clickjacking attacks",
            "remediation": [
                "Add X-Frame-Options: DENY or SAMEORIGIN",
                "Or use CSP frame-ancestors directive",
            ],
        },
        "X-XSS-Protection": {
            "severity": Severity.LOW,
            "category": "OWASP A03",
            "description": "X-XSS-Protection header missing (legacy protection)",
            "remediation": [
                "Add X-XSS-Protection: 1; mode=block",
                "Note: CSP is the modern replacement for XSS protection",
            ],
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "category": "OWASP A05",
            "description": "Referrer-Policy missing - may leak sensitive URL information",
            "remediation": [
                "Add Referrer-Policy: strict-origin-when-cross-origin",
                "Or use no-referrer for maximum privacy",
            ],
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "category": "OWASP A05",
            "description": "Permissions-Policy missing - browser features not restricted",
            "remediation": [
                "Add Permissions-Policy header to restrict browser features",
                "Disable unused features like geolocation, camera, microphone",
            ],
        },
    }

    # Dangerous headers that should not be exposed
    DANGEROUS_HEADERS = {
        "Server": {
            "severity": Severity.LOW,
            "description": "Server header reveals technology information",
        },
        "X-Powered-By": {
            "severity": Severity.LOW,
            "description": "X-Powered-By header reveals technology information",
        },
        "X-AspNet-Version": {
            "severity": Severity.MEDIUM,
            "description": "ASP.NET version exposed",
        },
        "X-AspNetMvc-Version": {
            "severity": Severity.MEDIUM,
            "description": "ASP.NET MVC version exposed",
        },
    }

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.finding_counter = 0

    def _generate_finding_id(self) -> str:
        self.finding_counter += 1
        return f"HDR-{self.finding_counter:04d}"

    async def analyze(self, target_url: str) -> list[Finding]:
        """
        Perform HTTP headers and cookies analysis on the target URL.
        Returns a list of findings.
        """
        findings = []
        
        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,  # Allow self-signed certs for analysis
            ) as client:
                response = await client.get(target_url)
                
                # Analyze security headers
                findings.extend(self._analyze_security_headers(target_url, response.headers))
                
                # Analyze information disclosure
                findings.extend(self._analyze_info_disclosure(target_url, response.headers))
                
                # Analyze cookies
                findings.extend(self._analyze_cookies(target_url, response.cookies, response.headers))
                
                # Check for HSTS specifics
                findings.extend(self._analyze_hsts(target_url, response.headers))
                
        except httpx.TimeoutException:
            findings.append(
                Finding(
                    id=self._generate_finding_id(),
                    asset=Asset(type="url", value=target_url),
                    category="OWASP A05",
                    check="headers_probe",
                    severity=Severity.MEDIUM,
                    summary="Connection timeout during headers analysis",
                    evidence=Evidence(
                        details="The server did not respond within the timeout period.",
                    ),
                    remediation=[
                        "Check server availability",
                        "Review server response times",
                    ],
                    source="custom_probe",
                    run_id=self.run_id,
                )
            )
        except httpx.RequestError as e:
            logger.error(f"Headers probe error for {target_url}: {e}")
            findings.append(
                Finding(
                    id=self._generate_finding_id(),
                    asset=Asset(type="url", value=target_url),
                    category="OWASP A05",
                    check="headers_probe",
                    severity=Severity.MEDIUM,
                    summary="Unable to analyze HTTP headers",
                    evidence=Evidence(
                        details=f"Connection error: {str(e)}",
                    ),
                    remediation=[
                        "Ensure the server is reachable",
                        "Check network connectivity",
                    ],
                    source="custom_probe",
                    run_id=self.run_id,
                )
            )

        return findings

    def _analyze_security_headers(self, target_url: str, headers: httpx.Headers) -> list[Finding]:
        """Check for missing security headers."""
        findings = []
        
        for header_name, config in self.SECURITY_HEADERS.items():
            if header_name.lower() not in [h.lower() for h in headers.keys()]:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category=config["category"],
                        check="headers_probe",
                        severity=config["severity"],
                        summary=config["description"],
                        evidence=Evidence(
                            details=f"The {header_name} header is not present in the response.",
                            headers=dict(headers),
                        ),
                        remediation=config["remediation"],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
        
        return findings

    def _analyze_info_disclosure(self, target_url: str, headers: httpx.Headers) -> list[Finding]:
        """Check for headers that reveal sensitive information."""
        findings = []
        
        for header_name, config in self.DANGEROUS_HEADERS.items():
            header_value = headers.get(header_name)
            if header_value:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A05",
                        check="headers_probe",
                        severity=config["severity"],
                        summary=config["description"],
                        evidence=Evidence(
                            details=f"{header_name}: {header_value}",
                            headers={header_name: header_value},
                        ),
                        remediation=[
                            f"Remove or obfuscate the {header_name} header",
                            "Configure your server to hide version information",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
        
        return findings

    def _analyze_cookies(
        self, target_url: str, cookies: httpx.Cookies, headers: httpx.Headers
    ) -> list[Finding]:
        """Analyze cookies for security attributes."""
        findings = []
        parsed = urlparse(target_url)
        is_https = parsed.scheme == "https"
        
        # Get Set-Cookie headers for detailed analysis
        set_cookie_headers = headers.get_list("set-cookie")
        
        for cookie_header in set_cookie_headers:
            cookie_parts = cookie_header.split(";")
            cookie_name = cookie_parts[0].split("=")[0].strip() if cookie_parts else "unknown"
            
            cookie_lower = cookie_header.lower()
            
            # Check Secure flag
            if is_https and "secure" not in cookie_lower:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A05",
                        check="headers_probe",
                        severity=Severity.MEDIUM,
                        summary=f"Cookie '{cookie_name}' missing Secure flag",
                        evidence=Evidence(
                            details=f"Set-Cookie: {cookie_header}",
                            headers={"Set-Cookie": cookie_header},
                        ),
                        remediation=[
                            "Add the Secure flag to all cookies on HTTPS sites",
                            "Example: Set-Cookie: name=value; Secure",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
            
            # Check HttpOnly flag (important for session cookies)
            if "httponly" not in cookie_lower:
                severity = Severity.HIGH if self._is_session_cookie(cookie_name) else Severity.MEDIUM
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A03",
                        check="headers_probe",
                        severity=severity,
                        summary=f"Cookie '{cookie_name}' missing HttpOnly flag",
                        evidence=Evidence(
                            details=f"Set-Cookie: {cookie_header}\n"
                                    "Without HttpOnly, JavaScript can access this cookie (XSS risk).",
                            headers={"Set-Cookie": cookie_header},
                        ),
                        remediation=[
                            "Add the HttpOnly flag to prevent JavaScript access",
                            "Example: Set-Cookie: name=value; HttpOnly",
                            "This is critical for session cookies",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
            
            # Check SameSite attribute
            if "samesite" not in cookie_lower:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A01",
                        check="headers_probe",
                        severity=Severity.MEDIUM,
                        summary=f"Cookie '{cookie_name}' missing SameSite attribute",
                        evidence=Evidence(
                            details=f"Set-Cookie: {cookie_header}\n"
                                    "Without SameSite, cookie is vulnerable to CSRF attacks.",
                            headers={"Set-Cookie": cookie_header},
                        ),
                        remediation=[
                            "Add SameSite=Strict or SameSite=Lax",
                            "SameSite=Strict provides maximum CSRF protection",
                            "SameSite=Lax is a reasonable default",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A05",
                        check="headers_probe",
                        severity=Severity.HIGH,
                        summary=f"Cookie '{cookie_name}' has SameSite=None without Secure",
                        evidence=Evidence(
                            details=f"Set-Cookie: {cookie_header}\n"
                                    "SameSite=None requires the Secure flag.",
                            headers={"Set-Cookie": cookie_header},
                        ),
                        remediation=[
                            "Add the Secure flag when using SameSite=None",
                            "Or use SameSite=Strict/Lax instead",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
        
        return findings

    def _is_session_cookie(self, cookie_name: str) -> bool:
        """Check if a cookie name suggests it's a session cookie."""
        session_indicators = [
            "session", "sess", "sid", "ssid", "jsessionid", 
            "phpsessid", "asp.net_sessionid", "token", "auth",
            "login", "user", "remember"
        ]
        cookie_lower = cookie_name.lower()
        return any(indicator in cookie_lower for indicator in session_indicators)

    def _analyze_hsts(self, target_url: str, headers: httpx.Headers) -> list[Finding]:
        """Detailed HSTS analysis."""
        findings = []
        hsts = headers.get("Strict-Transport-Security")
        
        if hsts:
            hsts_lower = hsts.lower()
            
            # Check max-age value
            if "max-age=" in hsts_lower:
                try:
                    max_age_str = hsts_lower.split("max-age=")[1].split(";")[0].strip()
                    max_age = int(max_age_str)
                    
                    # Recommended: at least 1 year (31536000 seconds)
                    if max_age < 31536000:
                        findings.append(
                            Finding(
                                id=self._generate_finding_id(),
                                asset=Asset(type="url", value=target_url),
                                category="OWASP A05",
                                check="headers_probe",
                                severity=Severity.LOW,
                                summary="HSTS max-age is less than recommended",
                                evidence=Evidence(
                                    details=f"Current max-age: {max_age} seconds\n"
                                            f"Recommended: 31536000 seconds (1 year) or more",
                                    headers={"Strict-Transport-Security": hsts},
                                ),
                                remediation=[
                                    "Increase max-age to at least 31536000 (1 year)",
                                    "For preload eligibility, use max-age=31536000",
                                ],
                                source="custom_probe",
                                run_id=self.run_id,
                            )
                        )
                except (ValueError, IndexError):
                    pass
            
            # Check for includeSubDomains
            if "includesubdomains" not in hsts_lower:
                findings.append(
                    Finding(
                        id=self._generate_finding_id(),
                        asset=Asset(type="url", value=target_url),
                        category="OWASP A05",
                        check="headers_probe",
                        severity=Severity.LOW,
                        summary="HSTS does not include subdomains",
                        evidence=Evidence(
                            details=f"HSTS: {hsts}\n"
                                    "Subdomains are not protected by HSTS.",
                            headers={"Strict-Transport-Security": hsts},
                        ),
                        remediation=[
                            "Add includeSubDomains directive if applicable",
                            "Ensure all subdomains support HTTPS first",
                        ],
                        source="custom_probe",
                        run_id=self.run_id,
                    )
                )
        
        return findings
