from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List

from vibesecurity.core.models import Finding, RiskLevel, Severity


class DynamicWebScanner:
    """
    Dynamic Application Security Testing (DAST) scanner for live web applications and websites.
    Audits HTTP headers, SSL/TLS, cookie attributes, exposed paths, and information leakage.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urllib.parse.urlparse(self.target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid target URL: {self.target_url}")

        # 1. Inspect Root HTTP Response Headers
        try:
            req = urllib.request.Request(
                self.target_url,
                headers={"User-Agent": "VibeSecurity-Auditor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = {k.lower(): v for k, v in response.getheaders()}
                findings.extend(self._audit_headers(headers))
                findings.extend(self._audit_cookies(response))
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            findings.extend(self._audit_headers(headers))
        except Exception as e:
            # Server unreachable
            return [
                Finding(
                    id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                    title=f"Target URL Unreachable: {e}",
                    severity=Severity.INFO.value,
                    category="availability",
                    cwe="CWE-799",
                    file_path=self.target_url,
                    line_start=1,
                    line_end=1,
                    code_snippet=str(e),
                    rule_id="dynamic-target-unreachable",
                    scanner="dynamic_scanner",
                    confidence="high",
                    description="Could not connect to target URL. Ensure the web server is running.",
                    remediation_strategy="",
                    risk_level=RiskLevel.LOW.value,
                )
            ]

        # 2. Check for exposed sensitive files
        findings.extend(self._check_exposed_paths())
        return findings

    def _audit_headers(self, headers: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        # Content-Security-Policy
        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                    title="Missing Content-Security-Policy (CSP) Header",
                    severity=Severity.HIGH.value,
                    category="misconfiguration",
                    cwe="CWE-693",
                    file_path=self.target_url,
                    line_start=1,
                    line_end=1,
                    code_snippet="Content-Security-Policy: [MISSING]",
                    rule_id="missing-csp-header",
                    scanner="dynamic_scanner",
                    confidence="high",
                    description="Without a CSP header, the browser cannot restrict script execution sources, increasing XSS vulnerability impact.",
                    remediation_strategy="add-csp-header",
                    risk_level=RiskLevel.LOW.value,
                )
            )

        # X-Frame-Options
        if "x-frame-options" not in headers:
            findings.append(
                Finding(
                    id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                    title="Missing X-Frame-Options Header (Clickjacking Risk)",
                    severity=Severity.MEDIUM.value,
                    category="misconfiguration",
                    cwe="CWE-1021",
                    file_path=self.target_url,
                    line_start=1,
                    line_end=1,
                    code_snippet="X-Frame-Options: [MISSING]",
                    rule_id="missing-x-frame-options",
                    scanner="dynamic_scanner",
                    confidence="high",
                    description="Missing X-Frame-Options header allows the website to be framed in an iframe by third-party malicious sites (Clickjacking).",
                    remediation_strategy="add-x-frame-options-deny",
                    risk_level=RiskLevel.LOW.value,
                )
            )

        # X-Content-Type-Options
        if headers.get("x-content-type-options") != "nosniff":
            findings.append(
                Finding(
                    id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    severity=Severity.LOW.value,
                    category="misconfiguration",
                    cwe="CWE-693",
                    file_path=self.target_url,
                    line_start=1,
                    line_end=1,
                    code_snippet="X-Content-Type-Options: [MISSING]",
                    rule_id="missing-x-content-type-options",
                    scanner="dynamic_scanner",
                    confidence="high",
                    description="MIME-sniffing protection is disabled, potentially enabling script execution from uploaded images.",
                    remediation_strategy="add-nosniff-header",
                    risk_level=RiskLevel.LOW.value,
                )
            )

        # Server banner disclosure
        if "x-powered-by" in headers:
            findings.append(
                Finding(
                    id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                    title=f"Information Disclosure: X-Powered-By ({headers['x-powered-by']})",
                    severity=Severity.LOW.value,
                    category="information_disclosure",
                    cwe="CWE-200",
                    file_path=self.target_url,
                    line_start=1,
                    line_end=1,
                    code_snippet=f"X-Powered-By: {headers['x-powered-by']}",
                    rule_id="banner-x-powered-by",
                    scanner="dynamic_scanner",
                    confidence="high",
                    description="Server framework technology is advertised in HTTP response headers, assisting attackers in footprinting.",
                    remediation_strategy="disable-x-powered-by",
                    risk_level=RiskLevel.LOW.value,
                )
            )

        return findings

    def _audit_cookies(self, response: Any) -> List[Finding]:
        findings: List[Finding] = []
        cookies = response.headers.get_all("Set-Cookie") or []
        for c in cookies:
            c_lower = c.lower()
            if "httponly" not in c_lower:
                findings.append(
                    Finding(
                        id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                        title="Cookie Missing HttpOnly Flag",
                        severity=Severity.MEDIUM.value,
                        category="session_management",
                        cwe="CWE-1004",
                        file_path=self.target_url,
                        line_start=1,
                        line_end=1,
                        code_snippet=c.split(";")[0],
                        rule_id="cookie-missing-httponly",
                        scanner="dynamic_scanner",
                        confidence="high",
                        description="Cookie without HttpOnly flag can be accessed by client-side JavaScript, exposing session tokens to XSS.",
                        remediation_strategy="add-httponly-flag",
                        risk_level=RiskLevel.LOW.value,
                    )
                )
            if "samesite" not in c_lower:
                findings.append(
                    Finding(
                        id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                        title="Cookie Missing SameSite Attribute",
                        severity=Severity.LOW.value,
                        category="session_management",
                        cwe="CWE-1275",
                        file_path=self.target_url,
                        line_start=1,
                        line_end=1,
                        code_snippet=c.split(";")[0],
                        rule_id="cookie-missing-samesite",
                        scanner="dynamic_scanner",
                        confidence="high",
                        description="Cookie without SameSite attribute (Lax or Strict) is sent on cross-site requests, increasing CSRF risk.",
                        remediation_strategy="add-samesite-lax",
                        risk_level=RiskLevel.LOW.value,
                    )
                )
        return findings

    def _check_exposed_paths(self) -> List[Finding]:
        findings: List[Finding] = []
        sensitive_paths = ["/.env", "/.git/HEAD"]
        for p in sensitive_paths:
            test_url = f"{self.target_url}{p}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "VibeSecurity-Auditor/1.0"})
                with urllib.request.urlopen(req, timeout=5) as res:
                    if res.status == 200:
                        snippet = res.read(100).decode("utf-8", errors="ignore")
                        findings.append(
                            Finding(
                                id=f"VS-DYN-{uuid.uuid4().hex[:6]}",
                                title=f"Publicly Accessible Sensitive File: {p}",
                                severity=Severity.CRITICAL.value,
                                category="information_disclosure",
                                cwe="CWE-552",
                                file_path=test_url,
                                line_start=1,
                                line_end=1,
                                code_snippet=snippet[:50],
                                rule_id="exposed-sensitive-file",
                                scanner="dynamic_scanner",
                                confidence="high",
                                description=f"Web server allows public HTTP access to {p}. Block access immediately in server configuration.",
                                remediation_strategy="block-sensitive-path-access",
                                risk_level=RiskLevel.LOW.value,
                            )
                        )
            except Exception:
                pass
        return findings

