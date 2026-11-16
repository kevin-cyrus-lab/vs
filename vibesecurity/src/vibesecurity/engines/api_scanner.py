from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import List

from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.engines.base import BaseSecurityScanner
from vibesecurity.repository.discovery import discover_files


class ApiSecurityScanner(BaseSecurityScanner):
    """Audits API routes and website endpoints for authentication, authorization, and rate-limiting flaws."""

    name: str = "api_scanner"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        files = discover_files(self.root)

        for f in files:
            rel = str(f.relative_to(self.root))
            ext = f.suffix.lower()

            if ext in {".ts", ".tsx", ".js", ".jsx", ".py"}:
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                findings.extend(self._audit_route_file(f, rel, content))

        findings.extend(self._check_nextjs_security_headers())
        return findings

    def _audit_route_file(self, file_path: Path, rel: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Check if route is an administrative or mutating endpoint
        is_admin_route = "/admin" in rel.lower() or "admin" in file_path.name.lower()
        has_auth_check = any(term in content for term in [
            "session", "getServerSession", "auth(", "verifyToken", "isAuthenticated",
            "req.user", "authenticate", "require_auth", "Depends(get_current_user)", "current_user"
        ])

        if is_admin_route and not has_auth_check:
            findings.append(
                Finding(
                    id=f"VS-API-{uuid.uuid4().hex[:6]}",
                    title="Administrative Route Lacking Authentication Check",
                    severity=Severity.HIGH.value,
                    category="broken_auth",
                    cwe="CWE-306",
                    file_path=rel,
                    line_start=1,
                    line_end=1,
                    code_snippet=rel,
                    rule_id="admin-route-missing-auth",
                    scanner="api_scanner",
                    confidence="medium",
                    description=f"Route {rel} appears to be an administrative interface but does not check user authentication or role permissions.",
                    remediation_strategy="add-authentication-middleware",
                    risk_level=RiskLevel.HIGH.value,
                )
            )

        # Check sensitive operations (login, checkout, password reset) for rate limiting
        is_sensitive_action = any(act in rel.lower() for act in ["login", "checkout", "forgot-password", "reset-password", "register"])
        has_rate_limit = any(term in content for term in ["rateLimit", "limiter", "ratelimit", "throttle", "slowDown"])

        if is_sensitive_action and not has_rate_limit:
            findings.append(
                Finding(
                    id=f"VS-API-{uuid.uuid4().hex[:6]}",
                    title="Sensitive Endpoint Missing Rate Limiting",
                    severity=Severity.MEDIUM.value,
                    category="dos_mitigation",
                    cwe="CWE-799",
                    file_path=rel,
                    line_start=1,
                    line_end=1,
                    code_snippet=rel,
                    rule_id="missing-rate-limiter",
                    scanner="api_scanner",
                    confidence="medium",
                    description=f"Sensitive endpoint {rel} is not protected with rate limiting, exposing it to brute force or credential stuffing attacks.",
                    remediation_strategy="add-rate-limiter",
                    risk_level=RiskLevel.LOW.value,
                )
            )

        return findings

    def _check_nextjs_security_headers(self) -> List[Finding]:
        findings: List[Finding] = []
        for name in ["next.config.ts", "next.config.js", "next.config.mjs"]:
            cfg = self.root / name
            if cfg.is_file():
                rel = str(cfg.relative_to(self.root))
                try:
                    content = cfg.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                if "headers" not in content or "Content-Security-Policy" not in content:
                    findings.append(
                        Finding(
                            id=f"VS-API-{uuid.uuid4().hex[:6]}",
                            title="Missing Recommended HTTP Security Headers in Next.js",
                            severity=Severity.MEDIUM.value,
                            category="misconfiguration",
                            cwe="CWE-693",
                            file_path=rel,
                            line_start=1,
                            line_end=1,
                            code_snippet=name,
                            rule_id="nextjs-missing-security-headers",
                            scanner="api_scanner",
                            confidence="high",
                            description="Next.js config does not configure standard security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).",
                            remediation_strategy="inject-nextjs-security-headers",
                            risk_level=RiskLevel.LOW.value,
                        )
                    )
        return findings

