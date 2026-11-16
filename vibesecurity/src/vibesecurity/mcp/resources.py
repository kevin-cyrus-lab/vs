from __future__ import annotations

import json
from typing import Any, Dict, List

from vibesecurity.core.policies import SecurityPolicy


class McpResourcesRegistry:
    """Manages discoverable MCP resources for VibeSecurity."""

    def list_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "uri": "vibesecurity://policies/current",
                "name": "Active Security Policies",
                "description": "Risk boundaries, permitted automated repairs, and verification rules.",
                "mimeType": "application/json",
            },
            {
                "uri": "vibesecurity://security/owasp",
                "name": "OWASP Top 10 Reference Guide for Vibe Coders",
                "description": "Classification and mitigation strategies for web and API security vulnerabilities.",
                "mimeType": "text/markdown",
            },
        ]

    def read_resource(self, uri: str) -> Dict[str, Any]:
        if uri == "vibesecurity://policies/current":
            policy = SecurityPolicy.load("default")
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(policy.__dict__, indent=2),
                    }
                ]
            }
        elif uri == "vibesecurity://security/owasp":
            doc = """# OWASP Top 10 for AI & Vibe Coders
1. A01: Broken Access Control — Missing authentication/authorization checks on routes & object IDs.
2. A02: Cryptographic Failures — Plaintext passwords, weak MD5/SHA1 hashing, hardcoded keys.
3. A03: Injection — SQL injection via string concatenation or f-strings; Command injection via `os.system` / `shell=True`.
4. A04: Insecure Design — Lack of rate limiting on login/sensitive actions; missing transaction guards.
5. A05: Security Misconfiguration — CORS wildcard with credentials, missing CSP/HSTS headers, exposed .env files.
6. A06: Vulnerable and Outdated Components — Outdated npm/pip packages with published CVEs.
7. A07: Identification and Authentication Failures — Weak session management, missing HttpOnly flags on cookies.
8. A08: Software and Data Integrity Failures — Unsafe deserialization via `pickle.loads` or `yaml.load`.
9. A09: Security Logging and Monitoring Failures — Logging raw passwords or API tokens in log files.
10. A10: Server-Side Request Forgery (SSRF) — Fetching arbitrary user-supplied URLs without allowlist validation.
"""
            return {
                "contents": [
                    {"uri": uri, "mimeType": "text/markdown", "text": doc}
                ]
            }
        return {"contents": []}

