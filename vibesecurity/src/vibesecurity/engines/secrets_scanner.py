from __future__ import annotations

import math
import re
import uuid
from pathlib import Path
from typing import List, Tuple

from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.engines.base import BaseSecurityScanner
from vibesecurity.repository.discovery import discover_files

SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        r"""(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[:=]\s*['"]([A-Z0-9]{20,40})['"]""",
        "Exposed AWS Access Key / Secret",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
    (
        r"""\b(AKIA[0-9A-Z]{16})\b""",
        "Exposed AWS Access Key ID",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
    (
        r"""\b(sk-[a-zA-Z0-9]{40,60})\b""",
        "Exposed OpenAI API Key",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
    (
        r"""\b(sk-ant-[a-zA-Z0-9_-]{40,100})\b""",
        "Exposed Anthropic API Key",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
    (
        r"""\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{80,100})\b""",
        "Exposed GitHub Personal Access Token",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
    (
        r"""\b(AIza[0-9A-Za-z\\-_]{35})\b""",
        "Exposed Google API Key",
        "CWE-798",
        Severity.HIGH.value,
    ),
    (
        r"""\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b""",
        "Exposed Slack Token",
        "CWE-798",
        Severity.HIGH.value,
    ),
    (
        r"""\b(sk_live_[0-9a-zA-Z]{24,34})\b""",
        "Exposed Stripe Live API Key",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
    (
        r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----""",
        "Exposed Private Encryption Key",
        "CWE-312",
        Severity.CRITICAL.value,
    ),
    (
        r"""(?i)(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_-]+:[^@\s]{4,}@[a-zA-Z0-9.-]+""",
        "Exposed Database Connection String with Credentials",
        "CWE-798",
        Severity.CRITICAL.value,
    ),
]


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy to detect high-entropy secret strings."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += -p_x * math.log(p_x, 2)
    return entropy


def redact_secret(val: str) -> str:
    if len(val) <= 6:
        return "***REDACTED***"
    return f"{val[:3]}...{val[-3:]} [REDACTED]"


class SecretsScanner(BaseSecurityScanner):
    """Detects exposed API keys, private keys, database URLs, and credentials."""

    name: str = "secrets_scanner"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        files = discover_files(self.root)

        for file_path in files:
            # Skip binary and test lock files
            if file_path.suffix.lower() in {".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".pdf"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel_path = str(file_path.relative_to(self.root))
            lines = content.splitlines()

            for idx, line in enumerate(lines):
                # Pattern based detection
                for pat, title, cwe, sev in SECRET_PATTERNS:
                    match = re.search(pat, line)
                    if match:
                        matched_str = match.group(0)
                        redacted_snippet = line.replace(matched_str, redact_secret(matched_str)).strip()
                        findings.append(
                            Finding(
                                id=f"VS-SEC-{uuid.uuid4().hex[:6]}",
                                title=title,
                                severity=sev,
                                category="secrets",
                                cwe=cwe,
                                file_path=rel_path,
                                line_start=idx + 1,
                                line_end=idx + 1,
                                code_snippet=redacted_snippet,
                                rule_id="hardcoded-secret-detected",
                                scanner="secrets_scanner",
                                confidence="high",
                                description=f"Hardcoded sensitive secret found in source code: {title}. Move secrets to environment variables.",
                                remediation_strategy="extract-to-env-variable",
                                risk_level=RiskLevel.LOW.value,
                            )
                        )
                        break

                # Generic secret assignment check (e.g. api_key = "...", secret = "...")
                generic_match = re.search(r"""(?i)\b(api_key|secret|password|auth_token|client_secret)\s*[:=]\s*['"]([^'"]{16,})['"]""", line)
                if generic_match and not any(f.file_path == rel_path and f.line_start == idx + 1 for f in findings):
                    secret_val = generic_match.group(2)
                    entropy = calculate_entropy(secret_val)
                    if entropy > 3.2:
                        redacted = line.replace(secret_val, redact_secret(secret_val)).strip()
                        findings.append(
                            Finding(
                                id=f"VS-SEC-{uuid.uuid4().hex[:6]}",
                                title="Generic High-Entropy Hardcoded Secret",
                                severity=Severity.HIGH.value,
                                category="secrets",
                                cwe="CWE-798",
                                file_path=rel_path,
                                line_start=idx + 1,
                                line_end=idx + 1,
                                code_snippet=redacted,
                                rule_id="high-entropy-secret-detected",
                                scanner="secrets_scanner",
                                confidence="medium",
                                description=f"Potential high-entropy secret detected (entropy: {entropy:.2f}).",
                                remediation_strategy="extract-to-env-variable",
                                risk_level=RiskLevel.LOW.value,
                            )
                        )

        return findings

