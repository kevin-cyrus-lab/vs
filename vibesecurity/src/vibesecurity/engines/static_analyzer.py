from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path
from typing import List, Optional

from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.engines.base import BaseSecurityScanner
from vibesecurity.repository.discovery import discover_files


class StaticAnalysisScanner(BaseSecurityScanner):
    """
    Multi-language Static Application Security Testing (SAST) engine.
    Detects OWASP Top 10 vulnerabilities commonly introduced in AI-generated and vibe-coded applications.
    """

    name: str = "static_analysis"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        files = discover_files(self.root)

        for file_path in files:
            ext = file_path.suffix.lower()
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel_path = str(file_path.relative_to(self.root))

            if ext in {".py"}:
                findings.extend(self._scan_python(file_path, rel_path, content))
            elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
                findings.extend(self._scan_javascript(file_path, rel_path, content))

            # Multi-language common patterns
            findings.extend(self._scan_common_patterns(file_path, rel_path, content))

        return findings

    def _scan_python(self, file_path: Path, rel_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # 1. SQL Injection via string interpolation in execute/query or query assignment
        sqli_patterns = [
            (
                r"""(?:execute|cursor\.execute|session\.execute)\s*\(\s*f["'].*?\{.*?\}""",
                "SQL Injection (f-string in execute)",
                "CWE-89",
                Severity.HIGH.value,
                "parameterized-query",
                RiskLevel.MEDIUM.value,
                "Dynamic SQL query constructed with f-string interpolation allows attackers to manipulate SQL syntax.",
            ),
            (
                r"""(?:query|sql|stmt)\s*=\s*f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{.*?\}""",
                "SQL Injection (f-string query assignment)",
                "CWE-89",
                Severity.HIGH.value,
                "parameterized-query",
                RiskLevel.MEDIUM.value,
                "Dynamic SQL query assigned via f-string interpolation allows SQL injection.",
            ),
            (
                r"""(?:execute|cursor\.execute)\s*\(\s*["'].*?%s.*?["']\s*%\s*""",
                "SQL Injection (% formatting)",
                "CWE-89",
                Severity.HIGH.value,
                "parameterized-query",
                RiskLevel.MEDIUM.value,
                "Dynamic SQL query constructed with '%' operator string formatting allows SQL injection.",
            ),
        ]

        for pat, title, cwe, sev, strat, risk, desc in sqli_patterns:
            for idx, line in enumerate(lines):
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id=f"VS-SQLI-{uuid.uuid4().hex[:6]}",
                            title=title,
                            severity=sev,
                            category="injection",
                            cwe=cwe,
                            file_path=rel_path,
                            line_start=idx + 1,
                            line_end=idx + 1,
                            code_snippet=line.strip(),
                            rule_id="python-sql-injection-dynamic",
                            scanner="static_analyzer",
                            confidence="high",
                            description=desc,
                            remediation_strategy=strat,
                            risk_level=risk,
                        )
                    )

        # 2. Command Injection (os.system, subprocess with shell=True)
        for idx, line in enumerate(lines):
            if re.search(r"""os\.system\s*\(""", line) or re.search(r"""shell\s*=\s*True""", line):
                findings.append(
                    Finding(
                        id=f"VS-CMDI-{uuid.uuid4().hex[:6]}",
                        title="Command Injection Risk (shell=True / os.system)",
                        severity=Severity.HIGH.value,
                        category="injection",
                        cwe="CWE-78",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="python-command-injection",
                        scanner="static_analyzer",
                        confidence="high",
                        description="Direct shell execution allows arbitrary shell command execution if input contains shell metacharacters.",
                        remediation_strategy="subprocess-argument-list",
                        risk_level=RiskLevel.MEDIUM.value,
                    )
                )

        # 3. Insecure Deserialization (pickle.loads)
        for idx, line in enumerate(lines):
            if re.search(r"""pickle\.loads?\s*\(""", line):
                findings.append(
                    Finding(
                        id=f"VS-DESER-{uuid.uuid4().hex[:6]}",
                        title="Insecure Deserialization (pickle)",
                        severity=Severity.CRITICAL.value,
                        category="deserialization",
                        cwe="CWE-502",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="python-pickle-insecure",
                        scanner="static_analyzer",
                        confidence="high",
                        description="Pickle deserialization of untrusted data can lead to remote code execution.",
                        remediation_strategy="safe-json-serialization",
                        risk_level=RiskLevel.HIGH.value,
                    )
                )

        # 4. Weak Cryptography (MD5 / SHA1)
        for idx, line in enumerate(lines):
            if re.search(r"""hashlib\.(?:md5|sha1)\s*\(""", line):
                findings.append(
                    Finding(
                        id=f"VS-CRYPTO-{uuid.uuid4().hex[:6]}",
                        title="Weak Hash Algorithm (MD5/SHA1)",
                        severity=Severity.LOW.value,
                        category="cryptography",
                        cwe="CWE-328",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="python-weak-hash",
                        scanner="static_analyzer",
                        confidence="medium",
                        description="MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.",
                        remediation_strategy="upgrade-to-sha256",
                        risk_level=RiskLevel.LOW.value,
                    )
                )

        return findings

    def _scan_javascript(self, file_path: Path, rel_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            # 1. dangerouslySetInnerHTML in React / Next.js
            if "dangerouslySetInnerHTML" in line and not line.strip().startswith("//"):
                findings.append(
                    Finding(
                        id=f"VS-XSS-{uuid.uuid4().hex[:6]}",
                        title="Cross-Site Scripting (XSS) via dangerouslySetInnerHTML",
                        severity=Severity.HIGH.value,
                        category="xss",
                        cwe="CWE-79",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="react-dangerouslysetinnerhtml",
                        scanner="static_analyzer",
                        confidence="high",
                        description="Direct injection of unescaped HTML can lead to Stored or Reflected XSS.",
                        remediation_strategy="sanitize-html-dompurify",
                        risk_level=RiskLevel.MEDIUM.value,
                    )
                )

            # 2. Template literal SQL injection in Node/TS
            if re.search(r"""(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{.*?\}""", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"VS-SQLI-{uuid.uuid4().hex[:6]}",
                        title="SQL Injection via Template Literal",
                        severity=Severity.HIGH.value,
                        category="injection",
                        cwe="CWE-89",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="node-sql-injection-template-literal",
                        scanner="static_analyzer",
                        confidence="high",
                        description="Template literal string interpolation in database query allows SQL injection.",
                        remediation_strategy="parameterized-query",
                        risk_level=RiskLevel.MEDIUM.value,
                    )
                )

            # 3. Node child_process.exec
            if re.search(r"""(?:child_process\.)?exec\s*\(\s*`.*?\$\{.*?\}`,?""", line):
                findings.append(
                    Finding(
                        id=f"VS-CMDI-{uuid.uuid4().hex[:6]}",
                        title="Command Injection via child_process.exec",
                        severity=Severity.HIGH.value,
                        category="injection",
                        cwe="CWE-78",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="node-command-injection-exec",
                        scanner="static_analyzer",
                        confidence="high",
                        description="Dynamic string formatting into child_process.exec allows arbitrary shell command execution.",
                        remediation_strategy="use-execfile-or-spawn",
                        risk_level=RiskLevel.MEDIUM.value,
                    )
                )

            # 4. Insecure CORS
            if re.search(r"""["']Access-Control-Allow-Origin["']\s*:\s*["']\*["']""", line):
                findings.append(
                    Finding(
                        id=f"VS-CORS-{uuid.uuid4().hex[:6]}",
                        title="Overly Permissive CORS Policy",
                        severity=Severity.MEDIUM.value,
                        category="misconfiguration",
                        cwe="CWE-942",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="cors-wildcard-origin",
                        scanner="static_analyzer",
                        confidence="high",
                        description="Access-Control-Allow-Origin is set to '*' allowing any malicious website to read API responses.",
                        remediation_strategy="restrict-cors-allowlist",
                        risk_level=RiskLevel.LOW.value,
                    )
                )

            # 5. Insecure eval
            if re.search(r"""\beval\s*\(.*?\b""", line) and not line.strip().startswith("//"):
                findings.append(
                    Finding(
                        id=f"VS-EVAL-{uuid.uuid4().hex[:6]}",
                        title="Dangerous Use of eval()",
                        severity=Severity.CRITICAL.value,
                        category="code_execution",
                        cwe="CWE-95",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="javascript-eval-dangerous",
                        scanner="static_analyzer",
                        confidence="high",
                        description="eval() executes arbitrary strings as code, leading to client-side or server-side code execution.",
                        remediation_strategy="remove-eval",
                        risk_level=RiskLevel.HIGH.value,
                    )
                )

        return findings

    def _scan_common_patterns(self, file_path: Path, rel_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            # Path Traversal: opening user path without check
            if re.search(r"""(?:fs\.readFile|open|readFile)\s*\(\s*req\.(?:query|params|body)\.[a-zA-Z0-9_]+""", line):
                findings.append(
                    Finding(
                        id=f"VS-TRAV-{uuid.uuid4().hex[:6]}",
                        title="Path Traversal Risk",
                        severity=Severity.HIGH.value,
                        category="traversal",
                        cwe="CWE-22",
                        file_path=rel_path,
                        line_start=idx + 1,
                        line_end=idx + 1,
                        code_snippet=line.strip(),
                        rule_id="unvalidated-file-path-open",
                        scanner="static_analyzer",
                        confidence="medium",
                        description="Directly opening a file from request parameters allows attackers to read arbitrary files via '../'.",
                        remediation_strategy="sanitize-filepath-resolve",
                        risk_level=RiskLevel.MEDIUM.value,
                    )
                )
        return findings

