from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import List

from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.engines.base import BaseSecurityScanner


class InfrastructureScanner(BaseSecurityScanner):
    """Audits Dockerfile, docker-compose, and infrastructure configurations."""

    name: str = "infrastructure_scanner"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._scan_dockerfiles())
        findings.extend(self._scan_docker_compose())
        findings.extend(self._scan_env_files())
        return findings

    def _scan_dockerfiles(self) -> List[Finding]:
        findings: List[Finding] = []
        dockerfiles = list(self.root.glob("**/Dockerfile*"))
        for df in dockerfiles:
            rel = str(df.relative_to(self.root))
            try:
                content = df.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            has_user_directive = False

            for idx, line in enumerate(lines):
                # Check root user
                if re.match(r"""^\s*USER\s+root\b""", line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id=f"VS-INFRA-{uuid.uuid4().hex[:6]}",
                            title="Container Running as Root User",
                            severity=Severity.HIGH.value,
                            category="infrastructure",
                            cwe="CWE-250",
                            file_path=rel,
                            line_start=idx + 1,
                            line_end=idx + 1,
                            code_snippet=line.strip(),
                            rule_id="docker-running-as-root",
                            scanner="infrastructure_scanner",
                            confidence="high",
                            description="Containers should execute as a non-privileged user to limit the impact of container escapes.",
                            remediation_strategy="add-non-root-user",
                            risk_level=RiskLevel.LOW.value,
                        )
                    )
                elif re.match(r"""^\s*USER\s+""", line, re.IGNORECASE):
                    has_user_directive = True

                # Check curl | bash
                if re.search(r"""curl\s+.*?\|\s*(?:bash|sh)""", line):
                    findings.append(
                        Finding(
                            id=f"VS-INFRA-{uuid.uuid4().hex[:6]}",
                            title="Insecure Pipe to Shell (curl | sh)",
                            severity=Severity.HIGH.value,
                            category="infrastructure",
                            cwe="CWE-494",
                            file_path=rel,
                            line_start=idx + 1,
                            line_end=idx + 1,
                            code_snippet=line.strip(),
                            rule_id="docker-pipe-to-shell",
                            scanner="infrastructure_scanner",
                            confidence="high",
                            description="Piping remote scripts directly to bash/sh executes unverified code without checksum integrity checks.",
                            remediation_strategy="verify-checksum-before-execution",
                            risk_level=RiskLevel.MEDIUM.value,
                        )
                    )

            if not has_user_directive and len(lines) > 3:
                findings.append(
                    Finding(
                        id=f"VS-INFRA-{uuid.uuid4().hex[:6]}",
                        title="Missing Non-Root USER Directive in Dockerfile",
                        severity=Severity.MEDIUM.value,
                        category="infrastructure",
                        cwe="CWE-250",
                        file_path=rel,
                        line_start=len(lines),
                        line_end=len(lines),
                        code_snippet="[EOF]",
                        rule_id="docker-missing-user-directive",
                        scanner="infrastructure_scanner",
                        confidence="medium",
                        description="Dockerfile does not specify a USER directive, defaulting to root user inside container.",
                        remediation_strategy="add-non-root-user",
                        risk_level=RiskLevel.LOW.value,
                    )
                )

        return findings

    def _scan_docker_compose(self) -> List[Finding]:
        findings: List[Finding] = []
        candidates = list(self.root.glob("**/docker-compose*.yml")) + list(self.root.glob("**/docker-compose*.yaml")) + list(self.root.glob("**/compose.yaml"))
        for dc in candidates:
            rel = str(dc.relative_to(self.root))
            try:
                content = dc.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines):
                # Public DB port binding: "5432:5432" or "0.0.0.0:5432:5432"
                if re.search(r"""['"]?(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379):(5432|3306|27017|6379)['"]?""", line):
                    findings.append(
                        Finding(
                            id=f"VS-INFRA-{uuid.uuid4().hex[:6]}",
                            title="Database Port Exposed to Public Network",
                            severity=Severity.HIGH.value,
                            category="infrastructure",
                            cwe="CWE-668",
                            file_path=rel,
                            line_start=idx + 1,
                            line_end=idx + 1,
                            code_snippet=line.strip(),
                            rule_id="docker-compose-public-db-port",
                            scanner="infrastructure_scanner",
                            confidence="high",
                            description="Database port is bound to all network interfaces (0.0.0.0). Bind to 127.0.0.1 for local access.",
                            remediation_strategy="bind-to-localhost-only",
                            risk_level=RiskLevel.LOW.value,
                        )
                    )

                # Plaintext password environment variables
                if re.search(r"""(?i)(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*:\s*['"]?[a-zA-Z0-9_\-]{3,}['"]?""", line):
                    if "${" not in line:
                        findings.append(
                            Finding(
                                id=f"VS-INFRA-{uuid.uuid4().hex[:6]}",
                                title="Hardcoded Database Password in Docker Compose",
                                severity=Severity.HIGH.value,
                                category="infrastructure",
                                cwe="CWE-798",
                                file_path=rel,
                                line_start=idx + 1,
                                line_end=idx + 1,
                                code_snippet=line.strip(),
                                rule_id="docker-compose-hardcoded-password",
                                scanner="infrastructure_scanner",
                                confidence="high",
                                description="Database password is hardcoded directly in docker-compose. Use environment variable interpolation.",
                                remediation_strategy="extract-to-env-variable",
                                risk_level=RiskLevel.LOW.value,
                            )
                        )
        return findings

    def _scan_env_files(self) -> List[Finding]:
        findings: List[Finding] = []
        # Check if .env is committed or tracked by git
        gitignore_path = self.root / ".gitignore"
        env_files = list(self.root.glob("**/.env*"))
        has_gitignore = gitignore_path.exists()
        gitignore_text = gitignore_path.read_text(encoding="utf-8", errors="ignore") if has_gitignore else ""

        for ef in env_files:
            rel = str(ef.relative_to(self.root))
            if ef.name in {".env.example", ".env.sample", ".env.template"}:
                continue
            if not has_gitignore or ".env" not in gitignore_text:
                findings.append(
                    Finding(
                        id=f"VS-INFRA-{uuid.uuid4().hex[:6]}",
                        title=f"Sensitive Environment File {ef.name} Not in .gitignore",
                        severity=Severity.HIGH.value,
                        category="infrastructure",
                        cwe="CWE-552",
                        file_path=rel,
                        line_start=1,
                        line_end=1,
                        code_snippet=ef.name,
                        rule_id="env-file-not-ignored",
                        scanner="infrastructure_scanner",
                        confidence="high",
                        description=f"{ef.name} contains environment secrets and must be excluded in .gitignore to prevent committing to version control.",
                        remediation_strategy="add-to-gitignore",
                        risk_level=RiskLevel.LOW.value,
                    )
                )
        return findings

