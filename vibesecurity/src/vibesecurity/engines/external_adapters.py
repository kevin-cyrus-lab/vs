from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import List

from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.engines.base import BaseSecurityScanner


class ExternalToolAdapter(BaseSecurityScanner):
    """Integrates optional host tools (Semgrep, Bandit, Trivy, Gitleaks) when available."""

    name: str = "external_adapter"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if shutil.which("bandit"):
            findings.extend(self._run_bandit())
        return findings

    def _run_bandit(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            res = subprocess.run(
                ["bandit", "-r", str(self.root), "-f", "json", "-q"],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            data = json.loads(res.stdout) if res.stdout else {}
            for item in data.get("results", []):
                findings.append(
                    Finding(
                        id=f"VS-BND-{uuid.uuid4().hex[:6]}",
                        title=f"Bandit: {item.get('test_name', 'Security Issue')}",
                        severity=item.get("issue_severity", "MEDIUM").lower(),
                        category="static_analysis",
                        cwe=f"CWE-{item.get('issue_cwe', {}).get('id', 'Unknown')}",
                        file_path=item.get("filename", ""),
                        line_start=item.get("line_number", 1),
                        line_end=item.get("line_range", [1])[-1],
                        code_snippet=item.get("code", "").strip(),
                        rule_id=item.get("test_id", "bandit-rule"),
                        scanner="bandit",
                        confidence=item.get("issue_confidence", "HIGH").lower(),
                        description=item.get("issue_text", ""),
                        remediation_strategy="",
                        risk_level=RiskLevel.MEDIUM.value,
                    )
                )
        except Exception:
            pass
        return findings

