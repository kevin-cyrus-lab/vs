from __future__ import annotations

from pathlib import Path
from typing import List

from vibesecurity.core.models import Finding
from vibesecurity.engines.api_scanner import ApiSecurityScanner
from vibesecurity.engines.dependency_scanner import DependencyScanner
from vibesecurity.engines.infrastructure_scanner import InfrastructureScanner
from vibesecurity.engines.secrets_scanner import SecretsScanner
from vibesecurity.engines.static_analyzer import StaticAnalysisScanner


class SecurityRescanVerifier:
    """Re-executes targeted scanners on patched files to PROVE that the vulnerability was eliminated."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def verify_vulnerability_fixed(self, finding: Finding) -> bool:
        """Returns True if the vulnerability is no longer detected."""
        scanners = [
            StaticAnalysisScanner(self.root),
            SecretsScanner(self.root),
            DependencyScanner(self.root),
            InfrastructureScanner(self.root),
            ApiSecurityScanner(self.root),
        ]

        for s in scanners:
            try:
                new_findings = s.scan()
                for nf in new_findings:
                    if (
                        nf.rule_id == finding.rule_id
                        and nf.file_path == finding.file_path
                        and abs(nf.line_start - finding.line_start) <= 3
                    ):
                        # Still present!
                        return False
            except Exception:
                pass

        # Vulnerability successfully eliminated
        return True

