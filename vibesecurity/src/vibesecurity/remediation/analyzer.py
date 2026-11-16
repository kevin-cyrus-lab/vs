from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from vibesecurity.core.models import Finding


class VulnerabilityContextAnalyzer:
    """Extracts code context and call sites around a vulnerability finding."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def get_context(self, finding: Finding, window_lines: int = 5) -> Dict[str, Any]:
        target_file = self.root / finding.file_path
        if not target_file.is_file():
            return {
                "file_exists": False,
                "error": f"File {finding.file_path} not found.",
            }

        try:
            lines = target_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            return {"file_exists": False, "error": str(e)}

        total_lines = len(lines)
        start_idx = max(0, finding.line_start - 1 - window_lines)
        end_idx = min(total_lines, finding.line_end + window_lines)

        context_lines = []
        for i in range(start_idx, end_idx):
            line_no = i + 1
            is_vuln = (finding.line_start <= line_no <= finding.line_end)
            context_lines.append({
                "line_number": line_no,
                "code": lines[i],
                "is_vulnerable": is_vuln,
            })

        return {
            "file_exists": True,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "total_file_lines": total_lines,
            "context_lines": context_lines,
            "finding_title": finding.title,
            "cwe": finding.cwe,
            "remediation_strategy": finding.remediation_strategy,
            "risk_level": finding.risk_level,
        }

