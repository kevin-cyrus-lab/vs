from __future__ import annotations

from typing import Any, Dict, List

from vibesecurity.core.models import Finding, ProjectBreakdown, ScanReport


class MarkdownReporter:
    """Generates rich, actionable Markdown security audit reports."""

    @staticmethod
    def generate(report: ScanReport, breakdown: ProjectBreakdown, repairs_applied: int = 0) -> str:
        lines: List[str] = []
        lines.append(f"# 🛡️ VibeSecurity Audit & Remediation Report")
        lines.append(f"**Project:** `{breakdown.name}` ({breakdown.project_path})")
        lines.append(f"**Timestamp:** `{report.timestamp}`")
        lines.append(f"**Security Score:** **{report.security_score}/100 (Grade: {report.grade})**")
        lines.append("")

        # Executive Summary
        lines.append("## 📊 Executive Summary")
        lines.append(f"- **Primary Tech:** {breakdown.primary_language} | {breakdown.frontend_framework or 'N/A'} | {breakdown.backend_framework or 'N/A'}")
        lines.append(f"- **Database / Auth:** {breakdown.database or 'None'} | {breakdown.auth_system or 'None'}")
        lines.append(f"- **Total Files Audited:** {breakdown.total_files} ({breakdown.lines_of_code} LOC)")
        lines.append(f"- **Total Vulnerabilities Detected:** {len(report.findings)}")
        lines.append(f"  - 🔴 Critical: {report.findings_count.get('critical', 0)}")
        lines.append(f"  - 🟠 High: {report.findings_count.get('high', 0)}")
        lines.append(f"  - 🟡 Medium: {report.findings_count.get('medium', 0)}")
        lines.append(f"  - 🔵 Low: {report.findings_count.get('low', 0)}")
        lines.append(f"- **Automated Verified Repairs Applied:** `{repairs_applied}`")
        lines.append("")

        # Findings Detail Table
        lines.append("## 🔍 Security Findings")
        if not report.findings:
            lines.append("🎉 **No vulnerabilities detected! Application conforms to baseline security policies.**")
        else:
            lines.append("| ID | Severity | Category | Title | File & Line | Status |")
            lines.append("| :--- | :---: | :--- | :--- | :--- | :---: |")
            for f in report.findings:
                sev_icon = {
                    "critical": "🔴 CRITICAL",
                    "high": "🟠 HIGH",
                    "medium": "🟡 MEDIUM",
                    "low": "🔵 LOW",
                    "info": "⚪ INFO",
                }.get(f.severity.lower(), f.severity.upper())
                loc = f"`{f.file_path}:{f.line_start}`"
                lines.append(f"| `{f.id}` | {sev_icon} | {f.category} | {f.title} | {loc} | `{f.status}` |")

            lines.append("")
            lines.append("### Remediation Actions")
            for idx, f in enumerate(report.findings, 1):
                lines.append(f"#### {idx}. [{f.severity.upper()}] {f.title} (`{f.id}`)")
                lines.append(f"- **Location:** `{f.file_path}:{f.line_start}` ({f.cwe})")
                lines.append(f"- **Scanner:** `{f.scanner}` (`{f.rule_id}`)")
                lines.append(f"- **Description:** {f.description}")
                lines.append(f"- **Recommended Fix:** `{f.remediation_strategy or 'Manual code review'}`")
                lines.append(f"- **Code Snippet:**")
                lines.append("```")
                lines.append(f.code_snippet)
                lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append("*Generated autonomously by [VibeSecurity](https://github.com/vibesecurity/vibesecurity). Fix the vulnerability. Preserve the application. Prove that the fix works.*")
        return "\n".join(lines)

