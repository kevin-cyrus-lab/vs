from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from vibesecurity import __product__, __version__
from vibesecurity.core.service import VibeSecurityService
from vibesecurity.mcp.server import VibeSecurityMcpServer
from vibesecurity.reporting.markdown import MarkdownReporter
from vibesecurity.reporting.sarif import SarifReporter


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibesecurity",
        description=f"{__product__} v{__version__} — Autonomous Security Engineering Layer for AI & Vibe Coders.",
    )
    parser.add_argument("--version", action="version", version=f"{__product__} {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # breakdown
    p_breakdown = subparsers.add_parser("breakdown", help="Break down application or website architecture.")
    p_breakdown.add_argument("path", nargs="?", default=".", help="Project path (default: current directory)")
    p_breakdown.add_argument("--json", action="store_true", help="Output as raw JSON")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run comprehensive security scan.")
    p_scan.add_argument("path", nargs="?", default=".", help="Project path (default: current directory)")
    p_scan.add_argument("--type", choices=["all", "source", "secrets", "dependencies", "infrastructure", "api"], default="all")
    p_scan.add_argument("--json", action="store_true", help="Output as raw JSON")

    # fix / auto-remediate
    p_fix = subparsers.add_parser("fix", help="Autonomous remediation with behavioral verification & rollback.")
    p_fix.add_argument("path", nargs="?", default=".", help="Project path (default: current directory)")
    p_fix.add_argument("--policy", choices=["default", "conservative", "strict"], default="default")

    # baseline
    p_baseline = subparsers.add_parser("baseline", help="Record pre-remediation baseline.")
    p_baseline.add_argument("path", nargs="?", default=".", help="Project path")

    # report
    p_report = subparsers.add_parser("report", help="Generate security audit report.")
    p_report.add_argument("path", nargs="?", default=".", help="Project path")
    p_report.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    p_report.add_argument("--output", "-o", help="Output file destination")

    # audit-web
    p_web = subparsers.add_parser("audit-web", help="Dynamic web security inspection for live apps.")
    p_web.add_argument("url", help="Target URL (e.g. http://localhost:3000)")

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Start Universal MCP Server over STDIO.")

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Verify system environment, runtimes, and scanner integrations.")

    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    service = VibeSecurityService()

    if args.command == "breakdown":
        bd = service.breakdown_project(args.path)
        if args.json:
            print(json.dumps(bd.to_dict(), indent=2))
        else:
            print("\n" + "=" * 60)
            print(f"🛡️  VibeSecurity Architecture Breakdown: {bd.name}")
            print("=" * 60)
            print(f"  Primary Language:   {bd.primary_language}")
            print(f"  Frontend Framework: {bd.frontend_framework or 'None / Vanilla'}")
            print(f"  Backend Framework:  {bd.backend_framework or 'None'}")
            print(f"  Database / ORM:     {bd.database or 'None'}")
            print(f"  Authentication:     {bd.auth_system or 'None'}")
            print(f"  Package Manager:    {bd.package_manager or 'Unknown'}")
            print(f"  Test Framework:     {bd.test_framework or 'None detected'}")
            print(f"  Docker Container:   {'Yes' if bd.docker else 'No'}")
            print(f"  Docker Compose:     {'Yes' if bd.docker_compose else 'No'}")
            print(f"  Total Files:        {bd.total_files} ({bd.lines_of_code} LOC)")
            if bd.api_endpoints:
                print(f"  Discovered APIs:    {len(bd.api_endpoints)} routes (e.g. {', '.join(bd.api_endpoints[:4])})")
            if bd.sensitive_files:
                print(f"  ⚠️ Sensitive Files:  {', '.join(bd.sensitive_files)}")
            print("=" * 60 + "\n")
        return 0

    elif args.command == "scan":
        rep = service.scan_project(args.path, args.type)
        if args.json:
            print(json.dumps(rep.to_dict(), indent=2))
        else:
            print("\n" + "=" * 60)
            print(f"🛡️  VibeSecurity Scan Results: {Path(args.path).resolve().name}")
            print("=" * 60)
            print(f"  Security Score:  {rep.security_score}/100 (Grade: {rep.grade})")
            print(f"  Findings Found:  {len(rep.findings)}")
            print(f"    Critical:      {rep.findings_count.get('critical', 0)}")
            print(f"    High:          {rep.findings_count.get('high', 0)}")
            print(f"    Medium:        {rep.findings_count.get('medium', 0)}")
            print(f"    Low:           {rep.findings_count.get('low', 0)}")
            print("-" * 60)
            if rep.findings:
                for f in rep.findings:
                    print(f"  [{f.severity.upper()}] {f.title} -> {f.file_path}:{f.line_start} ({f.cwe})")
            else:
                print("  🎉 No vulnerabilities found! Codebase is secure.")
            print("=" * 60 + "\n")
        return 0

    elif args.command == "fix":
        print(f"\n🚀 Running Autonomous Remediation on {args.path} [Policy: {args.policy}]...")
        result = service.auto_remediate_project(args.path, args.policy)
        print("\n" + "=" * 60)
        print(f"🛡️  VibeSecurity Remediation Outcome")
        print("=" * 60)
        print(f"  Initial Score:        {result['initial_score']}/100 ({result['initial_grade']})")
        print(f"  Final Score:          {result['final_score']}/100 ({result['final_grade']})")
        print(f"  Repairs Verified:     {result['repairs_verified_and_applied']}")
        print(f"  Repairs Blocked:      {result['repairs_blocked_by_policy']}")
        print(f"  Repairs Rolled Back:  {result['repairs_rolled_back']}")
        print(f"  Remaining Issues:     {result['remaining_findings']}")
        print("-" * 60)
        for log in result["remediation_log"]:
            status_icon = "✅" if log["action"] == "remediated_and_verified" else "⚠️"
            print(f"  {status_icon} [{log['action']}] {log['title']}")
        print("=" * 60 + "\n")
        return 0

    elif args.command == "baseline":
        b = service.get_security_baseline(args.path)
        print(json.dumps(b.to_dict(), indent=2))
        return 0

    elif args.command == "report":
        rep = service.scan_project(args.path, "all")
        bd = service.breakdown_project(args.path)
        if args.format == "sarif":
            out_str = json.dumps(SarifReporter.generate(rep), indent=2)
        elif args.format == "json":
            out_str = json.dumps(rep.to_dict(), indent=2)
        else:
            out_str = MarkdownReporter.generate(rep, bd)

        if args.output:
            Path(args.output).write_text(out_str, encoding="utf-8")
            print(f"Report saved to {args.output}")
        else:
            print(out_str)
        return 0

    elif args.command == "audit-web":
        findings = service.scan_running_website(args.url)
        print(f"\n🌐 Live Website Audit: {args.url}")
        print(f"Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f.severity.upper()}] {f.title} ({f.rule_id})")
        return 0

    elif args.command == "mcp":
        server = VibeSecurityMcpServer(service)
        server.run()
        return 0

    elif args.command == "doctor":
        print(f"\n🩺 {__product__} Doctor Diagnostics")
        print("-" * 40)
        print(f"  Python Version:     {sys.version.split()[0]}")
        print(f"  SQLite3 Support:    OK")
        print(f"  Git Installed:      {'Yes' if shutil.which('git') else 'No'}")
        print(f"  Semgrep Available:  {'Yes' if shutil.which('semgrep') else 'Optional (not found)'}")
        print(f"  Trivy Available:    {'Yes' if shutil.which('trivy') else 'Optional (not found)'}")
        print(f"  Bandit Available:   {'Yes' if shutil.which('bandit') else 'Optional (not found)'}")
        print(f"  Database Path:      {service.db.db_path}")
        print("-" * 40 + "\n")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

