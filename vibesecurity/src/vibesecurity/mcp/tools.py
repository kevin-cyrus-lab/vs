from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from vibesecurity.core.service import VibeSecurityService
from vibesecurity.reporting.markdown import MarkdownReporter
from vibesecurity.reporting.sarif import SarifReporter


class McpToolsRegistry:
    """Declares and executes MCP tools for VibeSecurity."""

    def __init__(self, service: VibeSecurityService):
        self.service = service

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "breakdown_project",
                "description": "Deeply inspect and break down an application or website architecture (languages, frontend/backend frameworks, database, auth, package manager, test suites, API endpoints, sensitive files).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "get_security_baseline",
                "description": "Capture pre-remediation project baseline (git commit, uncommitted dirty files, existing test pass/fail status, build syntax).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_repository",
                "description": "Execute complete autonomous security scan across all domains (SAST, secrets, dependencies, infrastructure, APIs). Computes project security score (0-100) and grade.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_source_code",
                "description": "Run static application security testing (SAST) on source files to identify OWASP Top 10 vulnerabilities (SQLi, XSS, Command Injection, Path Traversal, SSRF, Deserialization, Broken Auth).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_secrets",
                "description": "Scan codebase for exposed credentials, API keys (AWS, OpenAI, Anthropic, GitHub, Stripe), private keys, and high-entropy secrets with automatic redaction.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_dependencies",
                "description": "Audit package manifests (package.json, requirements.txt) against known CVEs and vulnerability advisories.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_infrastructure",
                "description": "Audit Dockerfile, docker-compose, and configuration files for misconfigurations (running as root, public DB ports, unignored .env files).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_api_security",
                "description": "Audit website and backend API endpoints for missing authentication, missing rate limiting, CORS misconfigurations, and sensitive data leakage.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "scan_running_application",
                "description": "Perform dynamic security audit (DAST) on a running web application or website (HTTP security headers, CSP, cookie security flags, exposed endpoints).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "URL of running app or website (e.g. http://localhost:3000)"}
                    },
                    "required": ["target_url"],
                },
            },
            {
                "name": "analyze_vulnerability_context",
                "description": "Extract source code context, call sites, and lines surrounding a vulnerability finding.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "finding_id": {"type": "string", "description": "Finding ID from scan results"}
                    },
                    "required": ["project_path", "finding_id"],
                },
            },
            {
                "name": "generate_security_patch",
                "description": "Synthesize a minimal, surgical unified diff patch to fix a security finding without touching unnecessary code.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "finding_id": {"type": "string", "description": "Finding ID to repair"}
                    },
                    "required": ["project_path", "finding_id"],
                },
            },
            {
                "name": "validate_security_patch",
                "description": "Validate safety, boundaries, and syntax of a generated security patch before application.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "patch_id": {"type": "string", "description": "Staged patch ID"}
                    },
                    "required": ["project_path", "patch_id"],
                },
            },
            {
                "name": "apply_security_patch",
                "description": "Apply a validated security patch while automatically creating a rollback backup checkpoint.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "patch_id": {"type": "string", "description": "Patch ID to apply"}
                    },
                    "required": ["project_path", "patch_id"],
                },
            },
            {
                "name": "verify_security_fix",
                "description": "Execute multi-gate verification (syntax check + regression tests + security rescan) to prove vulnerability was resolved without breaking existing features.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "patch_id": {"type": "string", "description": "Patch ID"},
                        "finding_id": {"type": "string", "description": "Finding ID"}
                    },
                    "required": ["project_path", "patch_id", "finding_id"],
                },
            },
            {
                "name": "rollback_security_patch",
                "description": "Instantly revert an applied patch and restore the original code from the checkpoint backup.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "patch_id": {"type": "string", "description": "Patch ID to rollback"}
                    },
                    "required": ["project_path", "patch_id"],
                },
            },
            {
                "name": "auto_remediate_project",
                "description": "The ultimate autonomous security tool for vibe coders: scans the project, creates a baseline, generates minimal repairs for all eligible vulnerabilities, tests regressions, proves fixes, and rolls back if anything breaks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "policy": {"type": "string", "enum": ["default", "conservative", "strict"], "default": "default"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "generate_security_report",
                "description": "Generate an audit report in Markdown, JSON, or OASIS SARIF format.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "format": {"type": "string", "enum": ["markdown", "json", "sarif"], "default": "markdown"}
                    },
                    "required": ["project_path"],
                },
            },
            {
                "name": "get_scan_history",
                "description": "Retrieve previous scan results and security score progression for a project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_path": {"type": "string", "description": "Absolute path to repository root"},
                        "limit": {"type": "integer", "default": 10}
                    },
                    "required": ["project_path"],
                },
            },
        ]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        proj_path = arguments.get("project_path", "")
        try:
            if name == "breakdown_project":
                breakdown = self.service.breakdown_project(proj_path)
                return {"content": [{"type": "text", "text": json.dumps(breakdown.to_dict(), indent=2)}]}

            elif name == "get_security_baseline":
                baseline = self.service.get_security_baseline(proj_path)
                return {"content": [{"type": "text", "text": json.dumps(baseline.to_dict(), indent=2)}]}

            elif name == "scan_repository":
                report = self.service.scan_project(proj_path, "all")
                return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}

            elif name == "scan_source_code":
                report = self.service.scan_project(proj_path, "source")
                return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}

            elif name == "scan_secrets":
                report = self.service.scan_project(proj_path, "secrets")
                return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}

            elif name == "scan_dependencies":
                report = self.service.scan_project(proj_path, "dependencies")
                return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}

            elif name == "scan_infrastructure":
                report = self.service.scan_project(proj_path, "infrastructure")
                return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}

            elif name == "scan_api_security":
                report = self.service.scan_project(proj_path, "api")
                return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}

            elif name == "scan_running_application":
                url = arguments.get("target_url", "")
                findings = self.service.scan_running_website(url)
                return {"content": [{"type": "text", "text": json.dumps([f.to_dict() for f in findings], indent=2)}]}

            elif name == "analyze_vulnerability_context":
                finding_id = arguments.get("finding_id", "")
                context = self.service.get_vulnerability_context(proj_path, finding_id)
                return {"content": [{"type": "text", "text": json.dumps(context, indent=2)}]}

            elif name == "generate_security_patch":
                finding_id = arguments.get("finding_id", "")
                patch = self.service.generate_patch(proj_path, finding_id)
                if patch:
                    return {"content": [{"type": "text", "text": json.dumps(patch.to_dict(), indent=2)}]}
                return {"content": [{"type": "text", "text": "No patch available for this finding."}]}

            elif name == "validate_security_patch":
                patch_id = arguments.get("patch_id", "")
                patch = self.service._staged_patches.get(patch_id)
                if not patch:
                    return {"content": [{"type": "text", "text": "Patch not found in memory."}]}
                ok, msg = self.service.validate_patch(proj_path, patch)
                return {"content": [{"type": "text", "text": json.dumps({"valid": ok, "message": msg}, indent=2)}]}

            elif name == "apply_security_patch":
                patch_id = arguments.get("patch_id", "")
                patch = self.service._staged_patches.get(patch_id)
                if not patch:
                    return {"content": [{"type": "text", "text": "Patch not found."}]}
                ok, msg = self.service.apply_patch(proj_path, patch)
                return {"content": [{"type": "text", "text": json.dumps({"applied": ok, "message": msg}, indent=2)}]}

            elif name == "verify_security_fix":
                patch_id = arguments.get("patch_id", "")
                finding_id = arguments.get("finding_id", "")
                baseline = self.service.get_security_baseline(proj_path)
                vres = self.service.verify_patch(proj_path, patch_id, finding_id, baseline)
                return {"content": [{"type": "text", "text": json.dumps(vres.to_dict(), indent=2)}]}

            elif name == "rollback_security_patch":
                patch_id = arguments.get("patch_id", "")
                ok, msg = self.service.rollback_patch(proj_path, patch_id)
                return {"content": [{"type": "text", "text": json.dumps({"rolled_back": ok, "message": msg}, indent=2)}]}

            elif name == "auto_remediate_project":
                policy = arguments.get("policy", "default")
                result = self.service.auto_remediate_project(proj_path, policy)
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

            elif name == "generate_security_report":
                fmt = arguments.get("format", "markdown")
                report = self.service.scan_project(proj_path, "all")
                breakdown = self.service.breakdown_project(proj_path)
                if fmt == "sarif":
                    sarif_data = SarifReporter.generate(report)
                    return {"content": [{"type": "text", "text": json.dumps(sarif_data, indent=2)}]}
                elif fmt == "json":
                    return {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]}
                else:
                    md_text = MarkdownReporter.generate(report, breakdown)
                    return {"content": [{"type": "text", "text": md_text}]}

            elif name == "get_scan_history":
                limit = arguments.get("limit", 10)
                history = self.service.db.get_scan_history(proj_path, limit)
                return {"content": [{"type": "text", "text": json.dumps(history, indent=2)}]}

            else:
                return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}

        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error executing tool {name}: {str(e)}"}], "isError": True}

