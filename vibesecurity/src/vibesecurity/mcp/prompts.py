from __future__ import annotations

from typing import Any, Dict, List


class McpPromptsRegistry:
    """Manages MCP prompt templates for AI coding agents."""

    def list_prompts(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit_entire_repository",
                "description": "Comprehensive security audit: breaks down project architecture, runs all security engines, and prepares remediation roadmap.",
                "arguments": [
                    {"name": "project_path", "description": "Absolute path to repository", "required": True}
                ],
            },
            {
                "name": "auto_repair_vulnerabilities",
                "description": "Autonomously patch all eligible vulnerabilities, verify regression tests, and preserve existing application functionality.",
                "arguments": [
                    {"name": "project_path", "description": "Absolute path to repository", "required": True},
                    {"name": "policy", "description": "default | conservative | strict", "required": False}
                ],
            },
            {
                "name": "secure_new_feature",
                "description": "Inspect and harden a newly written feature or API endpoint against injection, auth bypasses, and secret exposure.",
                "arguments": [
                    {"name": "project_path", "description": "Absolute path to repository", "required": True},
                    {"name": "feature_files", "description": "Comma-separated list of modified files", "required": True}
                ],
            },
        ]

    def get_prompt(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        proj = arguments.get("project_path", ".")
        if name == "audit_entire_repository":
            return {
                "description": "Audit Entire Repository",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": f"Please run `breakdown_project` on `{proj}` to map its architecture, then run `scan_repository` to find all vulnerabilities and `get_security_baseline` to record the current test status. Summarize the findings by severity and recommend immediate fixes.",
                        },
                    }
                ],
            }
        elif name == "auto_repair_vulnerabilities":
            pol = arguments.get("policy", "default")
            return {
                "description": "Auto Repair Vulnerabilities",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": f"Please execute `auto_remediate_project` on `{proj}` using policy `{pol}`. Verify that all original test suites pass and that no new regressions are introduced. If any fix fails verification, confirm that it was automatically rolled back.",
                        },
                    }
                ],
            }
        return {"description": "Prompt", "messages": []}

