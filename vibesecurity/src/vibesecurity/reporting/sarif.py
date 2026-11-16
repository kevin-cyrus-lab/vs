from __future__ import annotations

import json
from typing import Any, Dict, List

from vibesecurity.core.models import ScanReport


class SarifReporter:
    """Exports findings in OASIS SARIF v2.1.0 format."""

    @staticmethod
    def generate(report: ScanReport) -> Dict[str, Any]:
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in report.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.title},
                    "defaultConfiguration": {
                        "level": "error" if f.severity in {"critical", "high"} else "warning"
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-', '')}.html" if "CWE-" in f.cwe else "https://vibesecurity.dev",
                }

            result = {
                "ruleId": f.rule_id,
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": max(1, f.line_start),
                                "endLine": max(1, f.line_end),
                                "snippet": {"text": f.code_snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "cwe": f.cwe,
                    "severity": f.severity,
                    "risk_level": f.risk_level,
                    "status": f.status,
                },
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VibeSecurity",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/vibesecurity/vibesecurity",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

