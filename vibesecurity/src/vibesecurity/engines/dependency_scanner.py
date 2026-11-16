from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List

from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.engines.base import BaseSecurityScanner

# Catalog of high-profile known vulnerabilities in popular packages frequently installed in vibe-coded apps
KNOWN_ADVISORIES: List[Dict[str, Any]] = [
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "affected_versions": ["<9.0.0"],
        "title": "jsonwebtoken Insecure Key Verification Bypass",
        "cwe": "CWE-347",
        "cve": "CVE-2022-23529",
        "severity": Severity.HIGH.value,
        "fixed_version": "9.0.2",
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "affected_versions": ["<1.7.4"],
        "title": "Axios Server-Side Request Forgery (SSRF) & Prototype Pollution",
        "cwe": "CWE-918",
        "cve": "CVE-2024-39338",
        "severity": Severity.HIGH.value,
        "fixed_version": "1.7.9",
    },
    {
        "ecosystem": "npm",
        "package": "lodash",
        "affected_versions": ["<4.17.21"],
        "title": "Lodash Prototype Pollution via template/zipObjectDeep",
        "cwe": "CWE-1321",
        "cve": "CVE-2021-23337",
        "severity": Severity.HIGH.value,
        "fixed_version": "4.17.21",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "affected_versions": ["<4.19.2"],
        "title": "Express Open Redirect & Denial of Service via Malformed URLs",
        "cwe": "CWE-601",
        "cve": "CVE-2024-29041",
        "severity": Severity.MEDIUM.value,
        "fixed_version": "4.21.2",
    },
    {
        "ecosystem": "npm",
        "package": "tar",
        "affected_versions": ["<6.2.1"],
        "title": "Node tar Arbitrary File Overwrite via Path Traversal",
        "cwe": "CWE-22",
        "cve": "CVE-2024-28863",
        "severity": Severity.HIGH.value,
        "fixed_version": "6.2.1",
    },
    {
        "ecosystem": "pypi",
        "package": "urllib3",
        "affected_versions": ["<2.0.7", "<1.26.18"],
        "title": "Urllib3 Cookie & Authorization Header Leakage via Redirects",
        "cwe": "CWE-200",
        "cve": "CVE-2023-45803",
        "severity": Severity.HIGH.value,
        "fixed_version": "2.2.2",
    },
    {
        "ecosystem": "pypi",
        "package": "django",
        "affected_versions": ["<4.2.16", "<5.0.9"],
        "title": "Django Denial of Service / SQL Injection Vulnerabilities",
        "cwe": "CWE-89",
        "cve": "CVE-2024-45230",
        "severity": Severity.CRITICAL.value,
        "fixed_version": "5.0.9",
    },
    {
        "ecosystem": "pypi",
        "package": "requests",
        "affected_versions": ["<2.31.0"],
        "title": "Requests Proxy-Authorization Header Leak to HTTPS Proxy",
        "cwe": "CWE-200",
        "cve": "CVE-2023-32681",
        "severity": Severity.MEDIUM.value,
        "fixed_version": "2.32.3",
    },
    {
        "ecosystem": "pypi",
        "package": "cryptography",
        "affected_versions": ["<42.0.4"],
        "title": "Cryptography Null-Pointer Dereference / Memory Corruption",
        "cwe": "CWE-476",
        "cve": "CVE-2024-26130",
        "severity": Severity.HIGH.value,
        "fixed_version": "43.0.1",
    },
]


def clean_version_str(ver: str) -> str:
    return re.sub(r"""^[~^>=< ]+""", "", ver.strip())


def is_version_vulnerable(installed: str, affected_rule: str) -> bool:
    clean_inst = clean_version_str(installed)
    clean_target = clean_version_str(affected_rule)
    try:
        parts_inst = [int(p) for p in re.findall(r"\d+", clean_inst)[:3]]
        parts_target = [int(p) for p in re.findall(r"\d+", clean_target)[:3]]
        while len(parts_inst) < 3:
            parts_inst.append(0)
        while len(parts_target) < 3:
            parts_target.append(0)
        if "<" in affected_rule:
            return parts_inst < parts_target
        return False
    except Exception:
        return False


class DependencyScanner(BaseSecurityScanner):
    """Audits direct and transitive dependencies against CVE databases and known vulnerability catalogs."""

    name: str = "dependency_scanner"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._scan_npm())
        findings.extend(self._scan_python())
        return findings

    def _scan_npm(self) -> List[Finding]:
        findings: List[Finding] = []
        pkg_path = self.root / "package.json"
        if not pkg_path.is_file():
            return findings

        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return findings

        dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

        for adv in KNOWN_ADVISORIES:
            if adv["ecosystem"] != "npm":
                continue
            pkg_name = adv["package"]
            if pkg_name in dependencies:
                installed_ver = dependencies[pkg_name]
                for aff in adv["affected_versions"]:
                    if is_version_vulnerable(installed_ver, aff):
                        findings.append(
                            Finding(
                                id=f"VS-DEP-{uuid.uuid4().hex[:6]}",
                                title=f"{adv['title']} ({pkg_name}@{installed_ver})",
                                severity=adv["severity"],
                                category="dependencies",
                                cwe=adv["cwe"],
                                file_path="package.json",
                                line_start=1,
                                line_end=1,
                                code_snippet=f'"{pkg_name}": "{installed_ver}"',
                                rule_id=f"dep-vuln-{adv['cve']}",
                                scanner="dependency_scanner",
                                confidence="high",
                                description=f"Vulnerable dependency {pkg_name} ({installed_ver}) matches advisory {adv['cve']}. Recommended upgrade to {adv['fixed_version']}.",
                                remediation_strategy=f"upgrade-dependency:{pkg_name}:{adv['fixed_version']}",
                                risk_level=RiskLevel.MEDIUM.value,
                            )
                        )
                        break

        return findings

    def _scan_python(self) -> List[Finding]:
        findings: List[Finding] = []
        req_path = self.root / "requirements.txt"
        if not req_path.is_file():
            return findings

        try:
            lines = req_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            parts = re.split(r"""[==<>~]+""", line_str)
            if not parts:
                continue
            pkg_name = parts[0].strip().lower()
            installed_ver = parts[1].strip() if len(parts) > 1 else ""

            for adv in KNOWN_ADVISORIES:
                if adv["ecosystem"] != "pypi":
                    continue
                if adv["package"].lower() == pkg_name and installed_ver:
                    for aff in adv["affected_versions"]:
                        if is_version_vulnerable(installed_ver, aff):
                            findings.append(
                                Finding(
                                    id=f"VS-DEP-{uuid.uuid4().hex[:6]}",
                                    title=f"{adv['title']} ({pkg_name}=={installed_ver})",
                                    severity=adv["severity"],
                                    category="dependencies",
                                    cwe=adv["cwe"],
                                    file_path="requirements.txt",
                                    line_start=idx + 1,
                                    line_end=idx + 1,
                                    code_snippet=line_str,
                                    rule_id=f"dep-vuln-{adv['cve']}",
                                    scanner="dependency_scanner",
                                    confidence="high",
                                    description=f"Vulnerable package {pkg_name} ({installed_ver}) matches advisory {adv['cve']}. Upgrade to {adv['fixed_version']}.",
                                    remediation_strategy=f"upgrade-dependency:{pkg_name}:{adv['fixed_version']}",
                                    risk_level=RiskLevel.MEDIUM.value,
                                )
                            )
                            break
        return findings

