from __future__ import annotations

import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vibesecurity.core.models import (
    Finding,
    ProjectBaseline,
    ProjectBreakdown,
    RiskLevel,
    ScanReport,
    ScanType,
    SecurityPatch,
    Severity,
    VerificationResult,
)
from vibesecurity.core.policies import SecurityPolicy
from vibesecurity.engines.api_scanner import ApiSecurityScanner
from vibesecurity.engines.dependency_scanner import DependencyScanner
from vibesecurity.engines.dynamic_scanner import DynamicWebScanner
from vibesecurity.engines.external_adapters import ExternalToolAdapter
from vibesecurity.engines.infrastructure_scanner import InfrastructureScanner
from vibesecurity.engines.secrets_scanner import SecretsScanner
from vibesecurity.engines.static_analyzer import StaticAnalysisScanner
from vibesecurity.preservation.test_runner import TestRunner
from vibesecurity.remediation.analyzer import VulnerabilityContextAnalyzer
from vibesecurity.remediation.patch_applier import PatchApplier
from vibesecurity.remediation.patch_generator import PatchGenerator
from vibesecurity.remediation.patch_validator import PatchValidator
from vibesecurity.remediation.rollback import PatchRollbackManager
from vibesecurity.repository.baseline import ProjectBaselineManager
from vibesecurity.repository.breakdown import ProjectBreakdownAnalyzer
from vibesecurity.storage.database import VibeSecurityDB
from vibesecurity.verification.verifier import RemediationVerifier


class VibeSecurityService:
    """
    Core Application Service orchestrating Intelligence, Scanning, Remediation,
    Preservation, and Verification.
    """

    def __init__(self, db: Optional[VibeSecurityDB] = None):
        self.db = db or VibeSecurityDB()
        self._staged_patches: Dict[str, SecurityPatch] = {}
        self._cached_findings: Dict[str, Finding] = {}

    def breakdown_project(self, project_path: str | Path) -> ProjectBreakdown:
        analyzer = ProjectBreakdownAnalyzer(project_path)
        breakdown = analyzer.analyze()
        self.db.record_project(breakdown)
        self.db.log_audit(str(project_path), "breakdown", {"files": breakdown.total_files})
        return breakdown

    def get_security_baseline(self, project_path: str | Path) -> ProjectBaseline:
        manager = ProjectBaselineManager(project_path)
        baseline = manager.capture_baseline()
        breakdown = self.breakdown_project(project_path)
        proj_id = self.db.record_project(breakdown)
        self.db.record_baseline(proj_id, baseline)
        return baseline

    def scan_project(
        self,
        project_path: str | Path,
        scan_type: str = ScanType.ALL.value,
    ) -> ScanReport:
        root = Path(project_path).resolve()
        start_time = time.time()
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

        scanners = []
        if scan_type in {ScanType.ALL.value, ScanType.SOURCE.value}:
            scanners.append(StaticAnalysisScanner(root))
        if scan_type in {ScanType.ALL.value, ScanType.SECRETS.value}:
            scanners.append(SecretsScanner(root))
        if scan_type in {ScanType.ALL.value, ScanType.DEPENDENCIES.value}:
            scanners.append(DependencyScanner(root))
        if scan_type in {ScanType.ALL.value, ScanType.INFRASTRUCTURE.value}:
            scanners.append(InfrastructureScanner(root))
        if scan_type in {ScanType.ALL.value, ScanType.API.value}:
            scanners.append(ApiSecurityScanner(root))

        scanners.append(ExternalToolAdapter(root))

        all_findings: List[Finding] = []
        for s in scanners:
            try:
                results = s.scan()
                all_findings.extend(results)
            except Exception as e:
                pass

        # De-duplicate by fingerprint
        unique_findings: List[Finding] = []
        seen = set()
        for f in all_findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)
                self._cached_findings[f.id] = f

        # Compute counts & score
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        deductions = 0
        for f in unique_findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
            if sev == "critical":
                deductions += 25
            elif sev == "high":
                deductions += 15
            elif sev == "medium":
                deductions += 8
            elif sev == "low":
                deductions += 2

        score = max(0, 100 - deductions)
        if score >= 90:
            grade = "A" if score < 97 else "A+"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        duration = int((time.time() - start_time) * 1000)
        report = ScanReport(
            scan_id=scan_id,
            project_path=str(root),
            timestamp=datetime.utcnow().isoformat(),
            duration_ms=duration,
            security_score=score,
            grade=grade,
            findings_count=counts,
            findings=unique_findings,
        )

        # Ensure project record exists in DB
        breakdown = self.breakdown_project(root)
        proj_id = self.db.record_project(breakdown)
        self.db.record_scan(proj_id, scan_id, score, grade, unique_findings)
        self.db.log_audit(str(root), "scan_completed", {"score": score, "findings": len(unique_findings)})
        return report

    def scan_running_website(self, url: str) -> List[Finding]:
        scanner = DynamicWebScanner(url)
        return scanner.scan()

    def get_vulnerability_context(self, project_path: str | Path, finding_id: str) -> Dict[str, Any]:
        finding = self._cached_findings.get(finding_id)
        if not finding:
            return {"error": f"Finding {finding_id} not found."}
        analyzer = VulnerabilityContextAnalyzer(project_path)
        return analyzer.get_context(finding)

    def generate_patch(self, project_path: str | Path, finding_id: str) -> Optional[SecurityPatch]:
        finding = self._cached_findings.get(finding_id)
        if not finding:
            return None
        generator = PatchGenerator(project_path)
        patch = generator.generate_patch(finding)
        if patch:
            self._staged_patches[patch.id] = patch
        return patch

    def validate_patch(self, project_path: str | Path, patch: SecurityPatch) -> Tuple[bool, str]:
        validator = PatchValidator(project_path)
        return validator.validate(patch)

    def apply_patch(self, project_path: str | Path, patch: SecurityPatch) -> Tuple[bool, str]:
        applier = PatchApplier(project_path)
        return applier.apply(patch)

    def rollback_patch(self, project_path: str | Path, patch_id: str) -> Tuple[bool, str]:
        patch = self._staged_patches.get(patch_id)
        if not patch:
            return False, f"Patch {patch_id} not found in staged history."
        rollback_mgr = PatchRollbackManager(project_path)
        return rollback_mgr.rollback(patch)

    def verify_patch(
        self,
        project_path: str | Path,
        patch_id: str,
        finding_id: str,
        baseline: Optional[ProjectBaseline] = None,
    ) -> VerificationResult:
        patch = self._staged_patches.get(patch_id)
        finding = self._cached_findings.get(finding_id)
        if not patch or not finding:
            return VerificationResult(
                patch_id=patch_id,
                syntax_passed=False,
                regression_tests_passed=False,
                security_rescan_passed=False,
                preservation_passed=False,
                promoted=False,
                status="failed",
                details={"error": "Patch or Finding not found."},
            )

        verifier = RemediationVerifier(project_path)
        vres = verifier.verify_and_settle(patch, finding, baseline)
        self.db.record_patch_and_verification(patch, vres)
        self.db.log_audit(str(project_path), "verification_result", {"promoted": vres.promoted, "status": vres.status})
        return vres

    def auto_remediate_project(
        self,
        project_path: str | Path,
        policy_name: str = "default",
    ) -> Dict[str, Any]:
        """
        End-to-end Autonomous Remediation Pipeline:
        1. Capture Baseline
        2. Scan Project
        3. Filter eligible vulnerabilities by risk policy
        4. For each eligible finding:
           - Generate minimal patch
           - Validate patch safety & syntax
           - Apply patch
           - Multi-gate verification (syntax + regression tests + rescan)
           - If verified -> Promote! If failed -> Rollback!
        5. Return structured report of repairs and remaining items.
        """
        root = Path(project_path).resolve()
        policy = SecurityPolicy.load(policy_name)
        baseline = self.get_security_baseline(root)
        scan_report = self.scan_project(root)

        applied_count = 0
        blocked_count = 0
        failed_count = 0
        remediation_details = []

        for finding in scan_report.findings:
            if not policy.can_auto_remediate(finding.risk_level):
                blocked_count += 1
                remediation_details.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "action": "blocked_by_policy",
                    "reason": f"Risk level '{finding.risk_level}' requires manual developer approval under '{policy_name}' policy.",
                })
                continue

            # Generate patch
            patch = self.generate_patch(root, finding.id)
            if not patch:
                remediation_details.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "action": "no_patch_available",
                    "reason": "Automated patch template not yet available for this finding.",
                })
                continue

            # Validate patch
            is_valid, val_msg = self.validate_patch(root, patch)
            if not is_valid:
                remediation_details.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "action": "validation_failed",
                    "reason": val_msg,
                })
                continue

            # Apply patch
            applied, apply_msg = self.apply_patch(root, patch)
            if not applied:
                remediation_details.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "action": "apply_failed",
                    "reason": apply_msg,
                })
                continue

            # Verify patch (Syntax + Regression Tests + Security Rescan)
            vres = self.verify_patch(root, patch.id, finding.id, baseline)
            if vres.promoted:
                applied_count += 1
                finding.status = "fixed"
                remediation_details.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "action": "remediated_and_verified",
                    "patch_id": patch.id,
                    "file_path": patch.file_path,
                    "details": vres.details,
                })
            else:
                failed_count += 1
                remediation_details.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "action": "rolled_back",
                    "patch_id": patch.id,
                    "reason": vres.details.get("error", "Verification failure."),
                })

        # Final Rescan to calculate new score
        rescan_report = self.scan_project(root)

        return {
            "project_path": str(root),
            "policy": policy_name,
            "initial_score": scan_report.security_score,
            "final_score": rescan_report.security_score,
            "initial_grade": scan_report.grade,
            "final_grade": rescan_report.grade,
            "repairs_verified_and_applied": applied_count,
            "repairs_blocked_by_policy": blocked_count,
            "repairs_rolled_back": failed_count,
            "remaining_findings": len(rescan_report.findings),
            "remediation_log": remediation_details,
        }
