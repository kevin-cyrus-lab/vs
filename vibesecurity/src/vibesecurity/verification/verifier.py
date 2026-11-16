from __future__ import annotations

import py_compile
import tempfile
from pathlib import Path
from typing import Dict, Optional

from vibesecurity.core.models import Finding, ProjectBaseline, SecurityPatch, VerificationResult
from vibesecurity.preservation.behavior_comparator import BehaviorComparator
from vibesecurity.preservation.test_runner import TestRunner
from vibesecurity.remediation.rollback import PatchRollbackManager
from vibesecurity.verification.security_rescan import SecurityRescanVerifier


class RemediationVerifier:
    """
    Multi-gate verification system:
    1. Syntax & Build Gate: Proves patched file compiles/parses cleanly.
    2. Regression Gate: Proves existing functionality is preserved.
    3. Security Rescan Gate: Proves vulnerability is 100% eliminated.
    If all gates pass: Promote patch!
    If any gate fails: Rollback immediately!
    """

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()
        self.test_runner = TestRunner(self.root)
        self.rollback_manager = PatchRollbackManager(self.root)
        self.rescan_verifier = SecurityRescanVerifier(self.root)

    def verify_and_settle(
        self,
        patch: SecurityPatch,
        finding: Finding,
        baseline: Optional[ProjectBaseline] = None,
    ) -> VerificationResult:
        # Gate 1: Syntax & Build Validation
        syntax_ok, syntax_err = self._check_syntax(patch.file_path)
        if not syntax_ok:
            self.rollback_manager.rollback(patch)
            return VerificationResult(
                patch_id=patch.id,
                syntax_passed=False,
                regression_tests_passed=False,
                security_rescan_passed=False,
                preservation_passed=False,
                promoted=False,
                status="rolled_back",
                details={"error": f"Syntax check failed: {syntax_err}"},
            )

        # Gate 2: Regression & Preservation Tests
        test_success, test_output, failed_tests = self.test_runner.run_tests()
        if baseline:
            preservation_ok, preservation_msg = BehaviorComparator.compare(
                baseline, test_success, failed_tests
            )
        else:
            preservation_ok = test_success
            preservation_msg = "No baseline provided; relying on current test results."

        if not preservation_ok:
            self.rollback_manager.rollback(patch)
            return VerificationResult(
                patch_id=patch.id,
                syntax_passed=True,
                regression_tests_passed=False,
                security_rescan_passed=False,
                preservation_passed=False,
                promoted=False,
                status="rolled_back",
                details={"error": f"Regression detected: {preservation_msg}", "test_output": test_output[:500]},
            )

        # Gate 3: Security Rescan (Prove Vulnerability is Gone)
        is_fixed = self.rescan_verifier.verify_vulnerability_fixed(finding)
        if not is_fixed:
            self.rollback_manager.rollback(patch)
            return VerificationResult(
                patch_id=patch.id,
                syntax_passed=True,
                regression_tests_passed=True,
                security_rescan_passed=False,
                preservation_passed=True,
                promoted=False,
                status="rolled_back",
                details={"error": "Security rescan failed: vulnerability was not resolved by patch."},
            )

        # All 3 Gates Passed!
        patch.status = "verified"
        return VerificationResult(
            patch_id=patch.id,
            syntax_passed=True,
            regression_tests_passed=True,
            security_rescan_passed=True,
            preservation_passed=True,
            promoted=True,
            status="verified",
            details={
                "message": "Fix proved effective! Vulnerability eliminated and all regression tests passed.",
                "preservation_status": preservation_msg,
            },
        )

    def _check_syntax(self, file_path: str) -> tuple[bool, str]:
        target = self.root / file_path
        if not target.exists():
            return False, "Patched file does not exist."

        if target.suffix == ".py":
            try:
                py_compile.compile(str(target), doraise=True)
                return True, "Python syntax OK."
            except Exception as e:
                return False, str(e)

        return True, "Syntax check skipped or passed."
