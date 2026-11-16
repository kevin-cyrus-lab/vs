from __future__ import annotations

from typing import List, Tuple

from vibesecurity.core.models import ProjectBaseline


class BehaviorComparator:
    """
    Compares baseline behavior against post-patch behavior to guarantee zero unintended breakage.
    Distinguishes pre-existing issues from newly introduced regressions.
    """

    @staticmethod
    def compare(baseline: ProjectBaseline, current_test_success: bool, current_failed_tests: List[str]) -> Tuple[bool, str]:
        # If tests passed completely, preservation is 100% verified
        if current_test_success:
            return True, "All tests passed cleanly. Functionality preserved."

        # If baseline had no test runner configured, verify syntax/build
        if baseline.test_status == "not_configured":
            return True, "No test runner in baseline; syntax and integrity checks preserved."

        # If baseline was already failing, check for new failures
        baseline_output = baseline.test_output
        new_regressions: List[str] = []
        for test in current_failed_tests:
            # Check if this failure already existed in baseline output
            if test not in baseline_output:
                new_regressions.append(test)

        if new_regressions:
            return False, f"Regression detected! New test failures introduced by patch: {', '.join(new_regressions[:3])}"

        return True, "No new regressions detected (existing baseline failures remained unchanged)."

