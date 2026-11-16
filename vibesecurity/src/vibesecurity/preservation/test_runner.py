from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class TestRunner:
    """Discovers and runs project regression test suites."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def run_tests(self) -> Tuple[bool, str, List[str]]:
        """Returns (success, output, failed_test_names)."""
        pkg_file = self.root / "package.json"
        if pkg_file.is_file():
            try:
                res = subprocess.run(
                    ["npm", "test", "--", "--run"],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    timeout=45,
                )
                output = res.stdout + "\n" + res.stderr
                success = (res.returncode == 0)
                failed_tests = [line.strip() for line in output.splitlines() if "FAIL" in line or "ERR" in line]
                return success, output[:2000], failed_tests
            except Exception as e:
                return False, f"npm test execution error: {e}", [str(e)]

        if (self.root / "pytest.ini").exists() or (self.root / "tests").exists():
            try:
                res = subprocess.run(
                    ["python3", "-m", "pytest", "-q"],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    timeout=45,
                )
                output = res.stdout + "\n" + res.stderr
                success = (res.returncode == 0)
                failed_tests = [line.strip() for line in output.splitlines() if "FAILED" in line]
                return success, output[:2000], failed_tests
            except Exception as e:
                return False, f"pytest execution error: {e}", [str(e)]

        # No automated test suite found
        return True, "No test runner configured.", []

