from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from vibesecurity.core.models import ProjectBaseline


class ProjectBaselineManager:
    """Records the exact pre-remediation baseline so any changes can be verified or rolled back."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def capture_baseline(self) -> ProjectBaseline:
        baseline_id = str(uuid.uuid4())[:8]
        git_commit = self._get_git_commit()
        has_uncommitted, dirty_files = self._get_git_status()
        test_runner, test_status, test_output = self._run_baseline_tests()
        build_status = self._check_baseline_build()

        return ProjectBaseline(
            id=baseline_id,
            project_path=str(self.root),
            git_commit=git_commit,
            has_uncommitted_changes=has_uncommitted,
            dirty_files=dirty_files,
            test_runner=test_runner,
            test_status=test_status,
            test_output=test_output,
            build_status=build_status,
        )

    def _get_git_commit(self) -> Optional[str]:
        if not (self.root / ".git").exists():
            return None
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception:
            pass
        return None

    def _get_git_status(self) -> tuple[bool, List[str]]:
        if not (self.root / ".git").exists():
            return False, []
        try:
            res = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                dirty_files = [line.split(maxsplit=1)[-1] for line in lines]
                return len(lines) > 0, dirty_files
        except Exception:
            pass
        return False, []

    def _run_baseline_tests(self) -> tuple[Optional[str], str, str]:
        pkg_file = self.root / "package.json"
        if pkg_file.exists():
            # Node project
            try:
                res = subprocess.run(
                    ["npm", "test", "--", "--run"],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                status = "passed" if res.returncode == 0 else "failed"
                return "npm test", status, (res.stdout + "\n" + res.stderr)[:1000]
            except Exception:
                pass

        if (self.root / "pytest.ini").exists() or (self.root / "tests").exists():
            try:
                res = subprocess.run(
                    ["python3", "-m", "pytest", "-q"],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                status = "passed" if res.returncode == 0 else "failed"
                return "pytest", status, (res.stdout + "\n" + res.stderr)[:1000]
            except Exception:
                pass

        return None, "not_configured", "No automated tests discovered."

    def _check_baseline_build(self) -> str:
        # Check syntax of key files
        py_files = list(self.root.glob("*.py")) + list(self.root.glob("src/**/*.py"))
        for py_file in py_files[:10]:
            try:
                res = subprocess.run(
                    ["python3", "-m", "py_compile", str(py_file)],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode != 0:
                    return f"failed (syntax error in {py_file.name})"
            except Exception:
                pass
        return "passed"

