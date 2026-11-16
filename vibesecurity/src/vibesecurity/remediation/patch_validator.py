from __future__ import annotations

import json
import py_compile
import tempfile
from pathlib import Path
from typing import Tuple

from vibesecurity.core.models import SecurityPatch


class PatchValidator:
    """Validates the safety, boundaries, and syntax of generated patches before application."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def validate(self, patch: SecurityPatch) -> Tuple[bool, str]:
        # 1. Path safety check: cannot escape project root
        target = (self.root / patch.file_path).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            return False, f"Path traversal attempt: {patch.file_path} escapes project root."

        # 2. Scope check: patch cannot modify sensitive system directories or .git directly
        rel_str = str(patch.file_path).replace("\\", "/")
        if rel_str.startswith(".git/") or rel_str.startswith("node_modules/"):
            return False, f"Target file {patch.file_path} is in a protected internal directory."

        # 3. Patch size check: protect against huge unintended file wipes
        if len(patch.diff.splitlines()) > 500:
            return False, "Patch diff exceeds safe size limit (500 lines)."

        # 4. Syntax check for Python / JSON
        if patch.file_path.endswith(".py"):
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
                tf.write(patch.patched_snippet)
                tf_path = tf.name
            try:
                py_compile.compile(tf_path, doraise=True)
            except Exception as e:
                Path(tf_path).unlink(missing_ok=True)
                return False, f"Patched code has Python syntax error: {e}"
            Path(tf_path).unlink(missing_ok=True)

        if patch.file_path.endswith(".json"):
            try:
                json.loads(patch.patched_snippet)
            except Exception as e:
                return False, f"Patched JSON is malformed: {e}"

        return True, "Patch passed safety and syntax validation."

