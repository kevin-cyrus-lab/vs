from __future__ import annotations

import shutil
from pathlib import Path
from typing import Tuple

from vibesecurity.config import GLOBAL_CONFIG
from vibesecurity.core.models import SecurityPatch


class PatchRollbackManager:
    """Restores files to their exact pre-patch baseline upon verification failure."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()
        self.checkpoints_dir = GLOBAL_CONFIG.home_dir / "checkpoints"

    def rollback(self, patch: SecurityPatch) -> Tuple[bool, str]:
        target_file = self.root / patch.file_path
        backup_file = self.checkpoints_dir / f"{patch.id}_{target_file.name}.bak"

        if not backup_file.exists():
            # If no backup found, try to use patch original_snippet
            if patch.original_snippet:
                target_file.write_text(patch.original_snippet, encoding="utf-8")
                patch.status = "rolled_back"
                patch.applied = False
                return True, f"Rolled back {patch.file_path} using stored original snippet."
            return False, f"Cannot rollback: no checkpoint backup found for patch {patch.id}."

        try:
            content = backup_file.read_text(encoding="utf-8")
            if content == "__VS_FILE_DID_NOT_EXIST__":
                target_file.unlink(missing_ok=True)
            else:
                shutil.copy2(backup_file, target_file)

            patch.status = "rolled_back"
            patch.applied = False
            return True, f"Successfully rolled back patch {patch.id} on {patch.file_path}."
        except Exception as e:
            return False, f"Failed during rollback of patch {patch.id}: {e}"

