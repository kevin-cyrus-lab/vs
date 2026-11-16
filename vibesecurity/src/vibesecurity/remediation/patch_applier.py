from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Tuple

from vibesecurity.config import GLOBAL_CONFIG
from vibesecurity.core.models import SecurityPatch


class PatchApplier:
    """Applies verified patches while maintaining rollback backups."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()
        self.checkpoints_dir = GLOBAL_CONFIG.home_dir / "checkpoints"
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)

    def apply(self, patch: SecurityPatch) -> Tuple[bool, str]:
        target_file = self.root / patch.file_path
        backup_file = self.checkpoints_dir / f"{patch.id}_{target_file.name}.bak"

        try:
            # 1. Create backup of original
            if target_file.exists():
                shutil.copy2(target_file, backup_file)
            else:
                # If creating new file, create an empty sentinel backup
                backup_file.write_text("__VS_FILE_DID_NOT_EXIST__", encoding="utf-8")

            # 2. Write patched content
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(patch.patched_snippet, encoding="utf-8")
            patch.applied = True
            patch.status = "applied"
            return True, f"Successfully applied patch {patch.id} to {patch.file_path}"
        except Exception as e:
            return False, f"Failed applying patch {patch.id}: {e}"

