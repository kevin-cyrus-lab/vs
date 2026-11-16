from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

def get_default_home() -> Path:
    if "VIBESECURITY_HOME" in os.environ:
        return Path(os.environ["VIBESECURITY_HOME"])
    candidate = Path.home() / ".vibesecurity"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except Exception:
        # Fallback to local workspace or tmp directory
        fallback = Path.cwd() / ".vibesecurity"
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback
        except Exception:
            tmp_fallback = Path("/tmp/.vibesecurity")
            tmp_fallback.mkdir(parents=True, exist_ok=True)
            return tmp_fallback

DEFAULT_HOME = get_default_home()

@dataclass
class VibeSecurityConfig:
    home_dir: Path = DEFAULT_HOME
    db_path: Path = DEFAULT_HOME / "vibesecurity.db"
    log_level: str = "INFO"
    timeout_seconds: int = 60
    allow_network_scans: bool = False
    redact_secrets: bool = True
    default_policy: str = "default"  # default | conservative | strict
    max_patch_lines: int = 200
    isolated_staging: bool = True

    def ensure_dirs(self) -> None:
        self.home_dir.mkdir(parents=True, exist_ok=True)
        (self.home_dir / "checkpoints").mkdir(parents=True, exist_ok=True)
        (self.home_dir / "reports").mkdir(parents=True, exist_ok=True)

GLOBAL_CONFIG = VibeSecurityConfig()

