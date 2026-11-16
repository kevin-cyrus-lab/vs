from __future__ import annotations

import abc
from pathlib import Path
from typing import List

from vibesecurity.core.models import Finding


class BaseSecurityScanner(abc.ABC):
    """Base class for all VibeSecurity scanners."""

    name: str = "base"

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    @abc.abstractmethod
    def scan(self) -> List[Finding]:
        """Execute scan and return normalized findings."""
        pass

    def is_available(self) -> bool:
        """Check if engine prerequisites are satisfied."""
        return True

