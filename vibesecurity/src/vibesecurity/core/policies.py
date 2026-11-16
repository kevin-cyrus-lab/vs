from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SecurityPolicy:
    name: str = "default"
    allowed_auto_risks: List[str] = field(default_factory=lambda: ["low", "medium"])
    require_git_checkpoint: bool = True
    use_isolated_worktree: bool = True
    preserve_user_changes: bool = True
    require_regression_tests: bool = True
    require_build_validation: bool = True
    require_security_rescan: bool = True
    rollback_on_failure: bool = True
    redact_secrets: bool = True
    fail_on_critical: bool = True
    max_auto_patch_lines: int = 150

    def can_auto_remediate(self, risk_level: str) -> bool:
        return risk_level.lower() in self.allowed_auto_risks

    @classmethod
    def load(cls, profile: str = "default") -> SecurityPolicy:
        if profile == "conservative":
            return cls(
                name="conservative",
                allowed_auto_risks=["low"],
                require_regression_tests=True,
                max_auto_patch_lines=50,
            )
        elif profile == "strict":
            return cls(
                name="strict",
                allowed_auto_risks=["low", "medium"],
                require_regression_tests=True,
                require_build_validation=True,
                require_security_rescan=True,
                fail_on_critical=True,
                max_auto_patch_lines=200,
            )
        return cls(name="default")

