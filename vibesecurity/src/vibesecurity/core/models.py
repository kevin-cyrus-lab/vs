from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, Enum):
    LOW = "low"          # Safe automatic remediation
    MEDIUM = "medium"    # Conditional auto-remediation (requires regression pass)
    HIGH = "high"        # Requires explicit developer confirmation


class ScanType(str, Enum):
    ALL = "all"
    SOURCE = "source"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    INFRASTRUCTURE = "infrastructure"
    API = "api"
    DYNAMIC = "dynamic"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    rule_id: str
    scanner: str
    confidence: str = "high"
    description: str = ""
    remediation_strategy: str = ""
    risk_level: str = RiskLevel.MEDIUM.value
    status: str = "open"
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            raw = f"{self.rule_id}:{self.file_path}:{self.line_start}:{self.title}"
            self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectBreakdown:
    project_path: str
    name: str
    primary_language: str
    languages: Dict[str, int] = field(default_factory=dict)
    frontend_framework: Optional[str] = None
    backend_framework: Optional[str] = None
    database: Optional[str] = None
    auth_system: Optional[str] = None
    package_manager: Optional[str] = None
    test_framework: Optional[str] = None
    docker: bool = False
    docker_compose: bool = False
    terraform: bool = False
    api_endpoints: List[str] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)
    total_files: int = 0
    lines_of_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectBaseline:
    id: str
    project_path: str
    git_commit: Optional[str]
    has_uncommitted_changes: bool
    dirty_files: List[str] = field(default_factory=list)
    test_runner: Optional[str] = None
    test_status: str = "unknown"  # passed | failed | not_configured
    test_output: str = ""
    build_status: str = "unknown"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityPatch:
    id: str
    finding_id: str
    file_path: str
    diff: str
    original_snippet: str
    patched_snippet: str
    risk_level: str
    strategy: str
    description: str
    applied: bool = False
    status: str = "staged"  # staged | applied | verified | rolled_back | rejected
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    patch_id: str
    syntax_passed: bool
    regression_tests_passed: bool
    security_rescan_passed: bool
    preservation_passed: bool
    promoted: bool
    status: str  # verified | failed | rolled_back
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    scan_id: str
    project_path: str
    timestamp: str
    duration_ms: int
    security_score: int  # 0 to 100
    grade: str           # A+, A, B, C, D, F
    findings_count: Dict[str, int]
    findings: List[Finding]
    remediation_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return res

