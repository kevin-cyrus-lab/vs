from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from vibesecurity.config import GLOBAL_CONFIG
from vibesecurity.core.models import Finding, ProjectBaseline, ProjectBreakdown, SecurityPatch, VerificationResult


class VibeSecurityDB:
    """Persistent SQLite store for scans, baselines, patches, verification runs, and audit logs."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or GLOBAL_CONFIG.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_tables(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    root_path TEXT NOT NULL UNIQUE,
                    primary_language TEXT,
                    framework TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS project_baselines (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    git_commit TEXT,
                    test_status TEXT,
                    build_status TEXT,
                    raw_json TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    security_score INTEGER,
                    grade TEXT,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    rule_id TEXT,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT,
                    cwe_id TEXT,
                    file_path TEXT,
                    line_start INTEGER,
                    line_end INTEGER,
                    code_snippet TEXT,
                    status TEXT DEFAULT 'open',
                    fingerprint TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                );

                CREATE TABLE IF NOT EXISTS patches (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    diff TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(finding_id) REFERENCES findings(id)
                );

                CREATE TABLE IF NOT EXISTS verification_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patch_id TEXT NOT NULL,
                    syntax_passed INTEGER,
                    regression_passed INTEGER,
                    security_rescan_passed INTEGER,
                    promoted INTEGER,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(patch_id) REFERENCES patches(id)
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_path TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT,
                    created_at TEXT NOT NULL
                );
            """)

    @staticmethod
    def get_project_id(path_str: str) -> str:
        return "proj-" + hashlib.sha256(path_str.encode("utf-8")).hexdigest()[:12]

    def record_project(self, breakdown: ProjectBreakdown) -> str:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT id FROM projects WHERE root_path = ?", (breakdown.project_path,))
            row = cur.fetchone()
            if row:
                proj_id = row[0]
                conn.execute(
                    """
                    UPDATE projects SET
                        name = ?,
                        primary_language = ?,
                        framework = ?
                    WHERE id = ?
                    """,
                    (
                        breakdown.name,
                        breakdown.primary_language,
                        breakdown.frontend_framework or breakdown.backend_framework or "Standard",
                        proj_id,
                    ),
                )
                return proj_id

            proj_id = self.get_project_id(breakdown.project_path)
            conn.execute(
                """
                INSERT INTO projects (id, name, root_path, primary_language, framework, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    proj_id,
                    breakdown.name,
                    breakdown.project_path,
                    breakdown.primary_language,
                    breakdown.frontend_framework or breakdown.backend_framework or "Standard",
                    datetime.utcnow().isoformat(),
                ),
            )
            return proj_id

    def record_baseline(self, project_id: str, baseline: ProjectBaseline) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO project_baselines (id, project_id, git_commit, test_status, build_status, raw_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    baseline.id,
                    project_id,
                    baseline.git_commit,
                    baseline.test_status,
                    baseline.build_status,
                    json.dumps(baseline.to_dict()),
                    baseline.created_at,
                ),
            )

    def record_scan(self, project_id: str, scan_id: str, score: int, grade: str, findings: List[Finding]) -> None:
        now = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, project_id, scan_type, security_score, grade, status, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, project_id, "all", score, grade, "completed", now, now),
            )
            for f in findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, rule_id, title, severity, confidence, cwe_id,
                        file_path, line_start, line_end, code_snippet, status, fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        scan_id,
                        f.rule_id,
                        f.title,
                        f.severity,
                        f.confidence,
                        f.cwe,
                        f.file_path,
                        f.line_start,
                        f.line_end,
                        f.code_snippet,
                        f.status,
                        f.fingerprint,
                    ),
                )

    def record_patch_and_verification(self, patch: SecurityPatch, vres: VerificationResult) -> None:
        now = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO patches (id, finding_id, file_path, risk_level, status, diff, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    patch.id,
                    patch.finding_id,
                    patch.file_path,
                    patch.risk_level,
                    patch.status,
                    patch.diff,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO verification_runs (patch_id, syntax_passed, regression_passed, security_rescan_passed, promoted, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vres.patch_id,
                    1 if vres.syntax_passed else 0,
                    1 if vres.regression_tests_passed else 0,
                    1 if vres.security_rescan_passed else 0,
                    1 if vres.promoted else 0,
                    vres.status,
                    now,
                ),
            )

    def log_audit(self, project_path: str, event_type: str, details: Dict[str, Any]) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (project_path, event_type, details_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (project_path, event_type, json.dumps(details), datetime.utcnow().isoformat()),
            )

    def get_scan_history(self, project_path: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT s.id, s.scan_type, s.security_score, s.grade, s.status, s.started_at, COUNT(f.id) as finding_count
                FROM scans s
                JOIN projects p ON s.project_id = p.id
                LEFT JOIN findings f ON f.scan_id = s.id
                WHERE p.root_path = ?
                GROUP BY s.id
                ORDER BY s.started_at DESC
                LIMIT ?
                """,
                (project_path, limit),
            ).fetchall()
            return [dict(r) for r in rows]
