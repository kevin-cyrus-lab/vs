# vs
(vs)VibeSecurity is an MCP-powered security engine for AI coding tools. It scans entire repositories, detects vulnerabilities, and applies targeted fixes. Checkpoints, rollback, and regression tests help preserve existing functionality and verify every repair.
**VibeSecurity – Intelligent Security & Automated Repair Engine**

VibeSecurity is an automated application security platform that detects vulnerabilities, generates targeted fixes, and verifies that existing functionality remains intact. It integrates six security engines, automated remediation, rollback protection, and Model Context Protocol (MCP) support.

The `vibesecurity/` directory contains the actual software, including Python modules, security scanners, remediation logic, CLI, MCP server, policies, and automated tests.

The hidden `.vibesecurity/` directory stores runtime data, including the SQLite database, repair checkpoints, security reports, and audit logs. It maintains project baselines, scan histories, vulnerability findings, patches, and verification records. Original files are backed up to support safe rollback.

**Testing Results:**
- All 8 reported unit and integration tests passed.
- SQL injection and command injection detection verified.
- Secret detection and redaction verified.
- Docker root-user detection verified.
- MCP protocol operations tested successfully.
- Patch generation, validation, and rollback tested.
- SQLite integrity passed with zero foreign-key violations.
- Four backup checkpoints preserved.

The database recorded 1 project, 5 scans, 14 findings, 1 patch, 1 verification run, and 18 audit events.

**Core Objective:** VibeSecurity goes beyond vulnerability detection by automatically identifying security weaknesses, applying controlled repairs, preserving original application functionality, and verifying fixes before accepting them.
