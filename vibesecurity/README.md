# 🛡️ VibeSecurity

### Autonomous Security Engineering Layer for AI & Vibe Coders
**Break it down. Scan vulnerabilities. Generate minimal patches. Preserve existing functionality. Prove that the fix works.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![MCP Protocol](https://img.shields.io/badge/MCP-2024--11--05-brightgreen.svg)](https://modelcontextprotocol.io/)
[![Zero Breakage](https://img.shields.io/badge/preservation-multi--gate%20verified-purple.svg)](#preservation-engine--zero-breakage-architecture)

---

## 🎯 The Central Problem & The Defining Principle

AI coding tools (Cursor, Claude Code, Windsurf, Copilot, ChatGPT) allow developers and "vibe coders" to build applications and websites in hours instead of months. However, AI generators frequently introduce critical security vulnerabilities:
- **SQL Injections** in dynamic queries
- **Stored & Reflected XSS** in React / Next.js (`dangerouslySetInnerHTML`, unescaped inputs)
- **Command Injections** (`os.system`, `child_process.exec`, `shell=True`)
- **Hardcoded Secrets & API Keys** (OpenAI, AWS, Stripe, Database URLs)
- **Vulnerable & Outdated Dependencies** (published CVEs)
- **Insecure CORS & Missing Security Headers** (CSP, X-Frame-Options Clickjacking)
- **Unprotected Admin Routes & Missing Rate Limiting**
- **Docker Containers Running as Root & Public Database Ports**

Traditional security scanners merely produce long lists of warnings without fixing anything. 

**VibeSecurity is different:**
> ### The Defining Principle:
> **Fix the vulnerability. Preserve the application. Prove that the fix works.**

---

## 🏗️ Overall Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │ AI Coding Clients (Claude Code · Cursor · Windsurf · AGY) │
                  └──────────────────────────┬─────────────────────────────┘
                                             │ JSON-RPC 2.0 (STDIO)
                  ┌──────────────────────────▼─────────────────────────────┐
                  │                 VibeSecurity MCP Gateway               │
                  │        Tool Discovery · Resources · Prompts            │
                  └──────────────────────────┬─────────────────────────────┘
                                             │
      ┌──────────────────────────────────────┴──────────────────────────────────────┐
      │                                                                            │
┌─────▼─────────────────────────┐  ┌──────────────────────────────┐  ┌─────────────▼────────────────┐
│   01. Breakdown & Discovery   │  │    02. Multi-Engine Scanners │  │  03. Remediation Engine      │
│ Languages, Frameworks, DB,    │  │ SAST, Secrets, Dependencies, │  │ Targeted minimal unified diff│
│ Auth, APIs, Configs, Baseline │  │ Infra, APIs, Dynamic DAST    │  │ surgical code patches        │
└───────────────────────────────┘  └──────────────────────────────┘  └─────────────┬────────────────┘
                                                                                   │
      ┌────────────────────────────────────────────────────────────────────────────┘
      │
┌─────▼────────────────────────────────────────────────────────────────────────────┐
│                  04. Preservation & Verification Multi-Gate Engine               │
│  Gate 1: Build & Syntax Check (compiles/parses cleanly?)                         │
│  Gate 2: Regression Suite (did existing tests pass without new failure?)         │
│  Gate 3: Security Rescan (did the vulnerability disappear from the scanner?)     │
│  Decision: All Gates Pass -> Promote Patch! | Any Gate Fails -> Instant Rollback!│
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (CLI)

```bash
# 1. Clone repository
git clone https://github.com/vibesecurity/vibesecurity.git
cd vibesecurity

# 2. Run system doctor check
./bin/vibesecurity doctor

# 3. Break down your application architecture
./bin/vibesecurity breakdown /path/to/your/project

# 4. Run full security scan (SAST, Secrets, Dependencies, Infra, APIs)
./bin/vibesecurity scan /path/to/your/project

# 5. Autonomous Auto-Remediation (fix, test, rescan, and rollback if broken)
./bin/vibesecurity fix /path/to/your/project --policy default

# 6. Generate audit report (Markdown, JSON, or OASIS SARIF)
./bin/vibesecurity report /path/to/your/project --format markdown
./bin/vibesecurity report /path/to/your/project --format sarif -o security.sarif
```

---

## 🔌 Universal MCP Client Setup

VibeSecurity runs natively as an official **Model Context Protocol (MCP)** server over standard I/O (STDIO), compatible with **Claude Code, Cursor, Windsurf, Antigravity, and any MCP client**.

### 1. Cursor Setup (`~/.cursor/mcp.json` or Project Settings)
```json
{
  "mcpServers": {
    "vibesecurity": {
      "command": "python3",
      "args": [
        "-m",
        "vibesecurity",
        "mcp"
      ],
      "env": {
        "PYTHONPATH": "/absolute/path/to/vibesecurity/src"
      }
    }
  }
}
```

### 2. Claude Code Setup (`claude.json` or `~/.claude/mcp.json`)
```bash
claude mcp add vibesecurity python3 -m vibesecurity mcp
```

### 3. Windsurf Setup (`~/.codeium/windsurf/mcp_config.json`)
```json
{
  "mcpServers": {
    "vibesecurity": {
      "command": "/absolute/path/to/vibesecurity/bin/vibesecurity",
      "args": ["mcp"]
    }
  }
}
```

---

## 🛠️ The 18 MCP Tools Reference

| Category | Tool | Description |
| :--- | :--- | :--- |
| **Breakdown** | `breakdown_project` | Deeply maps languages, frontend/backend frameworks, DB, auth, package manager, and routes. |
| **Baseline** | `get_security_baseline` | Records pre-remediation git commit, dirty files, and initial test pass/fail status. |
| **Scanning** | `scan_repository` | Comprehensive audit across all engines; computes 0-100 score and letter grade. |
| **Scanning** | `scan_source_code` | Static AST and pattern analysis for OWASP Top 10 vulnerabilities. |
| **Scanning** | `scan_secrets` | Detects API keys, tokens, and private keys with automatic redaction. |
| **Scanning** | `scan_dependencies` | Audits manifests against known CVEs and vulnerability advisories. |
| **Scanning** | `scan_infrastructure` | Inspects Dockerfile, docker-compose, and configuration files. |
| **Scanning** | `scan_api_security` | Audits endpoint security, auth guards, rate limits, and CORS policies. |
| **Dynamic** | `scan_running_application` | Live dynamic testing (DAST) of web servers / websites for HTTP security headers and cookies. |
| **Context** | `analyze_vulnerability_context` | Extracts surrounding code lines and call sites for an identified issue. |
| **Remediation** | `generate_security_patch` | Generates minimal unified diff patch for targeted repair. |
| **Remediation** | `validate_security_patch` | Checks path safety, syntax, and scope boundaries before modification. |
| **Remediation** | `apply_security_patch` | Applies patch to working tree while creating a rollback checkpoint. |
| **Remediation** | `rollback_security_patch` | Instantly reverts any repair back to the recorded baseline. |
| **Verification** | `verify_security_fix` | Executes multi-gate verification (syntax + regression tests + rescan). |
| **Autonomous** | `auto_remediate_project` | One-shot end-to-end autonomous pipeline: scan -> patch -> test -> prove -> settle. |
| **Reporting** | `generate_security_report` | Exports complete audit report in Markdown, JSON, or OASIS SARIF format. |
| **Reporting** | `get_scan_history` | Retrieves historical scan progression and security score trajectory. |

---

## 🛡️ Preservation Engine — Zero-Breakage Architecture

Most security tools focus only on finding issues. VibeSecurity's primary differentiator is **guaranteeing functional preservation**:

1. **Pre-Remediation Baseline:** Before touching any file, VibeSecurity records git status, uncommitted changes, and runs the application's existing test suite.
2. **Pre-Existing Failure Distinction:** If a test was *already* failing before VibeSecurity touched the code, it is recorded in the baseline so VibeSecurity does not misattribute prior bugs to its security patches.
3. **Multi-Gate Verification:**
   - **Gate 1 (Build/Syntax):** Does the modified file compile or parse without syntax errors?
   - **Gate 2 (Regression Tests):** Did all tests that previously passed continue to pass?
   - **Gate 3 (Security Rescan):** Does a targeted re-scan prove that the vulnerability is 100% eliminated?
4. **Autonomous Rollback:** If *any* gate fails, VibeSecurity immediately reverts the code to its original checkpoint.

---

## 📋 Security Policy Profiles

Configure repair risk boundaries in `policies/`:

| Policy | Auto-Repairs Allowed | Gate Requirements | Best For |
| :--- | :--- | :--- | :--- |
| **`conservative`** | Low risk only (headers, `.gitignore`, `.env` isolation) | Strict regression pass | High-risk legacy codebases |
| **`default`** | Low + Medium risk (SQLi parameterization, XSS wrappers, CORS allowlists, dependency bumps) | Regression test + rescan pass | Standard vibe-coded web apps |
| **`strict`** | Low + Medium risk | Mandatory syntax, build, regression, and rescan; fails gate on criticals | Production CI/CD pipelines |

---

## 📜 License

Licensed under the [MIT License](LICENSE).
*Fix the vulnerability. Preserve the application. Prove that the fix works.*

