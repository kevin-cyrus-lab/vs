from __future__ import annotations

import difflib
import json
import re
import uuid
from pathlib import Path
from typing import Optional

from vibesecurity.core.models import Finding, RiskLevel, SecurityPatch


class PatchGenerator:
    """Generates minimal, surgical code patches to remediate security vulnerabilities."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def generate_patch(self, finding: Finding) -> Optional[SecurityPatch]:
        target_file = self.root / finding.file_path
        if not target_file.is_file():
            # If finding is for .gitignore and it doesn't exist yet, we can create it
            if finding.file_path == ".gitignore" or finding.rule_id == "env-file-not-ignored":
                target_file = self.root / ".gitignore"
                if not target_file.exists():
                    target_file.write_text("", encoding="utf-8")
            else:
                return None

        try:
            original_content = target_file.read_text(encoding="utf-8")
        except Exception:
            return None

        patched_content = self._create_patched_content(finding, original_content)
        if not patched_content or patched_content == original_content:
            return None

        diff = "".join(
            difflib.unified_diff(
                original_content.splitlines(keepends=True),
                patched_content.splitlines(keepends=True),
                fromfile=f"a/{finding.file_path}",
                tofile=f"b/{finding.file_path}",
            )
        )

        patch_id = f"patch-{uuid.uuid4().hex[:8]}"

        return SecurityPatch(
            id=patch_id,
            finding_id=finding.id,
            file_path=finding.file_path,
            diff=diff,
            original_snippet=original_content,
            patched_snippet=patched_content,
            risk_level=finding.risk_level,
            strategy=finding.remediation_strategy or "automated-fix",
            description=f"Auto-repair for {finding.title} in {finding.file_path}",
        )

    def _create_patched_content(self, finding: Finding, content: str) -> Optional[str]:
        rule = finding.rule_id

        # 1. Add .env to .gitignore
        if rule == "env-file-not-ignored":
            lines = content.splitlines()
            if ".env" not in lines:
                lines.append("\n# Security: exclude environment secrets from version control")
                lines.append(".env")
                lines.append(".env.local")
                lines.append(".env*.local")
                return "\n".join(lines) + "\n"
            return content

        # 2. Bind public database port to localhost only in docker-compose
        if rule == "docker-compose-public-db-port":
            lines = content.splitlines()
            target_idx = finding.line_start - 1
            if 0 <= target_idx < len(lines):
                line = lines[target_idx]
                patched_line = re.sub(
                    r"""(['"]?)(?:0\.0\.0\.0:)?(5432|3306|27017|6379):(5432|3306|27017|6379)(['"]?)""",
                    r"""\1 127.0.0.1:\2:\3\4""",
                    line,
                )
                lines[target_idx] = patched_line
                return "\n".join(lines) + "\n"

        # 3. Add non-root user to Dockerfile
        if rule in {"docker-running-as-root", "docker-missing-user-directive"}:
            lines = content.splitlines()
            if not any("USER" in l for l in lines):
                lines.append("\n# Run as non-privileged user for container security")
                lines.append("RUN (addgroup -S appgroup 2>/dev/null || groupadd -r appgroup) && \\")
                lines.append("    (adduser -S appuser -G appgroup 2>/dev/null || useradd -r -g appgroup appuser)")
                lines.append("USER appuser\n")
                return "\n".join(lines)

        # 4. Inject HTTP Security Headers into Next.js config
        if rule == "nextjs-missing-security-headers":
            return self._patch_nextjs_config_headers(content)

        # 5. Restrict CORS wildcard
        if rule == "cors-wildcard-origin":
            lines = content.splitlines()
            target_idx = finding.line_start - 1
            if 0 <= target_idx < len(lines):
                line = lines[target_idx]
                # Replace '*' with origin or configured allowed domain
                patched_line = re.sub(r"""['"]\*['"]""", "process.env.ALLOWED_ORIGIN || 'http://localhost:3000'", line)
                lines[target_idx] = patched_line
                return "\n".join(lines) + "\n"

        # 6. Upgrade vulnerable dependencies in package.json
        if rule.startswith("dep-vuln-") and "package.json" in finding.file_path:
            parts = finding.remediation_strategy.split(":")
            if len(parts) >= 3:
                pkg_name, fixed_ver = parts[1], parts[2]
                try:
                    data = json.loads(content)
                    if "dependencies" in data and pkg_name in data["dependencies"]:
                        data["dependencies"][pkg_name] = f"^{fixed_ver}"
                    if "devDependencies" in data and pkg_name in data["devDependencies"]:
                        data["devDependencies"][pkg_name] = f"^{fixed_ver}"
                    return json.dumps(data, indent=2) + "\n"
                except Exception:
                    pass

        # 7. Upgrade vulnerable dependencies in requirements.txt
        if rule.startswith("dep-vuln-") and "requirements.txt" in finding.file_path:
            parts = finding.remediation_strategy.split(":")
            if len(parts) >= 3:
                pkg_name, fixed_ver = parts[1], parts[2]
                lines = content.splitlines()
                for idx, line in enumerate(lines):
                    if line.strip().lower().startswith(pkg_name.lower()):
                        lines[idx] = f"{pkg_name}>={fixed_ver}"
                return "\n".join(lines) + "\n"

        # 8. Python SQL Injection parameterization
        if rule == "python-sql-injection-dynamic":
            lines = content.splitlines()
            target_idx = finding.line_start - 1
            if 0 <= target_idx < len(lines):
                line = lines[target_idx]
                # Replace f"SELECT ... {id}" with ("SELECT ... %s", (id,))
                match = re.search(r"""f["'](.*?)["']""", line)
                if match:
                    sql_fstr = match.group(1)
                    variables = re.findall(r"""\{([a-zA-Z0-9_\.]+)\}""", sql_fstr)
                    if variables:
                        safe_sql = re.sub(r"""\{[a-zA-Z0-9_\.]+\}""", "%s", sql_fstr)
                        var_tuple = f"({', '.join(variables)},)" if len(variables) == 1 else f"({', '.join(variables)})"
                        patched_line = line.replace(match.group(0), f'"{safe_sql}", {var_tuple}')
                        lines[target_idx] = patched_line
                        return "\n".join(lines) + "\n"

        # 9. Node/React dangerouslySetInnerHTML sanitization note/wrapper
        if rule == "react-dangerouslysetinnerhtml":
            lines = content.splitlines()
            target_idx = finding.line_start - 1
            if 0 <= target_idx < len(lines):
                line = lines[target_idx]
                if "DOMPurify" not in line:
                    patched_line = re.sub(
                        r"""__html\s*:\s*([^}]+)\}""",
                        r"""__html: typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(\1) : \1}""",
                        line,
                    )
                    lines[target_idx] = patched_line
                    return "\n".join(lines) + "\n"

        return None

    def _patch_nextjs_config_headers(self, content: str) -> str:
        headers_snippet = """
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
          },
        ],
      },
    ];
  },
"""
        # Inject into nextConfig object
        if "const nextConfig" in content:
            # Insert headers right after const nextConfig: NextConfig = {
            patched = re.sub(
                r"""(const nextConfig(?::\s*NextConfig)?\s*=\s*\{)""",
                r"""\1""" + headers_snippet,
                content,
                count=1,
            )
            return patched
        elif "module.exports" in content:
            patched = re.sub(
                r"""(module\.exports\s*=\s*\{)""",
                r"""\1""" + headers_snippet,
                content,
                count=1,
            )
            return patched
        return content

