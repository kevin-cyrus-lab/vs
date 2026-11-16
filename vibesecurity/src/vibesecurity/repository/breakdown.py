from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from vibesecurity.core.models import ProjectBreakdown
from vibesecurity.repository.discovery import EXTENSIONS_BY_LANG, discover_files


class ProjectBreakdownAnalyzer:
    """Deeply inspects and breaks down an application or website architecture."""

    def __init__(self, project_path: str | Path):
        self.root = Path(project_path).resolve()

    def analyze(self) -> ProjectBreakdown:
        if not self.root.exists():
            raise FileNotFoundError(f"Directory {self.root} does not exist.")

        files = discover_files(self.root)
        name = self.root.name

        languages: Dict[str, int] = {}
        total_lines = 0
        sensitive_files: List[str] = []

        for f in files:
            ext = f.suffix.lower()
            if f.name.lower() in {"dockerfile", "dockerfile.dev", "dockerfile.prod"}:
                lang = "Dockerfile"
            else:
                lang = EXTENSIONS_BY_LANG.get(ext, "Other")
            languages[lang] = languages.get(lang, 0) + 1

            if any(part.startswith(".env") for part in [f.name]):
                sensitive_files.append(str(f.relative_to(self.root)))
            elif f.suffix.lower() in {".pem", ".key", ".pfx", ".pkcs12"}:
                sensitive_files.append(str(f.relative_to(self.root)))

            # Estimate lines of code for text files
            if ext in {".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".html", ".css", ".sql"}:
                try:
                    with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                        total_lines += sum(1 for _ in fh)
                except Exception:
                    pass

        # Sort languages by frequency
        sorted_langs = sorted(
            [(k, v) for k, v in languages.items() if k != "Other"],
            key=lambda x: x[1],
            reverse=True,
        )
        primary_lang = sorted_langs[0][0] if sorted_langs else "Unknown"

        frontend = self._detect_frontend()
        backend = self._detect_backend()
        database = self._detect_database()
        auth = self._detect_auth()
        pkg_mgr = self._detect_package_manager()
        test_fw = self._detect_testing()
        docker = (self.root / "Dockerfile").exists() or any((self.root).glob("**/Dockerfile"))
        docker_compose = (
            (self.root / "docker-compose.yml").exists()
            or (self.root / "docker-compose.yaml").exists()
            or (self.root / "compose.yaml").exists()
        )
        terraform = any(self.root.glob("**/*.tf"))

        api_endpoints = self._discover_api_endpoints()

        return ProjectBreakdown(
            project_path=str(self.root),
            name=name,
            primary_language=primary_lang,
            languages=dict(sorted_langs[:8]),
            frontend_framework=frontend,
            backend_framework=backend,
            database=database,
            auth_system=auth,
            package_manager=pkg_mgr,
            test_framework=test_fw,
            docker=docker,
            docker_compose=docker_compose,
            terraform=terraform,
            api_endpoints=api_endpoints[:50],
            sensitive_files=sensitive_files,
            total_files=len(files),
            lines_of_code=total_lines,
        )

    def _read_package_json(self) -> Dict[str, Any]:
        pkg_file = self.root / "package.json"
        if pkg_file.is_file():
            try:
                with open(pkg_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _read_pyproject_or_requirements(self) -> str:
        content = []
        for name in ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"]:
            p = self.root / name
            if p.is_file():
                try:
                    content.append(p.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    pass
        return "\n".join(content)

    def _detect_frontend(self) -> Optional[str]:
        pkg = self._read_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "next" in deps:
            return f"Next.js ({deps.get('next', '')})"
        if "react" in deps:
            return f"React ({deps.get('react', '')})"
        if "vue" in deps or "nuxt" in deps:
            return "Nuxt.js" if "nuxt" in deps else "Vue.js"
        if "svelte" in deps or "@sveltejs/kit" in deps:
            return "Svelte / SvelteKit"
        if "@angular/core" in deps:
            return "Angular"
        if (self.root / "index.html").exists():
            return "HTML / Vanilla JS"
        return None

    def _detect_backend(self) -> Optional[str]:
        pkg = self._read_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "express" in deps:
            return "Express.js"
        if "fastify" in deps:
            return "Fastify"
        if "nest" in deps or "@nestjs/core" in deps:
            return "NestJS"
        if "koa" in deps:
            return "Koa"

        py_content = self._read_pyproject_or_requirements().lower()
        if "fastapi" in py_content:
            return "FastAPI"
        if "django" in py_content:
            return "Django"
        if "flask" in py_content:
            return "Flask"
        if (self.root / "manage.py").exists():
            return "Django"

        if (self.root / "go.mod").exists():
            return "Go (Native/Gin/Fiber)"
        if (self.root / "Cargo.toml").exists():
            return "Rust (Actix/Axum)"
        return None

    def _detect_database(self) -> Optional[str]:
        pkg = self._read_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        py_content = self._read_pyproject_or_requirements().lower()

        found = []
        if "@prisma/client" in deps or (self.root / "prisma").exists():
            found.append("Prisma ORM")
        if "drizzle-orm" in deps:
            found.append("Drizzle ORM")
        if "pg" in deps or "postgres" in deps or "psycopg2" in py_content or "asyncpg" in py_content:
            found.append("PostgreSQL")
        if "mysql" in deps or "mysql2" in deps or "pymysql" in py_content:
            found.append("MySQL")
        if "mongoose" in deps or "mongodb" in deps or "motor" in py_content:
            found.append("MongoDB")
        if "sqlite3" in deps or "better-sqlite3" in deps or "sqlite" in py_content:
            found.append("SQLite")
        if "redis" in deps or "ioredis" in deps or "redis" in py_content:
            found.append("Redis")
        if "sqlalchemy" in py_content:
            found.append("SQLAlchemy")

        return ", ".join(found) if found else None

    def _detect_auth(self) -> Optional[str]:
        pkg = self._read_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        py_content = self._read_pyproject_or_requirements().lower()

        found = []
        if "next-auth" in deps or "@auth/core" in deps:
            found.append("NextAuth / Auth.js")
        if "jsonwebtoken" in deps or "pyjwt" in py_content or "jwt" in py_content:
            found.append("JWT")
        if "passport" in deps:
            found.append("Passport.js")
        if "clerk" in str(deps) or "@clerk/nextjs" in deps:
            found.append("Clerk Auth")
        if "supabase" in str(deps) or "@supabase/supabase-js" in deps:
            found.append("Supabase Auth")
        if "firebase" in str(deps) or "firebase-admin" in deps:
            found.append("Firebase Auth")
        return ", ".join(found) if found else None

    def _detect_package_manager(self) -> Optional[str]:
        if (self.root / "pnpm-lock.yaml").exists():
            return "pnpm"
        if (self.root / "yarn.lock").exists():
            return "yarn"
        if (self.root / "bun.lockb").exists() or (self.root / "bun.lock").exists():
            return "bun"
        if (self.root / "package-lock.json").exists() or (self.root / "package.json").exists():
            return "npm"
        if (self.root / "uv.lock").exists():
            return "uv"
        if (self.root / "poetry.lock").exists():
            return "poetry"
        if (self.root / "requirements.txt").exists():
            return "pip"
        if (self.root / "Cargo.toml").exists():
            return "cargo"
        return None

    def _detect_testing(self) -> Optional[str]:
        pkg = self._read_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        py_content = self._read_pyproject_or_requirements().lower()

        if "vitest" in deps:
            return "Vitest"
        if "jest" in deps:
            return "Jest"
        if "playwright" in deps or "@playwright/test" in deps:
            return "Playwright"
        if "cypress" in deps:
            return "Cypress"
        if "pytest" in py_content or (self.root / "pytest.ini").exists() or (self.root / "conftest.py").exists():
            return "Pytest"
        return None

    def _discover_api_endpoints(self) -> List[str]:
        endpoints: List[str] = []
        # Next.js App Router API routes
        app_dir = self.root / "src" / "app"
        if not app_dir.exists():
            app_dir = self.root / "app"
        if app_dir.exists():
            for route_file in app_dir.glob("**/route.*"):
                rel = route_file.relative_to(app_dir).parent
                endpoints.append(f"/api/{rel.as_posix()}" if not str(rel).startswith("api") else f"/{rel.as_posix()}")

        # Next.js Pages Router API routes
        pages_api = self.root / "pages" / "api"
        if not pages_api.exists():
            pages_api = self.root / "src" / "pages" / "api"
        if pages_api.exists():
            for api_file in pages_api.glob("**/*.*"):
                if api_file.stem != "_app" and api_file.stem != "_document":
                    rel = api_file.relative_to(pages_api.parent)
                    endpoints.append(f"/{rel.with_suffix('').as_posix()}")

        # Python FastAPI / Flask / Express regex search
        pattern = re.compile(r"""(?:app|router)\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
        for py_file in self.root.glob("**/*.py"):
            if not is_ignored_path(py_file, self.root):
                try:
                    text = py_file.read_text(encoding="utf-8", errors="ignore")
                    matches = pattern.findall(text)
                    for m in matches:
                        if m not in endpoints:
                            endpoints.append(m)
                except Exception:
                    pass

        for js_file in list(self.root.glob("**/*.js")) + list(self.root.glob("**/*.ts")):
            if not is_ignored_path(js_file, self.root):
                try:
                    text = js_file.read_text(encoding="utf-8", errors="ignore")
                    matches = pattern.findall(text)
                    for m in matches:
                        if m not in endpoints:
                            endpoints.append(m)
                except Exception:
                    pass

        return sorted(list(set(endpoints)))


def is_ignored_path(p: Path, root: Path) -> bool:
    try:
        rel = p.relative_to(root)
        for part in rel.parts:
            if part in {"node_modules", ".git", ".next", "dist", "build", ".venv", "venv", "__pycache__"}:
                return True
    except Exception:
        return True
    return False

