from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, List, Set

IGNORE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".turbo",
    "dist",
    "build",
    "out",
    ".idea",
    ".vscode",
    ".DS_Store",
    ".coverage",
}

EXTENSIONS_BY_LANG = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".sh": "Shell",
    ".dockerfile": "Dockerfile",
}


def is_ignored(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for part in rel.parts:
        if part in IGNORE_DIRS or part.startswith(".git"):
            return True
    return False


def discover_files(root_dir: str | Path) -> List[Path]:
    root = Path(root_dir).resolve()
    if not root.is_dir():
        return []

    collected: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".git")]
        current_dir = Path(dirpath)
        for fname in filenames:
            if fname in {".DS_Store", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"} and not fname.startswith(".env"):
                # keep lockfiles for dependency scanning if explicitly checked, but general walk can include or exclude
                pass
            fpath = current_dir / fname
            if not is_ignored(fpath, root):
                collected.append(fpath)
    return collected

