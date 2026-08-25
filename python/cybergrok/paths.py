"""Project-root discovery and standard workspace paths."""

from __future__ import annotations

from pathlib import Path


def find_project_root(start: Path | None = None) -> Path:
    start = (start or Path.cwd()).resolve()
    for candidate in [start, *start.parents]:
        if (candidate / "AGENTS.md").is_file() or (candidate / "plugin.json").is_file():
            return candidate
    return start


def workspace_dirs(root: Path) -> dict[str, Path]:
    return {
        "root": root,
        "knowledge": root / "knowledge",
        "skills": root / "skills",
        "reports": root / "reports",
        "recon": root / "recon",
        "tools": root / "tools",
        "templates": root / "templates",
    }
