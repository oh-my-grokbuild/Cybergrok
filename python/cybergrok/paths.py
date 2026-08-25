"""Plugin vs workspace root discovery."""

from __future__ import annotations

import os
from pathlib import Path


def _looks_like_plugin(path: Path) -> bool:
    return (path / "python" / "cybergrok").is_dir() and (
        (path / "plugin.json").is_file() or (path / "skills").is_dir()
    )


def find_plugin_root(start: Path | None = None) -> Path:
    for env_name in ("CYBERGROK_ROOT", "GROK_PLUGIN_ROOT"):
        raw = os.environ.get(env_name)
        if raw:
            candidate = Path(raw).expanduser().resolve()
            if _looks_like_plugin(candidate):
                return candidate
    start = (start or Path(__file__).resolve()).parent
    for candidate in [start, *start.parents]:
        if _looks_like_plugin(candidate):
            return candidate
    return start.resolve()


def find_workspace_root(start: Path | None = None) -> Path:
    raw = os.environ.get("GROK_WORKSPACE_ROOT") or os.environ.get("CYBERGROK_WORKSPACE")
    if raw:
        return Path(raw).expanduser().resolve()
    start = (start or Path.cwd()).resolve()
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "AGENTS.md").is_file():
            return candidate
    return start


def find_project_root(start: Path | None = None) -> Path:
    """Backward-compatible alias: prefer plugin tree, else workspace."""
    plugin = find_plugin_root(start)
    if _looks_like_plugin(plugin):
        return plugin
    return find_workspace_root(start)


def plugin_dirs(plugin_root: Path) -> dict[str, Path]:
    root = Path(plugin_root)
    return {
        "root": root,
        "knowledge": root / "knowledge",
        "skills": root / "skills",
        "tools": root / "tools",
        "templates": root / "templates",
    }


def workspace_dirs(workspace: Path) -> dict[str, Path]:
    root = Path(workspace)
    return {
        "root": root,
        "reports": root / "reports",
        "recon": root / "recon",
        "output": root / "output",
        "logs": root / "logs",
        "templates": root / "templates",
    }
