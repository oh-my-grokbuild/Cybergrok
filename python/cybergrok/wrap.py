"""Fail-closed wrappers: extract URLs from recon tool argv and check scope."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

from .paths import find_workspace_root
from .scope import ScopeError, find_scope_config, validate_target

NETWORK_TOOLS = {"curl", "httpx", "katana", "ffuf", "nuclei", "subfinder", "gau"}


def _looks_url(raw: str) -> bool:
    if raw.startswith(("http://", "https://")):
        return True
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    return bool(parsed.hostname) and ("." in parsed.hostname or parsed.hostname == "localhost")


def extract_targets(tool: str, argv: list[str]) -> list[str]:
    found: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in {"-u", "--u", "-url", "--url", "-d", "--domain"} and i + 1 < len(argv):
            found.append(argv[i + 1])
            i += 2
            continue
        if arg.startswith(("-u=", "--url=", "-d=")):
            found.append(arg.split("=", 1)[1])
            i += 1
            continue
        if arg.startswith(("http://", "https://")):
            found.append(arg)
        i += 1
    if tool == "subfinder" and not found:
        for i, arg in enumerate(argv):
            if arg in {"-d", "--domain"} and i + 1 < len(argv):
                found.append(argv[i + 1])
    return found


def check_targets(targets: list[str], workspace: Path) -> tuple[bool, str]:
    try:
        cfg, _ = find_scope_config(workspace)
    except ScopeError as exc:
        return False, str(exc)
    if not targets:
        return False, "no URL/host found in command; refusing unscoped network tool"
    for raw in targets:
        result = validate_target(raw, cfg)
        if not result.allowed:
            return False, result.reason or f"out of scope: {raw}"
    return True, ""


def main_wrap(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("Usage: cybergrok wrap <tool> -- <args...>", file=sys.stderr)
        return 2
    tool = Path(argv[0]).name
    rest = argv[1:]
    if rest[:1] == ["--"]:
        rest = rest[1:]
    workspace = find_workspace_root()
    if tool in NETWORK_TOOLS:
        ok, reason = check_targets(extract_targets(tool, rest), workspace)
        if not ok:
            print(f"cybergrok wrap: blocked {tool}: {reason}", file=sys.stderr)
            return 2
    real = os.environ.get("CYBERGROK_REAL_BIN")
    if not real:
        extras = os.environ.get("PATH", "")
        # Prefer tools/bin after skipping this wrappers dir.
        for folder in extras.split(os.pathsep):
            if not folder or folder.endswith("tools/wrappers"):
                continue
            cand = Path(folder) / tool
            if cand.is_file() and os.access(cand, os.X_OK):
                real = str(cand)
                break
    if not real:
        real = shutil.which(tool)
    if not real:
        print(f"cybergrok wrap: {tool} not found", file=sys.stderr)
        return 127
    os.execv(real, [real, *rest])
    return 127
