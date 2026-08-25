"""Fail-closed wrappers: extract URLs from recon tool argv and check scope."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

from .netguard import IMDS_HOSTS, UnsafeURL, assert_safe_url, normalize_http_url
from .scope import ScopeError, allow_private_for_target, find_scope_config, validate_target

NETWORK_TOOLS = {"curl", "httpx", "katana", "ffuf", "nuclei", "subfinder", "gau"}

# Flags that change the TCP hop or load extra URL lists. Refuse rather than parse.
_REFUSED_FLAGS = {
    "--resolve",
    "--connect-to",
    "--unix-socket",
    "--abstract-unix-socket",
    "-x",
    "--proxy",
    "--preproxy",
    "--socks4",
    "--socks4a",
    "--socks5",
    "--socks5-hostname",
    "--https-proxy",
    "-K",
    "--config",
    "-l",
    "--list",
    "-list",
    "-http-proxy",
}

_URL_VALUE_FLAGS: dict[str, set[str]] = {
    "curl": {"--url"},
    "httpx": {"-u", "--u", "-url", "--url", "-d", "--domain"},
    "nuclei": {"-u", "--u", "-url", "--url", "-target", "--target"},
    "katana": {"-u", "--u", "-url", "--url"},
    "ffuf": {"-u", "--u", "-url", "--url"},
    "subfinder": {"-d", "--domain"},
    "gau": set[str](),
}

_URL_EQ_PREFIXES = {
    "curl": ("--url=",),
    "httpx": ("-u=", "--url=", "-d="),
    "nuclei": ("-u=", "--url=", "-target="),
    "katana": ("-u=", "--url="),
    "ffuf": ("-u=", "--url="),
    "subfinder": ("-d=", "--domain="),
    "gau": (),
}


def _flag_name(arg: str) -> str:
    if "=" in arg and arg.startswith("-"):
        return arg.split("=", 1)[0]
    return arg


def refused_flags(argv: list[str]) -> str | None:
    for arg in argv:
        name = _flag_name(arg)
        if name in _REFUSED_FLAGS:
            return name
    return None


def extract_targets(tool: str, argv: list[str]) -> list[str]:
    found: list[str] = []
    flags = _URL_VALUE_FLAGS.get(tool, {"-u", "--url"})
    eq_prefixes = _URL_EQ_PREFIXES.get(tool, ("-u=", "--url="))
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in flags and i + 1 < len(argv):
            found.append(argv[i + 1])
            i += 2
            continue
        if arg.startswith(eq_prefixes):
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
    except ValueError as exc:
        return False, str(exc)
    if not targets:
        return False, "no URL/host found in command; refusing unscoped network tool"
    for raw in targets:
        result = validate_target(raw, cfg)
        if not result.allowed:
            return False, result.reason or f"out of scope: {raw}"
        try:
            parsed = urlparse(normalize_http_url(raw))
        except UnsafeURL as exc:
            return False, str(exc)
        host = (parsed.hostname or "").lower()
        if host in IMDS_HOSTS:
            return False, f"blocked metadata host '{host}'"
        try:
            _ = ipaddress.ip_address(host)
        except ValueError:
            continue
        try:
            _ = assert_safe_url(raw, allow_private=allow_private_for_target(raw, cfg))
        except UnsafeURL as exc:
            return False, str(exc)
    return True, ""


def is_wrapper_dir(folder: str) -> bool:
    norm = folder.replace("\\", "/").rstrip("/")
    return norm.endswith("tools/wrappers")


def is_wrapper_path(path: Path) -> bool:
    parts = [part.replace("\\", "/") for part in path.resolve().parts]
    return any(
        parts[index] == "tools" and parts[index + 1] == "wrappers"
        for index in range(len(parts) - 1)
    )


def find_real_binary(tool: str) -> str | None:
    pinned = os.environ.get("CYBERGROK_REAL_BIN")
    if pinned:
        candidate = Path(pinned)
        if candidate.is_file() and not is_wrapper_path(candidate):
            return str(candidate.resolve())
    names = (tool, f"{tool}.exe") if os.name == "nt" else (tool,)
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if not folder or is_wrapper_dir(folder):
            continue
        for name in names:
            cand = Path(folder) / name
            if cand.is_file() and os.access(cand, os.X_OK) and not is_wrapper_path(cand):
                return str(cand.resolve())
    which = shutil.which(tool)
    if which and not is_wrapper_path(Path(which)):
        return which
    return None


def wrap_workspace() -> Path:
    """Ignore agent-set GROK_WORKSPACE_ROOT; wrap follows cwd / repo markers."""
    start = Path.cwd().resolve()
    for candidate in [start, *start.parents]:
        if (
            (candidate / ".git").exists()
            or (candidate / "AGENTS.md").is_file()
            or (candidate / "scope.yaml").is_file()
            or (candidate / "scope.yml").is_file()
        ):
            return candidate
    return start


def main_wrap(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("Usage: cybergrok wrap <tool> -- <args...>", file=sys.stderr)
        return 2
    tool = Path(argv[0]).name
    rest = argv[1:]
    if rest[:1] == ["--"]:
        rest = rest[1:]
    workspace = wrap_workspace()
    if tool in NETWORK_TOOLS:
        blocked = refused_flags(rest)
        if blocked:
            print(
                f"cybergrok wrap: blocked {tool}: refusing flag {blocked} "
                + "(connection override or extra URL file)",
                file=sys.stderr,
            )
            return 2
        ok, reason = check_targets(extract_targets(tool, rest), workspace)
        if not ok:
            print(f"cybergrok wrap: blocked {tool}: {reason}", file=sys.stderr)
            return 2
    real = find_real_binary(tool)
    if not real:
        print(f"cybergrok wrap: {tool} not found", file=sys.stderr)
        return 127
    return _exec(real, rest)


def _exec(real: str, rest: list[str]) -> int:
    with contextlib.suppress(OSError):
        os.execv(real, [real, *rest])
    return 127
