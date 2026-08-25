#!/usr/bin/env python3
"""
scripts/setup_mcp.py — Cybergrok MCP Server Multi-Client Auto-Installer & Config Injector

Instantly detects and wires Cybergrok MCP Server into 11+ AI Clients:
Claude Desktop, Cursor, OpenCode, Windsurf, Cline, Roo Code, Claude Code, Continue, Zed, Kilo, Grok Build, Codex.

Usage:
  python scripts/setup_mcp.py [--all] [--local] [--dry-run] [--force] [--status] [--uninstall]
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import TypedDict

type JsonMap = dict[str, object]


class ServerDef(TypedDict, total=False):
    command: str
    args: list[str]
    env: dict[str, str]
    disabled: bool
    autoApprove: list[str]
    name: str
    transport: str


class ClientDef(TypedDict, total=False):
    id: str
    name: str
    paths: list[Path]
    type: str
    definition: ServerDef | JsonMap


class OpResult(TypedDict):
    status: str
    details: str


class StatusResult(TypedDict):
    installed: bool
    configured: bool
    details: str


def _reconfigure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            _ = reconfigure(encoding="utf-8", errors="replace")


_reconfigure_stdio()

VERSION = "3.0.0"
CYBERGROK_ROOT = Path(__file__).resolve().parent.parent
if str(CYBERGROK_ROOT / "python") not in sys.path:
    sys.path.insert(0, str(CYBERGROK_ROOT / "python"))
from cybergrok import _coerce


def get_local_binary_path() -> str | None:
    is_win = platform.system() == "Windows"
    if is_win:
        candidates = [
            CYBERGROK_ROOT / "scripts" / "cybergrok-mcp.cmd",
            CYBERGROK_ROOT / "mcp" / "launch.cjs",
        ]
    else:
        candidates = [
            CYBERGROK_ROOT / "scripts" / "cybergrok-mcp.sh",
            CYBERGROK_ROOT / "mcp" / "launch.cjs",
        ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def create_backup(file_path: Path) -> str | None:
    if file_path.is_file():
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        bak = file_path.with_name(f"{file_path.name}.bak-{ts}")
        _ = shutil.copy2(file_path, bak)
        return str(bak)
    return None


def safe_read_json(file_path: Path) -> JsonMap | None:
    if not file_path.is_file():
        return None
    try:
        content = file_path.read_text(encoding="utf-8").strip()
        return _coerce.json_object(content) if content else {}
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        return {"_parseError": str(exc)}


def safe_write_json(file_path: Path, data: JsonMap, dry_run: bool) -> bool:
    if dry_run:
        return True
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        _ = handle.write("\n")
    return True


def _child_map(data: JsonMap, key: str) -> JsonMap:
    mapped = _coerce.as_str_map(data.get(key))
    data[key] = mapped
    return mapped


def _client_paths(client: dict[str, object]) -> list[Path]:
    return _coerce.as_paths(client.get("paths"))


def _client_name(client: dict[str, object]) -> str:
    return str(client.get("name") or "")


def _client_id(client: dict[str, object]) -> str:
    return str(client.get("id") or "")


def _child_list(data: JsonMap, key: str) -> list[object]:
    boxed = _coerce.as_objects(data.get(key))
    data[key] = boxed
    return boxed


def get_client_definitions(
    use_local: bool = False, local_bin: str | None = None
) -> list[dict[str, object]]:
    if use_local and not local_bin:
        local_bin = get_local_binary_path()
    home = Path.home()
    is_win = platform.system() == "Windows"
    is_mac = platform.system() == "Darwin"

    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming")) if is_win else home

    launcher = local_bin or get_local_binary_path()
    default_def: ServerDef
    if launcher and launcher.endswith(".cjs"):
        default_def = {
            "command": "node",
            "args": [launcher],
            "env": {"CYBERGROK_ROOT": str(CYBERGROK_ROOT)},
        }
    elif launcher:
        default_def = {
            "command": launcher,
            "args": [],
            "env": {"CYBERGROK_ROOT": str(CYBERGROK_ROOT)},
        }
    else:
        default_def = {
            "command": "node",
            "args": [str(CYBERGROK_ROOT / "mcp" / "launch.cjs")],
            "env": {"CYBERGROK_ROOT": str(CYBERGROK_ROOT)},
        }

    return [
        {
            "id": "claude-desktop",
            "name": "Claude Desktop",
            "paths": [
                appdata / "Claude" / "claude_desktop_config.json"
                if is_win
                else (
                    home
                    / "Library"
                    / "Application Support"
                    / "Claude"
                    / "claude_desktop_config.json"
                    if is_mac
                    else home / ".config" / "Claude" / "claude_desktop_config.json"
                )
            ],
            "type": "json-mcpServers",
            "definition": default_def,
        },
        {
            "id": "cursor",
            "name": "Cursor IDE",
            "paths": [
                home / ".cursor" / "mcp.json",
                Path.cwd() / ".cursor" / "mcp.json",
            ],
            "type": "json-mcpServers",
            "definition": default_def,
        },
        {
            "id": "opencode",
            "name": "OpenCode Interpreter",
            "paths": [
                home / ".config" / "opencode" / "opencode.json",
                home / ".config" / "opencode" / "config.json",
            ],
            "type": "json-mcp_servers",
            "definition": default_def,
        },
        {
            "id": "windsurf",
            "name": "Windsurf IDE (Codeium)",
            "paths": [
                home / ".codeium" / "windsurf" / "mcp_config.json",
            ],
            "type": "json-mcpServers",
            "definition": default_def,
        },
        {
            "id": "cline",
            "name": "Cline (VS Code Extension)",
            "paths": [
                appdata
                / "Code"
                / "User"
                / "globalStorage"
                / "saoudrizwan.claude-dev"
                / "settings"
                / "cline_mcp_settings.json"
                if is_win
                else (
                    home
                    / "Library"
                    / "Application Support"
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "saoudrizwan.claude-dev"
                    / "settings"
                    / "cline_mcp_settings.json"
                    if is_mac
                    else home
                    / ".config"
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "saoudrizwan.claude-dev"
                    / "settings"
                    / "cline_mcp_settings.json"
                )
            ],
            "type": "json-cline",
            "definition": {
                **default_def,
                "disabled": False,
                "autoApprove": [
                    "cybergrok_list_skills",
                    "cybergrok_get_skill",
                ],
            },
        },
        {
            "id": "roo-code",
            "name": "Roo Code (VS Code Extension)",
            "paths": [
                appdata
                / "Code"
                / "User"
                / "globalStorage"
                / "rooveterinaryinc.roo-cline"
                / "settings"
                / "cline_mcp_settings.json"
                if is_win
                else (
                    home
                    / "Library"
                    / "Application Support"
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "rooveterinaryinc.roo-cline"
                    / "settings"
                    / "cline_mcp_settings.json"
                    if is_mac
                    else home
                    / ".config"
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "rooveterinaryinc.roo-cline"
                    / "settings"
                    / "cline_mcp_settings.json"
                )
            ],
            "type": "json-cline",
            "definition": {
                **default_def,
                "disabled": False,
                "autoApprove": [
                    "cybergrok_list_skills",
                    "cybergrok_get_skill",
                ],
            },
        },
        {
            "id": "claude-code",
            "name": "Claude Code CLI",
            "paths": [
                home / ".claude.json",
            ],
            "type": "json-mcpServers",
            "definition": default_def,
        },
        {
            "id": "continue",
            "name": "Continue.dev",
            "paths": [
                home / ".continue" / "config.json",
            ],
            "type": "json-continue",
            "definition": {
                "name": "cybergrok",
                "transport": {
                    "type": "stdio",
                    "command": default_def["command"],
                    "args": default_def["args"],
                },
            },
        },
        {
            "id": "zed",
            "name": "Zed Editor",
            "paths": [
                home / ".config" / "zed" / "settings.json",
                appdata / "Zed" / "settings.json" if is_win else None,
            ],
            "type": "json-zed",
            "definition": default_def,
        },
        {
            "id": "kilo",
            "name": "Kilo Code",
            "paths": [
                home / ".kilo" / "mcp.json",
            ],
            "type": "json-mcpServers",
            "definition": default_def,
        },
        {
            "id": "grok",
            "name": "Grok Build",
            "paths": [
                home / ".grok" / "config.toml",
                CYBERGROK_ROOT / ".grok" / "config.toml",
            ],
            "type": "toml-codex",
            "definition": default_def,
        },
        {
            "id": "codex",
            "name": "Codex CLI",
            "paths": [
                home / ".codex" / "config.toml",
            ],
            "type": "toml-codex",
            "definition": default_def,
        },
    ]


def inject_config(client: dict[str, object], file_path: Path, dry_run: bool) -> OpResult:
    ctype = str(client.get("type") or "")
    cdef_obj = client.get("definition")
    cdef: JsonMap = _coerce.as_str_map(cdef_obj)

    if ctype in ("json-mcpServers", "json-cline"):
        data = safe_read_json(file_path)
        if data and "_parseError" in data:
            return {"status": "error", "details": f"Invalid JSON: {data['_parseError']}"}
        if data is None:
            data = {}
        servers = _child_map(data, "mcpServers")
        if servers.get("cybergrok") == cdef:
            return {"status": "unchanged", "details": "Already up-to-date"}
        servers["cybergrok"] = cdef
        if not dry_run:
            bak = create_backup(file_path)
            _ = safe_write_json(file_path, data, False)
            return {
                "status": "injected",
                "details": f"Updated (backup: {Path(bak).name})" if bak else "Created config",
            }
        return {"status": "dry-run", "details": "Would inject mcpServers.cybergrok"}

    if ctype == "json-mcp_servers":
        data = safe_read_json(file_path)
        if data and "_parseError" in data:
            return {"status": "error", "details": f"Invalid JSON: {data['_parseError']}"}
        if data is None:
            data = {}
        cmd = str(cdef.get("command") or "")
        arg_list = _coerce.as_str_list(cdef.get("args"))
        opencode_entry: JsonMap = {
            "type": "local",
            "command": [cmd, *arg_list],
            "enabled": True,
        }
        if "mcp" in data or ("mcp_servers" not in data and "mcpServers" not in data):
            mcp = _child_map(data, "mcp")
            if mcp.get("cybergrok") == opencode_entry:
                return {"status": "unchanged", "details": "Already up-to-date in mcp"}
            mcp["cybergrok"] = opencode_entry
        else:
            servers = _child_map(data, "mcp_servers")
            if servers.get("cybergrok") == cdef:
                return {"status": "unchanged", "details": "Already up-to-date in mcp_servers"}
            servers["cybergrok"] = cdef
        if not dry_run:
            bak = create_backup(file_path)
            _ = safe_write_json(file_path, data, False)
            return {
                "status": "injected",
                "details": f"Updated (backup: {Path(bak).name})" if bak else "Created config",
            }
        return {"status": "dry-run", "details": "Would inject mcp.cybergrok"}

    if ctype == "json-continue":
        data = safe_read_json(file_path)
        if data and "_parseError" in data:
            return {"status": "error", "details": f"Invalid JSON: {data['_parseError']}"}
        if data is None:
            data = {}
        exp = _child_map(data, "experimental")
        srvs = _child_list(exp, "modelContextProtocolServers")
        idx = next(
            (
                i
                for i, item in enumerate(srvs)
                if _coerce.as_str_map(item).get("name") == "cybergrok"
            ),
            -1,
        )
        if idx >= 0 and srvs[idx] == cdef:
            return {"status": "unchanged", "details": "Already up-to-date"}
        if idx >= 0:
            srvs[idx] = cdef
        else:
            srvs.append(cdef)
        if not dry_run:
            bak = create_backup(file_path)
            _ = safe_write_json(file_path, data, False)
            return {
                "status": "injected",
                "details": f"Updated (backup: {Path(bak).name})" if bak else "Created config",
            }
        return {
            "status": "dry-run",
            "details": "Would inject experimental.modelContextProtocolServers",
        }

    if ctype == "json-zed":
        data = safe_read_json(file_path)
        if data and "_parseError" in data:
            return {"status": "error", "details": f"Invalid JSON: {data['_parseError']}"}
        if data is None:
            data = {}
        ctx = _child_map(data, "context_servers")
        if ctx.get("cybergrok") == cdef:
            return {"status": "unchanged", "details": "Already up-to-date"}
        ctx["cybergrok"] = cdef
        if not dry_run:
            bak = create_backup(file_path)
            _ = safe_write_json(file_path, data, False)
            return {
                "status": "injected",
                "details": f"Updated (backup: {Path(bak).name})" if bak else "Created config",
            }
        return {"status": "dry-run", "details": "Would inject context_servers.cybergrok"}

    if ctype == "yaml-grok":
        content = file_path.read_text(encoding="utf-8") if file_path.is_file() else ""
        if "cybergrok:" in content and ("cybergrok-mcp" in content or "cybergrok-mcp" in content):
            return {"status": "unchanged", "details": "Already up-to-date in YAML"}

        cmd_json = json.dumps(cdef.get("command"))
        args_json = json.dumps(cdef.get("args") or [])
        block = f"\nmcp_servers:\n  cybergrok:\n    command: {cmd_json}\n    args: {args_json}\n"

        if not dry_run:
            bak = create_backup(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "a", encoding="utf-8") as f:
                _ = f.write(block)
            return {
                "status": "injected",
                "details": f"Appended (backup: {Path(bak).name})" if bak else "Created config",
            }
        return {"status": "dry-run", "details": "Would append YAML block"}

    if ctype == "toml-codex":
        content = file_path.read_text(encoding="utf-8") if file_path.is_file() else ""
        if "[mcp_servers.cybergrok]" in content:
            return {"status": "unchanged", "details": "Already up-to-date in TOML"}

        cmd_json = json.dumps(cdef.get("command"))
        arg_list = _coerce.as_str_list(cdef.get("args"))
        args_json = ", ".join(json.dumps(item) for item in arg_list)
        block = f"\n[mcp_servers.cybergrok]\ncommand = {cmd_json}\nargs = [{args_json}]\n"

        if not dry_run:
            bak = create_backup(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "a", encoding="utf-8") as f:
                _ = f.write(block)
            return {
                "status": "injected",
                "details": f"Appended (backup: {Path(bak).name})" if bak else "Created config",
            }
        return {"status": "dry-run", "details": "Would append TOML block"}

    return {"status": "skipped", "details": "Unsupported format"}


def remove_config(client: dict[str, object], file_path: Path, dry_run: bool) -> OpResult:
    if not file_path.is_file():
        return {"status": "not_found", "details": "File does not exist"}

    ctype = client["type"]
    if ctype in ("json-mcpServers", "json-cline"):
        data = safe_read_json(file_path)
        servers = _child_map(data, "mcpServers") if data and "_parseError" not in data else {}
        if not data or "_parseError" in data or "cybergrok" not in servers:
            return {"status": "unchanged", "details": "Cybergrok not present"}
        del servers["cybergrok"]
        if not dry_run:
            bak = create_backup(file_path)
            _ = safe_write_json(file_path, data, False)
            return {
                "status": "removed",
                "details": f"Cleaned (backup: {Path(bak).name})" if bak else "Removed",
            }
        return {"status": "dry-run", "details": "Would remove mcpServers.cybergrok"}

    if ctype == "json-mcp_servers":
        data = safe_read_json(file_path)
        if not data or "_parseError" in data:
            return {"status": "unchanged", "details": "Cybergrok not present"}
        has_removed = False
        mcp = _child_map(data, "mcp")
        if "cybergrok" in mcp:
            del mcp["cybergrok"]
            has_removed = True
        servers = _child_map(data, "mcp_servers")
        if "cybergrok" in servers:
            del servers["cybergrok"]
            has_removed = True
        if not has_removed:
            return {"status": "unchanged", "details": "Cybergrok not present"}
        if not dry_run:
            bak = create_backup(file_path)
            _ = safe_write_json(file_path, data, False)
            return {
                "status": "removed",
                "details": f"Cleaned (backup: {Path(bak).name})" if bak else "Removed",
            }
        return {"status": "dry-run", "details": "Would remove mcp.cybergrok"}

    return {"status": "skipped", "details": "Manual cleanup recommended for YAML/TOML"}


def check_status(client: dict[str, object], file_path: Path | None) -> StatusResult:
    if not file_path or not file_path.is_file():
        return {"installed": False, "configured": False, "details": "Not detected"}

    ctype = str(client.get("type") or "")
    if ctype in ("json-mcpServers", "json-cline"):
        data = safe_read_json(file_path)
        has_cb = bool(data and "cybergrok" in _child_map(data, "mcpServers"))
        return {
            "installed": True,
            "configured": has_cb,
            "details": "Configured" if has_cb else "Detected (Missing Cybergrok)",
        }

    if ctype == "json-mcp_servers":
        data = safe_read_json(file_path)
        has_cb = bool(
            data
            and (
                "cybergrok" in _child_map(data, "mcp")
                or "cybergrok" in _child_map(data, "mcp_servers")
            )
        )
        return {
            "installed": True,
            "configured": has_cb,
            "details": "Configured" if has_cb else "Detected (Missing Cybergrok)",
        }

    if ctype in ("yaml-grok", "toml-codex"):
        content = file_path.read_text(encoding="utf-8")
        has_cb = "cybergrok" in content
        return {
            "installed": True,
            "configured": has_cb,
            "details": "Configured" if has_cb else "Detected (Missing Cybergrok)",
        }

    return {"installed": True, "configured": False, "details": "Detected"}


class _SetupArgs(argparse.Namespace):
    dry_run: bool = False
    local: bool = False
    force: bool = False
    status: bool = False
    uninstall: bool = False
    clients: str | None = None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Cybergrok MCP Universal Multi-Client Auto-Installer v{VERSION}"
    )
    _ = parser.add_argument(
        "--dry-run", action="store_true", help="Simulate execution without modifying files"
    )
    _ = parser.add_argument(
        "--local", action="store_true", help="Use local compiled binary (tools/bin/cybergrok-mcp)"
    )
    _ = parser.add_argument(
        "--force", action="store_true", help="Generate config files even if client not detected"
    )
    _ = parser.add_argument(
        "--status", action="store_true", help="Display client discovery and configuration matrix"
    )
    _ = parser.add_argument(
        "--uninstall", action="store_true", help="Cleanly remove Cybergrok MCP configuration"
    )
    _ = parser.add_argument("--clients", type=str, help="Comma-separated client IDs to target")

    args = parser.parse_args(namespace=_SetupArgs())

    local_bin = get_local_binary_path() if args.local else None
    clients = get_client_definitions(use_local=args.local, local_bin=local_bin)

    filter_list = [c.strip().lower() for c in args.clients.split(",")] if args.clients else None

    if args.status:
        print(f"\n📊 Cybergrok MCP Server — Client Discovery Matrix v{VERSION}")
        print("=" * 70)
        for client in clients:
            valid_paths = _client_paths(client)
            target_path = next(
                (p for p in valid_paths if p.is_file()), valid_paths[0] if valid_paths else None
            )
            st = check_status(client, target_path)
            mark = "✓" if st["configured"] else ("!" if st["installed"] else "-")
            state_str = (
                "[CONFIGURED]"
                if st["configured"]
                else ("[NOT WIRED]" if st["installed"] else "[NOT DETECTED]")
            )
            print(f"  {mark} {_client_name(client):<26} {state_str:<16} {target_path}")
        print("=" * 70)
        print("💡 Run `python scripts/setup_mcp.py` to auto-inject into all un-wired clients.\n")
        return 0

    if args.uninstall:
        print(f"\n🗑️  Cybergrok MCP Server — Uninstaller v{VERSION}")
        print("=" * 70)
        if args.dry_run:
            print("🔍 DRY RUN MODE ACTIVATED — No configuration files will be modified.\n")

        removed = 0
        for client in clients:
            if (
                filter_list
                and _client_id(client) not in filter_list
                and _client_name(client).lower() not in filter_list
            ):
                continue
            valid_paths = _client_paths(client)
            target_path = next((p for p in valid_paths if p.is_file()), None)
            if not target_path:
                continue
            res = remove_config(client, target_path, args.dry_run)
            if res["status"] in ("removed", "dry-run"):
                removed += 1
                print(
                    f"  ✓ {_client_name(client):<26} -> [{res['status'].upper()}] {target_path} ({res['details']})"
                )
        print("=" * 70)
        print(f"✨ Cleanup completed! Removed from {removed} client(s).\n")
        return 0

    # Default: Install / Auto-Inject
    print(f"\n🛡️  Cybergrok MCP Server — Universal Auto-Installer v{VERSION}")
    print("=" * 70)
    if args.dry_run:
        print("🔍 DRY RUN MODE ACTIVATED — No configuration files will be modified.\n")

    injected = 0
    detected = 0

    for client in clients:
        if (
            filter_list
            and _client_id(client) not in filter_list
            and _client_name(client).lower() not in filter_list
        ):
            continue

        valid_paths = _client_paths(client)
        target_path = next((p for p in valid_paths if p.is_file()), None)
        if not target_path:
            if args.force and valid_paths:
                target_path = valid_paths[0]
            else:
                continue

        detected += 1
        res = inject_config(client, target_path, args.dry_run)

        if res["status"] in ("injected", "dry-run"):
            injected += 1
            print(
                f"  ✓ {_client_name(client):<26} -> [{res['status'].upper()}] {target_path} ({res['details']})"
            )
        elif res["status"] == "unchanged":
            print(f"  = {_client_name(client):<26} -> [UNCHANGED] {target_path} ({res['details']})")
        elif res["status"] == "error":
            print(f"  ✗ {_client_name(client):<26} -> [ERROR] {target_path} ({res['details']})")

    print("=" * 70)
    print(f"🎉 Auto-installer finished! Evaluated: {detected}, Updated: {injected}")
    print("💡 Note: Restart your AI client (Cursor, Claude, Windsurf, etc.) to reload MCP tools.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
