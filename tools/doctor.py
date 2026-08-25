#!/usr/bin/env python3
"""
Cybergrok System Diagnostics & Health Check (Doctor)
Cross-platform environment inspector and auto-repair utility.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            _ = reconfigure(encoding="utf-8", errors="replace")


def print_header(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")


def print_status(status: str, msg: str, detail: str = "") -> None:
    badge_map = {
        "ok": f"{GREEN}[OK]{RESET}",
        "warn": f"{YELLOW}[WARN]{RESET}",
        "fail": f"{RED}[FAIL]{RESET}",
        "fixed": f"{CYAN}[FIXED]{RESET}",
    }
    badge = badge_map.get(status.lower(), f"[{status.upper()}]")
    detail_str = f" ({detail})" if detail else ""
    print(f"  {badge} {msg}{detail_str}")


def check_python() -> tuple[int, int, int]:
    print_header("1. Python Environment")
    passed, warns, fails = 0, 0, 0

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    required = (3, 14)
    current = (int(sys.version_info.major), int(sys.version_info.minor))
    if current >= required:
        print_status("ok", "Python Version", f"{py_ver} >= 3.14")
        passed += 1
    else:
        print_status("fail", "Python Version", f"{py_ver} (Requires 3.14+)")
        fails += 1

    in_venv = hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    )
    if in_venv:
        print_status("ok", "Virtual Environment", "Active")
        passed += 1
    else:
        print_status("warn", "Virtual Environment", "Not active in current shell")
        warns += 1

    core_pkgs = ["requests", "yaml", "jinja2", "rich", "markdown"]
    for pkg in core_pkgs:
        try:
            __import__(pkg)
            print_status("ok", f"Package '{pkg}'", "Installed")
            passed += 1
        except ImportError:
            print_status("warn", f"Package '{pkg}'", "Not installed")
            warns += 1

    return passed, warns, fails


def check_directories(root_dir: Path, auto_fix: bool = False) -> tuple[int, int, int]:
    print_header("2. Workspace Directories & Permissions")
    passed, warns, fails = 0, 0, 0
    dirs = ["reports", "recon", "output", "logs", "targets", "skills", "tools/bin"]

    for d in dirs:
        dir_path = root_dir / d
        if not dir_path.exists():
            if auto_fix:
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    print_status("fixed", f"Directory '{d}'", "Created")
                    passed += 1
                except Exception as e:
                    print_status("fail", f"Directory '{d}'", f"Failed to create: {e}")
                    fails += 1
            else:
                print_status("fail", f"Directory '{d}'", "Missing (Use --fix to create)")
                fails += 1
        else:
            try:
                test_file = dir_path / ".perm_test"
                _ = test_file.write_text("test", encoding="utf-8")
                test_file.unlink()
                print_status("ok", f"Directory '{d}'", "Writable")
                passed += 1
            except Exception as e:
                print_status("fail", f"Directory '{d}'", f"Not writable: {e}")
                fails += 1

    return passed, warns, fails


def check_config(root_dir: Path, auto_fix: bool = False) -> tuple[int, int, int]:
    print_header("3. Grok Build Plugin & Runtimes")
    passed, warns, fails = 0, 0, 0

    plugin = root_dir / "plugin.json"
    agents = root_dir / "AGENTS.md"
    session_agent = root_dir / ".grok" / "agents" / "cybergrok.md"
    project_plugin = root_dir / ".grok" / "plugins" / "cybergrok" / "plugin.json"
    py_pkg = root_dir / "python" / "cybergrok" / "rpc.py"

    for label, path in (
        ("plugin.json", plugin),
        ("session agent .grok/agents/cybergrok.md", session_agent),
        ("project plugin .grok/plugins/cybergrok", project_plugin),
        ("AGENTS.md", agents),
        ("Python core (python/cybergrok)", py_pkg),
    ):
        if path.exists():
            print_status("ok", label, str(path.relative_to(root_dir)))
            passed += 1
        else:
            print_status("fail", label, "Missing")
            fails += 1

    if shutil.which("grok"):
        print_status("ok", "Grok Build CLI", "grok on PATH")
        passed += 1
    else:
        print_status("warn", "Grok Build CLI", "Not on PATH — install grok to run the agent")
        warns += 1

    env_file = root_dir / ".env"
    if env_file.is_file():
        print_status("ok", "Environment File (.env)", "Present")
        passed += 1
    elif auto_fix and (root_dir / ".env.example").exists():
        _ = shutil.copy(root_dir / ".env.example", env_file)
        print_status("fixed", "Environment File (.env)", "Generated from .env.example")
        passed += 1
    else:
        print_status("warn", "Environment File (.env)", "Optional; copy from .env.example")
        warns += 1

    return passed, warns, fails


def check_tools(root_dir: Path, auto_fix: bool = False) -> tuple[int, int, int]:
    print_header("4. Security Toolchain Availability")
    passed, warns, fails = 0, 0, 0

    extra = [root_dir / "tools" / "bin", root_dir / "venv" / "bin", root_dir / "venv" / "Scripts"]
    sep = ";" if sys.platform == "win32" else ":"
    prefix = sep.join(str(p) for p in extra if p.is_dir())
    if prefix:
        os.environ["PATH"] = f"{prefix}{sep}{os.environ.get('PATH', '')}"

    tools = [
        ("smart_pipe", "Stream Output Filter (Python)"),
        ("secret_scan", "Secret Scanner (Python)"),
        ("search_knowledge", "Offline Knowledge Search (Python)"),
        ("aggregate_reports", "Report Aggregator (Python)"),
        ("subfinder", "Subdomain Discovery"),
        ("httpx", "HTTP Prober"),
        ("katana", "Web Crawler"),
        ("nuclei", "Vulnerability Scanner"),
    ]

    missing_tools: list[str] = []
    for name, desc in tools:
        found = shutil.which(name) or (sys.platform == "win32" and shutil.which(f"{name}.exe"))
        if found:
            print_status("ok", f"Tool: {name}", desc)
            passed += 1
        else:
            print_status("warn", f"Tool: {name}", f"{desc} not found")
            warns += 1
            missing_tools.append(name)

    if missing_tools and auto_fix:
        print(f"\n  {CYAN}⚡ Attempting automatic toolchain download...{RESET}")
        if sys.platform == "win32":
            updater = root_dir / "tools" / "update_tools.ps1"
            if updater.exists():
                _ = subprocess.run(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(updater)],
                    check=False,
                )
        else:
            updater = root_dir / "tools" / "update_tools.sh"
            if updater.exists():
                _ = subprocess.run(["bash", str(updater)], check=False)

    return passed, warns, fails


class _DoctorArgs(argparse.Namespace):
    fix: bool = False


def main() -> None:
    parser = argparse.ArgumentParser(description="Cybergrok Diagnostics & Health Check")
    _ = parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically repair missing directories, configs, and toolchain",
    )
    args = parser.parse_args(namespace=_DoctorArgs())

    root_dir = Path(__file__).resolve().parent.parent
    os.chdir(root_dir)

    print_header("🛡️  Cybergrok System Diagnostics & Health Check")
    print(f"System: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Directory: {root_dir}")
    if args.fix:
        print(f"Mode: {CYAN}Auto-Repair Enabled (--fix){RESET}")

    p1, w1, f1 = check_python()
    p2, w2, f2 = check_directories(root_dir, auto_fix=args.fix)
    p3, w3, f3 = check_config(root_dir, auto_fix=args.fix)
    p4, w4, f4 = check_tools(root_dir, auto_fix=args.fix)

    total_pass = p1 + p2 + p3 + p4
    total_warn = w1 + w2 + w3 + w4
    total_fail = f1 + f2 + f3 + f4

    print_header("Diagnostics Summary")
    print(f"  {GREEN}Passed Checks:{RESET}   {total_pass}")
    print(f"  {YELLOW}Warnings:{RESET}        {total_warn}")
    print(f"  {RED}Failures:{RESET}        {total_fail}\n")

    if total_fail == 0:
        print(f"  {GREEN}{BOLD}✓ System is healthy and ready to run Cybergrok!{RESET}\n")
    else:
        print(
            f"  {RED}{BOLD}! Some requirements need attention. Run with --fix or check setup guide.{RESET}\n"
        )


if __name__ == "__main__":
    main()
