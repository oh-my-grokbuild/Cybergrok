"""CLI entry points for Cybergrok Python tools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report, search, secrets, stream
from .paths import find_plugin_root, find_workspace_root
from .rpc import loads_and_run
from .wrap import main_wrap


def _safe_cli_slug(raw: str) -> str:
    slug = report.sanitize_slug(raw)
    if not slug or slug in {".", ".."} or "/" in slug or "\\" in slug:
        raise ValueError("invalid target slug")
    return slug


def main_smart_pipe(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smart_pipe")
    parser.add_argument("--target", "-t", default="default_target")
    parser.add_argument("--tool", "-n", default="tool")
    parser.add_argument("--limit", "-l", type=int, default=40)
    args = parser.parse_args(argv)
    if sys.stdin.isatty():
        print("Usage: <tool_command> | smart_pipe --target <SLUG> --tool <TOOL>", file=sys.stderr)
        return 1
    root = find_workspace_root()
    try:
        slug = _safe_cli_slug(args.target)
        tool = _safe_cli_slug(args.tool)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    dest_dir = root / "recon" / slug
    dest_dir.mkdir(parents=True, exist_ok=True)
    raw_path = dest_dir / f"{tool}_raw.txt"
    with raw_path.open("w", encoding="utf-8") as raw_out:
        stream.process_stream(sys.stdin, sys.stdout, raw_out, args.limit)
    try:
        rel = raw_path.relative_to(root)
    except ValueError:
        rel = raw_path
    print(f"💾 Full raw output preserved: {rel}")
    return 0


def main_secret_scan(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secret_scan")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)
    findings: list[secrets.Finding] = []
    if not args.paths:
        if sys.stdin.isatty():
            print(
                'Usage: echo "<content>" | secret_scan OR secret_scan <file1> <dir/> ...',
                file=sys.stderr,
            )
            return 2
        findings = secrets.scan_text(sys.stdin.read(), "<stdin>")
    else:
        for raw in args.paths:
            p = Path(raw)
            if p.is_dir():
                findings.extend(secrets.scan_directory(p))
            elif p.is_file():
                findings.extend(secrets.scan_file(p))
    for item in findings:
        payload = item.to_dict()
        payload["match"] = secrets.mask_secret(payload["match"])
        print(json.dumps(payload))
    return 0


def main_search_knowledge(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="search_knowledge")
    parser.add_argument("query", nargs="+")
    parser.add_argument("--source", "-s", default="all")
    parser.add_argument("--limit", "-l", "-n", type=int, default=3)
    parser.add_argument("--max-len", "-m", type=int, default=1400)
    parser.add_argument("--json", "-j", action="store_true")
    args = parser.parse_args(argv)
    query = " ".join(args.query)
    root = find_plugin_root()
    results = search.Searcher(root / "knowledge", root).search(
        query, args.source, args.limit, args.max_len
    )
    if args.json:
        print(
            json.dumps(
                {
                    "query": query,
                    "source": args.source,
                    "total_results": len(results),
                    "results": [r.to_dict() for r in results],
                },
                indent=2,
            )
        )
        return 0
    if not results:
        print(f"🔍 [Knowledge Search] No relevant knowledge found for query: '{query}'")
        return 0
    print("\n📚 ══════════════════════════════════════════════════════════════════")
    print(f"   CYBERGROK KNOWLEDGE BASE SEARCH: '{query}'")
    print(f"   Found {len(results)} high-signal snippets (Ranked by relevance)")
    print("══════════════════════════════════════════════════════════════════════")
    for i, res in enumerate(results, start=1):
        print(f"─── [Result #{i} | Score: {res.score}] ──────────────────────────────────────────")
        print(f"📂 KB Source : [{res.source_kb}]")
        print(f"📄 Location  : {res.file}:{res.start_line}")
        print(f"🏷️ Section   : {res.heading}\n")
        print(res.content)
        print()
    print("💡 Tip: Use '--limit N' or '--source [payloads|hacktricks|claude|strix]' to filter.")
    return 0


def main_aggregate_reports(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aggregate_reports")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--all", "-a", action="store_true")
    args = parser.parse_args(argv)
    root = find_workspace_root()
    reports_dir = root / "reports"
    if args.all:
        results = report.aggregate_all(reports_dir)
        print(f"✓ Successfully aggregated reports for {len(results)} targets.")
        return 0
    if not args.target:
        print("Usage: aggregate_reports <TARGET_SLUG> OR aggregate_reports --all")
        return 1
    try:
        slug = _safe_cli_slug(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    target_dir = reports_dir / slug
    target_dir.mkdir(parents=True, exist_ok=True)
    summary = report.aggregate_target(target_dir)
    print(
        f"✓ [Aggregate Reports] {summary.target} | Confirmed: {summary.total_findings} "
        f"(Crit: {summary.severity_summary['CRITICAL']}, High: {summary.severity_summary['HIGH']}, "
        f"Med: {summary.severity_summary['MEDIUM']}, Low: {summary.severity_summary['LOW']}, "
        f"Info: {summary.severity_summary['INFORMATIONAL']})"
    )
    print(f"  📄 Updated: reports/{summary.target}/SUMMARY.md")
    print(f"  📊 Updated: reports/{summary.target}/metadata.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(
            "Usage: python -m cybergrok <smart_pipe|secret_scan|search_knowledge|aggregate_reports|rpc|wrap> ..."
        )
        return 1
    cmd, rest = argv[0], argv[1:]
    if cmd == "smart_pipe":
        return main_smart_pipe(rest)
    if cmd == "secret_scan":
        return main_secret_scan(rest)
    if cmd in {"search_knowledge", "search"}:
        return main_search_knowledge(rest)
    if cmd in {"aggregate_reports", "report"}:
        return main_aggregate_reports(rest)
    if cmd == "rpc":
        raw = sys.stdin.read() if not rest else rest[0]
        if not raw.strip():
            print(json.dumps({"ok": False, "error": "empty RPC payload"}))
            return 1
        print(loads_and_run(raw))
        return 0
    if cmd == "wrap":
        return main_wrap(rest)
    print(f"Unknown command: {cmd}", file=sys.stderr)
    return 1
