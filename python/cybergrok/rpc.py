"""JSON RPC used by the TypeScript MCP server."""

from __future__ import annotations

import json
from pathlib import Path

from . import crawl, probe, report, scope, search, secrets, skills
from .paths import find_project_root, workspace_dirs


def _root(args: dict) -> Path:
    raw = args.get("workspace") or args.get("root")
    return Path(raw).resolve() if raw else find_project_root()


def dispatch(op: str, args: dict | None = None) -> dict:
    args = args or {}
    root = _root(args)
    dirs = workspace_dirs(root)

    if op == "search_knowledge":
        searcher = search.Searcher(dirs["knowledge"], root)
        results = searcher.search(
            args.get("query", ""),
            source=args.get("source", "all"),
            limit=int(args.get("limit") or 3),
            max_chars=int(args.get("max_len") or 1400),
        )
        return {"snippets": [s.to_dict() for s in results], "query": args.get("query", "")}

    if op == "list_skills":
        items = skills.list_skills(dirs["skills"])
        filt = (args.get("filter") or "").lower()
        limit = int(args.get("limit") or 30)
        matched = [
            s for s in items
            if not filt
            or filt in s.name.lower()
            or filt in s.description.lower()
            or filt in s.sources.lower()
        ][:limit]
        return {"total": len(items), "skills": [s.to_dict() for s in matched]}

    if op == "get_skill":
        content = skills.get_skill(dirs["skills"], args.get("skill_name", ""), args.get("section", ""))
        if content is None:
            return {"error": f"Skill '{args.get('skill_name')}' not found"}
        return {"content": content}

    if op == "scan_secrets":
        findings: list[secrets.Finding] = []
        if args.get("content"):
            findings = secrets.scan_text(args["content"], "raw_content")
        elif args.get("path"):
            target = Path(args["path"])
            if not target.is_absolute():
                target = root / target
            findings = secrets.scan_directory(target) if target.is_dir() else secrets.scan_file(target)
        else:
            return {"error": "Either content or path is required"}
        filtered = secrets.filter_by_severity(findings, args.get("min_severity") or "low")
        payload = [f.to_dict() for f in filtered]
        if args.get("mask_secrets", True):
            for item in payload:
                item["match"] = secrets.mask_secret(item["match"])
        return {"total": len(findings), "reported": len(filtered), "findings": payload}

    if op == "validate_scope":
        cfg, _path = scope.find_scope_config(root, args.get("target_slug") or "")
        result = scope.validate_target(args.get("target", ""), cfg)
        return result.to_dict()

    if op == "http_probe":
        cfg, _ = scope.find_scope_config(root, args.get("target_slug") or "")
        val = scope.validate_target(args.get("target_url", ""), cfg)
        if not val.allowed:
            return {"error": f"Scope Guard Violation: {val.reason}"}
        result = probe.probe_target(
            args.get("target_url", ""),
            timeout=int(args.get("timeout_seconds") or 10),
            follow_redirects=bool(args.get("follow_redirects")),
            tools_dir=dirs["tools"],
            prefer_httpx=args.get("prefer_httpx", True),
        )
        return result.to_dict()

    if op == "recon_crawl":
        target_url = args.get("target_url", "")
        slug = args.get("target_slug") or report.sanitize_slug(target_url)
        cfg, _ = scope.find_scope_config(root, slug)
        val = scope.validate_target(target_url, cfg)
        if not val.allowed:
            return {"error": f"Scope Guard Violation: {val.reason}"}
        result = crawl.crawl_target(
            target_url,
            depth=int(args.get("depth") or 2),
            max_endpoints=int(args.get("max_endpoints") or 25),
            timeout=int(args.get("timeout_seconds") or 30),
            tools_dir=dirs["tools"],
            output_dir=root / "recon" / slug,
            prefer_katana=args.get("prefer_katana", True),
        )
        return result.to_dict()

    if op == "aggregate_report":
        slug = (args.get("target_slug") or "").strip()
        if not slug or slug.lower() == "all":
            results = report.aggregate_all(dirs["reports"])
            return {"results": [r.to_dict() for r in results]}
        target_dir = dirs["reports"] / slug
        target_dir.mkdir(parents=True, exist_ok=True)
        return report.aggregate_target(target_dir).to_dict()

    if op == "list_findings":
        slug = (args.get("target_slug") or "").strip()
        target_dir = dirs["reports"] / slug
        if not target_dir.is_dir():
            return {"error": f"Report directory for target '{slug}' does not exist."}
        return report.aggregate_target(target_dir).to_dict()

    if op == "record_finding":
        return report.record_finding(
            dirs["reports"],
            args.get("target_slug", ""),
            args.get("severity", "medium"),
            args.get("title", ""),
            args.get("endpoint", ""),
            args.get("description", ""),
            args.get("reproduction_steps", ""),
            args.get("poc_script", ""),
            args.get("remediation", "Implement strict authorization checks and validate user access permissions."),
        )

    return {"error": f"Unknown operation: {op}"}


def run_rpc_payload(payload: dict) -> dict:
    op = payload.get("op") or payload.get("operation") or ""
    try:
        result = dispatch(op, payload.get("args") or {})
        if isinstance(result, dict) and result.get("error"):
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001 — surface to MCP
        return {"ok": False, "error": str(exc)}


def loads_and_run(raw: str) -> str:
    payload = json.loads(raw)
    return json.dumps(run_rpc_payload(payload), indent=2)
