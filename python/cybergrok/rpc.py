"""JSON RPC used by the TypeScript MCP server."""

from __future__ import annotations

import json
from pathlib import Path

from . import crawl, probe, report, scope, search, secrets, skills
from .netguard import UnsafeURL
from .paths import find_plugin_root, find_workspace_root, plugin_dirs, workspace_dirs
from .scope import ScopeError


def _plugin_root(args: dict) -> Path:
    raw = args.get("plugin_root")
    if raw:
        return Path(raw).expanduser().resolve()
    return find_plugin_root()


def _workspace(args: dict) -> Path:
    raw = args.get("workspace") or args.get("root")
    if raw:
        return Path(raw).expanduser().resolve()
    return find_workspace_root()


def _safe_slug(raw: str) -> str:
    slug = report.sanitize_slug(raw)
    if not slug or slug in {".", ".."} or "/" in slug or "\\" in slug:
        raise ValueError("invalid target_slug")
    return slug


def _confine(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"path '{path}' is outside the workspace") from exc
    return resolved


def dispatch(op: str, args: dict | None = None) -> dict:
    args = args or {}
    plugin = _plugin_root(args)
    workspace = _workspace(args)
    pdirs = plugin_dirs(plugin)
    wdirs = workspace_dirs(workspace)

    if op == "search_knowledge":
        searcher = search.Searcher(pdirs["knowledge"], plugin)
        results = searcher.search(
            args.get("query", ""),
            source=args.get("source", "all"),
            limit=int(args.get("limit") or 3),
            max_chars=int(args.get("max_len") or 1400),
        )
        return {"snippets": [s.to_dict() for s in results], "query": args.get("query", "")}

    if op == "list_skills":
        items = skills.list_skills(pdirs["skills"])
        filt = (args.get("filter") or "").lower()
        limit = int(args.get("limit") or 30)
        matched = [
            s
            for s in items
            if not filt
            or filt in s.name.lower()
            or filt in s.description.lower()
            or filt in s.sources.lower()
        ][:limit]
        return {"total": len(items), "skills": [s.to_dict() for s in matched]}

    if op == "get_skill":
        content = skills.get_skill(pdirs["skills"], args.get("skill_name", ""), args.get("section", ""))
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
                target = workspace / target
            try:
                target = _confine(target, workspace)
            except ValueError as exc:
                return {"error": str(exc)}
            allowed = {wdirs["recon"].resolve(), wdirs["reports"].resolve(), workspace.resolve()}
            if not any(str(target).startswith(str(a)) for a in allowed):
                return {"error": "scan_secrets path must be under the workspace recon/ or reports/ tree"}
            findings = secrets.scan_directory(target) if target.is_dir() else secrets.scan_file(target)
        else:
            return {"error": "Either content or path is required"}
        filtered = secrets.filter_by_severity(findings, args.get("min_severity") or "low")
        payload = [f.to_dict() for f in filtered]
        for item in payload:
            item["match"] = secrets.mask_secret(item["match"])
        return {"total": len(findings), "reported": len(filtered), "findings": payload}

    if op == "validate_scope":
        try:
            cfg, _path = scope.find_scope_config(workspace, _safe_slug(args.get("target_slug") or "target") if args.get("target_slug") else "")
        except ScopeError as exc:
            return {"error": str(exc), "allowed": False}
        except ValueError:
            cfg, _path = scope.find_scope_config(workspace, "")
        result = scope.validate_target(args.get("target", ""), cfg)
        return result.to_dict()

    if op == "http_probe":
        try:
            cfg, _ = scope.find_scope_config(workspace, args.get("target_slug") or "")
        except ScopeError as exc:
            return {"error": str(exc)}
        val = scope.validate_target(args.get("target_url", ""), cfg)
        if not val.allowed:
            return {"error": f"Scope Guard Violation: {val.reason}"}
        allow_private = bool(cfg.allow_ips) if cfg else False
        try:
            result = probe.probe_target(
                args.get("target_url", ""),
                timeout=int(args.get("timeout_seconds") or 10),
                follow_redirects=bool(args.get("follow_redirects")),
                tools_dir=pdirs["tools"],
                prefer_httpx=args.get("prefer_httpx", True),
                allow_private=allow_private,
            )
        except (UnsafeURL, RuntimeError) as exc:
            return {"error": str(exc)}
        if result.url:
            again = scope.validate_target(result.url, cfg)
            if not again.allowed:
                return {"error": f"Scope Guard Violation after redirect: {again.reason}"}
        return result.to_dict()

    if op == "recon_crawl":
        target_url = args.get("target_url", "")
        try:
            slug = _safe_slug(args.get("target_slug") or report.sanitize_slug(target_url))
        except ValueError as exc:
            return {"error": str(exc)}
        try:
            cfg, _ = scope.find_scope_config(workspace, slug)
        except ScopeError as exc:
            return {"error": str(exc)}
        val = scope.validate_target(target_url, cfg)
        if not val.allowed:
            return {"error": f"Scope Guard Violation: {val.reason}"}
        allow_private = bool(cfg.allow_ips) if cfg else False
        recon_dir = _confine(wdirs["recon"] / slug, workspace)
        try:
            result = crawl.crawl_target(
                target_url,
                depth=int(args.get("depth") or 2),
                max_endpoints=int(args.get("max_endpoints") or 25),
                timeout=int(args.get("timeout_seconds") or 30),
                tools_dir=pdirs["tools"],
                output_dir=recon_dir,
                prefer_katana=args.get("prefer_katana", True),
                allow_private=allow_private,
            )
        except (UnsafeURL, RuntimeError) as exc:
            return {"error": str(exc)}
        return result.to_dict()

    if op == "aggregate_report":
        raw_slug = (args.get("target_slug") or "").strip()
        if not raw_slug or raw_slug.lower() == "all":
            results = report.aggregate_all(wdirs["reports"])
            return {"results": [r.to_dict() for r in results]}
        try:
            slug = _safe_slug(raw_slug)
        except ValueError as exc:
            return {"error": str(exc)}
        target_dir = _confine(wdirs["reports"] / slug, workspace)
        target_dir.mkdir(parents=True, exist_ok=True)
        return report.aggregate_target(target_dir).to_dict()

    if op == "list_findings":
        try:
            slug = _safe_slug(args.get("target_slug") or "")
        except ValueError as exc:
            return {"error": str(exc)}
        target_dir = _confine(wdirs["reports"] / slug, workspace)
        if not target_dir.is_dir():
            return {"error": f"Report directory for target '{slug}' does not exist."}
        return report.aggregate_target(target_dir).to_dict()

    if op == "record_finding":
        return report.record_finding(
            wdirs["reports"],
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
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def loads_and_run(raw: str) -> str:
    payload = json.loads(raw)
    return json.dumps(run_rpc_payload(payload), indent=2)
