"""JSON RPC used by the TypeScript MCP server."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import crawl, probe, report, scope, search, secrets, skills
from .netguard import UnsafeURL, assert_safe_url
from .paths import find_plugin_root, find_workspace_root, plugin_dirs, workspace_dirs
from .scope import ScopeError

_DEFAULT_REMEDIATION = "Implement strict authorization checks and validate user access permissions."


@dataclass(frozen=True)
class _RpcEnv:
    plugin: Path
    workspace: Path
    pdirs: dict[str, Path]
    wdirs: dict[str, Path]


def _plugin_root(args: dict[str, Any]) -> Path:
    raw = args.get("plugin_root")
    if raw:
        return Path(raw).expanduser().resolve()
    return find_plugin_root()


def _workspace(args: dict[str, Any]) -> Path:
    pinned = os.environ.get("GROK_WORKSPACE_ROOT") or os.environ.get("CYBERGROK_WORKSPACE")
    if pinned:
        return Path(pinned).expanduser().resolve()
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


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _guard_url(raw: str, cfg: scope.ScopeConfig | None) -> str:
    val = scope.validate_target(raw, cfg)
    if not val.allowed:
        raise UnsafeURL(val.reason or "out of scope")
    return assert_safe_url(raw, allow_private=scope.allow_private_for_target(raw, cfg))


def _optional_slug(raw: object) -> str:
    if not raw:
        return ""
    return _safe_slug(str(raw))


def _op_search_knowledge(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    searcher = search.Searcher(env.pdirs["knowledge"], env.plugin)
    results = searcher.search(
        args.get("query", ""),
        source=args.get("source", "all"),
        limit=int(args.get("limit") or 3),
        max_chars=int(args.get("max_len") or 1400),
    )
    return {"snippets": [s.to_dict() for s in results], "query": args.get("query", "")}


def _op_list_skills(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    items = skills.list_skills(env.pdirs["skills"])
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


def _op_get_skill(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    content = skills.get_skill(
        env.pdirs["skills"], args.get("skill_name", ""), args.get("section", "")
    )
    if content is None:
        return {"error": f"Skill '{args.get('skill_name')}' not found"}
    return {"content": content}


def _op_scan_secrets(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    findings: list[secrets.Finding] = []
    if args.get("content"):
        findings = secrets.scan_text(args["content"], "raw_content")
    elif args.get("path"):
        target = Path(args["path"])
        if not target.is_absolute():
            target = env.workspace / target
        try:
            target = _confine(target, env.workspace)
        except ValueError as exc:
            return {"error": str(exc)}
        if not (_under(target, env.wdirs["recon"]) or _under(target, env.wdirs["reports"])):
            return {
                "error": "scan_secrets path must be under the workspace recon/ or reports/ tree"
            }
        if target.is_dir():
            findings = secrets.scan_directory(target, confine_to=target)
        else:
            findings = secrets.scan_file(target)
    else:
        return {"error": "Either content or path is required"}
    filtered = secrets.filter_by_severity(findings, args.get("min_severity") or "low")
    payload = [f.to_dict() for f in filtered]
    for item in payload:
        item["match"] = secrets.mask_secret(item["match"])
    return {"total": len(findings), "reported": len(filtered), "findings": payload}


def _op_validate_scope(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    try:
        slug = _optional_slug(args.get("target_slug"))
    except ValueError:
        slug = ""
    try:
        cfg, _path = scope.find_scope_config(env.workspace, slug)
    except ScopeError as exc:
        return {"error": str(exc), "allowed": False}
    result = scope.validate_target(args.get("target", ""), cfg)
    return result.to_dict()


def _load_scope(env: _RpcEnv, slug: str) -> tuple[scope.ScopeConfig | None, dict[str, Any] | None]:
    try:
        cfg, _ = scope.find_scope_config(env.workspace, slug)
    except ScopeError as exc:
        return None, {"error": str(exc)}
    return cfg, None


def _op_http_probe(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    try:
        slug = _optional_slug(args.get("target_slug"))
    except ValueError as exc:
        return {"error": str(exc)}
    cfg, err = _load_scope(env, slug)
    if err:
        return err
    val = scope.validate_target(args.get("target_url", ""), cfg)
    if not val.allowed:
        return {"error": f"Scope Guard Violation: {val.reason}"}
    allow_private = scope.allow_private_for_target(args.get("target_url", ""), cfg)
    try:
        result = probe.probe_target(
            args.get("target_url", ""),
            timeout=int(args.get("timeout_seconds") or 10),
            follow_redirects=bool(args.get("follow_redirects")),
            tools_dir=env.pdirs["tools"],
            prefer_httpx=bool(args.get("prefer_httpx")),
            allow_private=allow_private,
            guard=lambda url: _guard_url(url, cfg),
        )
    except (UnsafeURL, RuntimeError) as exc:
        return {"error": str(exc)}
    for hop in (result.url, result.redirect_url):
        if not hop:
            continue
        again = scope.validate_target(hop, cfg)
        if not again.allowed:
            return {"error": f"Scope Guard Violation after redirect: {again.reason}"}
    return result.to_dict()


def _op_recon_crawl(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    target_url = args.get("target_url", "")
    try:
        slug = _safe_slug(args.get("target_slug") or report.sanitize_slug(target_url))
    except ValueError as exc:
        return {"error": str(exc)}
    cfg, err = _load_scope(env, slug)
    if err:
        return err
    val = scope.validate_target(target_url, cfg)
    if not val.allowed:
        return {"error": f"Scope Guard Violation: {val.reason}"}
    allow_private = scope.allow_private_for_target(target_url, cfg)
    recon_dir = _confine(env.wdirs["recon"] / slug, env.workspace)
    try:
        result = crawl.crawl_target(
            target_url,
            depth=int(args.get("depth") or 2),
            max_endpoints=int(args.get("max_endpoints") or 25),
            timeout=int(args.get("timeout_seconds") or 30),
            output_dir=recon_dir,
            allow_private=allow_private,
            guard=lambda url: _guard_url(url, cfg),
        )
    except (UnsafeURL, RuntimeError) as exc:
        return {"error": str(exc)}
    return result.to_dict()


def _op_aggregate_report(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    raw_slug = (args.get("target_slug") or "").strip()
    if not raw_slug or raw_slug.lower() == "all":
        results = report.aggregate_all(env.wdirs["reports"], confine_to=env.workspace)
        return {"results": [r.to_dict() for r in results]}
    try:
        slug = _safe_slug(raw_slug)
    except ValueError as exc:
        return {"error": str(exc)}
    target_dir = _confine(env.wdirs["reports"] / slug, env.workspace)
    target_dir.mkdir(parents=True, exist_ok=True)
    return report.aggregate_target(target_dir).to_dict()


def _op_list_findings(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    try:
        slug = _safe_slug(args.get("target_slug") or "")
    except ValueError as exc:
        return {"error": str(exc)}
    target_dir = _confine(env.wdirs["reports"] / slug, env.workspace)
    if not target_dir.is_dir():
        return {"error": f"Report directory for target '{slug}' does not exist."}
    return report.aggregate_target(target_dir).to_dict()


def _op_record_finding(env: _RpcEnv, args: dict[str, Any]) -> dict[str, Any]:
    return report.record_finding(
        env.wdirs["reports"],
        args.get("target_slug", ""),
        args.get("severity", "medium"),
        args.get("title", ""),
        args.get("endpoint", ""),
        args.get("description", ""),
        args.get("reproduction_steps", ""),
        args.get("poc_script", ""),
        args.get("remediation", _DEFAULT_REMEDIATION),
    )


_HANDLERS: dict[str, Callable[[_RpcEnv, dict[str, Any]], dict[str, Any]]] = {
    "search_knowledge": _op_search_knowledge,
    "list_skills": _op_list_skills,
    "get_skill": _op_get_skill,
    "scan_secrets": _op_scan_secrets,
    "validate_scope": _op_validate_scope,
    "http_probe": _op_http_probe,
    "recon_crawl": _op_recon_crawl,
    "aggregate_report": _op_aggregate_report,
    "list_findings": _op_list_findings,
    "record_finding": _op_record_finding,
}

_RPC_ERRORS = (
    UnsafeURL,
    ScopeError,
    ValueError,
    OSError,
    RuntimeError,
    TypeError,
    KeyError,
    json.JSONDecodeError,
)


def dispatch(op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    plugin = _plugin_root(args)
    workspace = _workspace(args)
    env = _RpcEnv(
        plugin=plugin,
        workspace=workspace,
        pdirs=plugin_dirs(plugin),
        wdirs=workspace_dirs(workspace),
    )
    handler = _HANDLERS.get(op)
    if handler is None:
        return {"error": f"Unknown operation: {op}"}
    return handler(env, args)


def run_rpc_payload(payload: dict[str, Any]) -> dict[str, Any]:
    op = payload.get("op") or payload.get("operation") or ""
    try:
        result = dispatch(op, payload.get("args") or {})
        if isinstance(result, dict) and result.get("error"):
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}
    except _RPC_ERRORS as exc:
        return {"ok": False, "error": str(exc)}


def loads_and_run(raw: str) -> str:
    payload = json.loads(raw)
    return json.dumps(run_rpc_payload(payload), indent=2)
