"""JSON RPC used by `python -m cybergrok rpc`."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from . import _coerce, crawl, probe, report, scope, search, secrets, skills
from .netguard import UnsafeURL, assert_safe_url
from .paths import find_plugin_root, find_workspace_root, plugin_dirs, workspace_dirs
from .scope import ScopeError

_DEFAULT_REMEDIATION = "Implement strict authorization checks and validate user access permissions."

type RpcArgs = Mapping[str, object]
type RpcResult = dict[str, object]


@dataclass(frozen=True)
class _RpcEnv:
    plugin: Path
    workspace: Path
    pdirs: dict[str, Path]
    wdirs: dict[str, Path]


def _as_str(value: object, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _arg_str(args: RpcArgs, key: str, default: str = "") -> str:
    return _as_str(args.get(key, default), default)


def _arg_int(args: RpcArgs, key: str, default: int) -> int:
    value = args.get(key, default)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return int(str(value))


def _arg_bool(args: RpcArgs, key: str) -> bool:
    value = args.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, int):
        return value != 0
    return bool(value)


def _as_object_map(value: object) -> dict[str, object]:
    return _coerce.as_str_map(value)


def _plugin_root(args: RpcArgs) -> Path:
    raw = args.get("plugin_root")
    if raw:
        return Path(_as_str(raw)).expanduser().resolve()
    return find_plugin_root()


def _workspace(args: RpcArgs) -> Path:
    pinned = os.environ.get("GROK_WORKSPACE_ROOT") or os.environ.get("CYBERGROK_WORKSPACE")
    if pinned:
        return Path(pinned).expanduser().resolve()
    raw = args.get("workspace") or args.get("root")
    if raw:
        return Path(_as_str(raw)).expanduser().resolve()
    return find_workspace_root()


def _safe_slug(raw: str) -> str:
    slug = report.sanitize_slug(raw)
    if not slug or slug in {".", ".."} or "/" in slug or "\\" in slug:
        raise ValueError("invalid target_slug")
    return slug


def _confine(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        _ = resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"path '{path}' is outside the workspace") from exc
    return resolved


def _under(path: Path, root: Path) -> bool:
    try:
        _ = path.resolve().relative_to(root.resolve())
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


def _op_search_knowledge(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    searcher = search.Searcher(env.pdirs["knowledge"], env.plugin)
    results = searcher.search(
        _arg_str(args, "query"),
        source=_arg_str(args, "source", "all"),
        limit=_arg_int(args, "limit", 3),
        max_chars=_arg_int(args, "max_len", 1400),
    )
    return {"snippets": [s.to_dict() for s in results], "query": _arg_str(args, "query")}


def _op_list_skills(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    items = skills.list_skills(env.pdirs["skills"])
    filt = _arg_str(args, "filter").lower()
    limit = _arg_int(args, "limit", 30)
    matched = [
        s
        for s in items
        if not filt
        or filt in s.name.lower()
        or filt in s.description.lower()
        or filt in s.sources.lower()
    ][:limit]
    return {"total": len(items), "skills": [s.to_dict() for s in matched]}


def _op_get_skill(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    content = skills.get_skill(
        env.pdirs["skills"], _arg_str(args, "skill_name"), _arg_str(args, "section")
    )
    if content is None:
        return {"error": f"Skill '{_arg_str(args, 'skill_name')}' not found"}
    return {"content": content}


def _op_scan_secrets(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    findings: list[secrets.Finding] = []
    if args.get("content"):
        findings = secrets.scan_text(_arg_str(args, "content"), "raw_content")
    elif args.get("path"):
        target = Path(_arg_str(args, "path"))
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
    filtered = secrets.filter_by_severity(findings, _arg_str(args, "min_severity", "low"))
    payload: list[dict[str, object]] = [f.to_dict() for f in filtered]
    for item in payload:
        item["match"] = secrets.mask_secret(str(item["match"]))
    return {"total": len(findings), "reported": len(filtered), "findings": payload}


def _op_validate_scope(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    try:
        slug = _optional_slug(args.get("target_slug"))
    except ValueError:
        slug = ""
    try:
        cfg, _path = scope.find_scope_config(env.workspace, slug)
    except ScopeError as exc:
        return {"error": str(exc), "allowed": False}
    result = scope.validate_target(_arg_str(args, "target"), cfg)
    return result.to_dict()


def _load_scope(env: _RpcEnv, slug: str) -> tuple[scope.ScopeConfig | None, RpcResult | None]:
    try:
        cfg, _ = scope.find_scope_config(env.workspace, slug)
    except ScopeError as exc:
        return None, {"error": str(exc)}
    return cfg, None


def _op_http_probe(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    try:
        slug = _optional_slug(args.get("target_slug"))
    except ValueError as exc:
        return {"error": str(exc)}
    cfg, err = _load_scope(env, slug)
    if err:
        return err
    target_url = _arg_str(args, "target_url")
    val = scope.validate_target(target_url, cfg)
    if not val.allowed:
        return {"error": f"Scope Guard Violation: {val.reason}"}
    allow_private = scope.allow_private_for_target(target_url, cfg)
    try:
        result = probe.probe_target(
            target_url,
            timeout=_arg_int(args, "timeout_seconds", 10),
            follow_redirects=_arg_bool(args, "follow_redirects"),
            tools_dir=env.pdirs["tools"],
            prefer_httpx=_arg_bool(args, "prefer_httpx"),
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


def _op_recon_crawl(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    target_url = _arg_str(args, "target_url")
    try:
        slug = _safe_slug(_arg_str(args, "target_slug") or report.sanitize_slug(target_url))
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
            depth=_arg_int(args, "depth", 2),
            max_endpoints=_arg_int(args, "max_endpoints", 25),
            timeout=_arg_int(args, "timeout_seconds", 30),
            output_dir=recon_dir,
            allow_private=allow_private,
            guard=lambda url: _guard_url(url, cfg),
        )
    except (UnsafeURL, RuntimeError) as exc:
        return {"error": str(exc)}
    return result.to_dict()


def _op_aggregate_report(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    raw_slug = _arg_str(args, "target_slug").strip()
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


def _op_list_findings(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    try:
        slug = _safe_slug(_arg_str(args, "target_slug"))
    except ValueError as exc:
        return {"error": str(exc)}
    target_dir = _confine(env.wdirs["reports"] / slug, env.workspace)
    if not target_dir.is_dir():
        return {"error": f"Report directory for target '{slug}' does not exist."}
    return report.aggregate_target(target_dir).to_dict()


def _op_record_finding(env: _RpcEnv, args: RpcArgs) -> RpcResult:
    return report.record_finding(
        env.wdirs["reports"],
        _arg_str(args, "target_slug"),
        _arg_str(args, "severity", "medium"),
        _arg_str(args, "title"),
        _arg_str(args, "endpoint"),
        _arg_str(args, "description"),
        _arg_str(args, "reproduction_steps"),
        _arg_str(args, "poc_script"),
        _arg_str(args, "remediation", _DEFAULT_REMEDIATION),
    )


_HANDLERS: dict[str, Callable[[_RpcEnv, RpcArgs], RpcResult]] = {
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


def dispatch(op: str, args: RpcArgs | None = None) -> RpcResult:
    payload = args or {}
    plugin = _plugin_root(payload)
    workspace = _workspace(payload)
    env = _RpcEnv(
        plugin=plugin,
        workspace=workspace,
        pdirs=plugin_dirs(plugin),
        wdirs=workspace_dirs(workspace),
    )
    handler = _HANDLERS.get(op)
    if handler is None:
        return {"error": f"Unknown operation: {op}"}
    return handler(env, payload)


def run_rpc_payload(payload: RpcArgs) -> RpcResult:
    op = _arg_str(payload, "op") or _arg_str(payload, "operation")
    try:
        result = dispatch(op, _as_object_map(payload.get("args") or {}))
        if result.get("error"):
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}
    except _RPC_ERRORS as exc:
        return {"ok": False, "error": str(exc)}


def loads_and_run(raw: str) -> str:
    try:
        payload = _coerce.json_object(raw)
    except TypeError as exc:
        raise TypeError("RPC payload must be a JSON object") from exc
    return json.dumps(run_rpc_payload(payload), indent=2)
