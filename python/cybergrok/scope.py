"""Engagement scope loader and fail-closed target validator."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


class ScopeError(RuntimeError):
    """A scope file exists but cannot be used."""


@dataclass
class ScopeConfig:
    name: str = ""
    target_slug: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_ips: bool = False
    max_requests: int = 0
    dynamic_target_override: bool = False
    source_path: str = ""


@dataclass
class ValidationResult:
    allowed: bool
    target: str
    host: str = ""
    port: str = ""
    path: str = ""
    matched_by: str = ""
    reason: str = ""
    scope_found: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_scope_data(data: dict, source_path: str = "") -> ScopeConfig:
    in_scope = list(data.get("in_scope") or [])
    # A bare "*" is ignored (fail-closed).
    for item in data.get("targets") or []:
        if str(item).strip() == "*":
            continue
        in_scope.append(item)
    return ScopeConfig(
        name=str(data.get("name") or data.get("program") or ""),
        target_slug=str(data.get("target_slug") or ""),
        in_scope=in_scope,
        out_of_scope=list(data.get("out_of_scope") or []),
        allow_ips=bool(data.get("allow_ips", False)),
        max_requests=int(data.get("max_requests") or 0),
        dynamic_target_override=bool(data.get("dynamic_target_override", False)),
        source_path=source_path,
    )


def parse_scope_file(path: Path) -> ScopeConfig:
    if yaml is None:
        raise ScopeError("PyYAML is required to parse scope.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ScopeError(f"Failed to parse '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError(f"Invalid scope file '{path}': expected a mapping")
    return parse_scope_data(data, str(path))


def _confine_under(path: Path, root: Path) -> Path | None:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def find_scope_config(root_dir: Path, target_slug: str = "") -> tuple[ScopeConfig | None, Path | None]:
    """Return (config, path). Raises ScopeError if a candidate exists but is unreadable.

    The first existing candidate is the policy. A broken per-target file does
    not fall through to the workspace file.
    """
    root = Path(root_dir).resolve()
    candidates: list[Path] = []
    slug = (target_slug or "").strip()
    if slug:
        cleaned = re.sub(r"[^a-z0-9]+", "_", slug.lower()).strip("_")
        if cleaned and cleaned not in {".", ".."} and "/" not in cleaned and "\\" not in cleaned:
            reports = root / "reports"
            for name in ("scope.yaml", "scope.yml"):
                confined = _confine_under(reports / cleaned / name, reports)
                if confined is not None:
                    candidates.append(confined)
    candidates += [root / "scope.yaml", root / "scope.yml"]
    for path in candidates:
        if not path.is_file():
            continue
        return parse_scope_file(path), path
    return None, None


def normalize_target(raw: str) -> tuple[str, str, str, str]:
    target = raw.strip()
    if not target:
        raise ValueError("target string is empty")
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    port = str(parsed.port or "")
    path = parsed.path or "/"
    return parsed.scheme.lower(), host, port, path


def _split_host_path_rule(rule: str) -> tuple[str, str] | None:
    """Parse scheme-less host[/path] (not CIDR, not path-only)."""
    if "://" in rule or rule.startswith("/") or rule.startswith("*.") or rule.startswith("^"):
        return None
    if "/" in rule:
        try:
            ipaddress.ip_network(rule, strict=False)
            return None
        except ValueError:
            host, rest = rule.split("/", 1)
            if host:
                return host.lower(), "/" + rest
    return None


def _normalize_path(path: str) -> str:
    raw = unquote(path or "/")
    if not raw.startswith("/"):
        raw = "/" + raw
    normalized = posixpath.normpath(raw)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if raw.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized


def _path_prefix_ok(path: str, rule_path: str) -> bool:
    path_n = _normalize_path(path)
    rule_n = _normalize_path(rule_path)
    if rule_n == "/":
        return True
    prefix = rule_n.rstrip("/") or "/"
    return path_n == prefix or path_n == prefix + "/" or path_n.startswith(prefix + "/")


def host_is_private_literal(host: str) -> bool:
    name = (host or "").lower().rstrip(".")
    if name in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def allow_private_for_target(raw_target: str, cfg: ScopeConfig | None) -> bool:
    """Private/loopback hops are allowed only when that hop itself is in scope."""
    result = validate_target(raw_target, cfg)
    return bool(result.allowed and host_is_private_literal(result.host))


def _matches_host(host: str, port: str, rule_host: str) -> bool:
    rule_host = rule_host.lower()
    if rule_host.startswith("*."):
        root = rule_host[2:]
        return host == root or host.endswith("." + root)
    if port and f"{host}:{port}" == rule_host:
        return True
    return host == rule_host


def _matches_rule(host: str, port: str, path: str, raw_target: str, rule: str, *, path_only: bool = False) -> bool:
    rule = rule.lower().strip()
    host = host.lower()
    if not rule or rule == "*":
        return False

    split = _split_host_path_rule(rule)
    if split:
        r_host, r_path = split
        return _matches_host(host, port, r_host) and _path_prefix_ok(path, r_path)

    if "/" in rule and "://" not in rule:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            ip = ipaddress.ip_address(host)
            return ip in net
        except ValueError:
            pass

    try:
        if ipaddress.ip_address(host).compressed == rule:
            return True
    except ValueError:
        pass

    if "://" in rule:
        try:
            _, r_host, r_port, r_path = normalize_target(rule)
            if _matches_host(host, port, r_host) and (not r_port or port == r_port):
                return _path_prefix_ok(path, r_path)
        except ValueError:
            return False

    if rule.startswith("/"):
        # Path-only rules never authorize a host by themselves.
        return path_only and _path_prefix_ok(path, rule)

    if rule.startswith("*."):
        return _matches_host(host, port, rule)

    if host == rule:
        return True
    if port and f"{host}:{port}" == rule:
        return True
    if rule.startswith("^") or rule.endswith("$"):
        try:
            cre = re.compile(rule)
            # Match host only — a pattern like ^https?:// must not authorize every URL.
            return bool(cre.search(host) or (port and cre.search(f"{host}:{port}")))
        except re.error:
            return False
    return False


def validate_target(raw_target: str, cfg: ScopeConfig | None) -> ValidationResult:
    try:
        _, host, port, path = normalize_target(raw_target)
    except ValueError as exc:
        return ValidationResult(False, raw_target, reason=f"Invalid target format: {exc}", scope_found=cfg is not None)

    if cfg is None:
        return ValidationResult(
            False,
            raw_target,
            host,
            port,
            path,
            reason="No scope.yaml found. Add the host to workspace scope.yaml before probing.",
            scope_found=False,
        )

    for out_rule in cfg.out_of_scope:
        if _matches_rule(host, port, path, raw_target, out_rule, path_only=True):
            return ValidationResult(
                False,
                raw_target,
                host,
                port,
                path,
                matched_by=f"out_of_scope: {out_rule}",
                reason=f"Target '{raw_target}' is explicitly OUT OF SCOPE (matched rule '{out_rule}')",
                scope_found=True,
            )

    host_rules = [r for r in cfg.in_scope if str(r).strip() and str(r).strip() != "*" and not str(r).strip().startswith("/")]
    if not host_rules:
        return ValidationResult(
            False,
            raw_target,
            host,
            port,
            path,
            reason="scope.yaml has no in-scope hosts. Add the engagement hostname before testing.",
            scope_found=True,
        )

    for in_rule in host_rules:
        if _matches_rule(host, port, path, raw_target, in_rule, path_only=False):
            # Optional extra path-only constraints
            path_rules = [r.strip() for r in cfg.in_scope if str(r).strip().startswith("/")]
            if path_rules and not any(_matches_rule(host, port, path, raw_target, r, path_only=True) for r in path_rules):
                continue
            return ValidationResult(
                True,
                raw_target,
                host,
                port,
                path,
                matched_by=f"in_scope: {in_rule}",
                reason=f"Target '{raw_target}' is IN SCOPE (matched rule '{in_rule}')",
                scope_found=True,
            )

    return ValidationResult(
        False,
        raw_target,
        host,
        port,
        path,
        reason=f"Target '{raw_target}' (host: {host}) does not match any allowed in-scope host.",
        scope_found=True,
    )
