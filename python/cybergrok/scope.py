"""Engagement scope loader and fail-closed target validator."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_scope_data(data: dict[str, Any], source_path: str = "") -> ScopeConfig:
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
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
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


def find_scope_config(
    root_dir: Path, target_slug: str = ""
) -> tuple[ScopeConfig | None, Path | None]:
    """Return workspace scope.yaml only.

    Per-target reports/<slug>/scope.yaml is not an allowlist — agents can write it.
    `target_slug` is accepted for call-site compatibility and ignored.
    """
    del target_slug
    root = Path(root_dir).resolve()
    for name in ("scope.yaml", "scope.yml"):
        path = root / name
        if path.is_file():
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
    if "://" in rule or rule.startswith(("/", "*.", "^")):
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
    """In-scope hops may resolve to RFC1918/loopback. IMDS stays blocked in netguard."""
    return bool(validate_target(raw_target, cfg).allowed)


def _effective_ports(scheme: str, port: str) -> set[str]:
    if port:
        return {port}
    if scheme == "https":
        return {"443"}
    if scheme == "http":
        return {"80"}
    return set()


def _is_open_rule(rule: str) -> bool:
    r = rule.strip().lower()
    return r in {"*", "0.0.0.0/0", "::/0", "^.*$", ".*", ".+", "^", "$"}


def _host_matches_name(host: str, rule_host: str) -> bool:
    rule_host = rule_host.lower()
    if rule_host.startswith("*."):
        root = rule_host[2:]
        return host == root or host.endswith("." + root)
    return host == rule_host


def _matches_host(host: str, ports: set[str], rule_host: str, *, host_only: bool) -> bool:
    rule_host = rule_host.lower()
    if ":" in rule_host and not rule_host.startswith("[") and not rule_host.startswith("*."):
        name, _, maybe_port = rule_host.rpartition(":")
        if name and maybe_port.isdigit():
            return _host_matches_name(host, name) and maybe_port in ports
    if not _host_matches_name(host, rule_host):
        return False
    if host_only:
        return bool(ports & {"80", "443"})
    return True


def _matches_cidr_or_ip(host: str, ports: set[str], rule: str) -> bool | None:
    if "/" in rule and "://" not in rule:
        try:
            net = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return None
        if net.prefixlen == 0:
            return False
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    try:
        if ipaddress.ip_address(host).compressed == rule:
            return bool(ports & {"80", "443"})
    except ValueError:
        return None
    return None


def _matches_url_rule(host: str, ports: set[str], path: str, rule: str) -> bool:
    r_scheme, r_host, r_port, r_path = normalize_target(rule)
    rule_ports = _effective_ports(r_scheme, r_port)
    return (
        _host_matches_name(host, r_host)
        and bool(ports & rule_ports)
        and _path_prefix_ok(path, r_path)
    )


def _matches_host_regex(host: str, rule: str) -> bool:
    try:
        return bool(re.compile(rule).fullmatch(host))
    except re.error:
        return False


def _matches_rule(
    host: str,
    ports: set[str],
    path: str,
    rule: str,
    *,
    path_only: bool = False,
) -> bool:
    rule = rule.lower().strip()
    host = host.lower()
    if not rule or _is_open_rule(rule):
        return False

    split = _split_host_path_rule(rule)
    if split:
        r_host, r_path = split
        return _matches_host(host, ports, r_host, host_only=True) and _path_prefix_ok(path, r_path)

    cidr = _matches_cidr_or_ip(host, ports, rule)
    if cidr is not None:
        return cidr

    if "://" in rule:
        try:
            return _matches_url_rule(host, ports, path, rule)
        except ValueError:
            return False

    if rule.startswith("/"):
        return path_only and _path_prefix_ok(path, rule)
    if rule.startswith("*."):
        return _matches_host(host, ports, rule, host_only=True)
    if _matches_host(host, ports, rule, host_only=":" not in rule):
        return True
    if rule.startswith("^") or rule.endswith("$"):
        return _matches_host_regex(host, rule)
    return False


def validate_target(raw_target: str, cfg: ScopeConfig | None) -> ValidationResult:
    try:
        scheme, host, port, path = normalize_target(raw_target)
    except ValueError as exc:
        return ValidationResult(
            False, raw_target, reason=f"Invalid target format: {exc}", scope_found=cfg is not None
        )
    ports = _effective_ports(scheme, port)

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
        if _matches_rule(host, ports, path, out_rule, path_only=True):
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

    host_rules = [
        r
        for r in cfg.in_scope
        if str(r).strip() and str(r).strip() != "*" and not str(r).strip().startswith("/")
    ]
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
        if _matches_rule(host, ports, path, in_rule, path_only=False):
            # Optional extra path-only constraints
            path_rules = [r.strip() for r in cfg.in_scope if str(r).strip().startswith("/")]
            if path_rules and not any(
                _matches_rule(host, ports, path, r, path_only=True) for r in path_rules
            ):
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
