"""Engagement scope loader and fail-closed target validator."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

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
    # Legacy Cybermes key. A bare "*" is ignored (fail-closed).
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


def find_scope_config(root_dir: Path, target_slug: str = "") -> tuple[ScopeConfig | None, Path | None]:
    """Return (config, path). Raises ScopeError if a candidate exists but is unreadable."""
    candidates: list[Path] = []
    if target_slug:
        candidates += [
            root_dir / "reports" / target_slug / "scope.yaml",
            root_dir / "reports" / target_slug / "scope.yml",
        ]
    candidates += [root_dir / "scope.yaml", root_dir / "scope.yml"]
    last_error: ScopeError | None = None
    for path in candidates:
        if not path.is_file():
            continue
        try:
            return parse_scope_file(path), path
        except ScopeError as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error
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
        return _matches_host(host, port, r_host) and (r_path == "/" or path.startswith(r_path))

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
                return r_path == "/" or path.startswith(r_path)
        except ValueError:
            return False

    if rule.startswith("/"):
        # Path-only rules never authorize a host by themselves.
        return path_only and path.startswith(rule)

    if rule.startswith("*."):
        return _matches_host(host, port, rule)

    if host == rule:
        return True
    if port and f"{host}:{port}" == rule:
        return True
    if rule.startswith("^") or rule.endswith("$"):
        try:
            cre = re.compile(rule)
            return bool(cre.search(raw_target) or cre.search(host))
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
