"""Engagement scope loader and target validator."""

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


@dataclass
class ScopeConfig:
    name: str = ""
    target_slug: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_ips: bool = False
    max_requests: int = 0
    dynamic_target_override: bool = False


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

    def to_dict(self) -> dict:
        return asdict(self)


def parse_scope_data(data: dict) -> ScopeConfig:
    in_scope = list(data.get("in_scope") or data.get("targets") or [])
    out_of_scope = list(data.get("out_of_scope") or [])
    return ScopeConfig(
        name=str(data.get("name") or data.get("program") or ""),
        target_slug=str(data.get("target_slug") or ""),
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        allow_ips=bool(data.get("allow_ips", False)),
        max_requests=int(data.get("max_requests") or 0),
        dynamic_target_override=bool(data.get("dynamic_target_override", False)),
    )


def parse_scope_file(path: Path) -> ScopeConfig:
    if yaml is None:
        raise RuntimeError("PyYAML is required to parse scope.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid scope file: {path}")
    return parse_scope_data(data)


def find_scope_config(root_dir: Path, target_slug: str = "") -> tuple[ScopeConfig | None, Path | None]:
    candidates: list[Path] = []
    if target_slug:
        candidates += [
            root_dir / "reports" / target_slug / "scope.yaml",
            root_dir / "reports" / target_slug / "scope.yml",
        ]
    candidates += [root_dir / "scope.yaml", root_dir / "scope.yml"]
    for path in candidates:
        if path.is_file():
            try:
                return parse_scope_file(path), path
            except Exception:
                continue
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


def _matches_rule(host: str, port: str, path: str, raw_target: str, rule: str) -> bool:
    rule = rule.lower().strip()
    host = host.lower()
    if not rule:
        return False
    if rule == "*":
        return True
    if "/" in rule and "://" not in rule:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            return ipaddress.ip_address(host) in net
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
            if host == r_host and (not r_port or port == r_port) and (r_path == "/" or path.startswith(r_path)):
                return True
        except ValueError:
            return False
    elif rule.startswith("/"):
        return path.startswith(rule)
    if rule.startswith("*."):
        root = rule[2:]
        return host == root or host.endswith("." + root)
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
            True, raw_target, host, port, path,
            reason="No scope file loaded; target permitted under Direct Operator Authorization (AGENTS.md).",
            scope_found=False,
        )

    if cfg.dynamic_target_override and "*" in [t.strip() for t in cfg.in_scope]:
        # Still honor explicit out-of-scope rules.
        pass

    for out_rule in cfg.out_of_scope:
        if _matches_rule(host, port, path, raw_target, out_rule):
            return ValidationResult(
                False, raw_target, host, port, path,
                matched_by=f"out_of_scope: {out_rule}",
                reason=f"Target '{raw_target}' is explicitly OUT OF SCOPE (matched rule '{out_rule}')",
                scope_found=True,
            )

    if not cfg.in_scope:
        return ValidationResult(
            True, raw_target, host, port, path,
            reason="In-scope list is empty; target passed out-of-scope check.",
            scope_found=True,
        )

    for in_rule in cfg.in_scope:
        if _matches_rule(host, port, path, raw_target, in_rule):
            return ValidationResult(
                True, raw_target, host, port, path,
                matched_by=f"in_scope: {in_rule}",
                reason=f"Target '{raw_target}' is IN SCOPE (matched rule '{in_rule}')",
                scope_found=True,
            )

    return ValidationResult(
        False, raw_target, host, port, path,
        reason=f"Target '{raw_target}' (host: {host}) does not match any allowed in-scope pattern.",
        scope_found=True,
    )
