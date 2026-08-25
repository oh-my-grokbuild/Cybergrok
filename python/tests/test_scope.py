from pathlib import Path

import pytest

from cybergrok.scope import (
    ScopeConfig,
    ScopeError,
    find_scope_config,
    parse_scope_file,
    validate_target,
)
from cybergrok.wrap import check_targets, extract_targets


def test_url_regex_does_not_authorize_every_host():
    cfg = ScopeConfig(in_scope=[r"^https?://"])
    assert not validate_target("https://evil.example/", cfg).allowed


def test_wildcard_is_ignored():
    cfg = ScopeConfig(in_scope=["*"])
    assert not validate_target("https://evil.example", cfg).allowed


def test_explicit_host_allows():
    cfg = ScopeConfig(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert validate_target("https://app.example.com/x", cfg).allowed
    assert not validate_target("https://admin.example.com/", cfg).allowed
    assert not validate_target("https://other.com/", cfg).allowed


def test_scheme_less_host_path():
    cfg = ScopeConfig(in_scope=["example.com/api"])
    assert validate_target("https://example.com/api/v1", cfg).allowed
    assert not validate_target("https://example.com/other", cfg).allowed
    assert not validate_target("https://example.com/apitest", cfg).allowed
    assert not validate_target("https://example.com/api/../admin", cfg).allowed
    assert not validate_target("https://example.com/api/%2e%2e/admin", cfg).allowed


def test_path_only_does_not_authorize_any_host():
    cfg = ScopeConfig(in_scope=["/api"])
    assert not validate_target("https://evil.example/api", cfg).allowed


def test_no_scope_file_denies():
    result = validate_target("127.0.0.1:8888", None)
    assert not result.allowed


def test_broken_scope_raises(tmp_path: Path):
    _ = (tmp_path / "scope.yaml").write_text("{[ this is not valid yaml", encoding="utf-8")
    with pytest.raises(ScopeError):
        _ = find_scope_config(tmp_path)


def test_per_target_scope_is_ignored(tmp_path: Path):
    _ = (tmp_path / "scope.yaml").write_text("in_scope:\n  - lab.example\n", encoding="utf-8")
    target = tmp_path / "reports" / "acme"
    target.mkdir(parents=True)
    _ = (target / "scope.yaml").write_text("in_scope:\n  - evil.example\n", encoding="utf-8")
    cfg, path = find_scope_config(tmp_path, "acme")
    assert path == tmp_path / "scope.yaml"
    assert cfg is not None
    assert validate_target("https://lab.example/", cfg).allowed
    assert not validate_target("https://evil.example/", cfg).allowed


def test_open_rules_are_ignored():
    cfg = ScopeConfig(in_scope=["^.*$", "0.0.0.0/0", "*"])
    assert not validate_target("https://evil.example/", cfg).allowed
    assert not validate_target("http://1.2.3.4/", cfg).allowed


def test_default_https_port_matches_explicit_443():
    cfg = ScopeConfig(in_scope=["https://example.com:443"])
    assert validate_target("https://example.com/", cfg).allowed
    assert validate_target("https://example.com:443/", cfg).allowed
    assert not validate_target("https://example.com:8443/", cfg).allowed


def test_host_only_rule_is_default_ports():
    cfg = ScopeConfig(in_scope=["example.com"])
    assert validate_target("https://example.com/", cfg).allowed
    assert validate_target("http://example.com/", cfg).allowed
    assert not validate_target("https://example.com:8443/", cfg).allowed
    assert not validate_target("http://example.com:6379/", cfg).allowed


def test_absolute_slug_cannot_leave_workspace(tmp_path: Path):
    _ = (tmp_path / "scope.yaml").write_text("in_scope:\n  - lab.example\n", encoding="utf-8")
    evil = tmp_path.parent / "evil_scope_dir"
    evil.mkdir(exist_ok=True)
    _ = (evil / "scope.yaml").write_text("in_scope:\n  - evil.example\n", encoding="utf-8")
    cfg, path = find_scope_config(tmp_path, str(evil))
    assert path == tmp_path / "scope.yaml"
    assert cfg is not None
    assert cfg.in_scope == ["lab.example"]
    assert not validate_target("https://evil.example/", cfg).allowed


def test_wrap_extracts_and_blocks_oos(tmp_path: Path):
    _ = (tmp_path / "scope.yaml").write_text("in_scope:\n  - lab.example\n", encoding="utf-8")
    assert extract_targets("httpx", ["-u", "https://lab.example/"]) == ["https://lab.example/"]
    ok, _ = check_targets(["https://lab.example/"], tmp_path)
    assert ok
    bad, reason = check_targets(["https://evil.example/"], tmp_path)
    assert not bad
    assert "evil.example" in reason


def test_repo_scope_yaml_allows_lab_only():
    root = Path(__file__).resolve().parents[2]
    cfg = parse_scope_file(root / "scope.yaml")
    assert validate_target("http://127.0.0.1:8888/", cfg).allowed
    assert not validate_target("https://evil.example", cfg).allowed
    assert not validate_target("http://169.254.169.254/", cfg).allowed
