from pathlib import Path

import pytest

from cybergrok.scope import ScopeConfig, ScopeError, find_scope_config, parse_scope_file, validate_target


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


def test_path_only_does_not_authorize_any_host():
    cfg = ScopeConfig(in_scope=["/api"])
    assert not validate_target("https://evil.example/api", cfg).allowed


def test_no_scope_file_denies():
    result = validate_target("127.0.0.1:8888", None)
    assert not result.allowed


def test_broken_scope_raises(tmp_path: Path):
    (tmp_path / "scope.yaml").write_text("{[ this is not valid yaml", encoding="utf-8")
    with pytest.raises(ScopeError):
        find_scope_config(tmp_path)


def test_repo_scope_yaml_allows_lab_only():
    root = Path(__file__).resolve().parents[2]
    cfg = parse_scope_file(root / "scope.yaml")
    assert validate_target("http://127.0.0.1:8888/", cfg).allowed
    assert not validate_target("https://evil.example", cfg).allowed
    assert not validate_target("http://169.254.169.254/", cfg).allowed
