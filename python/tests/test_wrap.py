import os
from pathlib import Path
from typing import TYPE_CHECKING

from cybergrok.wrap import (
    check_targets,
    extract_targets,
    find_real_binary,
    is_wrapper_dir,
    is_wrapper_path,
    refused_flags,
    wrap_workspace,
)

if TYPE_CHECKING:
    import pytest


def test_curl_user_flag_is_not_a_target():
    found = extract_targets("curl", ["-u", "user:pass", "https://lab.example/"])
    assert found == ["https://lab.example/"]


def test_curl_data_flag_is_not_a_target():
    found = extract_targets("curl", ["-d", "q=1", "--url", "https://lab.example/x"])
    assert found == ["https://lab.example/x"]


def test_refuses_resolve_connect_to_proxy_and_list_files():
    assert refused_flags(["--resolve", "lab.example:443:169.254.169.254"]) == "--resolve"
    assert refused_flags(["--connect-to", "lab.example:443:169.254.169.254:80"]) == "--connect-to"
    assert refused_flags(["-x", "169.254.169.254:80"]) == "-x"
    assert refused_flags(["--proxy", "http://169.254.169.254/"]) == "--proxy"
    assert refused_flags(["-l", "urls.txt"]) == "-l"
    assert refused_flags(["--list", "urls.txt"]) == "--list"
    assert refused_flags(["-K", "curl.conf"]) == "-K"
    assert refused_flags(["-u", "https://lab.example/"]) is None


def test_httpx_list_file_is_refused_even_with_decoy_url():
    argv = ["-u", "https://lab.example/", "-l", "oos.txt"]
    assert refused_flags(argv) == "-l"
    assert extract_targets("httpx", argv) == ["https://lab.example/"]


def test_check_targets_blocks_imds_even_if_localhost_in_scope(tmp_path: Path):
    _ = (tmp_path / "scope.yaml").write_text(
        "in_scope:\n  - 127.0.0.1:8888\n  - 169.254.169.254\n", encoding="utf-8"
    )
    ok, reason = check_targets(["http://169.254.169.254/latest/meta-data"], tmp_path)
    assert not ok
    assert "metadata" in reason.lower() or "blocked" in reason.lower()


def test_wrapper_dir_skip_handles_slash_and_backslash():
    assert is_wrapper_dir("tools/wrappers")
    assert is_wrapper_dir("tools/wrappers/")
    assert is_wrapper_dir(r"C:\repo\tools\wrappers")
    assert is_wrapper_dir(r"C:\repo\tools\wrappers\\")
    assert not is_wrapper_dir("tools/bin")


def test_wrap_workspace_ignores_grok_workspace_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workspace = tmp_path / "engagement"
    decoy = tmp_path / "decoy"
    workspace.mkdir()
    decoy.mkdir()
    _ = (workspace / "scope.yaml").write_text("in_scope:\n  - lab.example\n", encoding="utf-8")
    _ = (decoy / "scope.yaml").write_text("in_scope:\n  - evil.example\n", encoding="utf-8")
    monkeypatch.setenv("GROK_WORKSPACE_ROOT", str(decoy))
    monkeypatch.chdir(workspace)
    assert wrap_workspace() == workspace.resolve()


def test_find_real_binary_skips_wrapper_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wrappers = tmp_path / "tools" / "wrappers"
    realdir = tmp_path / "tools" / "bin"
    wrappers.mkdir(parents=True)
    realdir.mkdir(parents=True)
    stub = wrappers / "httpx"
    real = realdir / "httpx"
    _ = stub.write_text("#!/bin/sh\n", encoding="utf-8")
    _ = real.write_text("#!/bin/sh\n", encoding="utf-8")
    stub.chmod(0o755)
    real.chmod(0o755)
    monkeypatch.setenv("PATH", f"{wrappers}{os.pathsep}{realdir}")
    monkeypatch.delenv("CYBERGROK_REAL_BIN", raising=False)
    found = find_real_binary("httpx")
    assert found is not None
    assert is_wrapper_path(Path(found)) is False
    assert Path(found).resolve() == real.resolve()
