import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import override

from cybergrok.paths import find_plugin_root
from cybergrok.rpc import dispatch


def test_list_skills_rpc():
    root = find_plugin_root()
    result = dispatch("list_skills", {"filter": "idor", "limit": 5, "plugin_root": str(root)})
    assert int(str(result["total"])) > 0
    from cybergrok import _coerce

    names = [str(item.get("name", "")) for item in _coerce.as_maps(result.get("skills"))]
    assert any("idor" in name for name in names)


def test_nested_skill_lookup():
    root = find_plugin_root()
    result = dispatch("get_skill", {"skill_name": "blackbox-web-audit", "plugin_root": str(root)})
    assert "content" in result
    assert result["content"]


def test_slug_escape_stays_in_workspace(tmp_path: Path):
    root = find_plugin_root()
    result = dispatch(
        "aggregate_report",
        {"target_slug": "../etc", "workspace": str(tmp_path), "plugin_root": str(root)},
    )
    assert "error" not in result
    assert (tmp_path / "reports" / "etc" / "SUMMARY.md").is_file()
    assert not (tmp_path.parent / "etc" / "SUMMARY.md").exists()


def test_unknown_op():
    result = dispatch("nope", {})
    assert "error" in result


def test_http_probe_absolute_slug_cannot_swap_scope(tmp_path: Path):
    root = find_plugin_root()
    _ = (tmp_path / "scope.yaml").write_text("in_scope:\n  - lab.example\n", encoding="utf-8")
    evil = tmp_path.parent / "rpc_evil_scope"
    evil.mkdir(exist_ok=True)
    _ = (evil / "scope.yaml").write_text(
        "in_scope:\n  - evil.example\nallow_ips: true\n", encoding="utf-8"
    )
    result = dispatch(
        "http_probe",
        {
            "target_url": "https://evil.example/",
            "target_slug": str(evil),
            "workspace": str(tmp_path),
            "plugin_root": str(root),
            "prefer_httpx": False,
            "timeout_seconds": 2,
        },
    )
    assert "error" in result
    assert "Scope Guard" in str(result["error"])


def test_scan_secrets_rejects_workspace_root(tmp_path: Path):
    root = find_plugin_root()
    _ = (tmp_path / ".env").write_text("ghp_" + ("a" * 36) + "\n", encoding="utf-8")
    result = dispatch(
        "scan_secrets",
        {"path": ".env", "workspace": str(tmp_path), "plugin_root": str(root)},
    )
    assert "error" in result
    assert "recon" in str(result["error"])


def test_scan_secrets_allows_recon_tree(tmp_path: Path):
    root = find_plugin_root()
    recon = tmp_path / "recon" / "lab"
    recon.mkdir(parents=True)
    _ = (recon / "js.txt").write_text("ghp_" + ("a" * 36) + "\n", encoding="utf-8")
    result = dispatch(
        "scan_secrets",
        {"path": "recon/lab/js.txt", "workspace": str(tmp_path), "plugin_root": str(root)},
    )
    assert "error" not in result
    assert int(str(result["reported"])) >= 1


def test_http_probe_blocks_out_of_scope_redirect(tmp_path: Path):
    ports = {"secret": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/go":
                _ = self.send_response(302)
                _ = self.send_header("Location", f"http://127.0.0.1:{ports['secret']}/secret")
                self.end_headers()
                return
            _ = self.send_response(200)
            self.end_headers()
            _ = self.wfile.write(b"SECRET")

        @override
        def log_message(self, format: str, *args: object) -> None:
            return

    secret = HTTPServer(("127.0.0.1", 0), Handler)
    seed = HTTPServer(("127.0.0.1", 0), Handler)
    ports["secret"] = int(secret.server_address[1])
    threads = [
        threading.Thread(target=seed.serve_forever, daemon=True),
        threading.Thread(target=secret.serve_forever, daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        seed_port = seed.server_address[1]
        secret_port = secret.server_address[1]
        _ = (tmp_path / "scope.yaml").write_text(
            f"in_scope:\n  - 127.0.0.1:{seed_port}\n",
            encoding="utf-8",
        )
        result = dispatch(
            "http_probe",
            {
                "target_url": f"http://127.0.0.1:{seed_port}/go",
                "workspace": str(tmp_path),
                "plugin_root": str(find_plugin_root()),
                "follow_redirects": True,
                "prefer_httpx": False,
                "timeout_seconds": 3,
            },
        )
        err = str(result.get("error") or "")
        assert err
        assert "SECRET" not in str(result)
        assert "does not match" in err or "Scope Guard" in err or "blocked" in err.lower()
        assert secret_port != seed_port
    finally:
        seed.shutdown()
        secret.shutdown()


def test_http_probe_ignores_planted_per_target_scope(tmp_path: Path):
    root = find_plugin_root()
    _ = (tmp_path / "scope.yaml").write_text("in_scope:\n  - lab.example\n", encoding="utf-8")
    planted = tmp_path / "reports" / "lab"
    planted.mkdir(parents=True)
    _ = (planted / "scope.yaml").write_text("in_scope:\n  - evil.example\n", encoding="utf-8")
    result = dispatch(
        "http_probe",
        {
            "target_url": "https://evil.example/",
            "target_slug": "lab",
            "workspace": str(tmp_path),
            "plugin_root": str(root),
            "prefer_httpx": False,
            "timeout_seconds": 2,
        },
    )
    assert "error" in result
    err = str(result["error"])
    assert "Scope Guard" in err or "does not match" in err
