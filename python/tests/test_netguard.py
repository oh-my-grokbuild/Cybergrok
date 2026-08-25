import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import override
from urllib.request import Request

import pytest

from cybergrok import _coerce
from cybergrok.netguard import UnsafeURL, assert_safe_url, prepare_safe_request, safe_opener


def test_rejects_file_and_metadata():
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("file:///etc/passwd")
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://169.254.169.254/latest/meta-data")


def test_rejects_loopback_unless_allowed():
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://127.0.0.1:8888/")
    assert assert_safe_url("http://127.0.0.1:8888/", allow_private=True).startswith("http://")


def test_rejects_alibaba_and_mapped_imds():
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://100.100.100.200/")
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://[::ffff:169.254.169.254]/")
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://[::ffff:127.0.0.1]/")
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://168.63.129.16/")
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://[::ffff:168.63.129.16]/")


def test_rejects_imds_hostnames():
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://metadata.google.internal/")
    with pytest.raises(UnsafeURL):
        _ = assert_safe_url("http://instance-data/")


def test_prepare_safe_request_keeps_hostname_url():
    safe = prepare_safe_request("http://127.0.0.1:8888/path", allow_private=True)
    assert safe.url == "http://127.0.0.1:8888/path"
    assert safe.connect_host == "127.0.0.1"
    assert safe.port == 8888
    assert safe.server_name == "127.0.0.1"
    assert safe.host_header == "127.0.0.1:8888"


def test_safe_opener_ignores_env_http_proxy(monkeypatch: pytest.MonkeyPatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            _ = self.send_response(200)
            self.end_headers()
            _ = self.wfile.write(b"direct")

        @override
        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        dead = "http://127.0.0.1:1"
        monkeypatch.setenv("HTTP_PROXY", dead)
        monkeypatch.setenv("http_proxy", dead)
        monkeypatch.setenv("HTTPS_PROXY", dead)
        monkeypatch.setenv("https_proxy", dead)
        opener = safe_opener(allow_private=True)
        body = _coerce.open_limited(opener, Request(f"http://127.0.0.1:{port}/"), 2, 64)
        assert body == "direct"
    finally:
        server.shutdown()
        server.server_close()
