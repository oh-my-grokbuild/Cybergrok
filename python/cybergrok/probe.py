"""HTTP probe + tech fingerprint (native Python, optional httpx binary)."""

from __future__ import annotations

import json
import re
import shutil
import ssl
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, NotRequired, TypedDict, override
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from . import _coerce
from .netguard import UnsafeURL, assert_safe_url, prepare_safe_request

TITLE_RE = re.compile(r"(?i)<title[^>]*>([^<]+)</title>")


def _tls_context(insecure: bool) -> ssl.SSLContext:
    if not insecure:
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _Sig(TypedDict):
    name: str
    headers: NotRequired[dict[str, str]]
    cookies: NotRequired[list[str]]
    body: NotRequired[list[str]]


SIGNATURES: list[_Sig] = [
    {
        "name": "Next.js",
        "headers": {"x-powered-by": "next.js"},
        "body": ["__NEXT_DATA__", "/_next/static/", "/_next/data/"],
    },
    {"name": "React", "body": ["data-reactroot", "react-dom", "react.production.min.js"]},
    {"name": "Vue.js", "body": ["data-v-", "vue.min.js", "__vue__"]},
    {"name": "Angular", "body": ["ng-version=", "ng-app=", "ng-controller="]},
    {
        "name": "Laravel",
        "cookies": ["laravel_session", "xsrf-token"],
        "body": ["laravel", "csrf-token"],
    },
    {
        "name": "Spring Boot",
        "headers": {"x-application-context": ""},
        "body": ["Whitelabel Error Page"],
    },
    {"name": "Django", "cookies": ["csrftoken", "sessionid"], "body": ["csrfmiddlewaretoken"]},
    {"name": "Express.js", "headers": {"x-powered-by": "express"}},
    {"name": "FastAPI / Uvicorn", "headers": {"server": "uvicorn"}},
    {
        "name": "WordPress",
        "headers": {"x-pingback": ""},
        "cookies": ["wordpress_logged_in", "wp-settings"],
        "body": ["/wp-content/", "/wp-includes/", "wp-json"],
    },
    {"name": "PHP", "headers": {"x-powered-by": "php"}, "cookies": ["phpsessid"]},
    {
        "name": "ASP.NET / IIS",
        "headers": {"x-aspnet-version": "", "x-powered-by": "asp.net", "server": "microsoft-iis"},
        "cookies": ["asp.net_sessionid"],
    },
    {"name": "Nginx", "headers": {"server": "nginx"}},
    {"name": "Apache HTTP Server", "headers": {"server": "apache"}},
    {
        "name": "Cloudflare",
        "headers": {"server": "cloudflare", "cf-ray": "", "cf-cache-status": ""},
    },
    {
        "name": "Swagger / OpenAPI",
        "body": ["swagger-ui", "swagger-ui-bundle", "openapi:", "/swagger/v1/swagger.json"],
    },
    {"name": "GraphQL", "body": ["__schema", "GraphiQL", "graphql-ws"]},
]


@dataclass
class ProbeResult:
    url: str
    scheme: str
    host: str
    port: str
    status_code: int
    status_text: str
    title: str = ""
    web_server: str = ""
    content_type: str = ""
    content_length: int = 0
    response_time_ms: int = 0
    redirect_url: str = ""
    technologies: list[str] = field(default_factory=list)
    tls_info: dict[str, str] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    engine_used: str = "native_python"

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "status_code": self.status_code,
            "status_text": self.status_text,
            "title": self.title,
            "web_server": self.web_server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "response_time_ms": self.response_time_ms,
            "redirect_url": self.redirect_url,
            "technologies": list(self.technologies),
            "tls_info": self.tls_info,
            "headers": dict(self.headers),
            "engine_used": self.engine_used,
        }


class GuardedRedirectHandler(HTTPRedirectHandler):
    allow_private: bool
    follow: bool
    guard: Callable[[str], str] | None

    def __init__(
        self,
        allow_private: bool,
        follow: bool,
        guard: Callable[[str], str] | None = None,
    ) -> None:
        self.allow_private = allow_private
        self.follow = follow
        self.guard = guard

    @override
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        if not self.follow:
            raise HTTPError(req.full_url, code, msg, headers, fp)
        try:
            if self.guard:
                _ = self.guard(newurl)
            fetch, host_hdr = prepare_safe_request(newurl, allow_private=self.allow_private)
        except (UnsafeURL, ValueError) as exc:
            raise HTTPError(newurl, code, f"blocked redirect: {exc}", headers, fp) from exc
        nxt = super().redirect_request(req, fp, code, msg, headers, fetch)
        if nxt is not None:
            nxt.add_unredirected_header("Host", host_hdr)
            nxt.headers["Host"] = host_hdr
        return nxt


def extract_title(html: str) -> str:
    m = TITLE_RE.search(html)
    return str(m.group(1)).strip() if m else ""


def detect_technologies(headers: dict[str, str], cookies: list[str], body: str) -> list[str]:
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    cookie_names = [c.lower() for c in cookies]
    lower_body = body.lower()
    found: list[str] = []
    for sig in SIGNATURES:
        hit = False
        for hk, hv in (sig.get("headers") or {}).items():
            val = lower_headers.get(hk)
            if val is not None and (hv == "" or hv in val):
                hit = True
                break
        if not hit:
            for cn in sig.get("cookies") or []:
                if any(cn.lower() in c for c in cookie_names):
                    hit = True
                    break
        if not hit:
            for bm in sig.get("body") or []:
                if bm.lower() in lower_body:
                    hit = True
                    break
        if hit:
            found.append(sig["name"])
    return found


def _json_object(raw: str) -> dict[str, object] | None:
    try:
        return _coerce.json_object(raw)
    except json.JSONDecodeError, TypeError:
        return None


def _json_str(data: dict[str, object], key: str, default: str = "") -> str:
    value = data.get(key, default)
    if value is None:
        return default
    return str(value)


def find_httpx(tools_dir: Path | None = None) -> str | None:
    if tools_dir:
        for name in ("httpx", "httpx.exe"):
            cand = Path(tools_dir) / "bin" / name
            if cand.is_file():
                return str(cand)
    return shutil.which("httpx")


def probe_httpx(
    url: str,
    timeout: int,
    tools_dir: Path | None,
    follow_redirects: bool,
    allow_private: bool = False,
) -> ProbeResult | None:
    binary = find_httpx(tools_dir)
    if not binary:
        return None
    # Never pass -fr: httpx follows hops before Cybergrok can apply scope/netguard.
    if follow_redirects:
        return None
    try:
        fetch, host_hdr = prepare_safe_request(url, allow_private=allow_private)
    except UnsafeURL:
        return None
    args = [
        binary,
        "-u",
        fetch,
        "-H",
        f"Host: {host_hdr}",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-json",
        "-timeout",
        str(timeout),
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout + 5, check=False
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    elapsed = int((time.monotonic() - started) * 1000)
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        data = _json_object(line)
        if data is None or not data.get("url"):
            continue
        tls = _coerce.as_str_map(data.get("tls"))
        technologies = _coerce.as_str_list(data.get("tech"))
        return ProbeResult(
            url=_json_str(data, "url", url),
            scheme=_json_str(data, "scheme"),
            host=_json_str(data, "host"),
            port=str(data.get("port") or ""),
            status_code=int(str(data.get("status_code") or 0)),
            status_text="",
            title=_json_str(data, "title"),
            web_server=_json_str(data, "webserver"),
            content_type=_json_str(data, "content_type"),
            response_time_ms=elapsed,
            technologies=technologies,
            tls_info={
                "version": str(tls.get("version", "")),
                "subject": str(tls.get("subject_dn", "")),
                "issuer": str(tls.get("issuer_dn", "")),
            }
            if tls
            else None,
            engine_used="httpx",
        )
    return None


def probe_native(
    url: str,
    timeout: int,
    follow_redirects: bool,
    user_agent: str,
    allow_private: bool = False,
    insecure_tls: bool = False,
    guard: Callable[[str], str] | None = None,
) -> ProbeResult:
    if guard:
        _ = guard(url)
    fetch, host_hdr = prepare_safe_request(url, allow_private=allow_private)
    raw = url
    parsed = urlparse(raw)
    ctx = _tls_context(insecure_tls)
    handler = GuardedRedirectHandler(
        allow_private=allow_private, follow=follow_redirects, guard=guard
    )
    opener = build_opener(handler, HTTPSHandler(context=ctx))
    req = Request(fetch, headers={"User-Agent": user_agent, "Accept": "*/*", "Host": host_hdr})
    started = time.monotonic()
    body = ""
    headers: dict[str, str] = {}
    status = 0
    final_url = raw
    tls_info = None
    try:
        body, headers, status, final_url = _coerce.open_probe(
            opener, req, timeout, 1024 * 1024, raw
        )
    except HTTPError as exc:
        body = exc.read(1024 * 1024).decode("utf-8", errors="ignore") if exc.fp else ""
        headers = dict(exc.headers.items()) if exc.headers else {}
        status = exc.code
        final_url = getattr(exc, "url", raw) or raw
    except URLError as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc
    elapsed = int((time.monotonic() - started) * 1000)
    try:
        content_length = int(headers.get("Content-Length") or 0)
    except ValueError:
        content_length = 0
    cookies = []
    if "Set-Cookie" in headers:
        cookies = [headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[0].strip()]
    redirect = "" if not follow_redirects or final_url == raw else final_url
    result_url = raw
    if follow_redirects and final_url != raw:
        result_url = (
            guard(final_url) if guard else assert_safe_url(final_url, allow_private=allow_private)
        )
        redirect = result_url
    return ProbeResult(
        url=result_url,
        scheme=parsed.scheme,
        host=parsed.hostname or "",
        port=str(parsed.port or ""),
        status_code=status,
        status_text=str(status),
        title=extract_title(body),
        web_server=headers.get("Server", ""),
        content_type=headers.get("Content-Type", ""),
        content_length=content_length,
        response_time_ms=elapsed,
        redirect_url=redirect,
        technologies=detect_technologies(headers, cookies, body),
        tls_info=tls_info,
        headers=headers,
        engine_used="native_python",
    )


def probe_target(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = False,
    tools_dir: Path | None = None,
    prefer_httpx: bool = False,
    user_agent: str = "Mozilla/5.0 (compatible; Cybergrok/1.0; Security Assessment)",
    allow_private: bool = False,
    insecure_tls: bool = False,
    guard: Callable[[str], str] | None = None,
) -> ProbeResult:
    _ = guard(url) if guard else assert_safe_url(url, allow_private=allow_private)
    if prefer_httpx and not follow_redirects:
        result = probe_httpx(
            url, timeout, tools_dir, follow_redirects=False, allow_private=allow_private
        )
        if result:
            if result.url:
                if guard:
                    _ = guard(result.url)
                else:
                    _ = assert_safe_url(result.url, allow_private=allow_private)
            return result
    return probe_native(
        url,
        timeout,
        follow_redirects,
        user_agent,
        allow_private=allow_private,
        insecure_tls=insecure_tls,
        guard=guard,
    )
