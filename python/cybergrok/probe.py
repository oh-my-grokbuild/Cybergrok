"""HTTP probe + tech fingerprint (native Python, optional httpx binary)."""

from __future__ import annotations

import json
import re
import shutil
import ssl
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TITLE_RE = re.compile(r"(?i)<title[^>]*>([^<]+)</title>")

SIGNATURES: list[dict] = [
    {"name": "Next.js", "headers": {"x-powered-by": "next.js"}, "body": ["__NEXT_DATA__", "/_next/static/", "/_next/data/"]},
    {"name": "React", "body": ["data-reactroot", "react-dom", "react.production.min.js"]},
    {"name": "Vue.js", "body": ["data-v-", "vue.min.js", "__vue__"]},
    {"name": "Angular", "body": ["ng-version=", "ng-app=", "ng-controller="]},
    {"name": "Laravel", "cookies": ["laravel_session", "xsrf-token"], "body": ["laravel", "csrf-token"]},
    {"name": "Spring Boot", "headers": {"x-application-context": ""}, "body": ["Whitelabel Error Page"]},
    {"name": "Django", "cookies": ["csrftoken", "sessionid"], "body": ["csrfmiddlewaretoken"]},
    {"name": "Express.js", "headers": {"x-powered-by": "express"}},
    {"name": "FastAPI / Uvicorn", "headers": {"server": "uvicorn"}},
    {"name": "WordPress", "headers": {"x-pingback": ""}, "cookies": ["wordpress_logged_in", "wp-settings"], "body": ["/wp-content/", "/wp-includes/", "wp-json"]},
    {"name": "PHP", "headers": {"x-powered-by": "php"}, "cookies": ["phpsessid"]},
    {"name": "ASP.NET / IIS", "headers": {"x-aspnet-version": "", "x-powered-by": "asp.net", "server": "microsoft-iis"}, "cookies": ["asp.net_sessionid"]},
    {"name": "Nginx", "headers": {"server": "nginx"}},
    {"name": "Apache HTTP Server", "headers": {"server": "apache"}},
    {"name": "Cloudflare", "headers": {"server": "cloudflare", "cf-ray": "", "cf-cache-status": ""}},
    {"name": "Swagger / OpenAPI", "body": ["swagger-ui", "swagger-ui-bundle", "openapi:", "/swagger/v1/swagger.json"]},
    {"name": "GraphQL", "body": ["__schema", "GraphiQL", "graphql-ws"]},
]


@dataclass
class TLSInfo:
    version: str = ""
    cipher_suite: str = ""
    issuer: str = ""
    subject: str = ""
    dns_names: list[str] = field(default_factory=list)
    expires_at: str = ""


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
    tls_info: dict | None = None
    headers: dict[str, str] = field(default_factory=dict)
    engine_used: str = "native_python"

    def to_dict(self) -> dict:
        return asdict(self)


def extract_title(html: str) -> str:
    m = TITLE_RE.search(html)
    return m.group(1).strip() if m else ""


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


def find_httpx(tools_dir: Path | None = None) -> str | None:
    if tools_dir:
        for name in ("httpx", "httpx.exe"):
            cand = tools_dir / "bin" / name
            if cand.is_file():
                return str(cand)
    return shutil.which("httpx")


def probe_httpx(url: str, timeout: int, tools_dir: Path | None) -> ProbeResult | None:
    binary = find_httpx(tools_dir)
    if not binary:
        return None
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [binary, "-u", url, "-silent", "-status-code", "-title", "-tech-detect", "-json", "-timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    elapsed = int((time.monotonic() - started) * 1000)
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not data.get("url"):
            continue
        tls = data.get("tls") or {}
        return ProbeResult(
            url=data.get("url", url),
            scheme=data.get("scheme", ""),
            host=data.get("host", ""),
            port=str(data.get("port") or ""),
            status_code=int(data.get("status_code") or 0),
            status_text="",
            title=data.get("title", ""),
            web_server=data.get("webserver", ""),
            content_type=data.get("content_type", ""),
            response_time_ms=elapsed,
            technologies=list(data.get("tech") or []),
            tls_info={"version": tls.get("version", ""), "subject": tls.get("subject_dn", ""), "issuer": tls.get("issuer_dn", "")} if tls else None,
            engine_used="httpx",
        )
    return None


def probe_native(url: str, timeout: int, follow_redirects: bool, user_agent: str) -> ProbeResult:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    from urllib.parse import urlparse

    parsed = urlparse(raw)
    ctx = ssl._create_unverified_context()
    req = Request(raw, headers={"User-Agent": user_agent, "Accept": "*/*"})
    started = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(1024 * 1024).decode("utf-8", errors="ignore")
            headers = {k: v for k, v in resp.headers.items()}
            status = getattr(resp, "status", 200)
            final_url = resp.geturl()
    except HTTPError as exc:
        body = exc.read(1024 * 1024).decode("utf-8", errors="ignore") if exc.fp else ""
        headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        status = exc.code
        final_url = raw
    except URLError as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc
    elapsed = int((time.monotonic() - started) * 1000)
    cookies = []
    if "Set-Cookie" in headers:
        cookies = [part.split("=", 1)[0] for part in headers["Set-Cookie"].split(",")]
    redirect = "" if follow_redirects or final_url == raw else final_url
    return ProbeResult(
        url=raw,
        scheme=parsed.scheme,
        host=parsed.hostname or "",
        port=str(parsed.port or ""),
        status_code=status,
        status_text=str(status),
        title=extract_title(body),
        web_server=headers.get("Server", ""),
        content_type=headers.get("Content-Type", ""),
        content_length=int(headers.get("Content-Length") or 0),
        response_time_ms=elapsed,
        redirect_url=redirect,
        technologies=detect_technologies(headers, cookies, body),
        headers=headers,
        engine_used="native_python",
    )


def probe_target(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = False,
    tools_dir: Path | None = None,
    prefer_httpx: bool = True,
    user_agent: str = "Mozilla/5.0 (compatible; Cybergrok/1.0; Security Assessment)",
) -> ProbeResult:
    if prefer_httpx:
        result = probe_httpx(url, timeout, tools_dir)
        if result:
            return result
    return probe_native(url, timeout, follow_redirects, user_agent)
