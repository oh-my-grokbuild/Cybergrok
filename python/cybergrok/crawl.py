"""Endpoint crawler (native Python, scope-guarded)."""

from __future__ import annotations

import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPSHandler, OpenerDirector, Request, build_opener

from . import _coerce
from .netguard import UnsafeURL, assert_safe_url, prepare_safe_request
from .probe import GuardedRedirectHandler
from .stream import score_line

HREF_RE = re.compile(r"""(?i)(?:href|src|action)=["']([^"'#\s>]+)["']""")
API_RE = re.compile(
    r"""(?i)["'](/(?:api|v[0-9]|rest|graphql|admin|auth|oauth|users|invoices|orders|documents|internal)[^"'#\s]*)["']"""
)


class _ScoredEndpoint(TypedDict):
    score: int
    text: str


@dataclass
class CrawlResult:
    target_url: str
    total_endpoints_found: int
    top_endpoints: list[_ScoredEndpoint]
    saved_file_path: str = ""
    engine_used: str = "native_python"
    duration_ms: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "target_url": self.target_url,
            "total_endpoints_found": self.total_endpoints_found,
            "top_endpoints": list(self.top_endpoints),
            "saved_file_path": self.saved_file_path,
            "engine_used": self.engine_used,
            "duration_ms": self.duration_ms,
        }


def _resolve(base: str, ref: str) -> str:
    if not ref or ref.startswith(("javascript:", "mailto:", "data:")):
        return ""
    return urljoin(base, ref)


def _fetch(
    opener: OpenerDirector, url: str, user_agent: str, timeout: int, allow_private: bool = False
) -> str:
    fetch, host_hdr = prepare_safe_request(url, allow_private=allow_private)
    req = Request(fetch, headers={"User-Agent": user_agent, "Host": host_hdr})
    try:
        return _coerce.open_limited(opener, req, min(5, timeout), 512 * 1024)
    except HTTPError as exc:
        if exc.fp:
            return _coerce.read_limited_text(exc, 512 * 1024)
        return ""
    except URLError, TimeoutError, OSError:
        return ""


def _default_port(scheme: str, port: int | None) -> int:
    if port:
        return port
    return 443 if scheme == "https" else 80


def _same_origin(left: str, right: str) -> bool:
    a = urlparse(left)
    b = urlparse(right)
    return (a.hostname or "").lower() == (b.hostname or "").lower() and _default_port(
        a.scheme, a.port
    ) == _default_port(b.scheme, b.port)


def _check(url: str, allow_private: bool, guard: Callable[[str], str] | None) -> str:
    _ = guard(url) if guard else assert_safe_url(url, allow_private=allow_private)
    return url


def _native_crawl(
    url: str,
    depth: int,
    timeout: int,
    user_agent: str,
    allow_private: bool,
    guard: Callable[[str], str] | None = None,
) -> list[str]:
    seed = _check(url, allow_private, guard)
    ctx = ssl.create_default_context()
    opener = build_opener(
        GuardedRedirectHandler(allow_private=allow_private, follow=False, guard=guard),
        HTTPSHandler(context=ctx),
    )
    visited: set[str] = set()
    endpoints: set[str] = set()
    queue = [seed]
    max_pages = 30
    for _ in range(max(1, depth)):
        nxt: list[str] = []
        for cur in queue:
            if cur in visited or len(visited) >= max_pages:
                continue
            try:
                current = _check(cur, allow_private, guard)
            except UnsafeURL, ValueError:
                continue
            visited.add(current)
            body = _fetch(opener, current, user_agent, timeout, allow_private=allow_private)
            if not body:
                continue
            for m in HREF_RE.finditer(body):
                resolved = _resolve(current, m.group(1).strip())
                if not resolved:
                    continue
                try:
                    safe = _check(resolved, allow_private, guard)
                except UnsafeURL, ValueError:
                    continue
                endpoints.add(safe)
                if _same_origin(safe, seed):
                    nxt.append(safe)
            for m in API_RE.finditer(body):
                resolved = _resolve(current, m.group(1).strip())
                if not resolved:
                    continue
                try:
                    endpoints.add(_check(resolved, allow_private, guard))
                except UnsafeURL, ValueError:
                    continue
        queue = nxt
    return list(endpoints)


def crawl_target(
    url: str,
    depth: int = 2,
    max_endpoints: int = 25,
    timeout: int = 30,
    output_dir: Path | None = None,
    user_agent: str = "Mozilla/5.0 (compatible; Cybergrok/1.0; Recon Crawler)",
    allow_private: bool = False,
    guard: Callable[[str], str] | None = None,
) -> CrawlResult:
    seed = _check(url, allow_private, guard)
    started = time.monotonic()
    engine = "native_python"
    # Katana fetches before per-URL scope/netguard. Always use the native crawler.
    raw = _native_crawl(seed, depth, timeout, user_agent, allow_private=allow_private, guard=guard)

    unique: dict[str, int] = {}
    for raw_ep in raw:
        endpoint = raw_ep.strip()
        if not endpoint or endpoint in unique:
            continue
        try:
            endpoint = _check(endpoint, allow_private, guard)
        except UnsafeURL, ValueError:
            continue
        unique[endpoint] = score_line(endpoint)
    scored: list[_ScoredEndpoint] = sorted(
        ({"score": s, "text": t} for t, s in unique.items()),
        key=lambda x: (-x["score"], len(x["text"])),
    )
    saved = ""
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        dest = output_dir / f"{engine}.txt"
        _ = dest.write_text("".join(item["text"] + "\n" for item in scored), encoding="utf-8")
        saved = str(dest)
    top = scored[: max(1, max_endpoints)]
    return CrawlResult(
        target_url=url,
        total_endpoints_found=len(scored),
        top_endpoints=top,
        saved_file_path=saved,
        engine_used=engine,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
