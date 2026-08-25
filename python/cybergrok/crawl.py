"""Endpoint crawler (optional katana, native Python fallback)."""

from __future__ import annotations

import re
import shutil
import ssl
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPSHandler, Request, build_opener

from .netguard import UnsafeURL, assert_safe_url
from .probe import GuardedRedirectHandler
from .stream import score_line

HREF_RE = re.compile(r"""(?i)(?:href|src|action)=["']([^"'#\s>]+)["']""")
API_RE = re.compile(
    r"""(?i)["'](/(?:api|v[0-9]|rest|graphql|admin|auth|oauth|users|invoices|orders|documents|internal)[^"'#\s]*)["']"""
)


@dataclass
class CrawlResult:
    target_url: str
    total_endpoints_found: int
    top_endpoints: list[dict]
    saved_file_path: str = ""
    engine_used: str = "native_python"
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def find_katana(tools_dir: Path | None = None) -> str | None:
    if tools_dir:
        for name in ("katana", "katana.exe"):
            cand = Path(tools_dir) / "bin" / name
            if cand.is_file():
                return str(cand)
    return shutil.which("katana")


def _run_katana(url: str, depth: int, timeout: int, binary: str) -> list[str]:
    try:
        proc = subprocess.run(
            [binary, "-u", url, "-d", str(depth), "-jc", "-silent", "-ct", f"{timeout}s"],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _resolve(base: str, ref: str) -> str:
    if not ref or ref.startswith(("javascript:", "mailto:", "data:")):
        return ""
    return urljoin(base, ref)


def _fetch(opener, url: str, user_agent: str, timeout: int) -> str:
    req = Request(url, headers={"User-Agent": user_agent})
    try:
        with opener.open(req, timeout=min(5, timeout)) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="ignore")
    except HTTPError as exc:
        if exc.fp:
            return exc.read(512 * 1024).decode("utf-8", errors="ignore")
        return ""
    except (URLError, TimeoutError, OSError):
        return ""


def _native_crawl(url: str, depth: int, timeout: int, user_agent: str, allow_private: bool) -> list[str]:
    seed = assert_safe_url(url, allow_private=allow_private)
    parsed = urlparse(seed)
    ctx = ssl.create_default_context()
    opener = build_opener(GuardedRedirectHandler(allow_private=allow_private, follow=False), HTTPSHandler(context=ctx))
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
                assert_safe_url(cur, allow_private=allow_private)
            except UnsafeURL:
                continue
            visited.add(cur)
            body = _fetch(opener, cur, user_agent, timeout)
            if not body:
                continue
            for m in HREF_RE.finditer(body):
                resolved = _resolve(cur, m.group(1).strip())
                if not resolved:
                    continue
                try:
                    safe = assert_safe_url(resolved, allow_private=allow_private)
                except UnsafeURL:
                    continue
                endpoints.add(safe)
                if urlparse(safe).hostname == parsed.hostname:
                    nxt.append(safe)
            for m in API_RE.finditer(body):
                resolved = _resolve(cur, m.group(1).strip())
                if not resolved:
                    continue
                try:
                    endpoints.add(assert_safe_url(resolved, allow_private=allow_private))
                except UnsafeURL:
                    continue
        queue = nxt
    return list(endpoints)


def crawl_target(
    url: str,
    depth: int = 2,
    max_endpoints: int = 25,
    timeout: int = 30,
    tools_dir: Path | None = None,
    output_dir: Path | None = None,
    prefer_katana: bool = True,
    user_agent: str = "Mozilla/5.0 (compatible; Cybergrok/1.0; Recon Crawler)",
    allow_private: bool = False,
) -> CrawlResult:
    assert_safe_url(url, allow_private=allow_private)
    started = time.monotonic()
    engine = "native_python"
    raw: list[str] = []
    if prefer_katana:
        binary = find_katana(tools_dir)
        if binary:
            raw = _run_katana(url, depth, timeout, binary)
            if raw:
                engine = "katana"
    if not raw:
        raw = _native_crawl(url, depth, timeout, user_agent, allow_private=allow_private)

    unique: dict[str, int] = {}
    for ep in raw:
        ep = ep.strip()
        if not ep or ep in unique:
            continue
        try:
            ep = assert_safe_url(ep, allow_private=allow_private)
        except UnsafeURL:
            continue
        unique[ep] = score_line(ep)
    scored = sorted(({"score": s, "text": t} for t, s in unique.items()), key=lambda x: (-x["score"], len(x["text"])))
    saved = ""
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        dest = output_dir / f"{engine}.txt"
        dest.write_text("".join(item["text"] + "\n" for item in scored), encoding="utf-8")
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
