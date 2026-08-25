"""Smart-pipe stream filter: score recon lines and archive the raw dump."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable, TextIO

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
UUID_RE = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

STATIC_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".mp4", ".mp3", ".webm", ".avi", ".mov",
)
CRITICAL_MARKERS = (
    "[critical]", "[high]", "cve-", "rce", "sql injection",
    "sqli", "idor", "ssrf", "xxe", "auth bypass",
)
SECRET_MARKERS = (
    ".env", ".git", "swagger", "openapi", "graphql",
    "id_rsa", "password", "secret_key", "bearer ", "token=", "jwt",
)


@dataclass
class ScoredLine:
    score: int
    text: str


@dataclass
class ProcessResult:
    total_raw: int
    unique_scored: int
    shown_count: int
    preserved_count: int


def clean_line(line: str) -> str:
    return ANSI_RE.sub("", line).strip()


def calculate_entropy(text: str) -> float:
    if len(text) < 16:
        return 0.0
    counts: dict[int, int] = {}
    for ch in text.encode("utf-8", errors="ignore"):
        counts[ch] = counts.get(ch, 0) + 1
    length = float(sum(counts.values()))
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_static_asset(lower: str) -> bool:
    for ext in STATIC_SUFFIXES:
        if lower.endswith(ext) or f"{ext}?" in lower or f"{ext}#" in lower:
            return True
    return False


def score_line(line: str) -> int:
    lower = line.lower()
    if _is_static_asset(lower):
        return 0

    score = 10
    if any(m in lower for m in CRITICAL_MARKERS):
        score += 80
    if any(m in lower for m in SECRET_MARKERS):
        score += 60

    if "200 ok" in lower or "[200]" in lower:
        score += 25
        if "/api/" in lower or "/v1/" in lower or "/v2/" in lower:
            score += 25
    elif "[401]" in lower or "[403]" in lower or "401 unauthorized" in lower or "403 forbidden" in lower:
        score += 20
        if "/admin" in lower or "/api/" in lower or "/internal" in lower:
            score += 25
    elif "[500]" in lower or "500 internal server error" in lower:
        score += 15

    if "?" in line and "=" in line:
        score += 20
    if UUID_RE.search(line):
        score += 20
    if any(k in lower for k in ("key", "secret", "tok", "pass")) and calculate_entropy(line) > 3.8:
        score += 30
    return score


def process_stream(lines: Iterable[str], stdout: TextIO, raw_out: TextIO, limit: int = 40) -> ProcessResult:
    total_raw = 0
    scored: list[ScoredLine] = []
    seen: set[str] = set()

    for raw in lines:
        cleaned = clean_line(raw)
        if not cleaned:
            continue
        total_raw += 1
        raw_out.write(cleaned + "\n")
        if cleaned in seen:
            continue
        seen.add(cleaned)
        score = score_line(cleaned)
        if score > 0:
            scored.append(ScoredLine(score=score, text=cleaned))

    scored.sort(key=lambda item: item.score, reverse=True)
    display = min(limit, len(scored))
    stdout.write(
        f"📊 [Smart Filter] {display} high-signal findings prioritized "
        f"(from {total_raw} total raw lines).\n\n"
    )
    for item in scored[:display]:
        stdout.write(item.text + "\n")
    if len(scored) > display:
        stdout.write(f"\n... (+{len(scored) - display} more filtered entries archived in raw log)\n")

    return ProcessResult(
        total_raw=total_raw,
        unique_scored=len(scored),
        shown_count=display,
        preserved_count=max(0, len(scored) - display),
    )
