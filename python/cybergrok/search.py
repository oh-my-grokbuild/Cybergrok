"""Offline knowledge-base search (PayloadsAllTheThings, skills, etc.)."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import final

from . import _coerce

HEADING_RE = re.compile(r"^#{1,4}\s+(.+)$")
CODE_BLOCK_RE = re.compile(r"```[a-zA-Z0-9_-]*\n.*?```", re.DOTALL)

KB_MAPPING = {
    "payloads": "PayloadsAllTheThings",
    "hacktricks": "hacktricks",
    "claude": "Claude-BugHunter",
    "strix": "strix-skills",
    "hack": "hack-skills",
}

SKIP_DIRS = {".git", "node_modules", "site", "vendor"}
SKIP_NAMES = {"summary.md", "_sidebar.md", "toc.md"}
SIGNAL_TERMS = ("payload", "bypass", "exploit", "poc", "syntax", "example")


def _collect_text_files(search_path: Path) -> list[Path]:
    files: list[Path] = []
    if not search_path.is_dir():
        return files
    for dirpath, dirnames, filenames in os.walk(search_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            name = filename.lower()
            if name in SKIP_NAMES or not name.endswith((".md", ".txt")):
                continue
            files.append(Path(dirpath) / filename)
    return files


def _score_file(path: Path, keywords: list[str]) -> tuple[Path, int] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lower = text.lower()
    total = 0
    unique = 0
    for kw in keywords:
        count = lower.count(kw)
        if count:
            total += count
            unique += 1
    if total <= 0:
        return None
    return path, total + unique * 15


def _split_sections(text: str) -> list[tuple[str, int, str]]:
    sections: list[tuple[str, int, str]] = []
    heading = "General"
    buf: list[str] = []
    start = 1
    for i, line in enumerate(text.splitlines(), start=1):
        if HEADING_RE.match(line):
            if buf:
                sections.append((heading, start, "\n".join(buf)))
            heading = line.strip()
            buf = [line]
            start = i
        else:
            buf.append(line)
    if buf:
        sections.append((heading, start, "\n".join(buf)))
    return sections


def _section_score(heading: str, body: str, keywords: list[str], file_lower: str) -> int:
    lower = body.lower()
    hits = sum(lower.count(kw) for kw in keywords)
    if hits == 0:
        return 0
    score = hits * 5
    if any(kw in heading.lower() for kw in keywords):
        score += 40
    if "```" in body:
        score += 35
    if any(term in lower for term in SIGNAL_TERMS):
        score += 25
    if file_lower in {"summary.md", "_sidebar.md"}:
        score -= 60
    return score


def _trim_section(heading: str, body: str, max_chars: int) -> str:
    if len(body) <= max_chars:
        return body
    first = _coerce.first_regex_group(CODE_BLOCK_RE, body)
    if first and len(first) < max_chars:
        return f"{heading}\n\n{first}\n\n*(Truncated for context efficiency)*"
    return body[:max_chars].rstrip() + "\n\n*(Truncated for context efficiency)*"


@dataclass
class Snippet:
    heading: str
    start_line: int
    score: int
    content: str
    file: str
    source_kb: str

    def to_dict(self) -> dict[str, object]:
        return {
            "heading": self.heading,
            "start_line": self.start_line,
            "score": self.score,
            "content": self.content,
            "file": self.file,
            "source_kb": self.source_kb,
        }


@final
class Searcher:
    base_dir: Path
    root_dir: Path

    def __init__(self, base_dir: Path, root_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.root_dir = Path(root_dir)

    def search(
        self, query: str, source: str = "all", limit: int = 3, max_chars: int = 1400
    ) -> list[Snippet]:
        search_path = self.base_dir
        mapped = KB_MAPPING.get(source, "")
        if mapped:
            candidate = self.base_dir / mapped
            if not candidate.is_dir():
                return []
            search_path = candidate

        keywords = [t for t in query.lower().split() if len(t) > 1]
        if not keywords:
            return []

        candidates = self._find_candidates(search_path, keywords)
        snippets: list[Snippet] = []
        for path, _score in candidates[:25]:
            snippets.extend(self._extract_snippets(path, keywords, max_chars))
        snippets.sort(key=lambda s: s.score, reverse=True)
        if limit > 0:
            snippets = snippets[:limit]
        return snippets

    def _find_candidates(self, search_path: Path, keywords: list[str]) -> list[tuple[Path, int]]:
        scored: list[tuple[Path, int]] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [
                pool.submit(_score_file, path, keywords)
                for path in _collect_text_files(search_path)
            ]
            for fut in as_completed(futs):
                item = fut.result()
                if item:
                    scored.append(item)
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def _detect_kb(self, file_path: Path) -> str:
        try:
            rel = file_path.relative_to(self.base_dir)
            return rel.parts[0] if rel.parts else "knowledge"
        except ValueError:
            return "knowledge"

    def _extract_snippets(
        self, file_path: Path, keywords: list[str], max_chars: int
    ) -> list[Snippet]:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        try:
            rel = str(file_path.relative_to(self.root_dir))
        except ValueError:
            rel = str(file_path)
        kb = self._detect_kb(file_path)
        file_lower = file_path.name.lower()
        snippets: list[Snippet] = []
        for heading, start_line, body in _split_sections(text):
            score = _section_score(heading, body, keywords, file_lower)
            if score == 0:
                continue
            snippets.append(
                Snippet(
                    heading, start_line, score, _trim_section(heading, body, max_chars), rel, kb
                )
            )
        snippets.sort(key=lambda s: s.score, reverse=True)
        return snippets[:2]
