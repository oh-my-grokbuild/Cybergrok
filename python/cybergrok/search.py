"""Offline knowledge-base search (PayloadsAllTheThings, skills, etc.)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

HEADING_RE = re.compile(r"^#{1,4}\s+(.+)$")
CODE_BLOCK_RE = re.compile(r"```[a-zA-Z0-9_-]*\n.*?```", re.S)

KB_MAPPING = {
    "payloads": "PayloadsAllTheThings",
    "hacktricks": "hacktricks",
    "claude": "Claude-BugHunter",
    "strix": "strix-skills",
    "hack": "hack-skills",
}

SKIP_DIRS = {".git", "node_modules", "site", "vendor"}
SKIP_NAMES = {"summary.md", "_sidebar.md", "toc.md"}


@dataclass
class Snippet:
    heading: str
    start_line: int
    score: int
    content: str
    file: str
    source_kb: str

    def to_dict(self) -> dict:
        return asdict(self)


class Searcher:
    def __init__(self, base_dir: Path, root_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.root_dir = Path(root_dir)

    def search(self, query: str, source: str = "all", limit: int = 3, max_chars: int = 1400) -> list[Snippet]:
        search_path = self.base_dir
        mapped = KB_MAPPING.get(source, "")
        if mapped:
            candidate = self.base_dir / mapped
            if candidate.is_dir():
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
        files: list[Path] = []
        if not search_path.is_dir():
            return []
        for p in search_path.rglob("*"):
            if p.is_dir() and p.name in SKIP_DIRS:
                continue
            if not p.is_file():
                continue
            name = p.name.lower()
            if name in SKIP_NAMES:
                continue
            if name.endswith((".md", ".txt")):
                files.append(p)

        scored: list[tuple[Path, int]] = []

        def score_file(path: Path) -> tuple[Path, int] | None:
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

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(score_file, f) for f in files]
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

    def _extract_snippets(self, file_path: Path, keywords: list[str], max_chars: int) -> list[Snippet]:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

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

        try:
            rel = str(file_path.relative_to(self.root_dir))
        except ValueError:
            rel = str(file_path)
        kb = self._detect_kb(file_path)
        file_lower = file_path.name.lower()
        snippets: list[Snippet] = []

        for heading, start_line, body in sections:
            lower = body.lower()
            hits = sum(lower.count(kw) for kw in keywords)
            if hits == 0:
                continue
            score = hits * 5
            if any(kw in heading.lower() for kw in keywords):
                score += 40
            if "```" in body:
                score += 35
            if any(t in lower for t in ("payload", "bypass", "exploit", "poc", "syntax", "example")):
                score += 25
            if file_lower in {"summary.md", "_sidebar.md"}:
                score -= 60

            trimmed = body
            if len(body) > max_chars:
                blocks = CODE_BLOCK_RE.findall(body)
                if blocks and len(blocks[0]) < max_chars:
                    trimmed = heading + "\n\n" + blocks[0] + "\n\n*(Truncated for context efficiency)*"
                else:
                    trimmed = body[:max_chars].rstrip() + "\n\n*(Truncated for context efficiency)*"

            snippets.append(Snippet(heading, start_line, score, trimmed, rel, kb))

        snippets.sort(key=lambda s: s.score, reverse=True)
        return snippets[:2]
