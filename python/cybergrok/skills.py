"""Skill index and playbook loader."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class SkillMetadata:
    name: str
    description: str
    sources: str = ""
    report_count: int = 0
    path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "sources": self.sources,
            "report_count": self.report_count,
            "path": self.path,
        }


def _parse_frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    meta: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        meta[key.strip().lower()] = val.strip().strip("'\"")
    return meta


def list_skills(skills_dir: Path) -> list[SkillMetadata]:
    skills: list[SkillMetadata] = []
    if not skills_dir.is_dir():
        return skills
    seen: set[str] = set()
    for skill_file in sorted(skills_dir.rglob("SKILL.md")):
        if not skill_file.is_file():
            continue
        text = skill_file.read_text(encoding="utf-8", errors="ignore")
        fm = _parse_frontmatter(text)
        report_count = 0
        raw_count = fm.get("report_count", "0")
        try:
            report_count = int(raw_count)
        except ValueError:
            report_count = 0
        name = fm.get("name") or skill_file.parent.name
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        skills.append(
            SkillMetadata(
                name=name,
                description=fm.get("description") or "",
                sources=fm.get("sources") or "",
                report_count=report_count,
                path=str(skill_file),
            )
        )
    return skills


def _skill_name_ok(name: str) -> bool:
    raw = name.strip()
    if not raw or raw in {".", ".."}:
        return False
    if Path(raw).is_absolute() or "/" in raw or "\\" in raw:
        return False
    return ".." not in Path(raw).parts


def _confine_skill(path: Path, skills_dir: Path) -> Path | None:
    try:
        resolved = path.resolve()
        _ = resolved.relative_to(skills_dir.resolve())
    except ValueError:
        return None
    return resolved if resolved.is_file() else None


def get_skill(skills_dir: Path, name: str, section: str = "") -> str | None:
    if not _skill_name_ok(name):
        return None
    needle = name.lower().strip()
    direct = skills_dir / name / "SKILL.md"
    path = _confine_skill(direct, skills_dir) if direct.is_file() else None
    if path is None:
        for skill_file in skills_dir.rglob("SKILL.md"):
            if skill_file.parent.name.lower() == needle:
                path = _confine_skill(skill_file, skills_dir)
                if path is not None:
                    break
    if path is None:
        for sk in list_skills(skills_dir):
            if sk.name.lower() == needle:
                path = _confine_skill(Path(sk.path), skills_dir)
                break
    if path is None:
        return None
    content = path.read_text(encoding="utf-8", errors="ignore")
    if not section:
        return content
    return extract_section(content, section) or content


def extract_section(content: str, query: str) -> str:
    q = query.lower()
    capturing = False
    level = 0
    out: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            current = len(stripped) - len(stripped.lstrip("#"))
            title = stripped[current:].strip()
            if capturing and current <= level:
                break
            if not capturing and q in title.lower():
                capturing = True
                level = current
        if capturing:
            out.append(line)
    return "\n".join(out).strip()
