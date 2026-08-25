from pathlib import Path

from cybergrok.skills import get_skill


def test_get_skill_rejects_absolute_and_traversal(tmp_path: Path):
    skills = tmp_path / "skills"
    planted = tmp_path / "exfil"
    planted.mkdir()
    _ = (planted / "SKILL.md").write_text("SECRET", encoding="utf-8")
    skills.mkdir()
    legit = skills / "demo"
    legit.mkdir()
    _ = (legit / "SKILL.md").write_text("---\nname: demo\n---\nok\n", encoding="utf-8")

    assert get_skill(skills, "demo") is not None
    assert get_skill(skills, str(planted)) is None
    assert get_skill(skills, str(planted / "SKILL.md")) is None
    assert get_skill(skills, "../exfil") is None
    assert get_skill(skills, "/tmp/exfil") is None
