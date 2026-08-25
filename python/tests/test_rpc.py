from pathlib import Path

from cybergrok.paths import find_plugin_root
from cybergrok.rpc import dispatch


def test_list_skills_rpc():
    root = find_plugin_root()
    result = dispatch("list_skills", {"filter": "idor", "limit": 5, "plugin_root": str(root)})
    assert result["total"] > 0
    assert any("idor" in s["name"] for s in result["skills"])


def test_nested_skill_lookup():
    root = find_plugin_root()
    result = dispatch("get_skill", {"skill_name": "blackbox-web-audit", "plugin_root": str(root)})
    assert "content" in result
    assert result["content"]


def test_slug_escape_stays_in_workspace(tmp_path: Path):
    root = find_plugin_root()
    result = dispatch(
        "aggregate_report",
        {"target_slug": "../etc", "workspace": str(tmp_path), "plugin_root": str(root)},
    )
    assert "error" not in result
    assert (tmp_path / "reports" / "etc" / "SUMMARY.md").is_file()
    assert not (tmp_path.parent / "etc" / "SUMMARY.md").exists()


def test_unknown_op():
    result = dispatch("nope", {})
    assert "error" in result
