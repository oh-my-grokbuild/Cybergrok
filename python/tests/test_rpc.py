from cybergrok.rpc import dispatch
from cybergrok.paths import find_project_root


def test_list_skills_rpc():
    root = find_project_root()
    result = dispatch("list_skills", {"filter": "idor", "limit": 5, "workspace": str(root)})
    assert result["total"] > 0
    assert any("idor" in s["name"] for s in result["skills"])


def test_unknown_op():
    result = dispatch("nope", {})
    assert "error" in result
