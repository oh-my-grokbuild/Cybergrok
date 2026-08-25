from cybergrok.scope import ScopeConfig, validate_target


def test_wildcard_and_out_of_scope():
    cfg = ScopeConfig(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert validate_target("https://app.example.com/x", cfg).allowed
    assert not validate_target("https://admin.example.com/", cfg).allowed
    assert not validate_target("https://other.com/", cfg).allowed


def test_operator_star_allows():
    cfg = ScopeConfig(in_scope=["*"], dynamic_target_override=True)
    assert validate_target("https://anything.test/api", cfg).allowed


def test_no_scope_file_allows():
    result = validate_target("127.0.0.1:8888", None)
    assert result.allowed
    assert result.host == "127.0.0.1"
    assert result.port == "8888"
