import pytest

from cybergrok.netguard import UnsafeURL, assert_safe_url


def test_rejects_file_and_metadata():
    with pytest.raises(UnsafeURL):
        assert_safe_url("file:///etc/passwd")
    with pytest.raises(UnsafeURL):
        assert_safe_url("http://169.254.169.254/latest/meta-data")


def test_rejects_loopback_unless_allowed():
    with pytest.raises(UnsafeURL):
        assert_safe_url("http://127.0.0.1:8888/")
    assert assert_safe_url("http://127.0.0.1:8888/", allow_private=True).startswith("http://")
