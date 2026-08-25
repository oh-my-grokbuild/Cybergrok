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


def test_rejects_alibaba_and_mapped_imds():
    with pytest.raises(UnsafeURL):
        assert_safe_url("http://100.100.100.200/")
    with pytest.raises(UnsafeURL):
        assert_safe_url("http://[::ffff:169.254.169.254]/")
    with pytest.raises(UnsafeURL):
        assert_safe_url("http://[::ffff:127.0.0.1]/")
