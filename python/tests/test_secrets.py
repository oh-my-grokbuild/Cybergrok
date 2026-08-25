from pathlib import Path

from cybergrok.secrets import filter_by_severity, mask_secret, scan_directory, scan_text


def test_aws_and_github_patterns():
    blob = "key=AKIAIOSFODNN7EXAMPLE\ntoken=ghp_" + ("a" * 36) + "\n"
    findings = scan_text(blob, "mem")
    names = {f.pattern for f in findings}
    assert "AWS_ACCESS_KEY" in names
    assert "GH_PAT_CLASSIC" in names


def test_multi_group_captures_secret_not_filler():
    secret = "A" * 40
    findings = scan_text(f"aws secret = {secret}\n", "mem")
    loose = [f for f in findings if f.pattern == "AWS_SECRET_LOOSE"]
    assert loose
    assert secret in loose[0].match


def test_dsa_private_key_keeps_full_header():
    findings = scan_text("-----BEGIN DSA PRIVATE KEY-----\n", "mem")
    dsa = [f for f in findings if f.pattern == "GENERIC_PRIVKEY"]
    assert dsa
    assert "BEGIN DSA PRIVATE KEY" in dsa[0].match


def test_directory_scan_skips_outside_symlinks(tmp_path: Path):
    outside = tmp_path / "outside.env"
    outside.write_text("ghp_" + ("a" * 36) + "\n", encoding="utf-8")
    recon = tmp_path / "recon" / "lab"
    recon.mkdir(parents=True)
    (recon / "leak.env").symlink_to(outside)
    (recon / "ok.txt").write_text("sk_test_" + ("a" * 24) + "\n", encoding="utf-8")
    findings = scan_directory(recon, confine_to=recon)
    sources = {Path(f.source).name for f in findings}
    assert "ok.txt" in sources
    assert "leak.env" not in sources
    assert "outside.env" not in sources


def test_severity_filter_and_mask():
    findings = scan_text("sk_test_" + ("a" * 24), "mem")
    assert findings
    assert filter_by_severity(findings, "critical") == []
    masked = mask_secret(findings[0].match)
    assert "…" in masked
