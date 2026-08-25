from cybergrok.secrets import filter_by_severity, mask_secret, scan_text


def test_aws_and_github_patterns():
    blob = "key=AKIAIOSFODNN7EXAMPLE\ntoken=ghp_" + ("a" * 36) + "\n"
    findings = scan_text(blob, "mem")
    names = {f.pattern for f in findings}
    assert "AWS_ACCESS_KEY" in names
    assert "GH_PAT_CLASSIC" in names


def test_severity_filter_and_mask():
    findings = scan_text("sk_test_" + ("a" * 24), "mem")
    assert findings
    assert filter_by_severity(findings, "critical") == []
    masked = mask_secret(findings[0].match)
    assert "…" in masked
