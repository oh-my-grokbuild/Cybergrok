from pathlib import Path

from cybergrok.report import aggregate_target, record_finding, sanitize_slug


def test_record_and_aggregate(tmp_path: Path):
    result = record_finding(
        tmp_path,
        "example_com",
        "high",
        "IDOR invoices",
        "GET /api/invoices/1",
        "Object-level auth missing.",
        "1. Login as B\n2. GET invoice 1",
        poc_script="print('poc')\n",
    )
    assert result["file"].endswith("high_idor_invoices.md")
    summary = aggregate_target(tmp_path / "example_com")
    assert summary.total_findings == 1
    assert summary.severity_summary["HIGH"] == 1
    assert (tmp_path / "example_com" / "SUMMARY.md").is_file()
    assert (tmp_path / "example_com" / "metadata.json").is_file()
    assert (tmp_path / "example_com" / "pocs" / "poc_idor_invoices.py").is_file()


def test_informational_goes_to_evidence(tmp_path: Path):
    result = record_finding(
        tmp_path,
        "example_com",
        "informational",
        "Missing security headers",
        "GET /",
        "No CSP",
        "curl /",
    )
    assert "evidence/recon_notes.md" in result["file"]
    summary = aggregate_target(tmp_path / "example_com")
    assert summary.total_findings == 0
    assert (tmp_path / "example_com" / "evidence" / "recon_notes.md").is_file()


def test_url_slug_is_host_only():
    assert sanitize_slug("https://Example.COM/app/v1") == "example_com"
    assert sanitize_slug("../etc") == "etc"
    assert sanitize_slug("!!!") == "target"
