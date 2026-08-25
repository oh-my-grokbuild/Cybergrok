from pathlib import Path

from cybergrok.report import aggregate_target, record_finding


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
