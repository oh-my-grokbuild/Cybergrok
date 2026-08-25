from io import StringIO

from cybergrok.stream import process_stream, score_line


def test_static_assets_score_zero():
    assert score_line("https://example.com/app.css") == 0
    assert score_line("https://example.com/logo.png?v=2") == 0


def test_api_200_outranks_noise():
    api = score_line("[200] https://example.com/api/v1/invoices?id=12")
    noise = score_line("https://example.com/about")
    assert api > noise


def test_process_stream_archives_and_limits():
    stdin = ["https://x.com/a.png", "[200] /api/v1/users", "[200] /api/v1/users", "[403] /admin"]
    stdout = StringIO()
    raw = StringIO()
    result = process_stream(stdin, stdout, raw, limit=1)
    assert result.total_raw == 4
    assert result.shown_count == 1
    assert "/api/v1/users" in raw.getvalue()
    assert "high-signal" in stdout.getvalue()
