"""
Cybergrok Mock Vulnerable Web Target
Used for safe local validation of IDOR, information disclosure, and reporting pipelines.
"""

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import override

DOCUMENTS = {
    "101": {
        "id": "101",
        "owner": "researcher_user_a",
        "title": "User A Public Notes",
        "content": "Public draft",
    },
    "102": {
        "id": "102",
        "owner": "researcher_user_b",
        "title": "User B Confidential Report",
        "content": "CONFIDENTIAL_FINANCIAL_DATA_FLAG{IDOR_VALIDATED_SUCCESSFULLY}",
    },
}


class VulnerableHandler(BaseHTTPRequestHandler):
    @override
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            _ = self.send_response(200)
            _ = self.send_header("Content-Type", "application/json")
            self.end_headers()
            _ = self.wfile.write(
                json.dumps(
                    {
                        "service": "Cybergrok Mock Target API",
                        "version": "1.0.0",
                        "status": "healthy",
                        "endpoints": ["/api/health", "/api/documents/<id>", "/search?q=<keyword>"],
                    }
                ).encode()
            )

        elif path == "/api/health":
            _ = self.send_response(200)
            _ = self.send_header("Content-Type", "application/json")
            self.end_headers()
            _ = self.wfile.write(b'{"status": "ok"}')

        elif path.startswith("/api/documents/"):
            doc_id = path.split("/")[-1]
            if doc_id in DOCUMENTS:
                _ = self.send_response(200)
                _ = self.send_header("Content-Type", "application/json")
                self.end_headers()
                _ = self.wfile.write(json.dumps(DOCUMENTS[doc_id]).encode())
            else:
                _ = self.send_response(404)
                _ = self.send_header("Content-Type", "application/json")
                self.end_headers()
                _ = self.wfile.write(b'{"error": "Document not found"}')

        elif path == "/search":
            q = query.get("q", [""])[0]
            _ = self.send_response(200)
            _ = self.send_header("Content-Type", "text/html")
            self.end_headers()
            _ = self.wfile.write(
                f"<html><body><h1>Search Results for: {q}</h1><p>No results found.</p></body></html>".encode()
            )

        else:
            _ = self.send_response(404)
            _ = self.send_header("Content-Type", "application/json")
            self.end_headers()
            _ = self.wfile.write(b'{"error": "Not Found"}')


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8888), VulnerableHandler)
    print("Mock Vulnerable Target listening on http://127.0.0.1:8888")
    server.serve_forever()
