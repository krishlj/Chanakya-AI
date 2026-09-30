"""Deliberately vulnerable local training target — reflected XSS.

    ⚠️  INTENTIONALLY VULNERABLE TRAINING CODE — DO NOT DEPLOY  ⚠️

This is a tiny, disposable local web application built for ONE purpose: to
practise driving the Chanakya AI security agent against a controlled target
that contains ONE known vulnerability. It is not production code and must
never be exposed beyond the local loopback interface.

The one intentional vulnerability: **reflected Cross-Site Scripting (XSS)**.
``GET /search?q=<input>`` reflects the ``q`` parameter straight into the HTML
response with no output encoding, so a value such as
``<script>alert(1)</script>`` is returned verbatim and executes in the
browser.

Everything else is deliberately absent: no authentication, no database, no
user accounts, no file uploads, no subprocess or shell execution, no
credentials, no real data, and no outbound network access. It is standard
library only (``http.server``) and binds ONLY to 127.0.0.1.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

#: The lab binds ONLY to the loopback interface. Never 0.0.0.0, never a
#: routable address. ``build_server`` refuses anything that is not loopback.
HOST = "127.0.0.1"
PORT = 8080

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_BANNER = (
    "<div style=\"background:#b00020;color:#fff;padding:8px;font-family:sans-serif\">"
    "⚠ INTENTIONALLY VULNERABLE TRAINING APP — reflected XSS — "
    "localhost only, do not deploy</div>"
)


def render_index() -> str:
    """A safe landing page with a search form. Nothing here is reflected."""
    return (
        "<!doctype html><html><head><title>XSS Training Lab</title></head><body>"
        f"{_BANNER}"
        "<h1>Search demo</h1>"
        "<form action=\"/search\" method=\"get\">"
        "<input name=\"q\" placeholder=\"search term\">"
        "<button type=\"submit\">Search</button>"
        "</form>"
        "<p>Try <code>/search?q=hello</code>.</p>"
        "</body></html>"
    )


def render_search(q: str) -> str:
    """Render the search results page.

    THE INTENTIONAL VULNERABILITY IS ON THE NEXT LINE: ``q`` is interpolated
    into the HTML response WITHOUT any output encoding (no ``html.escape``),
    which is a textbook reflected XSS. Encoding ``q`` with ``html.escape``
    would fix it — that is deliberately NOT done here.
    """
    reflected = q  # noqa: intentional — unescaped reflection of user input
    return (
        "<!doctype html><html><head><title>Results</title></head><body>"
        f"{_BANNER}"
        "<h1>Search results</h1>"
        f"<p>You searched for: {reflected}</p>"  # reflected XSS sink
        "<p><a href=\"/\">Back</a></p>"
        "</body></html>"
    )


class TrainingHandler(BaseHTTPRequestHandler):
    """Serves the index and the one vulnerable ``/search`` endpoint. No other
    path does anything (404)."""

    server_version = "XSSLab/1.0"

    def _send_html(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        # text/html is required for the reflected XSS to be demonstrable.
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        parts = urlsplit(self.path)
        if parts.path == "/":
            self._send_html(200, render_index())
            return
        if parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            self._send_html(200, render_search(q))
            return
        self._send_html(404, f"{_BANNER}<h1>404 Not Found</h1>")

    # Keep the default request logging (useful during the exercise); it writes
    # to stderr only and echoes no secret (there are none).


def build_server(host: str = HOST, port: int = PORT) -> HTTPServer:
    """Create the HTTP server, refusing any non-loopback bind address. This
    guard makes the localhost-only guarantee explicit and testable."""
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(f"refusing to bind training lab to non-loopback host {host!r}; loopback only")
    return HTTPServer((host, port), TrainingHandler)


def main() -> None:
    server = build_server()
    host, port = server.server_address[0], server.server_address[1]
    print(f"XSS training lab (INTENTIONALLY VULNERABLE) listening on http://{host}:{port}")
    print("Vulnerable endpoint: GET /search?q=<input>  (reflected without encoding)")
    print("Stop with Ctrl+C. Localhost only — never expose this.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
