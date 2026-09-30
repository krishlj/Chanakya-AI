"""Minimal validation for the local reflected-XSS training lab.

Confirms the five required facts:
  1. the application starts (the server binds);
  2. 127.0.0.1 responds on the served handler;
  3. /search responds;
  4. the ``q`` parameter is reflected;
  5. the reflection is intentionally unsafe (no output encoding).

Plus that the lab binds only to loopback (never 0.0.0.0) and that its
configured address is 127.0.0.1:8080.

This is a validation test, NOT a vulnerability scanner or an exploit
framework. It lives under ``labs/`` and is not part of the Chanakya test
suite (``pyproject.toml`` sets ``testpaths = ["tests"]``). Run it directly:

    python labs/local-xss/test_app.py        # prints a PASS line
    pytest -q labs/local-xss/test_app.py     # or via pytest
"""
from __future__ import annotations

import contextlib
import os
import sys
import threading
from typing import Iterator, Tuple
from urllib.parse import quote
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app  # noqa: E402 — path is set just above so the lab imports standalone

XSS_PAYLOAD = "<script>alert(1)</script>"


@contextlib.contextmanager
def running_server() -> Iterator[Tuple[str, int]]:
    """Start the lab's own handler on an ephemeral loopback port (so the test
    never collides with a real :8080) and tear it down cleanly."""
    server = app.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[0], server.server_address[1]
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(host: str, port: int, path: str) -> Tuple[int, str]:
    with urlopen(f"http://{host}:{port}{path}", timeout=5) as response:
        return response.status, response.read().decode("utf-8")


def test_configured_address_is_localhost_8080():
    assert app.HOST == "127.0.0.1"
    assert app.PORT == 8080
    assert app.HOST != "0.0.0.0"


def test_build_server_refuses_non_loopback_bind():
    for bad in ("0.0.0.0", "192.168.1.10", "10.0.0.5", "example.com"):
        try:
            app.build_server(bad, 0)
            raise AssertionError(f"expected refusal for {bad!r}")
        except ValueError:
            pass


def test_1_application_starts_and_2_localhost_responds():
    with running_server() as (host, port):
        assert host == "127.0.0.1"
        status, body = _get(host, port, "/")
        assert status == 200
        assert "INTENTIONALLY VULNERABLE" in body


def test_3_search_responds():
    with running_server() as (host, port):
        status, _body = _get(host, port, "/search?q=hello")
        assert status == 200


def test_4_q_parameter_is_reflected():
    with running_server() as (host, port):
        _status, body = _get(host, port, "/search?q=chanakya-marker-123")
        assert "chanakya-marker-123" in body


def test_5_reflection_is_intentionally_unsafe():
    with running_server() as (host, port):
        _status, body = _get(host, port, "/search?q=" + quote(XSS_PAYLOAD))
        # The raw script tag is present verbatim (unencoded) ...
        assert XSS_PAYLOAD in body
        # ... and it was NOT HTML-encoded (which would have neutralised it).
        assert "&lt;script&gt;" not in body


def _main() -> int:
    test_configured_address_is_localhost_8080()
    test_build_server_refuses_non_loopback_bind()
    test_1_application_starts_and_2_localhost_responds()
    test_3_search_responds()
    test_4_q_parameter_is_reflected()
    test_5_reflection_is_intentionally_unsafe()
    print("LOCAL XSS TRAINING LAB — PASS (5/5 checks + loopback guard)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
