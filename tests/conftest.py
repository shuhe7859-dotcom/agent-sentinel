"""Shared test setup.

Two things live here:

* the ``src`` path shim, so the suite runs straight from a checkout without
  ``pip install -e .`` first;
* a throwaway HTTP server, so the network tests exercise real requests without
  ever touching the internet.
"""

from __future__ import annotations

import http.server
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

HELLO = b"hello from the local server"
"""The body every successful request in the tests comes back with."""


@dataclass
class LocalServer:
    """A tiny HTTP server bound to a loopback port."""

    base_url: str
    body: bytes
    """What a successful request comes back with."""

    hits: list[str] = field(default_factory=list)
    """The paths requested so far, in order. Empty means nobody called."""

    @property
    def host(self) -> str:
        """The host as a policy pattern sees it, including the ephemeral port."""
        return self.base_url.removeprefix("http://")

    def url(self, path: str) -> str:
        return f"{self.base_url}{path}"


@pytest.fixture
def server() -> Iterator[LocalServer]:
    """Start a loopback HTTP server for the duration of one test."""
    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/hello")
                self.end_headers()
                return
            if self.path == "/missing":
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"nope")
                return
            if self.path == "/slow":
                time.sleep(1.5)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(HELLO)))
            self.end_headers()
            self.wfile.write(HELLO)

        def log_message(self, *args: object) -> None:
            """Keep the test output clean."""

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = int(httpd.server_address[1])
    try:
        yield LocalServer(f"http://127.0.0.1:{port}", HELLO, hits)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def _ignore_system_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not let a developer's proxy settings redirect a loopback request."""
    monkeypatch.setattr(urllib.request, "getproxies", dict)
