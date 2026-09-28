"""The network guard, exercised against a local server rather than the internet."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from agent_sentinel.approvals import SOURCE_OPERATOR, record_decision
from agent_sentinel.guards.network import GuardedNetwork, host_of
from agent_sentinel.journal import Journal
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import parse_policy
from agent_sentinel.policy.models import Action, ActionKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from conftest import LocalServer


def _engine(*, default: str = "allow", rules: list[dict[str, object]] | None = None):
    return PolicyEngine(parse_policy({"name": "test", "default": default, "rules": rules or []}))


def _allow(host: str) -> PolicyEngine:
    return _engine(
        default="deny",
        rules=[
            {
                "id": "net.allow",
                "kind": "network",
                "effect": "allow",
                "pattern": f"^{re.escape(host)}$",
            }
        ],
    )


def _guard(
    tmp_path: Path, engine: PolicyEngine, **kwargs: object
) -> tuple[GuardedNetwork, Journal]:
    journal = Journal(tmp_path / "session.jsonl")
    guard = GuardedNetwork(engine, journal, **kwargs)  # type: ignore[arg-type]
    return guard, journal


# ------------------------------------------------------------------- host shape
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://PyPI.org/simple/", "pypi.org"),
        ("http://example.com/", "example.com"),
        ("http://example.com:8080/x", "example.com:8080"),
        ("https://example.com:443/x", "example.com"),
        ("not a url", ""),
    ],
)
def test_host_of(url: str, expected: str) -> None:
    assert host_of(url) == expected


# ----------------------------------------------------------------------- fetch
def test_an_allowed_host_is_fetched(tmp_path: Path, server: LocalServer) -> None:
    guard, journal = _guard(tmp_path, _allow(server.host))

    result = guard.fetch(server.url("/hello"))

    assert result.ok
    assert result.status == "fetched"
    assert result.status_code == 200
    assert result.content_type == "text/plain; charset=utf-8"
    assert result.body == server.body
    assert result.bytes_received == len(server.body)
    assert result.sha256 == hashlib.sha256(server.body).hexdigest()
    assert not result.truncated
    assert server.hits == ["/hello"]
    assert journal.verify().ok


def test_the_policy_matches_the_host_and_the_journal_keeps_the_url(
    tmp_path: Path, server: LocalServer
) -> None:
    guard, journal = _guard(tmp_path, _allow(server.host))

    guard.fetch(server.url("/hello"))

    proposed = journal.read()[0]
    assert proposed.payload["target"] == server.host
    assert proposed.payload["metadata"]["url"] == server.url("/hello")
    assert proposed.payload["metadata"]["method"] == "GET"


def test_the_response_body_is_not_written_to_the_journal(
    tmp_path: Path, server: LocalServer
) -> None:
    guard, journal = _guard(tmp_path, _allow(server.host))

    guard.fetch(server.url("/hello"))

    serialised = json.dumps([event.to_record() for event in journal.read()])
    assert "hello from the local server" not in serialised
    assert hashlib.sha256(server.body).hexdigest() in serialised


def test_a_denied_host_never_reaches_the_server(tmp_path: Path, server: LocalServer) -> None:
    guard, journal = _guard(tmp_path, _engine(default="deny"))

    result = guard.fetch(server.url("/hello"))

    assert result.denied
    assert result.body == b""
    assert server.hits == []
    assert journal.read()[-1].payload["status"] == "denied"


def test_a_reviewed_host_waits_for_a_human_then_goes(tmp_path: Path, server: LocalServer) -> None:
    guard, journal = _guard(tmp_path, _engine(default="review"))

    first = guard.fetch(server.url("/hello"))
    assert first.awaiting_approval
    assert first.approval_request is not None
    assert server.hits == []

    record_decision(
        journal,
        action=Action(kind=ActionKind.NETWORK, target=server.host),
        granted=True,
        source=SOURCE_OPERATOR,
    )

    second = guard.fetch(server.url("/hello"))
    assert second.ok
    assert server.hits == ["/hello"]


# ------------------------------------------------------------------ constraints
def test_only_http_and_https_are_fetched(tmp_path: Path) -> None:
    guard, journal = _guard(tmp_path, _engine(default="allow"))

    result = guard.fetch("file:///etc/passwd")

    assert result.denied
    assert "only fetches http and https" in result.decision.reason
    assert journal.read()[1].payload["constraint"]


def test_a_url_without_a_host_is_refused(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path, _engine(default="allow"))

    result = guard.fetch("http:///no-host")

    assert result.denied
    assert "no host" in result.decision.reason


def test_redirects_are_not_followed(tmp_path: Path, server: LocalServer) -> None:
    guard, journal = _guard(tmp_path, _allow(server.host))

    result = guard.fetch(server.url("/redirect"))

    assert result.status == "fetched"
    assert result.status_code == 302
    assert result.location == "/hello"
    assert server.hits == ["/redirect"]
    assert journal.read()[-1].payload["location"] == "/hello"


def test_an_error_status_is_recorded_with_its_body(tmp_path: Path, server: LocalServer) -> None:
    guard, _ = _guard(tmp_path, _allow(server.host))

    result = guard.fetch(server.url("/missing"))

    assert result.status == "fetched"
    assert result.status_code == 404
    assert not result.ok
    assert result.body == b"nope"


def test_a_timeout_is_recorded(tmp_path: Path, server: LocalServer) -> None:
    guard, journal = _guard(tmp_path, _allow(server.host))

    result = guard.fetch(server.url("/slow"), timeout=0.5)

    assert result.status == "timeout"
    assert result.executed
    assert not result.ok
    assert journal.read()[-1].payload["status"] == "timeout"


def test_the_body_is_truncated_at_max_bytes(tmp_path: Path, server: LocalServer) -> None:
    guard, _ = _guard(tmp_path, _allow(server.host))

    result = guard.fetch(server.url("/hello"), max_bytes=5)

    assert result.ok
    assert result.bytes_received == 5
    assert result.body == server.body[:5]
    assert result.truncated
    assert result.sha256 == hashlib.sha256(server.body[:5]).hexdigest()
