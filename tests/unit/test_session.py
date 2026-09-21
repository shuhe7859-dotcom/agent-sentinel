"""Sessions: framing work, and tying a journal to the policy that was in force."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_sentinel.events import EventType
from agent_sentinel.journal import Journal
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import load_policy, parse_policy
from agent_sentinel.policy.presets import load_preset
from agent_sentinel.session import Session


def _engine(**overrides: object) -> PolicyEngine:
    data: dict[str, object] = {"name": "test", "default": "allow", "rules": []}
    data.update(overrides)
    return PolicyEngine(parse_policy(data))


# ------------------------------------------------------------------ fingerprints
def test_policy_fingerprint_does_not_depend_on_the_file_path(tmp_path: Path) -> None:
    body = 'schema = 1\nname = "same"\ndefault = "allow"\n'
    first = tmp_path / "one.toml"
    second = tmp_path / "nested" / "two.toml"
    second.parent.mkdir()
    first.write_text(body, encoding="utf-8")
    second.write_text(body, encoding="utf-8")

    assert load_policy(first).fingerprint() == load_policy(second).fingerprint()


def test_policy_fingerprint_changes_when_a_rule_changes() -> None:
    original = _engine(rules=[{"id": "a", "effect": "deny", "pattern": "rm", "reason": "before"}])
    edited = _engine(rules=[{"id": "a", "effect": "deny", "pattern": "rm", "reason": "after"}])
    widened = _engine(rules=[{"id": "a", "effect": "allow", "pattern": "rm", "reason": "before"}])

    assert original.policy.fingerprint() != edited.policy.fingerprint()
    assert original.policy.fingerprint() != widened.policy.fingerprint()


def test_policy_fingerprint_identifies_a_preset() -> None:
    assert load_preset("standard").fingerprint() == load_preset("standard").fingerprint()
    assert load_preset("standard").fingerprint() != load_preset("strict").fingerprint()


# ---------------------------------------------------------------------- sessions
def test_session_writes_a_matching_start_and_end(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with Session(_engine(), journal, cwd=str(tmp_path)) as session:
        journal.note("work happens here")

    events = journal.read()
    assert [event.type for event in events] == [
        EventType.SESSION_START,
        EventType.NOTE,
        EventType.SESSION_END,
    ]
    assert session.info is not None
    assert session.info.start_seq == 1
    assert session.info.end_seq == 3
    assert session.info.outcome == "closed"
    assert journal.verify().ok


def test_session_start_records_the_policy_identity(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(load_preset("standard"))

    with Session(engine, journal, cwd="."):
        pass

    payload = journal.read()[0].payload
    assert payload["policy"] == "standard"
    assert payload["policy_fingerprint"] == engine.policy.fingerprint()
    assert payload["policy_default"] == "allow"
    assert payload["rules"] == len(engine.rules)
    assert payload["cwd"] == "."
    assert payload["tool"].startswith("agent-sentinel ")
    assert payload["session_id"]


def test_session_counts_proposed_actions(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with Session(_engine(), journal) as session:
        journal.append(EventType.ACTION_PROPOSED, payload={"kind": "shell"})
        journal.append(EventType.ACTION_PROPOSED, payload={"kind": "shell"})

    assert journal.read()[-1].payload["actions"] == 2
    assert session.info is not None
    assert session.info.actions == 2


def test_session_end_records_the_head_hash_before_it_was_written(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with Session(_engine(), journal):
        note = journal.note("last thing before the close")

    end = journal.read()[-1]
    assert end.payload["head"] == note.hash
    assert end.payload["outcome"] == "ok"


def test_session_closes_even_when_the_body_raises(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with pytest.raises(RuntimeError), Session(_engine(), journal) as session:
        raise RuntimeError("boom")

    end = journal.read()[-1]
    assert end.type is EventType.SESSION_END
    assert end.payload["outcome"] == "error"
    assert session.info is not None
    assert session.info.outcome == "closed"
    assert journal.verify().ok


def test_session_info_is_none_before_it_is_entered(tmp_path: Path) -> None:
    session = Session(_engine(), Journal(tmp_path / "session.jsonl"))

    assert session.info is None


def test_a_session_cannot_be_entered_twice(tmp_path: Path) -> None:
    session = Session(_engine(), Journal(tmp_path / "session.jsonl"))

    with session, pytest.raises(RuntimeError, match="already been entered"), session:
        pass


def test_session_metadata_is_recorded(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with Session(_engine(), journal, session_id="abc123", metadata={"task": "course project"}):
        pass

    assert journal.read()[0].payload["session_id"] == "abc123"
    assert journal.read()[0].payload["metadata"] == {"task": "course project"}


def test_session_render_is_readable(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with Session(_engine(), journal, session_id="abcdef0123456789") as session:
        journal.append(EventType.ACTION_PROPOSED, payload={"kind": "shell"})

    assert session.info is not None
    text = session.info.render()
    assert "abcdef012345" in text
    assert "1 action(s)" in text
    assert "closed" in text
