"""Behaviour of the event record and its hash chain."""

from __future__ import annotations

import pytest

from agent_sentinel.events import (
    GENESIS_HASH,
    Actor,
    Event,
    EventType,
    canonical_dumps,
    hash_record,
)


def _event(**overrides: object) -> Event:
    kwargs: dict[str, object] = {
        "seq": 1,
        "type": EventType.NOTE,
        "actor": Actor.AGENT,
        "payload": {"message": "hello"},
    }
    kwargs.update(overrides)
    return Event.create(**kwargs)  # type: ignore[arg-type]


def test_canonical_dumps_ignores_key_order() -> None:
    assert canonical_dumps({"b": 1, "a": [1, 2]}) == canonical_dumps({"a": [1, 2], "b": 1})


def test_hash_depends_on_the_previous_hash() -> None:
    body = {"seq": 1, "type": "note"}
    assert hash_record(GENESIS_HASH, body) != hash_record("a" * 64, body)


def test_create_links_each_event_to_its_predecessor() -> None:
    first = _event()
    second = _event(seq=2, prev_hash=first.hash)

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert first.is_link_valid
    assert second.is_link_valid


def test_payload_tampering_invalidates_the_link() -> None:
    original = _event()
    tampered = Event(
        seq=original.seq,
        type=original.type,
        actor=original.actor,
        ts=original.ts,
        payload={"message": "goodbye"},
        prev_hash=original.prev_hash,
        hash=original.hash,
    )

    assert not tampered.is_link_valid


def test_record_round_trip() -> None:
    event = _event(seq=7, type=EventType.POLICY_DECISION, actor=Actor.SENTINEL)
    assert Event.from_record(event.to_record()) == event


@pytest.mark.parametrize("dropped", ["schema", "seq", "payload", "prev_hash", "hash"])
def test_from_record_rejects_incomplete_records(dropped: str) -> None:
    record = _event().to_record()
    del record[dropped]

    with pytest.raises(ValueError, match="missing required keys"):
        Event.from_record(record)


def test_from_record_rejects_unknown_type_and_actor() -> None:
    record = _event().to_record()
    record["type"] = "not.a.type"
    with pytest.raises(ValueError):
        Event.from_record(record)

    record = _event().to_record()
    record["actor"] = "robot"
    with pytest.raises(ValueError):
        Event.from_record(record)


def test_from_record_rejects_a_foreign_schema_version() -> None:
    record = _event().to_record()
    record["schema"] = "99.0"

    with pytest.raises(ValueError, match="unsupported schema version"):
        Event.from_record(record)


def test_render_is_a_single_line() -> None:
    assert "\n" not in _event().render()
