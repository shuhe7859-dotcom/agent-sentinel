"""Event records: the unit of truth written into the flight recorder.

An event is a small JSON object. Every record carries the hash of its
predecessor and a hash of its own body, which turns the journal into a hash
chain: editing, reordering or dropping a record is detectable afterwards.

Hashing uses a canonical JSON rendering (sorted keys, no insignificant
whitespace, UTF-8) so the same logical record always produces the same digest
on every platform.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
"""Version of the on-disk record format."""

GENESIS_HASH = "0" * 64
"""``prev_hash`` of the very first record in a journal."""

REQUIRED_RECORD_KEYS: tuple[str, ...] = (
    "schema",
    "seq",
    "type",
    "actor",
    "ts",
    "payload",
    "prev_hash",
    "hash",
)


class EventType(StrEnum):
    """The kinds of records a journal can hold."""

    SESSION_START = "session.start"
    """A guarded session was opened."""

    ACTION_PROPOSED = "action.proposed"
    """The agent asked to do something; nothing has run yet."""

    POLICY_DECISION = "policy.decision"
    """What the policy engine answered for a proposed action."""

    APPROVAL_REQUESTED = "approval.requested"
    """A ``review`` verdict was escalated to a human."""

    APPROVAL_DECIDED = "approval.decided"
    """Someone -- or something -- answered an escalation."""

    ACTION_RESULT = "action.result"
    """What actually happened: exit code, output digests, duration."""

    NOTE = "note"
    """A free-form annotation from an agent or a human."""

    SESSION_END = "session.end"
    """A guarded session was closed."""


class Actor(StrEnum):
    """Who caused a record to be written."""

    AGENT = "agent"
    HUMAN = "human"
    SENTINEL = "sentinel"


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string ending in ``Z``."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, Path):
        return value.as_posix()
    raise TypeError(
        f"{type(value).__name__} is not JSON serialisable; "
        "convert it to a plain type before recording it"
    )


def canonical_dumps(value: Any) -> str:
    """Serialise ``value`` deterministically, so equal records hash equally."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def hash_record(prev_hash: str, body: Mapping[str, Any]) -> str:
    """Hash ``body`` together with its predecessor's hash."""
    material = f"{prev_hash}\n{canonical_dumps(body)}".encode()
    return hashlib.sha256(material).hexdigest()


def content_digest(value: Any) -> str:
    """A SHA-256 over the canonical form of ``value``, used for fingerprints.

    Unlike :func:`hash_record` this is not part of the chain. It exists to give
    two things a stable name -- a policy and an action -- so a record can refer
    to them without repeating them in full.
    """
    return hashlib.sha256(canonical_dumps(value).encode()).hexdigest()


@dataclass(frozen=True)
class Event:
    """One hash-chained journal record."""

    seq: int
    type: EventType
    actor: Actor
    ts: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    @classmethod
    def create(
        cls,
        *,
        seq: int,
        type: EventType,
        actor: Actor,
        payload: Mapping[str, Any] | None = None,
        prev_hash: str = GENESIS_HASH,
        ts: str | None = None,
    ) -> Event:
        """Build an event and seal it with the hash of its predecessor."""
        event = cls(
            seq=seq,
            type=type,
            actor=actor,
            ts=ts or utc_now_iso(),
            payload=dict(payload or {}),
            prev_hash=prev_hash,
        )
        return cls(
            seq=event.seq,
            type=event.type,
            actor=event.actor,
            ts=event.ts,
            payload=event.payload,
            prev_hash=event.prev_hash,
            hash=event.recomputed_hash(),
        )

    def body(self) -> dict[str, Any]:
        """Everything the hash covers, i.e. the record without its digest."""
        return {
            "schema": SCHEMA_VERSION,
            "seq": self.seq,
            "type": self.type.value,
            "actor": self.actor.value,
            "ts": self.ts,
            "payload": dict(self.payload),
            "prev_hash": self.prev_hash,
        }

    def to_record(self) -> dict[str, Any]:
        """The record as it is written to disk."""
        record = self.body()
        record["hash"] = self.hash
        return record

    def recomputed_hash(self) -> str:
        """The hash this record *should* have, given its current content."""
        return hash_record(self.prev_hash, self.body())

    @property
    def is_link_valid(self) -> bool:
        """True when the stored digest matches the stored content."""
        return self.hash == self.recomputed_hash()

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> Event:
        """Rebuild an event from a parsed journal line.

        Raises:
            ValueError: the record is missing fields, carries an unknown
                ``type``/``actor``, or does not match the current schema.
        """
        missing = [key for key in REQUIRED_RECORD_KEYS if key not in record]
        if missing:
            raise ValueError(f"record is missing required keys: {', '.join(missing)}")
        if record["schema"] != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema version {record['schema']!r}; expected {SCHEMA_VERSION!r}"
            )
        seq = record["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise ValueError(f"seq must be an integer, got {type(seq).__name__}")
        if not isinstance(record["payload"], dict):
            raise ValueError("payload must be a JSON object")
        try:
            event_type = EventType(record["type"])
            actor = Actor(record["actor"])
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return cls(
            seq=seq,
            type=event_type,
            actor=actor,
            ts=str(record["ts"]),
            payload=dict(record["payload"]),
            prev_hash=str(record["prev_hash"]),
            hash=str(record["hash"]),
        )

    def render(self) -> str:
        """A single human-readable line, handy for ``sentinel journal show``."""
        return (
            f"#{self.seq:<4} {self.ts} {self.actor.value:<8} {self.type.value:<16} {self.hash[:12]}"
        )
