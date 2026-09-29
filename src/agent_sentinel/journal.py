"""The flight recorder: an append-only, tamper-evident log of agent activity.

Records are written as one canonical JSON object per line (JSON Lines). Each
record contains the digest of the record before it, so the file as a whole is
a hash chain with three useful properties:

* editing a record breaks its own digest;
* deleting or reordering records breaks the chain;
* the digest of the last record summarises the entire session.

The journal is deliberately boring: plain text, append-only, greppable,
diffable, and readable without this library.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import JournalIntegrityError
from .events import GENESIS_HASH, Actor, Event, EventType, canonical_dumps

_READ_CHUNK = 4096


@dataclass(frozen=True)
class IntegrityIssue:
    """A single problem found while verifying a journal."""

    kind: str
    """One of ``malformed``, ``sequence``, ``link`` or ``hash`` for the chain;
    ``truncated``, ``rewritten``, ``bad-anchor``, ``bad-signature`` or
    ``key-mismatch`` when an anchor file was supplied."""

    detail: str
    seq: int | None = None
    line: int | None = None
    source: str = "journal"
    """Which file the problem is in: ``journal`` or ``anchor``."""

    def render(self) -> str:
        where = self.source if self.line is None else f"{self.source} line {self.line}"
        seq = f" (seq {self.seq})" if self.seq is not None else ""
        return f"{where}{seq}: {self.kind}: {self.detail}"


@dataclass(frozen=True)
class VerifyReport:
    """The outcome of checking a journal's hash chain."""

    path: Path
    event_count: int
    head_hash: str | None
    issues: tuple[IntegrityIssue, ...]
    anchors_checked: int = 0
    """How many anchors were compared, when an anchor file was supplied."""

    latest_anchor_seq: int | None = None
    signer: str | None = None
    """Fingerprint of the key that signed the newest anchor, if any."""

    @property
    def ok(self) -> bool:
        """True when every record is intact and correctly linked."""
        return not self.issues

    def render(self) -> str:
        lines = [
            f"journal: {self.path}",
            f"records: {self.event_count}",
            f"head:    {self.head_hash or '(empty)'}",
        ]
        if self.anchors_checked:
            anchor_line = f"anchors: {self.anchors_checked} checked"
            if self.latest_anchor_seq is not None:
                anchor_line += f", latest at seq {self.latest_anchor_seq}"
            if self.signer:
                anchor_line += f", signed by {self.signer}"
            lines.append(anchor_line)
        if self.ok:
            lines.append("status:  ok - hash chain verified")
        else:
            lines.append(f"status:  BROKEN - {len(self.issues)} issue(s)")
            lines.extend(f"  - {issue.render()}" for issue in self.issues)
        return "\n".join(lines)


class Journal:
    """Read/write handle for one JSON Lines journal file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    # ------------------------------------------------------------------ write
    def append(
        self,
        event_type: EventType,
        actor: Actor = Actor.SENTINEL,
        payload: Mapping[str, Any] | None = None,
    ) -> Event:
        """Seal a new event onto the end of the chain and flush it to disk."""
        head = self.head()
        event = Event.create(
            seq=head.seq + 1 if head else 1,
            type=event_type,
            actor=actor,
            payload=payload,
            prev_hash=head.hash if head else GENESIS_HASH,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_dumps(event.to_record()))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return event

    def note(self, message: str, *, actor: Actor = Actor.HUMAN) -> Event:
        """Append a free-form annotation."""
        return self.append(EventType.NOTE, actor, {"message": message})

    # ------------------------------------------------------------------- read
    def exists(self) -> bool:
        return self.path.is_file()

    def iter_events(self) -> Iterator[Event]:
        """Yield every record in order.

        Raises:
            JournalIntegrityError: a line is not a valid record.
        """
        for line_number, raw in self._iter_raw_lines():
            yield self._parse(line_number, raw)

    def read(self) -> list[Event]:
        """Every record in the journal, in order."""
        return list(self.iter_events())

    def head(self) -> Event | None:
        """The last record, or ``None`` for a missing/empty journal."""
        raw = self._last_raw_line()
        if raw is None:
            return None
        try:
            record = json.loads(raw)
            return Event.from_record(record)
        except (ValueError, json.JSONDecodeError) as exc:
            raise JournalIntegrityError(
                f"{self.path}: the last record cannot be read ({exc})"
            ) from exc

    def tail(self, count: int = 20) -> list[Event]:
        """The last ``count`` records, oldest first."""
        events = self.read()
        return events[-count:] if count > 0 else []

    # --------------------------------------------------------------- verify
    def verify(self) -> VerifyReport:
        """Walk the whole chain and collect every integrity problem found."""
        issues: list[IntegrityIssue] = []
        expected_seq = 1
        expected_prev = GENESIS_HASH
        count = 0
        head_hash: str | None = None

        for line_number, raw in self._iter_raw_lines():
            try:
                event = self._parse(line_number, raw)
            except JournalIntegrityError as exc:
                issues.append(IntegrityIssue(kind="malformed", detail=str(exc), line=line_number))
                continue

            count += 1
            if event.seq != expected_seq:
                issues.append(
                    IntegrityIssue(
                        kind="sequence",
                        detail=f"expected seq {expected_seq}, found {event.seq}",
                        seq=event.seq,
                        line=line_number,
                    )
                )
            if event.prev_hash != expected_prev:
                issues.append(
                    IntegrityIssue(
                        kind="link",
                        detail=f"prev_hash does not chain onto record {expected_seq - 1}",
                        seq=event.seq,
                        line=line_number,
                    )
                )
            if not event.is_link_valid:
                issues.append(
                    IntegrityIssue(
                        kind="hash",
                        detail="record content no longer matches its digest",
                        seq=event.seq,
                        line=line_number,
                    )
                )

            expected_seq = event.seq + 1
            expected_prev = event.hash
            head_hash = event.hash

        return VerifyReport(
            path=self.path,
            event_count=count,
            head_hash=head_hash,
            issues=tuple(issues),
        )

    # ---------------------------------------------------------------- internal
    def _iter_raw_lines(self) -> Iterator[tuple[int, str]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if stripped:
                    yield line_number, stripped

    def _parse(self, line_number: int, raw: str) -> Event:
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JournalIntegrityError(
                f"{self.path}: line {line_number} is not JSON ({exc.msg})"
            ) from exc
        if not isinstance(record, dict):
            raise JournalIntegrityError(f"{self.path}: line {line_number} is not a JSON object")
        try:
            return Event.from_record(record)
        except ValueError as exc:
            raise JournalIntegrityError(
                f"{self.path}: line {line_number} is not a valid record ({exc})"
            ) from exc

    def _last_raw_line(self) -> str | None:
        """Read only the final non-empty line, without scanning the whole file."""
        if not self.path.is_file() or self.path.stat().st_size == 0:
            return None
        with self.path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            buffer = b""
            while position > 0:
                step = min(_READ_CHUNK, position)
                position -= step
                handle.seek(position)
                buffer = handle.read(step) + buffer
                lines = [line for line in buffer.split(b"\n") if line.strip()]
                if len(lines) >= 2 or position == 0:
                    return lines[-1].decode("utf-8") if lines else None
        return None


def read_events(path: str | Path) -> list[Event]:
    """Read every record from the journal at ``path``."""
    return Journal(path).read()


def verify_file(path: str | Path) -> VerifyReport:
    """Verify the hash chain of the journal at ``path``."""
    return Journal(path).verify()
