"""Anchors: putting the state of a journal somewhere the journal cannot reach.

A hash chain proves a journal is internally consistent. It cannot prove the
journal is *complete*, because whoever can write the file can also delete its
last lines and leave a shorter chain that verifies perfectly.

An anchor is that same head hash written down somewhere else -- a file the
attacker is less likely to control, a CI log line, another machine. Every anchor
is a checkpoint, so an early one still catches a rewrite of the records before
it even after the log has grown. Anchors may be signed; see ``docs/anchoring.md``
for what each mechanism does and does not prove.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ._version import __version__
from .errors import JournalError, SigningError
from .events import Event, EventType, canonical_dumps, utc_now_iso
from .journal import IntegrityIssue, Journal, VerifyReport
from .signing import (
    Signature,
    create_signature,
    fingerprint,
    public_key_bytes,
    signature_bytes,
)
from .signing import verify as verify_signature

ANCHOR_SCHEMA_VERSION = "1.0"
"""Version of the on-disk anchor format."""


@dataclass(frozen=True)
class Anchor:
    """One written-down statement that a journal reached a particular state."""

    seq: int
    hash: str
    ts: str
    journal: str = ""
    """The journal file name, for a reader's benefit. Not used when comparing."""

    session: str | None = None
    """The session that had just closed, when the anchored head ended one."""

    note: str = ""
    tool: str = ""
    signature: Signature | None = None

    def as_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema": ANCHOR_SCHEMA_VERSION,
            "seq": self.seq,
            "hash": self.hash,
            "ts": self.ts,
            "journal": self.journal,
            "session": self.session,
            "note": self.note,
            "tool": self.tool,
        }
        if include_signature:
            data["signature"] = self.signature.as_dict() if self.signature is not None else None
        return data

    def signed_payload(self) -> bytes:
        """The bytes a signature covers: everything except the signature itself."""
        return canonical_dumps(self.as_dict(include_signature=False)).encode("utf-8")

    @property
    def signer(self) -> str:
        """The fingerprint of whoever signed this, or an empty string."""
        return self.signature.fingerprint if self.signature is not None else ""

    def render(self) -> str:
        """A single line, suitable for a CI log."""
        parts = [f"anchor  seq {self.seq}", f"head {self.hash[:16]}"]
        if self.journal:
            parts.append(f"journal {self.journal}")
        if self.session:
            parts.append(f"session {self.session[:12]}")
        if self.signature is not None:
            parts.append(f"signed by {self.signer}")
        return "  ".join(parts)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Anchor:
        """Rebuild an anchor from a parsed line.

        Raises:
            ValueError: the object is not an anchor this release understands.
        """
        if data.get("schema") != ANCHOR_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported anchor schema {data.get('schema')!r}; "
                f"expected {ANCHOR_SCHEMA_VERSION!r}"
            )
        seq = data.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise ValueError(f"seq must be a positive integer, got {seq!r}")
        digest = data.get("hash")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("hash must be a 64-character digest")
        session = data.get("session")
        return cls(
            seq=seq,
            hash=digest,
            ts=_text(data, "ts"),
            journal=_text(data, "journal"),
            session=session if isinstance(session, str) and session else None,
            note=_text(data, "note"),
            tool=_text(data, "tool"),
            signature=_signature_from(data.get("signature")),
        )


@dataclass(frozen=True)
class AnchorFile:
    """Everything read out of an anchor file, good lines and bad."""

    path: Path
    anchors: tuple[Anchor, ...]
    issues: tuple[IntegrityIssue, ...]


def read_anchor_file(path: str | Path) -> AnchorFile:
    """Read an anchor file.

    A line that cannot be parsed is reported as a ``bad-anchor`` issue rather
    than stopping the read, so one damaged line does not hide the rest.

    Raises:
        JournalError: the file cannot be read.
    """
    anchor_path = Path(path)
    try:
        content = anchor_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JournalError(f"cannot read anchor file {anchor_path}: {exc}") from exc

    anchors: list[Anchor] = []
    issues: list[IntegrityIssue] = []
    for line_number, raw in enumerate(content.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            issues.append(
                IntegrityIssue(
                    kind="bad-anchor",
                    detail=f"not JSON ({exc.msg})",
                    line=line_number,
                    source="anchor",
                )
            )
            continue
        if not isinstance(payload, dict):
            issues.append(
                IntegrityIssue(
                    kind="bad-anchor",
                    detail="not a JSON object",
                    line=line_number,
                    source="anchor",
                )
            )
            continue
        try:
            anchors.append(Anchor.from_dict(payload))
        except ValueError as exc:
            issues.append(
                IntegrityIssue(
                    kind="bad-anchor", detail=str(exc), line=line_number, source="anchor"
                )
            )
    return AnchorFile(path=anchor_path, anchors=tuple(anchors), issues=tuple(issues))


def append_anchor(path: str | Path, anchor: Anchor) -> None:
    """Seal an anchor onto the end of an anchor file, and flush it to disk."""
    anchor_path = Path(path)
    anchor_path.parent.mkdir(parents=True, exist_ok=True)
    with anchor_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_dumps(anchor.as_dict()))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def sign_anchor(anchor: Anchor, private_key: bytes) -> Anchor:
    """Return a copy of ``anchor`` carrying a signature."""
    return replace(anchor, signature=create_signature(anchor.signed_payload(), private_key))


def anchor_journal(
    journal: Journal,
    *,
    note: str = "",
    tool: str | None = None,
    private_key: bytes | None = None,
) -> Anchor:
    """Describe the journal's current head, optionally signing the description.

    Raises:
        JournalError: the journal has no records, so there is nothing to anchor.
    """
    head = journal.head()
    if head is None:
        raise JournalError(f"nothing to anchor: {journal.path} has no records")
    anchor = Anchor(
        seq=head.seq,
        hash=head.hash,
        ts=utc_now_iso(),
        journal=Path(journal.path).name,
        session=_closing_session(head),
        note=note,
        tool=tool or f"agent-sentinel {__version__}",
    )
    if private_key is not None:
        anchor = sign_anchor(anchor, private_key)
    return anchor


def compare_anchors(
    journal: Journal,
    anchors: Iterable[Anchor],
    *,
    expected_key: bytes | None = None,
) -> list[IntegrityIssue]:
    """Check a journal against every anchor, and report what does not hold.

    Every anchor is a checkpoint, so a rewrite of an early stretch of the log is
    caught by an anchor taken before it, even after later records were appended.
    """
    anchors = list(anchors)
    issues: list[IntegrityIssue] = []
    for anchor in anchors:
        issues.extend(_check_signature(anchor, expected_key))

    head = journal.head()
    head_seq = head.seq if head is not None else 0
    wanted = {anchor.seq for anchor in anchors}
    seen = _events_at(journal, wanted)

    for anchor in anchors:
        if anchor.seq > head_seq:
            issues.append(
                IntegrityIssue(
                    kind="truncated",
                    detail=(
                        f"anchored at seq {anchor.seq}, but the journal now ends at "
                        f"seq {head_seq}: {_records(anchor.seq - head_seq)} missing"
                    ),
                    seq=anchor.seq,
                    source="anchor",
                )
            )
            continue
        event = seen.get(anchor.seq)
        if event is None:
            issues.append(
                IntegrityIssue(
                    kind="truncated",
                    detail=f"anchored at seq {anchor.seq}, which the journal no longer contains",
                    seq=anchor.seq,
                    source="anchor",
                )
            )
        elif event.hash != anchor.hash:
            issues.append(
                IntegrityIssue(
                    kind="rewritten",
                    detail=(
                        f"seq {anchor.seq} hashes to {event.hash[:16]}, "
                        f"but was anchored as {anchor.hash[:16]}"
                    ),
                    seq=anchor.seq,
                    source="anchor",
                )
            )
    return issues


def verify_with_anchors(
    journal: Journal,
    *,
    anchor_path: str | Path,
    expected_key: bytes | None = None,
) -> VerifyReport:
    """Verify the chain, then check it against an anchor file.

    An anchor file that cannot be read, or that holds no usable anchor, is an
    error rather than a pass: evidence that was supposed to exist and does not is
    exactly what anchoring is meant to catch.

    Raises:
        JournalError: the anchor file is missing, unreadable, or has no anchors.
        SigningError: signed anchors are present but cannot be checked.
    """
    report = journal.verify()
    anchor_file = read_anchor_file(anchor_path)
    if not anchor_file.anchors:
        raise JournalError(
            f"{anchor_file.path} holds no usable anchors "
            f"({len(anchor_file.issues)} unreadable line(s))"
        )

    issues = list(report.issues)
    issues.extend(anchor_file.issues)
    issues.extend(compare_anchors(journal, anchor_file.anchors, expected_key=expected_key))

    latest = max(anchor_file.anchors, key=lambda anchor: anchor.seq)
    return replace(
        report,
        issues=tuple(issues),
        anchors_checked=len(anchor_file.anchors),
        latest_anchor_seq=latest.seq,
        signer=latest.signer or None,
    )


# ---------------------------------------------------------------- internals
def _check_signature(anchor: Anchor, expected_key: bytes | None) -> list[IntegrityIssue]:
    signature = anchor.signature
    if signature is None:
        if expected_key is None:
            return []
        return [
            IntegrityIssue(
                kind="bad-signature",
                detail="a public key was given, but this anchor is unsigned",
                seq=anchor.seq,
                source="anchor",
            )
        ]

    try:
        embedded = public_key_bytes(signature.public_key)
        raw_signature = signature_bytes(signature.signature)
    except SigningError as exc:
        return [
            IntegrityIssue(kind="bad-signature", detail=str(exc), seq=anchor.seq, source="anchor")
        ]

    if expected_key is not None and embedded != expected_key:
        return [
            IntegrityIssue(
                kind="key-mismatch",
                detail=(
                    f"signed by {fingerprint(embedded)}, but {fingerprint(expected_key)} "
                    "was expected"
                ),
                seq=anchor.seq,
                source="anchor",
            )
        ]

    if not verify_signature(anchor.signed_payload(), raw_signature, embedded):
        return [
            IntegrityIssue(
                kind="bad-signature",
                detail=f"the signature does not match the anchor (key {fingerprint(embedded)})",
                seq=anchor.seq,
                source="anchor",
            )
        ]
    return []


def _records(count: int) -> str:
    return f"{count} record" if count == 1 else f"{count} records"


def _events_at(journal: Journal, wanted: set[int]) -> dict[int, Event]:
    """The records at the anchored seq numbers, without reading the whole file."""
    found: dict[int, Event] = {}
    if not wanted:
        return found
    for event in journal.iter_events():
        if event.seq in wanted:
            found[event.seq] = event
            if len(found) == len(wanted):
                break
    return found


def _closing_session(head: Event) -> str | None:
    """The session id when the anchored head is a ``session.end`` record."""
    if head.type is not EventType.SESSION_END:
        return None
    session = head.payload.get("session_id")
    return session if isinstance(session, str) and session else None


def _signature_from(value: Any) -> Signature | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("signature must be an object or null")
    algorithm = value.get("algorithm")
    public_key = value.get("public_key")
    raw = value.get("signature")
    if algorithm != Signature.algorithm:
        raise ValueError(f"unsupported signature algorithm {algorithm!r}")
    if not isinstance(public_key, str) or not isinstance(raw, str):
        raise ValueError("signature needs both public_key and signature strings")
    return Signature(public_key=public_key, signature=raw)


def _text(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) else ""
