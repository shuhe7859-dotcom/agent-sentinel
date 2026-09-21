"""Approvals: making a human "yes" part of the record.

A ``review`` verdict stops an action. Before that action may run, someone has to
say yes, and that yes belongs in the same hash-chained journal as the request it
answers. An approval is therefore:

* **auditable** -- the journal shows who approved what, and when;
* **scoped to one action** -- the fingerprint covers the command, so approving
  ``git push --force origin main`` does not also approve the next force push;
* **single use** -- the execution records which approval it consumed, so one yes
  cannot authorise two runs;
* **able to expire** -- an approval may carry a deadline after which it stops
  counting.

None of this is a lock. It is a record that the runner consults and that a human
reads afterwards, from the same file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .events import Actor, Event, EventType
from .journal import Journal
from .policy.models import Action, Decision

SOURCE_OPERATOR = "operator"
"""A person ran ``sentinel approve``."""

SOURCE_CALLBACK = "callback"
"""A ``reviewer`` callback answered in-process."""

SOURCE_CONFIG = "config"
"""A flag such as ``--allow-review`` pre-approved the run."""


@dataclass(frozen=True)
class ApprovalRequest:
    """A ``review`` verdict that was escalated to a human."""

    seq: int
    ts: str
    fingerprint: str
    kind: str
    command: str
    rule_id: str | None = None
    reason: str = ""

    def render(self) -> str:
        rule = self.rule_id or "(policy default)"
        return f"#{self.seq:<4} {self.kind:<11} {self.command}\n        {rule}: {self.reason}"


@dataclass(frozen=True)
class Approval:
    """An answer to an escalation, and whether it is still worth anything."""

    seq: int
    ts: str
    fingerprint: str
    kind: str
    command: str
    granted: bool
    actor: Actor
    source: str
    note: str = ""
    request_seq: int | None = None
    expires_at: str | None = None
    consumed_by: int | None = None
    """Seq of the ``action.result`` that used this approval, if any."""

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """True when the approval carried a deadline that has passed."""
        if self.expires_at is None:
            return False
        moment = now or datetime.now(UTC)
        return _parse_ts(self.expires_at) <= moment

    def is_usable(self, *, now: datetime | None = None) -> bool:
        """True when this approval can still authorise an execution."""
        return self.granted and self.consumed_by is None and not self.is_expired(now=now)

    def render(self) -> str:
        verdict = "granted" if self.granted else "refused"
        extra = []
        if self.source:
            extra.append(self.source)
        if self.expires_at:
            extra.append(f"expires {self.expires_at}")
        if self.consumed_by is not None:
            extra.append(f"used by #{self.consumed_by}")
        if self.note:
            extra.append(self.note)
        suffix = f"  ({', '.join(extra)})" if extra else ""
        return f"#{self.seq:<4} {verdict:<8} {self.kind:<11} {self.command}{suffix}"


def request_approval(journal: Journal, *, action: Action, decision: Decision) -> Event:
    """Record that a ``review`` verdict is waiting for a human."""
    return journal.append(
        EventType.APPROVAL_REQUESTED,
        Actor.SENTINEL,
        {
            "fingerprint": action.fingerprint(),
            "kind": action.kind.value,
            "command": action.subject,
            "target": action.target,
            "rule": decision.rule_id,
            "reason": decision.reason,
            "policy": decision.policy,
        },
    )


def record_decision(
    journal: Journal,
    *,
    action: Action,
    granted: bool,
    source: str,
    note: str = "",
    request_seq: int | None = None,
    expires_in_seconds: float | None = None,
    actor: Actor = Actor.HUMAN,
) -> Event:
    """Record an answer to an escalation.

    Args:
        source: One of :data:`SOURCE_OPERATOR`, :data:`SOURCE_CALLBACK` or
            :data:`SOURCE_CONFIG`, so the journal says *why* the answer exists.
        expires_in_seconds: When given, the approval stops counting this many
            seconds from now.
    """
    expires_at: str | None = None
    if expires_in_seconds is not None:
        expires_at = _iso(datetime.now(UTC) + timedelta(seconds=expires_in_seconds))
    return journal.append(
        EventType.APPROVAL_DECIDED,
        actor,
        {
            "granted": granted,
            "fingerprint": action.fingerprint(),
            "kind": action.kind.value,
            "command": action.subject,
            "request_seq": request_seq,
            "expires_at": expires_at,
            "source": source,
            "note": note,
        },
    )


def approval_requests(journal: Journal) -> list[ApprovalRequest]:
    """Every escalation in the journal, oldest first."""
    requests: list[ApprovalRequest] = []
    for event in journal.iter_events():
        if event.type is EventType.APPROVAL_REQUESTED:
            requests.append(request_from_event(event))
    return requests


def approvals(journal: Journal) -> list[Approval]:
    """Every answer in the journal, oldest first, with its consumption filled in."""
    consumed = consumed_approval_seqs(journal)
    decisions: list[Approval] = []
    for event in journal.iter_events():
        if event.type is EventType.APPROVAL_DECIDED:
            decisions.append(approval_from_event(event, consumed_by=consumed.get(event.seq)))
    return decisions


def request_from_event(event: Event) -> ApprovalRequest:
    """Build an :class:`ApprovalRequest` from an ``approval.requested`` record."""
    payload = event.payload
    return ApprovalRequest(
        seq=event.seq,
        ts=event.ts,
        fingerprint=_text(payload, "fingerprint"),
        kind=_text(payload, "kind"),
        command=_text(payload, "command"),
        rule_id=_optional_text(payload, "rule"),
        reason=_text(payload, "reason"),
    )


def approval_from_event(event: Event, *, consumed_by: int | None = None) -> Approval:
    """Build an :class:`Approval` from an ``approval.decided`` record."""
    payload = event.payload
    return Approval(
        seq=event.seq,
        ts=event.ts,
        fingerprint=_text(payload, "fingerprint"),
        kind=_text(payload, "kind"),
        command=_text(payload, "command"),
        granted=bool(payload.get("granted")),
        actor=event.actor,
        source=_text(payload, "source"),
        note=_text(payload, "note"),
        request_seq=_optional_int(payload, "request_seq"),
        expires_at=_optional_text(payload, "expires_at"),
        consumed_by=consumed_by,
    )


def consumed_approval_seqs(journal: Journal) -> dict[int, int]:
    """Map approval seq to the ``action.result`` seq that consumed it."""
    consumed: dict[int, int] = {}
    for event in journal.iter_events():
        if event.type is not EventType.ACTION_RESULT:
            continue
        approval_seq = event.payload.get("approval_seq")
        if isinstance(approval_seq, int) and not isinstance(approval_seq, bool):
            consumed[approval_seq] = event.seq
    return consumed


def find_grant(
    journal: Journal, fingerprint: str, *, now: datetime | None = None
) -> Approval | None:
    """The oldest still-usable approval for ``fingerprint``, if there is one.

    First in, first out, so approvals cannot pile up invisibly behind each other.
    """
    for approval in approvals(journal):
        if approval.fingerprint == fingerprint and approval.is_usable(now=now):
            return approval
    return None


def pending_requests(journal: Journal, *, now: datetime | None = None) -> list[ApprovalRequest]:
    """Escalations that would still stop the runner.

    An escalation stops being pending once *any* still-usable approval covers
    its fingerprint. When the same command was escalated more than once, only
    the most recent escalation is reported.
    """
    usable = {
        approval.fingerprint for approval in approvals(journal) if approval.is_usable(now=now)
    }
    seen: set[str] = set()
    pending: list[ApprovalRequest] = []
    for request in reversed(approval_requests(journal)):
        if request.fingerprint in usable or request.fingerprint in seen:
            continue
        seen.add(request.fingerprint)
        pending.append(request)
    pending.reverse()
    return pending


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    return value if isinstance(value, str) else ""


def _optional_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) and value else None


def _optional_int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None
