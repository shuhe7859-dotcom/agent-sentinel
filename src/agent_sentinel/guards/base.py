"""The shape every guard shares: propose, decide, escalate, act, record.

A guard puts the policy engine on the path of one kind of action. Whatever the
action is -- a command, a file write, an HTTP request -- the sequence is the
same, and so is what ends up in the journal:

```
action.proposed     the agent asked for something
policy.decision     the engine answered, with a reason
approval.*          only when the answer was review
action.result       what the guard did about it
```

That sequence, and the rule that an approval is consumed exactly once, lives
here. A subclass supplies three things and nothing else:

* how to describe its kind of action, as an :class:`~agent_sentinel.policy.models.Action`;
* how to carry it out, as the ``perform`` callable handed to :meth:`Guard.guard`;
* how to shape the outcome for the caller, in :meth:`Guard._result`.

What is written to the journal and what is handed back to the caller are two
separate mappings, deliberately. A response body or a file's contents belongs
in the caller's hands, not in a log that is meant to be shareable.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from ..approvals import (
    SOURCE_CALLBACK,
    SOURCE_CONFIG,
    Approval,
    ApprovalRequest,
    approval_from_event,
    find_grant,
    record_decision,
    request_approval,
    request_from_event,
)
from ..events import Actor, EventType
from ..journal import Journal
from ..policy.engine import PolicyEngine
from ..policy.models import Action, Decision, Effect

Reviewer = Callable[[Action, Decision], bool]
"""A callback that decides whether a ``review`` action may proceed."""

NON_EXECUTIONS = frozenset({"denied", "refused", "awaiting_approval"})
"""Statuses that mean the action was never attempted."""


@dataclass(frozen=True)
class Performed:
    """The two halves of carrying an action out.

    ``recorded`` is appended to the journal. ``private`` is handed to the caller
    and never written down, which is how a response body stays out of the log
    while still being usable.
    """

    recorded: Mapping[str, Any]
    private: Mapping[str, Any] = field(default_factory=dict)


Performer = Callable[[Action], Performed]
"""Carries out an allowed action."""


def as_text(value: Any, default: str = "") -> str:
    """Read a string out of a journal payload without trusting its type."""
    return value if isinstance(value, str) else default


def as_optional_text(value: Any) -> str | None:
    """Read an optional string out of a journal payload."""
    return value if isinstance(value, str) and value else None


def as_int(value: Any, default: int = 0) -> int:
    """Read an integer out of a journal payload, ignoring booleans."""
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def as_optional_int(value: Any) -> int | None:
    """Read an optional integer out of a journal payload."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def as_bool(value: Any) -> bool:
    """Read a boolean out of a journal payload."""
    return bool(value)


@dataclass(frozen=True)
class GuardResult:
    """What happened to one guarded action."""

    decision: Decision
    status: str
    """What the guard did: a per-guard success word, or ``denied``,
    ``refused``, ``awaiting_approval``, ``timeout`` or ``failed``."""

    approval_seq: int | None = None
    """The ``approval.decided`` record this run consumed, if it needed one."""

    approval_request: ApprovalRequest | None = None
    """The escalation this run left waiting, if it stopped for review."""

    @property
    def executed(self) -> bool:
        """True when the guard attempted the action rather than stopping first."""
        return self.status not in NON_EXECUTIONS

    @property
    def ok(self) -> bool:
        """True when the action was attempted and did not report failure."""
        return self.executed and self.status not in {"failed", "timeout"}

    @property
    def denied(self) -> bool:
        return self.status == "denied"

    @property
    def refused(self) -> bool:
        return self.status == "refused"

    @property
    def awaiting_approval(self) -> bool:
        return self.status == "awaiting_approval"


ResultT = TypeVar("ResultT", bound=GuardResult)


class Guard(ABC, Generic[ResultT]):
    """Runs one kind of action through a policy, recording everything it sees."""

    def __init__(
        self,
        engine: PolicyEngine,
        journal: Journal,
        *,
        allow_review: bool = False,
        reviewer: Reviewer | None = None,
    ) -> None:
        self.engine = engine
        self.journal = journal
        self.allow_review = allow_review
        self.reviewer = reviewer

    # ------------------------------------------------------------------ public
    def guard(self, action: Action, perform: Performer) -> ResultT:
        """Take ``action`` all the way through, calling ``perform`` if permitted."""
        self.journal.append(EventType.ACTION_PROPOSED, Actor.AGENT, action.as_dict())

        decision = self._constrain(action, self.engine.evaluate(action))
        self.journal.append(
            EventType.POLICY_DECISION, Actor.SENTINEL, self._decision_payload(action, decision)
        )

        if decision.effect is Effect.DENY:
            return self._refuse(action, decision, "denied")

        if decision.effect is Effect.REVIEW:
            approval = self._authorise(action, decision)
            if approval is None:
                return self._refuse(action, decision, "awaiting_approval", escalate=True)
            if not approval.granted:
                return self._refuse(action, decision, "refused")
            return self._act(action, decision, perform, approval.seq)

        return self._act(action, decision, perform, None)

    # ------------------------------------------------------------------- hooks
    @abstractmethod
    def _result(
        self,
        action: Action,
        decision: Decision,
        recorded: Mapping[str, Any],
        private: Mapping[str, Any],
        *,
        approval_seq: int | None = None,
        approval_request: ApprovalRequest | None = None,
    ) -> ResultT:
        """Turn a recorded payload back into a typed result."""

    def _constrain(self, action: Action, decision: Decision) -> Decision:
        """Tighten a verdict with a structural constraint.

        A guard may make a verdict stricter -- refusing something the policy
        would have allowed -- and must never make it looser. The default is to
        leave the engine's answer alone.
        """
        return decision

    def _context(self, action: Action, decision: Decision) -> Mapping[str, Any]:
        """Facts about the action worth recording beside every verdict."""
        return {}

    # ---------------------------------------------------------------- internals
    def _decision_payload(self, action: Action, decision: Decision) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "effect": decision.effect.value,
            "rule": decision.rule_id,
            "reason": decision.reason,
            "policy": decision.policy,
        }
        payload.update(self._context(action, decision))
        return payload

    def _authorise(self, action: Action, decision: Decision) -> Approval | None:
        """Decide what a ``review`` verdict means for this action.

        Returns an :class:`Approval` to act on -- ``granted=False`` means someone
        said no -- or ``None`` when nobody has answered yet, in which case the
        caller records an escalation and stops.
        """
        existing = find_grant(self.journal, action.fingerprint())
        if existing is not None:
            return existing

        if self.reviewer is not None:
            granted = bool(self.reviewer(action, decision))
            event = record_decision(
                self.journal,
                action=action,
                granted=granted,
                source=SOURCE_CALLBACK,
                note="answered by the configured reviewer callback",
            )
            return approval_from_event(event)

        if self.allow_review:
            event = record_decision(
                self.journal,
                action=action,
                granted=True,
                source=SOURCE_CONFIG,
                note="pre-approved by allow_review",
            )
            return approval_from_event(event)

        return None

    def _refuse(
        self,
        action: Action,
        decision: Decision,
        status: str,
        *,
        escalate: bool = False,
    ) -> ResultT:
        request: ApprovalRequest | None = None
        if escalate:
            request = request_from_event(
                request_approval(self.journal, action=action, decision=decision)
            )
        payload: dict[str, Any] = {
            "status": status,
            "rule": decision.rule_id,
            "reason": decision.reason,
        }
        payload.update(self._context(action, decision))
        self.journal.append(EventType.ACTION_RESULT, Actor.SENTINEL, payload)
        return self._result(action, decision, payload, {}, approval_request=request)

    def _act(
        self,
        action: Action,
        decision: Decision,
        perform: Performer,
        approval_seq: int | None,
    ) -> ResultT:
        started = time.perf_counter()
        recorded = dict(self._context(action, decision))
        private: Mapping[str, Any] = {}
        try:
            outcome = perform(action)
        except OSError as exc:
            recorded["status"] = "failed"
            recorded["error"] = f"{type(exc).__name__}: {exc}"
        else:
            recorded.update(outcome.recorded)
            private = outcome.private

        recorded.setdefault("duration_ms", int((time.perf_counter() - started) * 1000))
        if approval_seq is not None:
            recorded["approval_seq"] = approval_seq
        self.journal.append(EventType.ACTION_RESULT, Actor.SENTINEL, recorded)
        return self._result(action, decision, recorded, private, approval_seq=approval_seq)
