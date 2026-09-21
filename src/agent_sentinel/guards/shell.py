"""Guarded shell execution: the guardrail and the recorder working together.

Every command goes through the same four steps, and every step is recorded:

1. the agent proposes a command;
2. the policy engine answers;
3. the command runs only if the answer permits it;
4. the outcome is appended to the journal.

Output is recorded as a digest plus a truncated preview rather than in full,
so a chatty build cannot bloat the log, while still letting ``sentinel`` prove
what a command printed.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
from ..errors import GuardError
from ..events import Actor, EventType
from ..journal import Journal
from ..policy.engine import PolicyEngine
from ..policy.models import Action, ActionKind, Decision, Effect

DEFAULT_PREVIEW_CHARS = 2000
"""How much trailing output to keep verbatim in the journal."""

Reviewer = Callable[[Action, Decision], bool]
"""A callback that decides whether a ``review`` action may proceed."""


@dataclass(frozen=True)
class GuardedResult:
    """What happened to one guarded command."""

    decision: Decision
    status: str
    """One of ``executed``, ``timeout``, ``denied``, ``awaiting_approval`` or
    ``refused``."""

    returncode: int | None = None
    duration_ms: int = 0
    stdout_preview: str = ""
    stderr_preview: str = ""
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    approval_seq: int | None = None
    """The ``approval.decided`` record this run consumed, if it needed one."""

    approval_request: ApprovalRequest | None = None
    """The escalation this run left waiting, if it stopped for review."""

    @property
    def executed(self) -> bool:
        """True when the command was actually handed to the operating system."""
        return self.status in {"executed", "timeout"}

    @property
    def ok(self) -> bool:
        """True when the command ran and reported success."""
        return self.status == "executed" and self.returncode == 0


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _preview(text: str, limit: int = DEFAULT_PREVIEW_CHARS) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n... [{omitted} characters omitted; see the digest]"


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


class GuardedRunner:
    """Runs shell commands through a policy, recording everything it sees."""

    def __init__(
        self,
        engine: PolicyEngine,
        journal: Journal,
        *,
        cwd: str | Path | None = None,
        allow_review: bool = False,
        reviewer: Reviewer | None = None,
        timeout: float | None = None,
    ) -> None:
        self.engine = engine
        self.journal = journal
        self.cwd = str(cwd) if cwd is not None else None
        self.allow_review = allow_review
        self.reviewer = reviewer
        self.timeout = timeout

    def run(self, command: str, *, timeout: float | None = None) -> GuardedResult:
        """Evaluate ``command``, run it if permitted, and record the outcome."""
        action = Action(kind=ActionKind.SHELL, target=command, cwd=self.cwd)
        self.journal.append(EventType.ACTION_PROPOSED, Actor.AGENT, action.as_dict())

        decision = self.engine.evaluate(action)
        self.journal.append(
            EventType.POLICY_DECISION,
            Actor.SENTINEL,
            {
                "effect": decision.effect.value,
                "rule": decision.rule_id,
                "reason": decision.reason,
                "policy": decision.policy,
            },
        )

        if decision.effect is Effect.DENY:
            return self._refuse(decision, "denied")

        if decision.effect is Effect.REVIEW:
            approval = self._authorise(action, decision)
            if approval is None:
                return self._refuse(decision, "awaiting_approval", escalate=action)
            if not approval.granted:
                return self._refuse(decision, "refused")
            return self._execute(decision, command, self._timeout(timeout), approval.seq)

        return self._execute(decision, command, self._timeout(timeout))

    # ---------------------------------------------------------------- internal
    def _timeout(self, timeout: float | None) -> float | None:
        return timeout if timeout is not None else self.timeout

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
        self, decision: Decision, status: str, *, escalate: Action | None = None
    ) -> GuardedResult:
        request: ApprovalRequest | None = None
        if escalate is not None:
            request = request_from_event(
                request_approval(self.journal, action=escalate, decision=decision)
            )
        self.journal.append(
            EventType.ACTION_RESULT,
            Actor.SENTINEL,
            {"status": status, "rule": decision.rule_id, "reason": decision.reason},
        )
        return GuardedResult(decision=decision, status=status, approval_request=request)

    def _execute(
        self,
        decision: Decision,
        command: str,
        timeout: float | None,
        approval_seq: int | None = None,
    ) -> GuardedResult:
        started = time.perf_counter()
        try:
            completed = subprocess.run(  # noqa: S602 - shell semantics are intentional
                command,
                shell=True,
                cwd=self.cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _as_text(exc.stdout)
            stderr = _as_text(exc.stderr)
            duration_ms = int((time.perf_counter() - started) * 1000)
            payload: dict[str, Any] = {
                "status": "timeout",
                "timeout_s": timeout,
                "duration_ms": duration_ms,
                "stdout_sha256": _digest(stdout),
                "stderr_sha256": _digest(stderr),
            }
            if approval_seq is not None:
                payload["approval_seq"] = approval_seq
            self.journal.append(EventType.ACTION_RESULT, Actor.SENTINEL, payload)
            return GuardedResult(
                decision=decision,
                status="timeout",
                duration_ms=duration_ms,
                stdout_preview=_preview(stdout),
                stderr_preview=_preview(stderr),
                stdout_sha256=_digest(stdout),
                stderr_sha256=_digest(stderr),
                approval_seq=approval_seq,
            )
        except OSError as exc:
            raise GuardError(f"cannot run {command!r}: {exc}") from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        stdout_digest = _digest(stdout)
        stderr_digest = _digest(stderr)

        payload = {
            "status": "executed",
            "returncode": completed.returncode,
            "duration_ms": duration_ms,
            "stdout_sha256": stdout_digest,
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stderr_sha256": stderr_digest,
            "stderr_bytes": len(stderr.encode("utf-8")),
            "stdout_preview": _preview(stdout),
            "stderr_preview": _preview(stderr),
        }
        if approval_seq is not None:
            payload["approval_seq"] = approval_seq
        self.journal.append(EventType.ACTION_RESULT, Actor.SENTINEL, payload)

        return GuardedResult(
            decision=decision,
            status="executed",
            returncode=completed.returncode,
            duration_ms=duration_ms,
            stdout_preview=_preview(stdout),
            stderr_preview=_preview(stderr),
            stdout_sha256=stdout_digest,
            stderr_sha256=stderr_digest,
            approval_seq=approval_seq,
        )
