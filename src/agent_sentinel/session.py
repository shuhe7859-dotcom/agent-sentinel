"""Framing guarded work, so a journal says which policy was in force.

A journal is far more useful if it opens by stating the rules of the game. A
session writes ``session.start`` -- carrying the policy's name and a fingerprint
of its content -- and ``session.end`` when the work is done.

The fingerprint matters because the policy file is not copied into the journal.
Six months later, "what was it allowed to do?" is answered by the fingerprint,
checked against whichever revision of the policy was in force.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from ._version import __version__
from .events import Actor, Event, EventType
from .journal import Journal
from .policy.engine import PolicyEngine


@dataclass(frozen=True)
class SessionInfo:
    """What a session recorded about itself."""

    session_id: str
    policy: str
    policy_fingerprint: str
    start_seq: int
    end_seq: int | None = None
    actions: int = 0
    outcome: str = "open"

    def render(self) -> str:
        span = f"#{self.start_seq}"
        if self.end_seq is not None:
            span = f"#{self.start_seq}-#{self.end_seq}"
        return (
            f"session {self.session_id[:12]} [{self.policy} {self.policy_fingerprint[:12]}] "
            f"{span}: {self.actions} action(s), {self.outcome}"
        )


class Session:
    """Context manager that brackets guarded work with start and end records.

    Example:
        >>> with Session(engine, journal, cwd=".") as session:  # doctest: +SKIP
        ...     runner = GuardedRunner(engine, journal)
        ...     runner.run("pytest -q")
        ... print(session.info.render())
    """

    def __init__(
        self,
        engine: PolicyEngine,
        journal: Journal,
        *,
        cwd: str | None = None,
        session_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.engine = engine
        self.journal = journal
        self.cwd = cwd
        self.session_id = session_id or uuid.uuid4().hex
        self.metadata = dict(metadata or {})
        self._start: Event | None = None
        self._end: Event | None = None
        self._actions = 0

    @property
    def info(self) -> SessionInfo | None:
        """What has been recorded so far, or ``None`` before ``__enter__``."""
        if self._start is None:
            return None
        return SessionInfo(
            session_id=self.session_id,
            policy=self.engine.name,
            policy_fingerprint=self.engine.policy.fingerprint(),
            start_seq=self._start.seq,
            end_seq=self._end.seq if self._end is not None else None,
            actions=self._actions,
            outcome="closed" if self._end is not None else "open",
        )

    def __enter__(self) -> Session:
        if self._start is not None:
            raise RuntimeError("this Session has already been entered")
        policy = self.engine.policy
        self._start = self.journal.append(
            EventType.SESSION_START,
            Actor.SENTINEL,
            {
                "session_id": self.session_id,
                "policy": policy.name,
                "policy_fingerprint": policy.fingerprint(),
                "policy_source": policy.source,
                "policy_default": policy.default_effect.value,
                "rules": len(self.engine.rules),
                "cwd": self.cwd,
                "tool": f"agent-sentinel {__version__}",
                "metadata": self.metadata,
            },
        )
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> Literal[False]:
        start = self._start
        if start is None:
            return False
        actions, head_hash = self._summarise(start.seq)
        self._actions = actions
        self._end = self.journal.append(
            EventType.SESSION_END,
            Actor.SENTINEL,
            {
                "session_id": self.session_id,
                "actions": actions,
                "outcome": "error" if exc_type is not None else "ok",
                "head": head_hash,
            },
        )
        return False

    def _summarise(self, start_seq: int) -> tuple[int, str | None]:
        """Count proposed actions since the session opened, and note the head."""
        actions = 0
        head_hash: str | None = None
        for event in self.journal.iter_events():
            if event.seq <= start_seq:
                continue
            head_hash = event.hash
            if event.type is EventType.ACTION_PROPOSED:
                actions += 1
        return actions, head_hash
