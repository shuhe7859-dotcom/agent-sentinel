"""Guarded shell execution: commands run only after the policy says so.

The flow itself lives in :class:`~agent_sentinel.guards.base.Guard`. This module
supplies the two things that are specific to running a command: how to describe
it, and how to run it.

Output is recorded as a digest plus a truncated preview rather than in full, so
a chatty build cannot bloat the log while ``sentinel`` can still prove what a
command printed. Command output is transient and is what you reach for when
reading a journal, which is why the preview is here and not in the filesystem
or network guards.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..approvals import ApprovalRequest
from ..journal import Journal
from ..policy.engine import PolicyEngine
from ..policy.models import Action, ActionKind, Decision
from .base import (
    Guard,
    GuardResult,
    Performed,
    Reviewer,
    as_int,
    as_optional_int,
    as_optional_text,
    as_text,
)

DEFAULT_PREVIEW_CHARS = 2000
"""How much output to keep verbatim in the journal."""


@dataclass(frozen=True)
class GuardedResult(GuardResult):
    """What happened to one guarded command."""

    returncode: int | None = None
    duration_ms: int = 0
    stdout_preview: str = ""
    stderr_preview: str = ""
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None

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


class GuardedShell(Guard[GuardedResult]):
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
        super().__init__(engine, journal, allow_review=allow_review, reviewer=reviewer)
        self.cwd = str(cwd) if cwd is not None else None
        self.timeout = timeout

    def run(self, command: str, *, timeout: float | None = None) -> GuardedResult:
        """Evaluate ``command``, run it if permitted, and record the outcome."""
        metadata: dict[str, Any] = {}
        if timeout is not None:
            metadata["timeout_s"] = timeout
        action = Action(kind=ActionKind.SHELL, target=command, cwd=self.cwd, metadata=metadata)
        return self.guard(action, self._run_command)

    # ---------------------------------------------------------------- internals
    def _run_command(self, action: Action) -> Performed:
        timeout = self._timeout(action)
        started = time.perf_counter()
        try:
            completed = subprocess.run(  # noqa: S602 - shell semantics are intentional
                action.target,
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
            return Performed(
                recorded={
                    "status": "timeout",
                    "timeout_s": timeout,
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "stdout_sha256": _digest(stdout),
                    "stderr_sha256": _digest(stderr),
                    "stdout_preview": _preview(stdout),
                    "stderr_preview": _preview(stderr),
                }
            )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return Performed(
            recorded={
                "status": "executed",
                "returncode": completed.returncode,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "stdout_sha256": _digest(stdout),
                "stdout_bytes": len(stdout.encode("utf-8")),
                "stderr_sha256": _digest(stderr),
                "stderr_bytes": len(stderr.encode("utf-8")),
                "stdout_preview": _preview(stdout),
                "stderr_preview": _preview(stderr),
            }
        )

    def _timeout(self, action: Action) -> float | None:
        declared = action.metadata.get("timeout_s")
        if isinstance(declared, int | float) and not isinstance(declared, bool):
            return float(declared)
        return self.timeout

    def _result(
        self,
        action: Action,
        decision: Decision,
        recorded: Mapping[str, Any],
        private: Mapping[str, Any],
        *,
        approval_seq: int | None = None,
        approval_request: ApprovalRequest | None = None,
    ) -> GuardedResult:
        return GuardedResult(
            decision=decision,
            status=as_text(recorded.get("status"), "failed"),
            returncode=as_optional_int(recorded.get("returncode")),
            duration_ms=as_int(recorded.get("duration_ms")),
            stdout_preview=as_text(recorded.get("stdout_preview")),
            stderr_preview=as_text(recorded.get("stderr_preview")),
            stdout_sha256=as_optional_text(recorded.get("stdout_sha256")),
            stderr_sha256=as_optional_text(recorded.get("stderr_sha256")),
            approval_seq=approval_seq,
            approval_request=approval_request,
        )


GuardedRunner = GuardedShell
"""The name this guard shipped under; kept so existing code keeps working."""
