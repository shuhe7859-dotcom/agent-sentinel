"""Guarded writes and deletes inside one workspace root.

The guard answers two questions, in this order.

**Structurally.** Does the target, once resolved, still live inside the
workspace? A path that escapes through ``..``, through an absolute path, or
through a symbolic link that points outside is refused before any policy is
consulted, and no policy can relax that. A guard may tighten a verdict, never
loosen it.

**By policy.** Is this particular write or delete allowed, reviewed or denied?
Rules match the path much as the caller wrote it, so patterns such as
``(?:^|/)\\.\\.(?:/|$)`` stay readable, while the resolved path and the
workspace-relative path are recorded alongside for anyone reading the journal.

Only once both have had their say does anything touch the disk.
"""

from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

from ..approvals import ApprovalRequest
from ..journal import Journal
from ..policy.engine import PolicyEngine
from ..policy.models import Action, ActionKind, Decision, Effect
from .base import (
    Guard,
    GuardResult,
    Performed,
    Reviewer,
    as_int,
    as_optional_text,
    as_text,
)

INSIDE = "inside"
OUTSIDE = "outside"


@dataclass(frozen=True)
class FileSystemResult(GuardResult):
    """What happened to one guarded write or delete."""

    path: str = ""
    """The path as the caller wrote it."""

    resolved: str = ""
    """The absolute path it actually referred to."""

    relative: str | None = None
    """The path relative to the workspace, when it was inside."""

    containment: str = INSIDE
    bytes_written: int = 0
    sha256: str | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        """True when the file was written or the file was removed."""
        return self.status in {"written", "deleted"}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def normalize_path(path: str) -> str:
    """Normalise separators and dot segments, keeping a leading ``..`` visible."""
    return posixpath.normpath(path.replace("\\", "/"))


class GuardedFileSystem(Guard[FileSystemResult]):
    """Writes and deletes files, but only inside one workspace root."""

    def __init__(
        self,
        engine: PolicyEngine,
        journal: Journal,
        *,
        workspace: str | Path,
        allow_review: bool = False,
        reviewer: Reviewer | None = None,
        reviewer_note: str | None = None,
    ) -> None:
        super().__init__(
            engine,
            journal,
            allow_review=allow_review,
            reviewer=reviewer,
            reviewer_note=reviewer_note,
        )
        self.workspace = Path(workspace).expanduser().resolve()

    @property
    def workspace_path(self) -> str:
        return self.workspace.as_posix()

    # ------------------------------------------------------------------ public
    def write(
        self,
        path: str | Path,
        data: str | bytes,
        *,
        create_parents: bool = False,
    ) -> FileSystemResult:
        """Write ``data`` to ``path``, relative to the workspace root."""
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        action = self._describe(
            ActionKind.FILE_WRITE,
            path,
            {
                "bytes": len(payload),
                "sha256": _sha256(payload),
                "create_parents": create_parents,
            },
        )
        return self.guard(action, partial(self._write, payload))

    def delete(self, path: str | Path) -> FileSystemResult:
        """Remove a single file, relative to the workspace root."""
        action = self._describe(ActionKind.FILE_DELETE, path, {})
        return self.guard(action, self._delete)

    # ------------------------------------------------------------------- hooks
    def _context(self, action: Action, decision: Decision) -> Mapping[str, Any]:
        metadata = action.metadata
        context: dict[str, Any] = {
            "path": action.target,
            "resolved": metadata.get("resolved"),
            "containment": metadata.get("containment"),
        }
        if metadata.get("relative") is not None:
            context["relative"] = metadata["relative"]
        return context

    def _constrain(self, action: Action, decision: Decision) -> Decision:
        """Refuse anything that resolves outside the workspace, whatever the policy says."""
        if action.metadata.get("containment") != OUTSIDE:
            return decision
        resolved = action.metadata.get("resolved")
        return Decision(
            effect=Effect.DENY,
            action=action,
            rule_id=decision.rule_id,
            reason=(
                f"'{action.target}' resolves to {resolved}, outside the workspace "
                f"'{self.workspace_path}'; the filesystem guard does not allow escapes "
                f"(the policy had said {decision.effect.value})"
            ),
            policy=decision.policy,
        )

    def _result(
        self,
        action: Action,
        decision: Decision,
        recorded: Mapping[str, Any],
        private: Mapping[str, Any],
        *,
        approval_seq: int | None = None,
        approval_request: ApprovalRequest | None = None,
    ) -> FileSystemResult:
        return FileSystemResult(
            decision=decision,
            status=as_text(recorded.get("status"), "failed"),
            path=as_text(recorded.get("path"), action.target),
            resolved=as_text(recorded.get("resolved")),
            relative=as_optional_text(recorded.get("relative")),
            containment=as_text(recorded.get("containment"), INSIDE),
            bytes_written=as_int(recorded.get("bytes_written")),
            sha256=as_optional_text(recorded.get("sha256")),
            error=as_text(recorded.get("error")),
            approval_seq=approval_seq,
            approval_request=approval_request,
        )

    # ---------------------------------------------------------------- internals
    def _describe(self, kind: ActionKind, path: str | Path, extra: Mapping[str, Any]) -> Action:
        given = normalize_path(str(path))
        resolved = self._resolve(path)
        relative = self._relative(resolved)
        metadata: dict[str, Any] = {
            "workspace": self.workspace_path,
            "resolved": resolved.as_posix(),
            "containment": INSIDE if relative is not None else OUTSIDE,
        }
        if relative is not None:
            metadata["relative"] = relative
        metadata.update(extra)
        return Action(kind=kind, target=given, metadata=metadata)

    def _resolve(self, path: str | Path) -> Path:
        """Resolve a target against the workspace, following symbolic links."""
        candidate = Path(str(path))
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        return candidate.resolve()

    def _relative(self, resolved: Path) -> str | None:
        """The workspace-relative form of ``resolved``, or ``None`` if outside."""
        try:
            return resolved.relative_to(self.workspace).as_posix()
        except ValueError:
            return None

    def _target(self, action: Action) -> Path:
        return Path(str(action.metadata["resolved"]))

    def _lexical(self, action: Action) -> Path:
        """The path as given, made absolute but *not* resolved.

        Symbolic links are followed when deciding containment, but the final
        component has to be inspected as written, or a link would be reported as
        its target.
        """
        candidate = Path(action.target)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        return candidate

    def _write(self, payload: bytes, action: Action) -> Performed:
        target = self._target(action)
        if bool(action.metadata.get("create_parents")):
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return Performed(
            recorded={
                "status": "written",
                "bytes_written": len(payload),
                "sha256": _sha256(payload),
            }
        )

    def _delete(self, action: Action) -> Performed:
        target = self._target(action)
        if self._lexical(action).is_symlink():
            return Performed(
                recorded={
                    "status": "failed",
                    "error": (
                        "refusing to delete a symbolic link, because it is ambiguous whether "
                        "the link or its target is meant; remove it with the shell guard if "
                        "that is really the intent"
                    ),
                }
            )
        if target.is_dir():
            return Performed(
                recorded={
                    "status": "failed",
                    "error": (
                        "recursive directory deletion is out of scope for this guard; "
                        "delete the files, or use the shell guard"
                    ),
                }
            )
        target.unlink()
        return Performed(recorded={"status": "deleted"})
