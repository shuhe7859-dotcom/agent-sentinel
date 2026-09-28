"""The filesystem guard: containment first, policy second, disk third."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent_sentinel.approvals import SOURCE_OPERATOR, record_decision
from agent_sentinel.guards.filesystem import OUTSIDE, GuardedFileSystem, normalize_path
from agent_sentinel.journal import Journal
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import parse_policy
from agent_sentinel.policy.models import Action, ActionKind
from agent_sentinel.policy.presets import load_preset


def _engine(*, default: str = "allow", rules: list[dict[str, object]] | None = None):
    return PolicyEngine(parse_policy({"name": "test", "default": default, "rules": rules or []}))


def _guard(
    tmp_path: Path, engine: PolicyEngine | None = None, **kwargs: object
) -> tuple[GuardedFileSystem, Journal]:
    journal = Journal(tmp_path / "session.jsonl")
    guard = GuardedFileSystem(
        engine or _engine(),
        journal,
        workspace=tmp_path,
        **kwargs,  # type: ignore[arg-type]
    )
    return guard, journal


def _symlink_or_skip(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform dependent
        pytest.skip(f"symbolic links are not available here: {exc}")


# ------------------------------------------------------------------ path shapes
def test_normalize_path_keeps_escapes_visible() -> None:
    assert normalize_path(r".\notes\todo.md") == "notes/todo.md"
    assert normalize_path("../outside.py") == "../outside.py"
    assert normalize_path("a/../b.txt") == "b.txt"


# ---------------------------------------------------------------------- writes
def test_a_write_inside_the_workspace_succeeds(tmp_path: Path) -> None:
    guard, journal = _guard(tmp_path)
    (tmp_path / "notes").mkdir()

    result = guard.write("notes/todo.md", "buy milk")

    assert result.ok
    assert result.status == "written"
    assert result.containment == "inside"
    assert result.relative == "notes/todo.md"
    assert result.bytes_written == 8
    assert result.sha256 == hashlib.sha256(b"buy milk").hexdigest()
    assert (tmp_path / "notes" / "todo.md").read_text(encoding="utf-8") == "buy milk"
    assert journal.verify().ok


def test_accepts_bytes_as_well_as_text(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)

    result = guard.write("data.bin", b"\x00\x01\x02")

    assert result.ok
    assert (tmp_path / "data.bin").read_bytes() == b"\x00\x01\x02"


def test_the_journal_records_a_digest_but_not_the_contents(tmp_path: Path) -> None:
    guard, journal = _guard(tmp_path)

    guard.write("notes.md", "TOP SECRET")

    records = [event.to_record() for event in journal.read()]
    serialised = json.dumps(records)
    assert "TOP SECRET" not in serialised
    assert hashlib.sha256(b"TOP SECRET").hexdigest() in serialised


def test_a_missing_parent_directory_fails(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)

    result = guard.write("deep/nested/file.txt", "x")

    assert result.status == "failed"
    assert "FileNotFoundError" in result.error
    assert not (tmp_path / "deep").exists()


def test_create_parents_makes_the_directories(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)

    result = guard.write("deep/nested/file.txt", "x", create_parents=True)

    assert result.ok
    assert (tmp_path / "deep" / "nested" / "file.txt").read_text(encoding="utf-8") == "x"


# ------------------------------------------------------------------ containment
def test_a_parent_traversal_is_refused_by_the_guard(tmp_path: Path) -> None:
    guard, journal = _guard(tmp_path)

    result = guard.write("../outside.txt", "x")

    assert result.status == "denied"
    assert result.containment == OUTSIDE
    assert not (tmp_path.parent / "outside.txt").exists()
    payload = journal.read()[1].payload
    assert payload["containment"] == OUTSIDE
    assert "outside the workspace" in payload["reason"]


def test_an_absolute_path_outside_is_refused(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)
    elsewhere = tmp_path.parent / "elsewhere.txt"

    result = guard.write(elsewhere, "x")

    assert result.status == "denied"
    assert not elsewhere.exists()


def test_a_policy_cannot_relax_containment(tmp_path: Path) -> None:
    """Even a policy that allows everything cannot talk the guard out of this."""
    guard, _ = _guard(tmp_path, _engine(default="allow"))

    result = guard.write("../outside.txt", "x")

    assert result.denied
    assert "(the policy had said allow)" in result.decision.reason


def test_a_symlink_that_points_outside_is_refused(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-dir"
    outside.mkdir(exist_ok=True)
    _symlink_or_skip(outside, tmp_path / "escape")
    guard, _ = _guard(tmp_path)

    result = guard.write("escape/planted.txt", "x")

    assert result.status == "denied"
    assert not (outside / "planted.txt").exists()


# ----------------------------------------------------------------- policy rules
def test_writing_into_git_internals_is_denied(tmp_path: Path) -> None:
    guard, journal = _guard(tmp_path, PolicyEngine(load_preset("standard")))

    result = guard.write(".git/config", "[core]")

    assert result.denied
    assert result.decision.rule_id == "fs.git-internals"
    assert not (tmp_path / ".git").exists()
    assert journal.read()[-1].payload["status"] == "denied"


def test_a_secret_file_is_reviewed_and_then_needs_approving_again(tmp_path: Path) -> None:
    guard, journal = _guard(tmp_path, PolicyEngine(load_preset("standard")))

    first = guard.write(".env", "TOKEN=1")
    assert first.awaiting_approval
    assert first.approval_request is not None
    assert not (tmp_path / ".env").exists()

    record_decision(
        journal,
        action=Action(kind=ActionKind.FILE_WRITE, target=".env"),
        granted=True,
        source=SOURCE_OPERATOR,
    )

    second = guard.write(".env", "TOKEN=2")
    assert second.ok
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "TOKEN=2"

    third = guard.write(".env", "TOKEN=3")
    assert third.awaiting_approval


# --------------------------------------------------------------------- deletes
def test_deleting_a_file_inside_the_workspace_succeeds(tmp_path: Path) -> None:
    (tmp_path / "junk.txt").write_text("bye", encoding="utf-8")
    guard, journal = _guard(tmp_path)

    result = guard.delete("junk.txt")

    assert result.ok
    assert result.status == "deleted"
    assert not (tmp_path / "junk.txt").exists()
    assert journal.verify().ok


def test_deleting_a_directory_is_out_of_scope(tmp_path: Path) -> None:
    (tmp_path / "build").mkdir()
    guard, _ = _guard(tmp_path)

    result = guard.delete("build")

    assert result.status == "failed"
    assert "recursive directory deletion is out of scope" in result.error
    assert (tmp_path / "build").is_dir()


def test_deleting_a_symbolic_link_is_refused(tmp_path: Path) -> None:
    (tmp_path / "real.txt").write_text("x", encoding="utf-8")
    _symlink_or_skip(tmp_path / "real.txt", tmp_path / "link.txt")
    guard, _ = _guard(tmp_path)

    result = guard.delete("link.txt")

    assert result.status == "failed"
    assert "symbolic link" in result.error
    assert (tmp_path / "link.txt").is_symlink()


def test_deleting_something_missing_fails(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)

    result = guard.delete("absent.txt")

    assert result.status == "failed"
    assert "FileNotFoundError" in result.error


def test_deleting_outside_the_workspace_is_refused(tmp_path: Path) -> None:
    victim = tmp_path.parent / "victim.txt"
    victim.write_text("important", encoding="utf-8")
    guard, _ = _guard(tmp_path)

    result = guard.delete("../victim.txt")

    assert result.denied
    assert victim.exists()
