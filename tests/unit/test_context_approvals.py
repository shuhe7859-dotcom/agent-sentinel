"""Execution-context approvals, crash safety and cooperating process writers."""

from __future__ import annotations

import multiprocessing
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agent_sentinel.approvals import claim_grant, record_decision
from agent_sentinel.events import Actor, EventType
from agent_sentinel.guards import GuardedFileSystem, GuardedNetwork, GuardedShell
from agent_sentinel.journal import Journal
from agent_sentinel.policy import Action, PolicyEngine, load_preset


def approve(journal: Journal, action: Action) -> None:
    record_decision(journal, action=action, granted=True, source="operator")


def test_shell_context_binds_directory_timeout_policy_and_raw_text(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    engine = PolicyEngine(load_preset("strict"))
    first = GuardedShell(engine, journal, cwd=tmp_path, timeout=5).run("echo hello")
    approve(journal, first.decision.action)
    (tmp_path / "other").mkdir()
    assert (
        GuardedShell(engine, journal, cwd=tmp_path / "other", timeout=5)
        .run("echo hello")
        .awaiting_approval
    )
    assert (
        GuardedShell(engine, journal, cwd=tmp_path, timeout=6).run("echo hello").awaiting_approval
    )
    assert (
        GuardedShell(engine, journal, cwd=tmp_path, timeout=5).run("echo  hello").awaiting_approval
    )
    changed = PolicyEngine(replace(engine.policy, description="changed", name="new-policy"))
    assert (
        GuardedShell(changed, journal, cwd=tmp_path, timeout=5).run("echo hello").awaiting_approval
    )
    assert GuardedShell(engine, journal, cwd=tmp_path, timeout=5).run("echo hello").ok
    assert (
        GuardedShell(engine, journal, cwd=tmp_path, timeout=5).run("echo hello").awaiting_approval
    )


@pytest.mark.parametrize("change", ["content", "before", "path", "workspace", "parents"])
def test_file_approval_binds_both_contents_and_paths(tmp_path: Path, change: str) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    engine = PolicyEngine(load_preset("strict"))
    guard = GuardedFileSystem(engine, journal, workspace=tmp_path)
    first = guard.write("note.txt", "approved")
    approve(journal, first.decision.action)
    if change == "before":
        (tmp_path / "note.txt").write_text("changed by user", encoding="utf-8")
    if change == "workspace":
        (tmp_path / "other").mkdir()
        guard = GuardedFileSystem(engine, journal, workspace=tmp_path / "other")
    result = guard.write(
        "other.txt" if change == "path" else "note.txt",
        "different" if change == "content" else "approved",
        create_parents=change == "parents",
    )
    assert result.awaiting_approval
    assert not any(e.type is EventType.APPROVAL_CLAIMED for e in journal.read())


def test_file_changed_inside_reviewer_requires_fresh_approval(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    target = tmp_path / "note.txt"
    target.write_text("before", encoding="utf-8")

    def reviewer(action: Action, decision: Any) -> bool:
        target.write_text("edited during review", encoding="utf-8")
        return True

    guard = GuardedFileSystem(
        PolicyEngine(load_preset("strict")), journal, workspace=tmp_path, reviewer=reviewer
    )
    result = guard.write("note.txt", "replacement")
    assert result.awaiting_approval
    assert target.read_text(encoding="utf-8") == "edited during review"
    assert result.approval_request is not None
    assert result.approval_request.action["metadata"]["before"].startswith("sha256:")


def test_delete_approval_does_not_cover_replacement_file(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    target = tmp_path / "note.txt"
    target.write_text("before", encoding="utf-8")
    guard = GuardedFileSystem(PolicyEngine(load_preset("strict")), journal, workspace=tmp_path)
    approve(journal, guard.delete("note.txt").decision.action)
    target.write_text("replacement", encoding="utf-8")
    assert guard.delete("note.txt").awaiting_approval
    assert target.exists()


@pytest.mark.parametrize(
    "changed",
    [
        {"url": "https://example.com/other"},
        {"method": "POST"},
        {"headers": {"Authorization": "different-secret"}},
        {"body": b"different-body"},
        {"timeout": 2},
        {"max_bytes": 2},
    ],
)
def test_network_approval_binds_request_without_leaking_body_or_headers(
    tmp_path: Path,
    changed: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    guard = GuardedNetwork(PolicyEngine(load_preset("strict")), journal)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a changed request must never reach the network")

    monkeypatch.setattr(guard, "_request", forbidden)
    kwargs: dict[str, Any] = {
        "url": "https://example.com/read",
        "method": "GET",
        "headers": {"Authorization": "original-secret"},
        "body": b"original-body",
    }
    first = guard.fetch(**kwargs)
    approve(journal, first.decision.action)
    assert guard.fetch(**(kwargs | changed)).awaiting_approval
    text = journal.path.read_text(encoding="utf-8")
    assert "original-secret" not in text and "different-secret" not in text
    assert "original-body" not in text and "different-body" not in text


def test_legacy_grant_cannot_authorize_and_claim_survives_crash(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    guard = GuardedShell(PolicyEngine(load_preset("strict")), journal)
    action = guard.run("echo hello").decision.action
    journal.append(
        EventType.APPROVAL_DECIDED,
        Actor.HUMAN,
        {"granted": True, "fingerprint": action.fingerprint()},
    )
    assert claim_grant(journal, action) is None
    approve(journal, action)
    assert claim_grant(journal, action) is not None
    # Simulate a process dying after durable reservation, before an action.result.
    assert claim_grant(Journal(journal.path), action) is None
    assert guard.run("echo hello").awaiting_approval


def test_header_case_collisions_and_absent_body_have_distinct_identities(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    guard = GuardedNetwork(PolicyEngine(load_preset("strict")), journal)
    first = guard.fetch("https://example.com", headers={"X-Key": "one", "x-key": "two"})
    second = guard.fetch("https://example.com", headers={"X-Key": "two", "x-key": "one"})
    assert first.decision.action.fingerprint() != second.decision.action.fingerprint()
    absent = guard.fetch("https://example.com")
    empty = guard.fetch("https://example.com", body=b"")
    assert absent.decision.action.fingerprint() != empty.decision.action.fingerprint()


def _append_worker(path: str) -> None:
    for n in range(12):
        Journal(path).note(str(n))


def _claim_worker(path: str, data: dict[str, Any]) -> None:
    raise SystemExit(0 if claim_grant(Journal(path), Action.from_dict(data)) else 2)


def _join(processes: list[Any]) -> list[int | None]:
    try:
        for process in processes:
            process.join(timeout=20)
        assert all(not p.is_alive() for p in processes), "worker failed to finish"
        return [p.exitcode for p in processes]
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)


def test_multiple_processes_preserve_chain_and_only_one_claims(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    context = multiprocessing.get_context("spawn")
    writers = [context.Process(target=_append_worker, args=(str(journal.path),)) for _ in range(4)]
    for process in writers:
        process.start()
    assert _join(writers) == [0] * 4
    assert journal.verify().ok and len(journal.read()) == 48
    action = (
        GuardedShell(PolicyEngine(load_preset("strict")), journal).run("echo hi").decision.action
    )
    approve(journal, action)
    claimers = [
        context.Process(target=_claim_worker, args=(str(journal.path), action.as_dict()))
        for _ in range(4)
    ]
    for process in claimers:
        process.start()
    assert sorted(_join(claimers)) == [0, 2, 2, 2]
    assert journal.verify().ok
    assert sum(e.type is EventType.APPROVAL_CLAIMED for e in journal.read()) == 1
