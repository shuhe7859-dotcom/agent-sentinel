"""Approvals: scope, single use, expiry, and what counts as pending."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_sentinel.approvals import (
    SOURCE_OPERATOR,
    approvals,
    find_grant,
    pending_requests,
    record_decision,
    request_approval,
)
from agent_sentinel.events import Actor, EventType
from agent_sentinel.journal import Journal
from agent_sentinel.policy.models import Action, ActionKind, Decision, Effect


def _action(command: str = "echo hello") -> Action:
    return Action(kind=ActionKind.SHELL, target=command)


def _decision(action: Action) -> Decision:
    return Decision(
        effect=Effect.REVIEW,
        action=action,
        rule_id="test.review",
        reason="for the test",
        policy="test",
    )


def _journal(tmp_path: Path) -> Journal:
    return Journal(tmp_path / "session.jsonl")


def _escalate(journal: Journal, command: str = "echo hello") -> Action:
    action = _action(command)
    request_approval(journal, action=action, decision=_decision(action))
    return action


# ------------------------------------------------------------------ fingerprints
def test_action_fingerprint_ignores_the_working_directory() -> None:
    here = Action(kind=ActionKind.SHELL, target="echo hi", cwd="/one")
    there = Action(kind=ActionKind.SHELL, target="echo hi", cwd="/two")

    assert here.fingerprint() == there.fingerprint()


def test_action_fingerprint_separates_kinds_and_commands() -> None:
    shell = Action(kind=ActionKind.SHELL, target="notes.md")
    write = Action(kind=ActionKind.FILE_WRITE, target="notes.md")

    assert shell.fingerprint() != write.fingerprint()
    assert shell.fingerprint() != Action(kind=ActionKind.SHELL, target="other.md").fingerprint()


# ------------------------------------------------------------------- escalation
def test_request_approval_records_what_is_being_asked(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _escalate(journal)

    event = journal.read()[-1]
    assert event.type is EventType.APPROVAL_REQUESTED
    assert event.payload["fingerprint"] == action.fingerprint()
    assert event.payload["command"] == "echo hello"
    assert event.payload["rule"] == "test.review"
    assert journal.verify().ok


def test_pending_requests_lists_an_unanswered_escalation(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _escalate(journal)

    pending = pending_requests(journal)

    assert len(pending) == 1
    assert pending[0].command == "echo hello"
    assert "test.review" in pending[0].render()


# ----------------------------------------------------------------------- grants
def test_no_grant_exists_before_anyone_answers(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _escalate(journal)

    assert find_grant(journal, action.fingerprint()) is None


def test_a_grant_is_found_and_reported_as_usable(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _escalate(journal)
    event = record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)

    grant = find_grant(journal, action.fingerprint())

    assert grant is not None
    assert grant.seq == event.seq
    assert grant.actor is Actor.HUMAN
    assert grant.source == SOURCE_OPERATOR
    assert grant.is_usable()
    assert pending_requests(journal) == []


def test_a_refusal_is_not_a_grant(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _escalate(journal)
    record_decision(
        journal, action=action, granted=False, source=SOURCE_OPERATOR, note="not this time"
    )

    assert find_grant(journal, action.fingerprint()) is None
    assert len(pending_requests(journal)) == 1

    approval = approvals(journal)[0]
    assert not approval.granted
    assert not approval.is_usable()
    assert "refused" in approval.render()
    assert "not this time" in approval.render()


def test_a_grant_for_another_command_does_not_apply(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    record_decision(journal, action=_action("echo hello"), granted=True, source=SOURCE_OPERATOR)

    assert find_grant(journal, _action("echo goodbye").fingerprint()) is None


def test_a_grant_is_single_use(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _action()
    record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)
    journal.append(
        EventType.ACTION_RESULT,
        Actor.SENTINEL,
        {"status": "executed", "approval_seq": 1},
    )

    assert find_grant(journal, action.fingerprint()) is None
    assert approvals(journal)[0].consumed_by == 2


def test_a_grant_can_expire(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _escalate(journal)
    record_decision(
        journal,
        action=action,
        granted=True,
        source=SOURCE_OPERATOR,
        expires_in_seconds=60,
    )

    later = datetime.now(UTC) + timedelta(minutes=5)
    assert find_grant(journal, action.fingerprint()) is not None
    assert find_grant(journal, action.fingerprint(), now=later) is None
    assert approvals(journal)[0].is_expired(now=later)


def test_an_expired_grant_leaves_the_request_pending_again(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _escalate(journal)
    record_decision(
        journal, action=action, granted=True, source=SOURCE_OPERATOR, expires_in_seconds=60
    )

    later = datetime.now(UTC) + timedelta(minutes=5)
    assert len(pending_requests(journal, now=later)) == 1


def test_grants_are_consumed_first_in_first_out(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = _action()
    first = record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)
    record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)

    grant = find_grant(journal, action.fingerprint())

    assert grant is not None
    assert grant.seq == first.seq


def test_pending_requests_keep_only_the_latest_escalation_per_command(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _escalate(journal)
    _escalate(journal)
    _escalate(journal, "something else")

    pending = pending_requests(journal)

    # Oldest escalation first, and only the most recent one per command.
    assert [request.command for request in pending] == ["echo hello", "something else"]
    assert pending[0].seq == 2
