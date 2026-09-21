"""The guarded runner: what it runs, what it refuses, and what it writes down."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from agent_sentinel.approvals import (
    SOURCE_CALLBACK,
    SOURCE_CONFIG,
    SOURCE_OPERATOR,
    record_decision,
)
from agent_sentinel.guards.shell import GuardedRunner
from agent_sentinel.journal import Journal
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import parse_policy
from agent_sentinel.policy.models import Action, ActionKind, Decision
from agent_sentinel.policy.presets import load_preset


def _engine(*, effect: str = "allow") -> PolicyEngine:
    """A one-rule policy that lets the tests control the verdict."""
    return PolicyEngine(
        parse_policy(
            {
                "name": "test",
                "default": "allow",
                "rules": [
                    {
                        "id": "echo.rule",
                        "kind": "shell",
                        "effect": effect,
                        "pattern": r"^echo ",
                        "reason": "for the test",
                    }
                ],
            }
        )
    )


def _journal(tmp_path: Path) -> Journal:
    return Journal(tmp_path / "session.jsonl")


def _types(journal: Journal) -> list[str]:
    return [event.type.value for event in journal.read()]


# -------------------------------------------------------------------- allow/deny
def test_an_allowed_command_runs_and_is_recorded(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    result = GuardedRunner(_engine(), journal).run("echo hello")

    assert result.ok
    assert result.returncode == 0
    assert result.status == "executed"
    assert "hello" in result.stdout_preview
    assert _types(journal) == ["action.proposed", "policy.decision", "action.result"]
    assert journal.verify().ok


def test_a_denied_command_never_reaches_the_shell(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    result = GuardedRunner(_engine(effect="deny"), journal).run("echo hello")

    assert result.status == "denied"
    assert not result.executed
    assert result.returncode is None
    assert result.stdout_preview == ""
    assert _types(journal) == ["action.proposed", "policy.decision", "action.result"]
    assert journal.read()[-1].payload["rule"] == "echo.rule"


def test_output_is_stored_as_a_digest_and_a_preview(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    result = GuardedRunner(_engine(), journal).run("echo recorded")
    payload = journal.read()[-1].payload

    assert payload["stdout_sha256"] == hashlib.sha256(result.stdout_preview.encode()).hexdigest()
    assert payload["stdout_bytes"] == len(result.stdout_preview.encode())
    assert "recorded" in payload["stdout_preview"]


def test_the_proposal_is_recorded_before_the_decision(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    GuardedRunner(_engine(effect="deny"), journal).run("echo hello")

    proposal, decision = journal.read()[0], journal.read()[1]
    assert proposal.payload["target"] == "echo hello"
    assert decision.payload["effect"] == "deny"
    assert decision.payload["policy"] == "test"


# ------------------------------------------------------------------------ review
def test_a_reviewed_command_stops_and_is_escalated(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    result = GuardedRunner(_engine(effect="review"), journal).run("echo hello")

    assert result.status == "awaiting_approval"
    assert not result.executed
    assert result.approval_request is not None
    assert result.approval_request.rule_id == "echo.rule"
    assert _types(journal) == [
        "action.proposed",
        "policy.decision",
        "approval.requested",
        "action.result",
    ]


def test_a_recorded_grant_lets_the_command_run(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = Action(kind=ActionKind.SHELL, target="echo hello")
    grant = record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)

    result = GuardedRunner(_engine(effect="review"), journal).run("echo hello")

    assert result.ok
    assert result.approval_seq == grant.seq
    assert journal.read()[-1].payload["approval_seq"] == grant.seq
    assert journal.verify().ok


def test_a_grant_is_consumed_by_the_run_that_used_it(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = Action(kind=ActionKind.SHELL, target="echo hello")
    record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)
    runner = GuardedRunner(_engine(effect="review"), journal)

    first = runner.run("echo hello")
    second = runner.run("echo hello")

    assert first.ok
    assert second.status == "awaiting_approval"


def test_a_grant_for_one_command_does_not_cover_another(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = Action(kind=ActionKind.SHELL, target="echo hello")
    record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)

    result = GuardedRunner(_engine(effect="review"), journal).run("echo goodbye")

    assert result.status == "awaiting_approval"


def test_a_reviewer_callback_can_grant_and_is_recorded(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    seen: list[Decision] = []

    def reviewer(action: Action, decision: Decision) -> bool:
        seen.append(decision)
        return True

    result = GuardedRunner(_engine(effect="review"), journal, reviewer=reviewer).run("echo hello")

    assert result.ok
    assert result.approval_seq is not None
    decided = [event for event in journal.read() if event.type.value == "approval.decided"]
    assert decided[0].payload["source"] == SOURCE_CALLBACK
    assert decided[0].payload["granted"] is True
    assert seen[0].rule_id == "echo.rule"


def test_a_reviewer_callback_can_refuse(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    runner = GuardedRunner(
        _engine(effect="review"), journal, reviewer=lambda action, decision: False
    )

    result = runner.run("echo hello")

    assert result.status == "refused"
    assert not result.executed
    assert result.approval_request is None
    decided = [event for event in journal.read() if event.type.value == "approval.decided"]
    assert [event.payload["granted"] for event in decided] == [False]
    assert decided[0].payload["source"] == SOURCE_CALLBACK
    assert journal.read()[-1].payload["status"] == "refused"


def test_a_callback_is_not_consulted_when_a_grant_already_exists(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    action = Action(kind=ActionKind.SHELL, target="echo hello")
    record_decision(journal, action=action, granted=True, source=SOURCE_OPERATOR)

    def reviewer(action: Action, decision: Decision) -> bool:
        raise AssertionError("the callback should not have been asked")

    result = GuardedRunner(_engine(effect="review"), journal, reviewer=reviewer).run("echo hello")

    assert result.ok


def test_allow_review_pre_approves_and_says_so(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    runner = GuardedRunner(_engine(effect="review"), journal, allow_review=True)

    result = runner.run("echo hello")

    assert result.ok
    decided = [event for event in journal.read() if event.type.value == "approval.decided"]
    assert decided[0].payload["source"] == SOURCE_CONFIG


# ----------------------------------------------------------------------- timeout
def test_a_command_that_overruns_its_timeout_is_recorded_as_such(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    runner = GuardedRunner(PolicyEngine(load_preset("permissive")), journal, timeout=1)
    command = f'"{sys.executable}" -c "import time; time.sleep(3)"'

    result = runner.run(command)

    assert result.status == "timeout"
    assert result.executed
    assert not result.ok
    payload = journal.read()[-1].payload
    assert payload["status"] == "timeout"
    assert payload["timeout_s"] == 1
    assert journal.verify().ok
