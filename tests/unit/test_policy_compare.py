"""Counterfactual replay must remain read-only, verified, and explicit about labels."""

from __future__ import annotations

import json
import runpy
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from agent_sentinel import cli
from agent_sentinel.anchors import anchor_journal, append_anchor
from agent_sentinel.approvals import claim_grant, record_decision
from agent_sentinel.errors import SentinelError
from agent_sentinel.events import Actor, EventType
from agent_sentinel.guards import GuardedShell
from agent_sentinel.guards.base import Guard
from agent_sentinel.journal import Journal
from agent_sentinel.policy import Action, ActionKind, Effect, PolicyEngine, load_preset
from agent_sentinel.policy.cases import Case
from agent_sentinel.policy.compare import (
    compare_cases,
    compare_journal,
    comparison_html,
    comparison_text,
)
from agent_sentinel.policy.loader import parse_policy
from agent_sentinel.report import html_report, sessions


def engine(name: str) -> PolicyEngine:
    return PolicyEngine(load_preset(name))


def test_replay_never_executes_or_writes_even_dangerous_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    for target in ("echo hello", "git push --force origin main", "rm -rf /"):
        journal.append(
            EventType.ACTION_PROPOSED, Actor.AGENT, Action(ActionKind.SHELL, target).as_dict()
        )
    before = journal.path.read_bytes()
    files = set(tmp_path.iterdir())

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("comparison must not perform any action or write to a journal")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)
    monkeypatch.setattr(Guard, "guard", forbidden)
    monkeypatch.setattr(Journal, "append", forbidden)
    result = compare_journal(journal, engine("permissive"), engine("strict"))
    assert result["summary"]["actions"] == 3
    assert result["summary"]["changed"] == 2
    assert result["summary"]["transitions"]["allow"]["review"] == 2
    assert result["summary"]["transitions"]["deny"]["deny"] == 1
    assert "metrics" not in result and result["labelled"] is False
    assert result["rows"][1]["new"]["rule"] == "shell.git-force-push"
    assert journal.path.read_bytes() == before and set(tmp_path.iterdir()) == files


def test_all_nine_transitions_are_counted(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    rules: dict[str, list[dict[str, Any]]] = {"old": [], "new": []}
    for a in Effect:
        for b in Effect:
            target = f"{a.value}-{b.value}"
            journal.append(EventType.ACTION_PROPOSED, payload={"kind": "shell", "target": target})
            for side, effect in (("old", a), ("new", b)):
                rules[side].append({"id": target, "pattern": f"^{target}$", "effect": effect.value})
    engines = {
        side: PolicyEngine(
            parse_policy({"schema": 1, "name": side, "default": "review", "rules": rule})
        )
        for side, rule in rules.items()
    }
    result = compare_journal(journal, engines["old"], engines["new"])
    assert result["summary"]["changed"] == 6
    assert all(
        count == 1 for row in result["summary"]["transitions"].values() for count in row.values()
    )


def test_empty_missing_damaged_and_unrestorable_logs(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    old, new = engine("standard"), engine("strict")
    with pytest.raises(SentinelError, match="does not exist"):
        compare_journal(journal, old, new)
    journal.path.touch()
    assert compare_journal(journal, old, new)["summary"]["actions"] == 0
    journal.append(EventType.ACTION_PROPOSED, payload={"kind": "shell"})
    with pytest.raises(SentinelError, match="cannot restore"):
        compare_journal(journal, old, new)
    journal.path.write_text("not JSON\n", encoding="utf-8")
    with pytest.raises(SentinelError, match="BROKEN"):
        compare_journal(journal, old, new)


def test_anchors_are_verified_and_key_requires_anchors(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    journal.note("before")
    anchors = tmp_path / "anchors.jsonl"
    append_anchor(anchors, anchor_journal(journal))
    result = compare_journal(journal, engine("standard"), engine("strict"), anchors=anchors)
    assert result["integrity"]["anchors_checked"] == 1
    with pytest.raises(SentinelError, match="requires"):
        compare_journal(journal, engine("standard"), engine("strict"), key=b"invalid")
    journal.path.write_text("", encoding="utf-8")
    with pytest.raises(SentinelError, match="truncated"):
        compare_journal(journal, engine("standard"), engine("strict"), anchors=anchors)


def test_labelled_rates_and_zero_denominators() -> None:
    cases = [Case("echo hi", Effect.ALLOW), Case("git push --force origin main", Effect.REVIEW)]
    result = compare_cases(cases, engine("permissive"), engine("strict"))
    assert result["metrics"]["old"]["unsafe_allow_rate"]["rate"] == 1
    assert result["metrics"]["new"]["unsafe_allow_rate"]["rate"] == 0
    assert result["metrics"]["new"]["unnecessary_restriction_rate"]["rate"] == 1
    assert result["metrics"]["new"]["review_rate"]["rate"] == 1
    empty = compare_cases([], engine("standard"), engine("strict"))
    assert empty["metrics"]["old"]["review_rate"]["rate"] is None
    assert "不适用" in comparison_text(empty) and "不适用" in comparison_html(empty)


def test_html_escapes_inputs_and_displays_consistent_metrics(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    journal.append(
        EventType.ACTION_PROPOSED,
        payload={"kind": "shell", "target": '<script>alert("x")</script>'},
    )
    result = compare_journal(journal, engine("standard"), engine("strict"))
    rendered = comparison_html(result)
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert "0 → 1" in rendered and "allow → review" in rendered
    assert "unsafe_allow_rate" not in rendered
    assert "<script" not in rendered and "<link " not in rendered
    legacy = html_report(journal)
    assert "Legacy events" in legacy and "&lt;script&gt;" in legacy


def test_claim_without_result_is_visible_and_sessions_do_not_interleave(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    first = GuardedShell(engine("strict"), journal).run("echo hi")
    record_decision(journal, action=first.decision.action, granted=True, source="operator")
    # A new attempt claims the grant, then disappears before recording a result.
    data = first.decision.action.as_dict() | {"action_id": "crashed-action"}
    action = Action.from_dict(data)
    journal.append(EventType.ACTION_PROPOSED, payload=data)
    assert claim_grant(journal, action) is not None
    assert "结果未知" in html_report(journal)
    for sid in ("one", "two"):
        journal.append(EventType.SESSION_START, payload={"session_id": sid})
    journal.append(
        EventType.ACTION_PROPOSED,
        payload={"session_id": "one", "action_id": "a", "kind": "shell", "target": "echo"},
    )
    journal.append(EventType.SESSION_END, payload={"session_id": "two"})
    journal.append(EventType.SESSION_END, payload={"session_id": "one"})
    block = next(block for block in sessions(journal.read()) if block.session_id == "one")
    assert all(event.payload["session_id"] == "one" for event in block.events)


def test_compare_cli_formats_and_input_protection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal = Journal(tmp_path / "log.jsonl")
    journal.append(EventType.ACTION_PROPOSED, payload={"kind": "shell", "target": "echo hi"})
    args = [
        "policy",
        "compare",
        "--journal",
        str(journal.path),
        "--old",
        "standard",
        "--new",
        "strict",
    ]
    assert cli.main([*args, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == 1
    for format_name in ("text", "html"):
        out = tmp_path / f"report.{format_name}"
        assert cli.main([*args, "--format", format_name, "--out", str(out)]) == 0
        assert out.stat().st_size > 0
    before = journal.path.read_bytes()
    assert cli.main([*args, "--out", str(journal.path)]) == 1
    assert journal.path.read_bytes() == before
    bad = tmp_path / "bad.toml"
    bad.write_text("not a policy", encoding="utf-8")
    assert cli.main([*args, "--new", str(bad)]) == 1


def test_demo_is_repeatable_offline_and_preserves_original_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("offline demo must not execute shell commands or network requests")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)
    script = Path(__file__).resolve().parents[2] / "examples" / "evidence_demo.py"
    build = runpy.run_path(str(script))["build_demo"]
    first = build(tmp_path)
    original = (first / "approval.jsonl").read_bytes()
    second = build(tmp_path)
    assert first != second and (first / "approval.jsonl").read_bytes() == original
    assert Journal(first / "approval.jsonl").verify().ok
    assert not Journal(first / "tampered-copy.jsonl").verify().ok
    assert (first / "workspace" / "note.txt").read_text(encoding="utf-8") == "approved version"
    assert not (first / "workspace" / "unknown.txt").exists()
    assert "结果未知" in (first / "approval.html").read_text(encoding="utf-8")
    comparison = json.loads((first / "comparison.json").read_text(encoding="utf-8"))
    assert comparison["summary"]["actions"] == 14
    evaluation = json.loads((first / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation["metrics"]["old"]["unsafe_allow_rate"]["denominator"] == 10
