"""Reading a journal back: transcripts, HTML and SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from agent_sentinel.anchors import anchor_journal, append_anchor
from agent_sentinel.events import Actor, EventType
from agent_sentinel.guards.shell import GuardedShell
from agent_sentinel.journal import Journal
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import parse_policy
from agent_sentinel.policy.presets import load_preset
from agent_sentinel.report import (
    html_report,
    sarif_report,
    sessions,
    transcript,
    transcript_json,
)
from agent_sentinel.session import Session


def _run(tmp_path: Path, command: str) -> Journal:
    """A journal holding one framed session that tried to run ``command``."""
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(load_preset("standard"))
    with Session(engine, journal, workspace=str(tmp_path)):
        GuardedShell(engine, journal).run(command)
    return journal


# ----------------------------------------------------------------- grouping
def test_a_session_becomes_one_block(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")

    blocks = sessions(journal.read())

    assert len(blocks) == 1
    assert blocks[0].session_id is not None
    assert blocks[0].policy == "standard"
    assert len(blocks[0].fingerprint) == 64
    assert blocks[0].outcome == "ok"
    assert "policy standard" in blocks[0].render_title()


def test_records_outside_a_session_get_a_block_of_their_own(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")
    journal.note("looked at this by hand")

    blocks = sessions(journal.read())

    assert len(blocks) == 2
    assert blocks[1].session_id is None
    assert blocks[1].start is None
    assert "outside any session" in blocks[1].render_title()


def test_sessions_separate_correctly(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo one")
    journal.note("between")
    _second_session(journal)

    blocks = sessions(journal.read())

    assert len(blocks) == 3
    assert blocks[0].session_id != blocks[2].session_id
    assert blocks[1].session_id is None


def _second_session(journal: Journal) -> None:
    engine = PolicyEngine(load_preset("standard"))
    with Session(engine, journal):
        GuardedShell(engine, journal).run("echo two")


# --------------------------------------------------------------- transcript
def test_the_transcript_reads_the_story(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")

    text = transcript(journal)

    assert f"journal: {journal.path}" in text
    assert "records: 5" in text
    assert "status:  ok" in text
    assert "session " in text
    assert "action.proposed" in text
    assert "allow from (policy default)" in text
    assert "executed" in text
    assert "1 action(s), ok" in text


def test_the_transcript_shows_a_refusal(tmp_path: Path) -> None:
    journal = _run(tmp_path, "rm -rf /")

    text = transcript(journal)

    assert "deny from shell.rm-root" in text
    assert "denied" in text


def test_the_transcript_can_be_narrowed_to_one_session(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo one")
    first = sessions(journal.read())[0].session_id
    _second_session(journal)

    text = transcript(journal, session=(first or "")[:12])

    assert "echo one" in text
    assert "echo two" not in text


def test_the_transcript_reports_an_empty_journal(tmp_path: Path) -> None:
    text = transcript(Journal(tmp_path / "absent.jsonl"))

    assert "nothing to replay" in text


def test_the_transcript_shows_problems_without_stopping(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")
    with journal.path.open("a", encoding="utf-8") as handle:
        handle.write("not a record\n")

    text = transcript(journal)

    assert "problems found" in text
    assert "malformed" in text
    assert "status:  BROKEN" in text


def test_replaying_reads_proposals_it_does_not_act_on_them(tmp_path: Path) -> None:
    """A journal is evidence, not a script."""
    journal = Journal(tmp_path / "session.jsonl")
    marker = tmp_path / "should-not-appear.txt"
    journal.append(
        EventType.ACTION_PROPOSED, Actor.AGENT, {"kind": "shell", "target": f"touch {marker}"}
    )

    transcript(journal)

    assert not marker.exists()


def test_the_json_transcript_is_machine_readable(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")

    payload = transcript_json(journal)

    assert payload["records"] == 5
    assert payload["ok"] is True
    assert len(payload["sessions"]) == 1
    assert payload["sessions"][0]["policy"] == "standard"
    assert len(payload["sessions"][0]["events"]) == 5
    json.dumps(payload)  # must be serialisable as it stands


# --------------------------------------------------------------------- html
def test_the_html_report_carries_the_head_and_the_verdict(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")
    head = journal.head()
    assert head is not None

    html = html_report(journal)

    assert html.startswith("<!doctype html>")
    assert head.hash in html
    assert "agent-sentinel journal" in html
    assert "ok" in html
    assert "<script" not in html


def test_the_html_report_escapes_what_the_journal_holds(tmp_path: Path) -> None:
    """An agent can type anything, including a script tag."""
    journal = _run(tmp_path, "echo hi")
    journal.note('<script>alert("xss")</script>')

    html = html_report(journal)

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_the_html_report_says_when_the_anchors_disagree(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")
    anchors = tmp_path / "anchors.jsonl"
    append_anchor(anchors, anchor_journal(journal))
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    html = html_report(journal, anchors=anchors)

    assert "BROKEN" in html
    assert "truncated" in html


def test_the_html_report_lists_unreadable_lines(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")
    with journal.path.open("a", encoding="utf-8") as handle:
        handle.write("{}\n")

    html = html_report(journal)

    assert "Problems found" in html


# -------------------------------------------------------------------- sarif
def test_the_sarif_report_has_the_shape_tools_expect(tmp_path: Path) -> None:
    journal = _run(tmp_path, "rm -rf /")

    sarif = sarif_report(journal)

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-sentinel"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["shell.rm-root"]
    assert run["results"][0]["ruleId"] == "shell.rm-root"
    assert run["results"][0]["level"] == "error"
    assert run["invocations"][0]["executionSuccessful"] is True
    json.dumps(sarif)


def test_a_reviewed_action_becomes_a_warning(tmp_path: Path) -> None:
    journal = _run(tmp_path, "git push --force origin main")

    sarif = sarif_report(journal)

    assert sarif["runs"][0]["results"][0]["level"] == "warning"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "shell.git-force-push"


def test_allowed_actions_are_not_findings(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")

    assert sarif_report(journal)["runs"][0]["results"] == []


def test_an_unmatched_deny_gets_a_stable_rule_id(tmp_path: Path) -> None:
    """A denial with no rule keeps a stable id rather than borrowing its wording."""
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(parse_policy({"name": "closed", "default": "deny", "rules": []}))
    with Session(engine, journal):
        GuardedShell(engine, journal).run("echo hi")

    result = sarif_report(journal)["runs"][0]["results"][0]

    assert result["ruleId"] == "policy-default"
    assert result["level"] == "error"


def test_journal_problems_become_notifications_not_findings(tmp_path: Path) -> None:
    journal = _run(tmp_path, "echo hi")
    with journal.path.open("a", encoding="utf-8") as handle:
        handle.write("not a record\n")

    sarif = sarif_report(journal)
    run = sarif["runs"][0]

    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"] == "malformed"
