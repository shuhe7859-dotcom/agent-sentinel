"""Appending to and verifying the flight recorder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_sentinel.errors import JournalIntegrityError
from agent_sentinel.events import Actor, EventType
from agent_sentinel.journal import Journal, read_events, verify_file


def _journal(tmp_path: Path, count: int = 3) -> Journal:
    journal = Journal(tmp_path / "session.jsonl")
    for index in range(count):
        journal.append(EventType.NOTE, Actor.AGENT, {"index": index})
    return journal


def test_append_builds_a_linked_chain(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")
    first = journal.append(EventType.SESSION_START, Actor.AGENT, {"cwd": str(tmp_path)})
    second = journal.append(EventType.NOTE, Actor.HUMAN, {"message": "hi"})

    assert (first.seq, second.seq) == (1, 2)
    assert second.prev_hash == first.hash
    assert journal.verify().ok


def test_append_resumes_an_existing_journal(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    Journal(path).append(EventType.NOTE, Actor.AGENT, {"index": 0})

    resumed = Journal(path).append(EventType.NOTE, Actor.AGENT, {"index": 1})

    assert resumed.seq == 2
    assert len(read_events(path)) == 2
    assert verify_file(path).ok


def test_head_is_none_for_a_missing_or_empty_journal(tmp_path: Path) -> None:
    assert Journal(tmp_path / "absent.jsonl").head() is None

    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    assert Journal(path).head() is None


def test_verify_accepts_an_intact_journal(tmp_path: Path) -> None:
    report = _journal(tmp_path).verify()

    assert report.ok
    assert report.event_count == 3
    assert report.head_hash is not None
    assert "ok" in report.render()


def test_verify_detects_an_edited_record(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["payload"]["index"] = 99
    lines[1] = json.dumps(record)
    journal.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = journal.verify()

    assert not report.ok
    assert [issue.kind for issue in report.issues] == ["hash"]
    assert report.issues[0].seq == 2


def test_verify_detects_a_removed_record(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    report = journal.verify()

    kinds = {issue.kind for issue in report.issues}
    assert kinds == {"sequence", "link"}


def test_verify_reports_a_malformed_line(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=1)
    with journal.path.open("a", encoding="utf-8") as handle:
        handle.write("this is not json\n")

    report = journal.verify()

    assert report.event_count == 1
    assert [issue.kind for issue in report.issues] == ["malformed"]


def test_reading_a_malformed_line_raises(tmp_path: Path) -> None:
    path = tmp_path / "broken.jsonl"
    path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(JournalIntegrityError, match="not a valid record"):
        read_events(path)


def test_tail_returns_the_last_records_oldest_first(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=5)

    assert [event.seq for event in journal.tail(2)] == [4, 5]
    assert journal.tail(0) == []


def test_note_records_a_human_message(tmp_path: Path) -> None:
    event = Journal(tmp_path / "session.jsonl").note("reviewed by hand")

    assert event.type is EventType.NOTE
    assert event.actor is Actor.HUMAN
    assert event.payload == {"message": "reviewed by hand"}


def test_verify_on_a_missing_journal_is_ok(tmp_path: Path) -> None:
    report = Journal(tmp_path / "absent.jsonl").verify()

    assert report.ok
    assert report.event_count == 0
    assert report.head_hash is None
