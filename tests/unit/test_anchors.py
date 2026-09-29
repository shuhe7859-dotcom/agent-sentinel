"""Anchors: catching a log that was shortened or rewritten."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_sentinel.anchors import (
    ANCHOR_SCHEMA_VERSION,
    Anchor,
    anchor_journal,
    append_anchor,
    compare_anchors,
    read_anchor_file,
    sign_anchor,
    verify_with_anchors,
)
from agent_sentinel.errors import JournalError
from agent_sentinel.events import Actor, EventType
from agent_sentinel.journal import IntegrityIssue, Journal
from agent_sentinel.signing import generate_keypair


def _journal(tmp_path: Path, count: int = 3) -> Journal:
    journal = Journal(tmp_path / "session.jsonl")
    for index in range(count):
        journal.append(EventType.NOTE, Actor.AGENT, {"message": f"note {index}"})
    return journal


def _anchor_path(tmp_path: Path) -> Path:
    return tmp_path / "anchors.jsonl"


def _kinds(issues: list[IntegrityIssue]) -> list[str]:
    return [issue.kind for issue in issues]


# ------------------------------------------------------------------ describing
def test_anchoring_describes_the_current_head(tmp_path: Path) -> None:
    journal = _journal(tmp_path)

    anchor = anchor_journal(journal, note="end of the run")

    head = journal.head()
    assert head is not None
    assert anchor.seq == head.seq == 3
    assert anchor.hash == head.hash
    assert anchor.journal == "session.jsonl"
    assert anchor.note == "end of the run"
    assert anchor.signature is None
    assert "seq 3" in anchor.render()
    assert "\n" not in anchor.render()


def test_anchoring_records_the_session_that_had_just_closed(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")
    journal.append(EventType.SESSION_END, Actor.SENTINEL, {"session_id": "abc123", "actions": 0})

    assert anchor_journal(journal).session == "abc123"


def test_anchoring_an_empty_journal_is_refused(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")

    with pytest.raises(JournalError, match="nothing to anchor"):
        anchor_journal(journal)


def test_anchor_render_names_the_signer(tmp_path: Path) -> None:
    private, _ = generate_keypair()
    anchor = sign_anchor(anchor_journal(_journal(tmp_path)), private)

    assert "signed by" in anchor.render()
    assert anchor.signer


# ---------------------------------------------------------------- file format
def test_anchors_round_trip_through_a_file(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    path = _anchor_path(tmp_path)
    first = anchor_journal(journal, note="first")
    second = anchor_journal(journal, note="second")

    append_anchor(path, first)
    append_anchor(path, second)
    read = read_anchor_file(path)

    assert read.issues == ()
    assert read.anchors == (first, second)
    assert read.path == path


def test_blank_lines_are_ignored(tmp_path: Path) -> None:
    path = _anchor_path(tmp_path)
    append_anchor(path, anchor_journal(_journal(tmp_path)))
    path.write_text(path.read_text(encoding="utf-8") + "\n\n", encoding="utf-8")

    assert len(read_anchor_file(path).anchors) == 1


def test_a_bad_line_is_reported_rather_than_hiding_the_rest(tmp_path: Path) -> None:
    path = _anchor_path(tmp_path)
    append_anchor(path, anchor_journal(_journal(tmp_path)))
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")

    read = read_anchor_file(path)

    assert len(read.anchors) == 1
    assert _kinds(list(read.issues)) == ["bad-anchor"]
    assert read.issues[0].source == "anchor"
    assert "anchor line 2" in read.issues[0].render()


def test_an_unknown_anchor_schema_is_reported(tmp_path: Path) -> None:
    path = _anchor_path(tmp_path)
    path.write_text(
        json.dumps({"schema": "9.9", "seq": 1, "hash": "a" * 64}) + "\n", encoding="utf-8"
    )

    assert _kinds(list(read_anchor_file(path).issues)) == ["bad-anchor"]


@pytest.mark.parametrize(
    "payload",
    [
        {"schema": ANCHOR_SCHEMA_VERSION, "seq": 0, "hash": "a" * 64},
        {"schema": ANCHOR_SCHEMA_VERSION, "seq": True, "hash": "a" * 64},
        {"schema": ANCHOR_SCHEMA_VERSION, "seq": 1, "hash": "short"},
        {"schema": ANCHOR_SCHEMA_VERSION, "seq": 1},
    ],
)
def test_anchor_from_dict_validates_its_fields(payload: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Anchor.from_dict(payload)


def test_reading_a_missing_anchor_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(JournalError, match="cannot read anchor file"):
        read_anchor_file(tmp_path / "absent.jsonl")


# ------------------------------------------------------------------ comparison
def test_a_clean_journal_matches_its_anchors(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    anchor = anchor_journal(journal)

    assert compare_anchors(journal, [anchor]) == []


def test_a_journal_that_grew_past_its_anchor_still_matches(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=2)
    anchor = anchor_journal(journal)
    journal.append(EventType.NOTE, Actor.AGENT, {"message": "later"})

    assert compare_anchors(journal, [anchor]) == []


def test_a_truncated_tail_is_reported(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=3)
    anchor = anchor_journal(journal)
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text("\n".join(lines[:1]) + "\n", encoding="utf-8")

    issues = compare_anchors(journal, [anchor])

    assert _kinds(issues) == ["truncated"]
    assert "2 records missing" in issues[0].detail
    assert issues[0].source == "anchor"


def test_a_consistent_rewrite_is_caught_by_an_earlier_anchor(tmp_path: Path) -> None:
    """A rewrite that keeps the chain valid still changes the anchored hashes.

    Editing a payload and leaving the hashes stale is the chain's job to notice.
    An anchor is for the harder case: a rewrite the chain accepts.
    """
    journal = _journal(tmp_path, count=1)
    early = anchor_journal(journal, note="before")
    journal.append(EventType.NOTE, Actor.AGENT, {"message": "after"})
    later = anchor_journal(journal, note="after")

    rebuilt = Journal(tmp_path / "rebuilt.jsonl")
    rebuilt.append(EventType.NOTE, Actor.AGENT, {"message": "rewritten"})
    rebuilt.append(EventType.NOTE, Actor.AGENT, {"message": "after"})
    journal.path.write_text(rebuilt.path.read_text(encoding="utf-8"), encoding="utf-8")

    issues = compare_anchors(journal, [early, later])

    # Rewriting the first record changes every hash after it, so both anchors speak.
    assert _kinds(issues) == ["rewritten", "rewritten"]
    assert [issue.seq for issue in issues] == [1, 2]


def test_a_later_anchor_narrows_what_a_truncation_looks_like(tmp_path: Path) -> None:
    """Why anchor more than once: an old checkpoint cannot see a shorter log."""
    journal = _journal(tmp_path, count=1)
    early = anchor_journal(journal)
    journal.append(EventType.NOTE, Actor.AGENT, {"message": "later"})
    later = anchor_journal(journal)

    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text(lines[0] + "\n", encoding="utf-8")

    # Cutting back to exactly the earlier anchor's state is invisible to it...
    assert compare_anchors(journal, [early]) == []
    # ...but the later anchor knows a record was there.
    assert _kinds(compare_anchors(journal, [later])) == ["truncated"]


def test_a_whole_journal_rewrite_is_reported(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=3)
    anchor = anchor_journal(journal)
    replacement = Journal(tmp_path / "rebuilt.jsonl")
    for index in range(3):
        replacement.append(EventType.NOTE, Actor.AGENT, {"message": f"different {index}"})
    journal.path.write_text(replacement.path.read_text(encoding="utf-8"), encoding="utf-8")

    issues = compare_anchors(journal, [anchor])

    assert _kinds(issues) == ["rewritten"]
    assert issues[0].seq == 3


def test_an_anchor_beyond_the_journal_is_a_truncation(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=1)
    notional = Anchor(seq=5, hash="a" * 64, ts="2026-01-01T00:00:00.000Z")

    issues = compare_anchors(journal, [notional])

    assert _kinds(issues) == ["truncated"]
    assert issues[0].seq == 5


def test_compare_anchors_on_an_empty_journal(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")
    notional = Anchor(seq=1, hash="a" * 64, ts="2026-01-01T00:00:00.000Z")

    assert _kinds(compare_anchors(journal, [notional])) == ["truncated"]


# -------------------------------------------------------------- verify report
def test_verify_with_anchors_passes_and_reports_the_checkpoint(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    path = _anchor_path(tmp_path)
    append_anchor(path, anchor_journal(journal))

    report = verify_with_anchors(journal, anchor_path=path)

    assert report.ok
    assert report.anchors_checked == 1
    assert report.latest_anchor_seq == 3
    assert "anchors: 1 checked, latest at seq 3" in report.render()


def test_verify_with_anchors_fails_on_a_truncated_journal(tmp_path: Path) -> None:
    journal = _journal(tmp_path, count=3)
    path = _anchor_path(tmp_path)
    append_anchor(path, anchor_journal(journal))
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    report = verify_with_anchors(journal, anchor_path=path)

    assert not report.ok
    assert _kinds(list(report.issues)) == ["truncated"]
    assert "BROKEN" in report.render()


def test_verify_with_anchors_keeps_the_chain_issues_too(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    path = _anchor_path(tmp_path)
    append_anchor(path, anchor_journal(journal))
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text(lines[0] + "\n", encoding="utf-8")

    report = verify_with_anchors(journal, anchor_path=path)

    assert "truncated" in _kinds(list(report.issues))


def test_verify_with_anchors_needs_usable_anchors(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    path = _anchor_path(tmp_path)
    path.write_text("not json\n", encoding="utf-8")

    with pytest.raises(JournalError, match="holds no usable anchors"):
        verify_with_anchors(journal, anchor_path=path)


def test_verify_with_anchors_needs_the_file_to_exist(tmp_path: Path) -> None:
    journal = _journal(tmp_path)

    with pytest.raises(JournalError, match="cannot read anchor file"):
        verify_with_anchors(journal, anchor_path=tmp_path / "absent.jsonl")
