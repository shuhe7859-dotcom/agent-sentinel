"""End-to-end checks of the ``sentinel`` command line."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_sentinel import Actor, EventType, __version__, cli
from agent_sentinel.journal import Journal


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["version"]) == cli.EXIT_OK
    assert __version__ in capsys.readouterr().out


def test_policy_presets_lists_the_built_ins(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["policy", "presets"]) == cli.EXIT_OK
    output = capsys.readouterr().out

    for name in ("permissive", "standard", "strict"):
        assert name in output


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("pytest -q", cli.EXIT_OK),
        ("git push --force origin main", cli.EXIT_REVIEW),
        ("rm -rf /", cli.EXIT_DENY),
    ],
)
def test_policy_check_exit_codes(
    target: str, expected: int, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(
        ["policy", "check", "--policy", "standard", "--kind", "shell", "--target", target]
    )

    assert code == expected
    assert target.split()[0] in capsys.readouterr().out


def test_policy_check_can_print_json(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(
        [
            "policy",
            "check",
            "--policy",
            "standard",
            "--kind",
            "file.write",
            "--target",
            "../escape.py",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == cli.EXIT_DENY
    assert payload["effect"] == "deny"
    assert payload["rule"] == "fs.path-traversal"


def test_policy_check_reads_a_policy_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text(
        'schema = 1\nname = "team"\ndefault = "deny"\n',
        encoding="utf-8",
    )

    code = cli.main(["policy", "check", "--policy", str(policy_file), "--target", "echo hi"])

    assert code == cli.EXIT_DENY
    assert "team" in capsys.readouterr().out


def test_run_records_a_guarded_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = tmp_path / "session.jsonl"
    command = f'"{sys.executable}" -c "print(41 + 1)"'

    code = cli.main(
        [
            "run",
            "--policy",
            "standard",
            "--journal",
            str(journal_path),
            "--",
            *command.split(" "),
        ]
    )
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert "42" in captured.out
    assert "executed" in captured.err

    events = Journal(journal_path).read()
    assert [event.type.value for event in events] == [
        "action.proposed",
        "policy.decision",
        "action.result",
    ]
    assert events[-1].payload["status"] == "executed"
    assert Journal(journal_path).verify().ok


def test_run_refuses_a_denied_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = tmp_path / "session.jsonl"

    code = cli.main(
        [
            "run",
            "--policy",
            "standard",
            "--journal",
            str(journal_path),
            "--",
            "rm",
            "-rf",
            "/",
        ]
    )

    assert code == cli.EXIT_DENY
    assert "denied" in capsys.readouterr().err
    assert Journal(journal_path).read()[-1].payload["status"] == "denied"


def test_run_stops_at_a_review_decision(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = tmp_path / "session.jsonl"

    code = cli.main(
        [
            "run",
            "--policy",
            "standard",
            "--journal",
            str(journal_path),
            "--",
            "git",
            "push",
            "--force",
            "origin",
            "main",
        ]
    )

    assert code == cli.EXIT_REVIEW
    assert "awaiting_approval" in capsys.readouterr().err


def test_run_reports_a_failing_command(tmp_path: Path) -> None:
    journal_path = tmp_path / "session.jsonl"
    command = f'"{sys.executable}" -c "raise SystemExit(7)"'

    code = cli.main(
        ["run", "--policy", "standard", "--journal", str(journal_path), "--", *command.split(" ")]
    )

    assert code == cli.EXIT_COMMAND_FAILED
    assert Journal(journal_path).read()[-1].payload["returncode"] == 7


def test_run_requires_a_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["run", "--policy", "standard", "--journal", str(tmp_path / "j.jsonl"), "--"])

    assert code == cli.EXIT_ERROR
    assert "no command given" in capsys.readouterr().err


def test_journal_note_show_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = tmp_path / "session.jsonl"

    assert cli.main(["journal", "note", str(journal_path), "reviewed by hand"]) == cli.EXIT_OK
    assert "event #1" in capsys.readouterr().out

    assert cli.main(["journal", "show", str(journal_path)]) == cli.EXIT_OK
    assert "reviewed by hand" in capsys.readouterr().out

    assert cli.main(["journal", "show", str(journal_path), "--json"]) == cli.EXIT_OK
    record = json.loads(capsys.readouterr().out)
    assert record["payload"]["message"] == "reviewed by hand"

    assert cli.main(["journal", "verify", str(journal_path)]) == cli.EXIT_OK
    assert "ok" in capsys.readouterr().out


def test_journal_show_on_an_empty_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["journal", "show", str(tmp_path / "absent.jsonl")]) == cli.EXIT_OK
    assert "no events recorded" in capsys.readouterr().out


def test_journal_verify_fails_on_a_broken_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "session.jsonl"
    journal = Journal(path)
    journal.append(EventType.NOTE, Actor.HUMAN, {"message": "original"})

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["payload"]["message"] = "tampered"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    assert cli.main(["journal", "verify", str(path)]) == cli.EXIT_ERROR
    assert "BROKEN" in capsys.readouterr().out


def test_missing_policy_file_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(
        ["policy", "check", "--policy", str(tmp_path / "absent.toml"), "--target", "echo hi"]
    )

    assert code == cli.EXIT_ERROR
    assert "sentinel:" in capsys.readouterr().err
