"""End-to-end checks of the ``sentinel`` command line."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from agent_sentinel import Actor, EventType, __version__, cli
from agent_sentinel.journal import Journal

if TYPE_CHECKING:  # pragma: no cover - typing only
    from conftest import LocalServer


def _event_types(path: Path) -> list[str]:
    return [event.type.value for event in Journal(path).read()]


def _results(path: Path) -> list[dict[str, object]]:
    return [
        dict(event.payload)
        for event in Journal(path).read()
        if event.type is EventType.ACTION_RESULT
    ]


def _pending_seq(journal_path: Path, capsys: pytest.CaptureFixture[str]) -> int:
    """Ask what is pending and read the seq number out of the printed hint."""
    cli.main(["journal", "pending", str(journal_path)])
    return int(re.search(r"--request-seq (\d+)", capsys.readouterr().out).group(1))


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

    assert _event_types(journal_path) == [
        "session.start",
        "action.proposed",
        "policy.decision",
        "action.result",
        "session.end",
    ]
    assert _results(journal_path)[-1]["status"] == "executed"
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
    assert _results(journal_path)[-1]["status"] == "denied"


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
    assert _results(journal_path)[-1]["returncode"] == 7


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


# ------------------------------------------------------------------- approvals
REVIEWED_COMMAND = ["echo", ".netrc"]
"""Harmless to run, but the standard preset escalates it as credential access."""


def _run_reviewed(journal_path: Path) -> int:
    return cli.main(
        ["run", "--policy", "standard", "--journal", str(journal_path), "--", *REVIEWED_COMMAND]
    )


def test_run_writes_a_session_around_the_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"

    assert _run_reviewed(journal_path) == cli.EXIT_REVIEW

    events = Journal(journal_path).read()
    assert events[0].type is EventType.SESSION_START
    assert events[-1].type is EventType.SESSION_END
    assert events[0].payload["policy"] == "standard"
    assert len(events[0].payload["policy_fingerprint"]) == 64
    assert "fingerprint" in capsys.readouterr().err


def test_an_escalation_tells_you_how_to_approve_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"

    assert _run_reviewed(journal_path) == cli.EXIT_REVIEW
    err = capsys.readouterr().err

    assert "awaiting_approval" in err
    assert "--request-seq" in err
    assert "sentinel approve" in err


def test_journal_pending_lists_and_then_clears(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    _run_reviewed(journal_path)
    capsys.readouterr()

    assert cli.main(["journal", "pending", str(journal_path)]) == cli.EXIT_OK
    listed = capsys.readouterr().out
    assert "echo .netrc" in listed
    request_seq = int(re.search(r"--request-seq (\d+)", listed).group(1))

    assert (
        cli.main(["approve", str(journal_path), "--request-seq", str(request_seq)]) == cli.EXIT_OK
    )
    assert "granted" in capsys.readouterr().out

    assert cli.main(["journal", "pending", str(journal_path)]) == cli.EXIT_OK
    assert "no approvals pending" in capsys.readouterr().out


def test_approving_lets_the_command_run_exactly_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    _run_reviewed(journal_path)
    capsys.readouterr()
    cli.main(["journal", "pending", str(journal_path)])
    listed = capsys.readouterr().out
    request_seq = int(re.search(r"--request-seq (\d+)", listed).group(1))

    cli.main(["approve", str(journal_path), "--request-seq", str(request_seq)])
    capsys.readouterr()

    assert _run_reviewed(journal_path) == cli.EXIT_OK
    executed = capsys.readouterr()
    assert ".netrc" in executed.out
    assert "granted by event" in executed.err

    assert _run_reviewed(journal_path) == cli.EXIT_REVIEW


def test_a_grant_can_be_made_directly_by_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"

    code = cli.main(["approve", str(journal_path), "--command", "echo .netrc", "--note", "manual"])
    assert code == cli.EXIT_OK
    assert "fingerprint:" in capsys.readouterr().out

    assert _run_reviewed(journal_path) == cli.EXIT_OK


def test_a_grant_can_expire_before_it_is_used(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"

    cli.main(["approve", str(journal_path), "--command", "echo .netrc", "--expires-in", "0"])
    capsys.readouterr()

    assert _run_reviewed(journal_path) == cli.EXIT_REVIEW


def test_a_refusal_is_recorded_but_does_not_block(tmp_path: Path) -> None:
    journal_path = tmp_path / "session.jsonl"

    cli.main(["approve", str(journal_path), "--command", "echo .netrc", "--refuse"])
    decisions = [
        event.payload
        for event in Journal(journal_path).read()
        if event.type is EventType.APPROVAL_DECIDED
    ]
    assert decisions[0]["granted"] is False

    # A refusal is evidence, not a permanent ban: the action is escalated again.
    assert _run_reviewed(journal_path) == cli.EXIT_REVIEW


def test_approving_an_unknown_request_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    _run_reviewed(journal_path)

    code = cli.main(["approve", str(journal_path), "--request-seq", "999"])

    assert code == cli.EXIT_ERROR
    assert "no approval request recorded as #999" in capsys.readouterr().err


# ----------------------------------------------------------- guarded writes
def _write_args(journal_path: Path, workspace: Path, path: str, **extra: str) -> list[str]:
    args = [
        "write",
        "--policy",
        "standard",
        "--journal",
        str(journal_path),
        "--workspace",
        str(workspace),
        path,
    ]
    for key, value in extra.items():
        args += [f"--{key.replace('_', '-')}", value]
    return args


def test_write_writes_the_file_and_frames_a_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    workspace = tmp_path / "ws"
    workspace.mkdir()

    code = cli.main(_write_args(journal_path, workspace, "notes.txt", content="hello"))

    assert code == cli.EXIT_OK
    assert (workspace / "notes.txt").read_text(encoding="utf-8") == "hello"
    assert _event_types(journal_path) == [
        "session.start",
        "action.proposed",
        "policy.decision",
        "action.result",
        "session.end",
    ]
    assert _results(journal_path)[-1]["status"] == "written"
    assert Path(Journal(journal_path).read()[0].payload["workspace"]) == workspace.resolve()

    err = capsys.readouterr().err
    assert "written" in err
    assert "sha256" in err
    assert Journal(journal_path).verify().ok


def test_write_can_read_the_content_from_a_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    source = tmp_path / "source.txt"
    source.write_text("from a file", encoding="utf-8")
    capsys.readouterr()

    code = cli.main(_write_args(journal_path, workspace, "copy.txt", **{"from_file": str(source)}))

    assert code == cli.EXIT_OK
    assert (workspace / "copy.txt").read_text(encoding="utf-8") == "from a file"


def test_write_outside_the_workspace_is_denied(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    workspace = tmp_path / "ws"
    workspace.mkdir()

    code = cli.main(_write_args(journal_path, workspace, "../escape.txt", content="nope"))

    assert code == cli.EXIT_DENY
    assert not (tmp_path / "escape.txt").exists()
    assert "outside the workspace" in capsys.readouterr().err


def test_write_to_a_reviewed_path_needs_approving_twice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    args = _write_args(journal_path, workspace, ".env", content="TOKEN=1")

    assert cli.main(args) == cli.EXIT_REVIEW
    capsys.readouterr()
    assert not (workspace / ".env").exists()

    cli.main(
        ["approve", str(journal_path), "--request-seq", str(_pending_seq(journal_path, capsys))]
    )
    capsys.readouterr()

    assert cli.main(args) == cli.EXIT_OK
    assert (workspace / ".env").read_text(encoding="utf-8") == "TOKEN=1"

    assert cli.main(args) == cli.EXIT_REVIEW


def test_delete_removes_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = tmp_path / "session.jsonl"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "junk.txt").write_text("bye", encoding="utf-8")

    code = cli.main(
        [
            "delete",
            "--policy",
            "standard",
            "--journal",
            str(journal_path),
            "--workspace",
            str(workspace),
            "junk.txt",
        ]
    )

    assert code == cli.EXIT_OK
    assert not (workspace / "junk.txt").exists()
    assert _results(journal_path)[-1]["status"] == "deleted"
    assert "deleted" in capsys.readouterr().err


def test_delete_reports_a_directory_as_out_of_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = tmp_path / "session.jsonl"
    workspace = tmp_path / "ws"
    (workspace / "build").mkdir(parents=True)

    code = cli.main(
        [
            "delete",
            "--policy",
            "standard",
            "--journal",
            str(journal_path),
            "--workspace",
            str(workspace),
            "build",
        ]
    )

    assert code == cli.EXIT_COMMAND_FAILED
    assert "out of scope" in capsys.readouterr().err
    assert (workspace / "build").is_dir()


# ----------------------------------------------------------- guarded fetching
def _fetch_args(journal_path: Path, workspace: Path, url: str, **extra: str) -> list[str]:
    args = [
        "fetch",
        "--policy",
        "standard",
        "--journal",
        str(journal_path),
        "--workspace",
        str(workspace),
        url,
    ]
    for key, value in extra.items():
        args += [f"--{key.replace('_', '-')}", value]
    return args


def test_fetch_refuses_a_file_url(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = tmp_path / "session.jsonl"

    code = cli.main(_fetch_args(journal_path, tmp_path, "file:///etc/passwd"))

    assert code == cli.EXIT_DENY
    assert "only fetches http and https" in capsys.readouterr().err
    assert "file://" in json.dumps([event.to_record() for event in Journal(journal_path).read()])


def test_fetch_prints_the_body_and_records_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], server: LocalServer
) -> None:
    journal_path = tmp_path / "session.jsonl"
    policy = tmp_path / "allow.toml"
    policy.write_text(
        f'schema = 1\nname = "allow-local"\ndefault = "deny"\n\n'
        f"[[rules]]\nid = 'net.allow'\nkind = 'network'\neffect = 'allow'\n"
        f"pattern = '^{re.escape(server.host)}$'\n",
        encoding="utf-8",
    )

    code = cli.main(
        [
            "fetch",
            "--policy",
            str(policy),
            "--journal",
            str(journal_path),
            server.url("/hello"),
        ]
    )
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert captured.out == server.body.decode()
    assert "200" in captured.err
    assert _results(journal_path)[-1]["status"] == "fetched"
    assert server.hits == ["/hello"]


def test_fetch_reports_an_error_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], server: LocalServer
) -> None:
    journal_path = tmp_path / "session.jsonl"
    policy = tmp_path / "allow.toml"
    policy.write_text(
        f'schema = 1\nname = "allow-local"\ndefault = "review"\n\n'
        f"[[rules]]\nid = 'net.allow'\nkind = 'network'\neffect = 'allow'\n"
        f"pattern = '^{re.escape(server.host)}$'\n",
        encoding="utf-8",
    )

    code = cli.main(
        ["fetch", "--policy", str(policy), "--journal", str(journal_path), server.url("/missing")]
    )
    captured = capsys.readouterr()

    assert code == cli.EXIT_COMMAND_FAILED
    assert captured.out == "nope"
    assert "404" in captured.err


# ------------------------------------------------------------------- anchors
def _noted_journal(tmp_path: Path, count: int = 2) -> Path:
    """A journal with a few notes in it, ready to anchor."""
    journal_path = tmp_path / "session.jsonl"
    for index in range(count):
        cli.main(["journal", "note", str(journal_path), f"note {index}"])
    return journal_path


def _keypair(tmp_path: Path, name: str = "signing") -> tuple[Path, Path]:
    private = tmp_path / f"{name}.key.json"
    public = tmp_path / f"{name}.pub.json"
    cli.main(["keygen", "--private", str(private), "--public", str(public)])
    return private, public


def test_keygen_writes_a_pair_and_refuses_to_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private = tmp_path / "keys" / "signing.key.json"
    public = tmp_path / "keys" / "signing.pub.json"

    code = cli.main(["keygen", "--private", str(private), "--public", str(public)])
    printed = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert private.is_file()
    assert public.is_file()
    assert "fingerprint:" in printed.out

    assert (
        cli.main(["keygen", "--private", str(private), "--public", str(public)]) == cli.EXIT_ERROR
    )
    assert "refusing to overwrite" in capsys.readouterr().err


def test_journal_anchor_prints_a_summary_and_writes_the_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    anchors = tmp_path / "anchors.jsonl"
    capsys.readouterr()

    code = cli.main(
        ["journal", "anchor", str(journal_path), "--file", str(anchors), "--note", "end of the run"]
    )
    printed = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert printed.out.startswith("anchor  seq 2")
    assert "appended to" in printed.err
    record = json.loads(anchors.read_text(encoding="utf-8").strip())
    assert record["schema"] == "1.0"
    assert record["seq"] == 2
    assert record["note"] == "end of the run"
    assert record["journal"] == "session.jsonl"
    assert record["signature"] is None


def test_journal_verify_against_anchors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal_path = _noted_journal(tmp_path, count=3)
    anchors = tmp_path / "anchors.jsonl"
    cli.main(["journal", "anchor", str(journal_path), "--file", str(anchors)])
    capsys.readouterr()

    assert (
        cli.main(["journal", "verify", str(journal_path), "--anchors", str(anchors)]) == cli.EXIT_OK
    )
    assert "anchors: 1 checked, latest at seq 3" in capsys.readouterr().out

    lines = journal_path.read_text(encoding="utf-8").splitlines()
    journal_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    code = cli.main(["journal", "verify", str(journal_path), "--anchors", str(anchors)])
    printed = capsys.readouterr()

    assert code == cli.EXIT_ERROR
    assert "truncated" in printed.out
    assert "anchor (seq 3)" in printed.out


def test_a_signed_anchor_can_be_verified_and_pinned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    anchors = tmp_path / "signed.jsonl"
    private, public = _keypair(tmp_path)
    _, other_public = _keypair(tmp_path, name="other")
    capsys.readouterr()

    code = cli.main(
        [
            "journal",
            "anchor",
            str(journal_path),
            "--file",
            str(anchors),
            "--sign-with",
            str(private),
        ]
    )
    assert code == cli.EXIT_OK
    assert "signed by" in capsys.readouterr().out

    code = cli.main(
        ["journal", "verify", str(journal_path), "--anchors", str(anchors), "--key", str(public)]
    )
    assert code == cli.EXIT_OK
    assert "signed by" in capsys.readouterr().out

    code = cli.main(
        [
            "journal",
            "verify",
            str(journal_path),
            "--anchors",
            str(anchors),
            "--key",
            str(other_public),
        ]
    )
    printed = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "key-mismatch" in printed.out


def test_a_tampered_anchor_fails_its_signature(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    anchors = tmp_path / "signed.jsonl"
    private, public = _keypair(tmp_path)
    capsys.readouterr()
    cli.main(
        [
            "journal",
            "anchor",
            str(journal_path),
            "--file",
            str(anchors),
            "--sign-with",
            str(private),
        ]
    )
    anchors.write_text(
        anchors.read_text(encoding="utf-8").replace('"note":""', '"note":"tampered"'),
        encoding="utf-8",
    )
    capsys.readouterr()

    code = cli.main(
        ["journal", "verify", str(journal_path), "--anchors", str(anchors), "--key", str(public)]
    )

    assert code == cli.EXIT_ERROR
    assert "bad-signature" in capsys.readouterr().out


def test_anchoring_an_empty_journal_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(["journal", "anchor", str(tmp_path / "empty.jsonl")])

    assert code == cli.EXIT_ERROR
    assert "nothing to anchor" in capsys.readouterr().err


def test_anchor_hands_the_json_to_an_external_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    captured = tmp_path / "captured.json"
    script = tmp_path / "capture.py"
    script.write_text(
        "import pathlib, sys\npathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    capsys.readouterr()

    code = cli.main(
        [
            "journal",
            "anchor",
            str(journal_path),
            "--command",
            f'"{sys.executable}" "{script}" "{captured}"',
        ]
    )

    assert code == cli.EXIT_OK
    payload = json.loads(captured.read_text(encoding="utf-8"))
    assert payload["seq"] == 2
    assert payload["hash"] == Journal(journal_path).head().hash


def test_a_failing_anchor_command_still_leaves_the_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    anchors = tmp_path / "anchors.jsonl"
    capsys.readouterr()

    code = cli.main(
        [
            "journal",
            "anchor",
            str(journal_path),
            "--file",
            str(anchors),
            "--command",
            f'"{sys.executable}" -c "raise SystemExit(3)"',
        ]
    )
    printed = capsys.readouterr()

    assert code == cli.EXIT_COMMAND_FAILED
    assert anchors.is_file()
    assert "was still written" in printed.err
    assert printed.out.startswith("anchor  seq 2")


def test_pinning_a_key_without_anchors_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    _, public = _keypair(tmp_path)
    capsys.readouterr()

    code = cli.main(["journal", "verify", str(journal_path), "--key", str(public)])

    assert code == cli.EXIT_ERROR
    assert "--anchors" in capsys.readouterr().err


def test_a_missing_anchor_file_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_path = _noted_journal(tmp_path)
    capsys.readouterr()

    code = cli.main(
        [
            "journal",
            "verify",
            str(journal_path),
            "--anchors",
            str(tmp_path / "absent.jsonl"),
        ]
    )

    assert code == cli.EXIT_ERROR
    assert "cannot read anchor file" in capsys.readouterr().err
