"""The ``sentinel`` command line interface.

The CLI is a thin shell over the library: it reads a policy, evaluates or runs
something, and shows what the flight recorder holds. Exit codes are stable so
the tool can be used from scripts:

===== ==========================================
Code  Meaning
===== ==========================================
0     allowed, or the command succeeded
1     sentinel itself failed (bad policy, bad journal)
2     the action needs review and was not run
3     the action was denied by policy
4     a guarded command ran and returned non-zero
===== ==========================================
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .anchors import Anchor, anchor_journal, append_anchor, verify_with_anchors
from .approvals import (
    SOURCE_OPERATOR,
    approval_requests,
    pending_requests,
    record_decision,
)
from .errors import SentinelError
from .events import canonical_dumps
from .guards import (
    DEFAULT_MAX_BYTES,
    GuardedFileSystem,
    GuardedNetwork,
    GuardedShell,
    GuardResult,
)
from .journal import Journal
from .policy.engine import PolicyEngine
from .policy.loader import load_policy
from .policy.models import Action, ActionKind, Effect
from .policy.presets import available_presets, load_preset
from .session import Session
from .signing import (
    DEFAULT_KEY_DIR,
    DEFAULT_PRIVATE_KEY,
    DEFAULT_PUBLIC_KEY,
    private_key_from_file,
    public_key_from_file,
    write_keypair,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REVIEW = 2
EXIT_DENY = 3
EXIT_COMMAND_FAILED = 4

_EFFECT_EXIT = {
    Effect.ALLOW: EXIT_OK,
    Effect.REVIEW: EXIT_REVIEW,
    Effect.DENY: EXIT_DENY,
}


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Guardrails and flight recorder for coding agents.",
    )
    parser.add_argument("--version", action="version", version=f"agent-sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="group", required=True)

    # ------------------------------------------------------------------ policy
    policy = subparsers.add_parser("policy", help="inspect and evaluate policies")
    policy_sub = policy.add_subparsers(dest="action", required=True)

    presets = policy_sub.add_parser("presets", help="list the built-in policies")
    presets.set_defaults(handler=_handle_policy_presets)

    check = policy_sub.add_parser("check", help="evaluate one action against a policy")
    check.add_argument(
        "--policy",
        required=True,
        help="a preset name (permissive, standard, strict) or a path to a .toml file",
    )
    check.add_argument(
        "--kind", default=ActionKind.SHELL.value, choices=[k.value for k in ActionKind]
    )
    check.add_argument("--target", required=True, help="the command line, path or host to evaluate")
    check.add_argument("--cwd", default=None, help="working directory to record with the action")
    check.add_argument("--json", action="store_true", help="print the decision as JSON")
    check.set_defaults(handler=_handle_policy_check)

    # --------------------------------------------------------------------- run
    run = subparsers.add_parser(
        "run",
        help="run a command through the guardrail, recording everything",
        epilog="example: sentinel run --policy standard --journal .sentinel/session.jsonl -- pytest -q",
    )
    run.add_argument("--policy", required=True, help="preset name or path to a .toml file")
    run.add_argument("--journal", required=True, help="journal file to append to")
    run.add_argument("--cwd", default=None, help="working directory for the command")
    run.add_argument(
        "--workspace",
        default=None,
        help="workspace root to record in the session (default: current directory)",
    )
    run.add_argument(
        "--timeout", type=float, default=None, help="seconds before the command is killed"
    )
    run.add_argument(
        "--allow-review",
        action="store_true",
        help="treat 'review' as 'allow' (records the decision either way)",
    )
    run.add_argument("command", nargs=argparse.REMAINDER, help="the command, after '--'")
    run.set_defaults(handler=_handle_run)

    # ---------------------------------------------------------------- filesystem
    write = subparsers.add_parser(
        "write",
        help="write a file through the guardrail, inside the workspace",
        epilog=(
            "example: sentinel write --policy standard --journal .sentinel/session.jsonl "
            "--workspace . notes/todo.md --content 'hello'"
        ),
    )
    _add_guard_arguments(write)
    write.add_argument("--create-parents", action="store_true", help="create missing directories")
    content = write.add_mutually_exclusive_group()
    content.add_argument("--content", default=None, help="text to write")
    content.add_argument("--from-file", default=None, help="read the content from this file")
    write.add_argument("path", help="destination path, relative to the workspace")
    write.set_defaults(handler=_handle_write)

    delete = subparsers.add_parser(
        "delete",
        help="delete a single file through the guardrail",
        epilog=(
            "example: sentinel delete --policy standard --journal .sentinel/session.jsonl "
            "notes/todo.md"
        ),
    )
    _add_guard_arguments(delete)
    delete.add_argument("path", help="path to remove, relative to the workspace")
    delete.set_defaults(handler=_handle_delete)

    fetch = subparsers.add_parser(
        "fetch",
        help="fetch a URL through the guardrail; the guard makes the request",
        epilog=(
            "example: sentinel fetch --policy standard --journal .sentinel/session.jsonl "
            "https://example.com/"
        ),
    )
    _add_guard_arguments(fetch)
    fetch.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    fetch.add_argument("--timeout", type=float, default=None, help="seconds before giving up")
    fetch.add_argument(
        "--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="how much of the body to read"
    )
    fetch.add_argument("url", help="the URL to fetch")
    fetch.set_defaults(handler=_handle_fetch)

    # ----------------------------------------------------------------- approve
    approve = subparsers.add_parser(
        "approve",
        help="record an approval, or a refusal, for an action that was reviewed",
        epilog=(
            "example: sentinel approve .sentinel/session.jsonl --request-seq 12\n"
            "         sentinel approve .sentinel/session.jsonl --command 'git push --force' "
            "--expires-in 30"
        ),
    )
    approve.add_argument("journal", help="journal file to append to")
    approve_source = approve.add_mutually_exclusive_group(required=True)
    approve_source.add_argument(
        "--request-seq", type=int, help="approve the escalation with this seq number"
    )
    approve_source.add_argument("--command", help="approve this command line directly")
    approve.add_argument(
        "--kind", default=ActionKind.SHELL.value, choices=[kind.value for kind in ActionKind]
    )
    approve.add_argument(
        "--refuse", action="store_true", help="record a refusal instead of a grant"
    )
    approve.add_argument(
        "--expires-in", type=float, default=None, metavar="MINUTES", help="how long the grant lasts"
    )
    approve.add_argument("--note", default="", help="why, in your own words")
    approve.set_defaults(handler=_handle_approve)

    # ----------------------------------------------------------------- journal
    journal = subparsers.add_parser("journal", help="read and verify flight recorder files")
    journal_sub = journal.add_subparsers(dest="action", required=True)

    pending = journal_sub.add_parser("pending", help="list escalations that still need a human")
    pending.add_argument("path")
    pending.set_defaults(handler=_handle_journal_pending)

    show = journal_sub.add_parser("show", help="print recorded events")
    show.add_argument("path")
    show.add_argument("--limit", type=int, default=20, help="how many trailing events (0 for all)")
    show.add_argument("--json", action="store_true", help="print raw records as JSON lines")
    show.set_defaults(handler=_handle_journal_show)

    verify = journal_sub.add_parser("verify", help="check the hash chain")
    verify.add_argument("path")
    verify.add_argument(
        "--anchors",
        default=None,
        metavar="PATH",
        help="also check against an anchor file; a missing or empty file is an error",
    )
    verify.add_argument(
        "--key",
        default=None,
        metavar="PATH",
        help="the public key file every anchor must be signed by",
    )
    verify.set_defaults(handler=_handle_journal_verify)

    anchor = journal_sub.add_parser(
        "anchor",
        help="write the journal's current head somewhere the journal cannot reach",
        epilog=(
            "example: sentinel journal anchor .sentinel/session.jsonl "
            "--file .sentinel/anchors.jsonl --note 'end of CI job'"
        ),
    )
    anchor.add_argument("path")
    anchor.add_argument(
        "--file", default=None, metavar="PATH", help="append the anchor to this file"
    )
    anchor.add_argument(
        "--command",
        default=None,
        metavar="CMD",
        help="run this command with the anchor JSON on its standard input",
    )
    anchor.add_argument("--note", default="", help="why this anchor was taken")
    anchor.add_argument(
        "--sign-with",
        default=None,
        metavar="PATH",
        help="private key file to sign the anchor with",
    )
    anchor.set_defaults(handler=_handle_journal_anchor)

    note = journal_sub.add_parser("note", help="append a human annotation")
    note.add_argument("path")
    note.add_argument("message")
    note.set_defaults(handler=_handle_journal_note)

    version = subparsers.add_parser("version", help="print the version")
    version.set_defaults(handler=_handle_version)

    keygen = subparsers.add_parser(
        "keygen",
        help="generate an Ed25519 key pair for signing anchors",
        epilog="example: sentinel keygen --private .sentinel/keys/signing.key.json",
    )
    keygen.add_argument(
        "--private",
        default=None,
        metavar="PATH",
        help=f"where to write the private key (default: {DEFAULT_KEY_DIR / DEFAULT_PRIVATE_KEY})",
    )
    keygen.add_argument(
        "--public",
        default=None,
        metavar="PATH",
        help=f"where to write the public key (default: {DEFAULT_KEY_DIR / DEFAULT_PUBLIC_KEY})",
    )
    keygen.add_argument("--force", action="store_true", help="overwrite existing key files")
    keygen.set_defaults(handler=_handle_keygen)

    return parser


# ------------------------------------------------------------------ handlers
def _add_guard_arguments(parser: argparse.ArgumentParser) -> None:
    """The options that every guarded action shares."""
    parser.add_argument("--policy", required=True, help="preset name or path to a .toml file")
    parser.add_argument("--journal", required=True, help="journal file to append to")
    parser.add_argument(
        "--workspace",
        default=None,
        help="workspace root (default: current directory)",
    )
    parser.add_argument(
        "--allow-review",
        action="store_true",
        help="treat 'review' as 'allow' (records the decision either way)",
    )


def _resolve_engine(engine_source: str) -> PolicyEngine:
    if engine_source in available_presets():
        return PolicyEngine(load_preset(engine_source))
    return PolicyEngine(load_policy(engine_source))


def _workspace_of(args: argparse.Namespace) -> Path:
    """The workspace root for this run: what was asked for, or the current directory."""
    raw = getattr(args, "workspace", None)
    return Path(raw).expanduser().resolve() if raw else Path.cwd().resolve()


def _report(
    result: GuardResult,
    *,
    engine: PolicyEngine,
    journal_path: str,
    session: Session,
    detail: str = "",
) -> None:
    """Print what happened, to stderr, in the order a reader wants it."""
    print(
        f"policy:  {engine.name} (fingerprint {engine.policy.fingerprint()[:12]})",
        file=sys.stderr,
    )
    print(result.decision.render(), file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    print(f"status:  {result.status}", file=sys.stderr)
    if result.approval_seq is not None:
        print(f"approval: granted by event #{result.approval_seq}", file=sys.stderr)
    if result.approval_request is not None:
        print(
            "this is waiting for a human. to grant it:\n"
            f"  sentinel approve {journal_path} --request-seq {result.approval_request.seq}\n"
            "then run it again",
            file=sys.stderr,
        )
    if session.info is not None:
        print(f"session: {session.info.render()}", file=sys.stderr)


def _exit_for(result: GuardResult, *, failed: bool = False) -> int:
    """Map a guard result onto the documented exit codes."""
    if result.status == "denied":
        return EXIT_DENY
    if result.status in {"refused", "awaiting_approval"}:
        return EXIT_REVIEW
    if failed or result.status in {"failed", "timeout"}:
        return EXIT_COMMAND_FAILED
    return EXIT_OK


def _handle_version(args: argparse.Namespace) -> int:
    print(f"agent-sentinel {__version__}")
    return EXIT_OK


def _handle_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.private) if args.private else DEFAULT_KEY_DIR / DEFAULT_PRIVATE_KEY
    public_path = Path(args.public) if args.public else DEFAULT_KEY_DIR / DEFAULT_PUBLIC_KEY
    pair = write_keypair(private_path, public_path, force=args.force)

    print(f"private key: {pair.private_path}")
    print(f"public key:  {pair.public_path}")
    print(f"fingerprint: {pair.fingerprint}")
    if not pair.permissions_enforced:
        print(
            "note: this platform does not restrict a file to its owner with chmod; "
            "keep the private key where only you can read it, and share only the public one",
            file=sys.stderr,
        )
    return EXIT_OK


def _handle_policy_presets(args: argparse.Namespace) -> int:
    width = max(len(name) for name in available_presets())
    for name, description in available_presets().items():
        print(f"{name:<{width}}  {description}")
    return EXIT_OK


def _handle_policy_check(args: argparse.Namespace) -> int:
    engine = _resolve_engine(args.policy)
    action = Action(kind=ActionKind(args.kind), target=args.target, cwd=args.cwd)
    decision = engine.evaluate(action)
    if args.json:
        print(json.dumps(decision.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(decision.render())
    return _EFFECT_EXIT[decision.effect]


def _handle_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SentinelError("no command given; put it after '--'")

    engine = _resolve_engine(args.policy)
    journal = Journal(args.journal)
    workspace = _workspace_of(args)
    with Session(engine, journal, cwd=args.cwd, workspace=str(workspace)) as session:
        runner = GuardedShell(
            engine,
            journal,
            cwd=args.cwd,
            allow_review=args.allow_review,
            timeout=args.timeout,
        )
        result = runner.run(" ".join(command))

    _report(result, engine=engine, journal_path=args.journal, session=session)
    if result.stdout_preview:
        sys.stdout.write(result.stdout_preview)
    if result.stderr_preview:
        sys.stderr.write(result.stderr_preview)
    return _exit_for(result, failed=bool(result.returncode))


def _handle_write(args: argparse.Namespace) -> int:
    engine = _resolve_engine(args.policy)
    journal = Journal(args.journal)
    payload = _write_payload(args)
    workspace = _workspace_of(args)

    with Session(engine, journal, cwd=str(Path.cwd()), workspace=str(workspace)) as session:
        guard = GuardedFileSystem(
            engine, journal, workspace=workspace, allow_review=args.allow_review
        )
        result = guard.write(args.path, payload, create_parents=args.create_parents)

    detail = f"target:  {result.path} -> {result.resolved}"
    if result.status == "written":
        detail += f" ({result.bytes_written} bytes, sha256 {(result.sha256 or '')[:12]})"
    _report(result, engine=engine, journal_path=args.journal, session=session, detail=detail)
    if result.error:
        print(f"error:   {result.error}", file=sys.stderr)
    return _exit_for(result)


def _handle_delete(args: argparse.Namespace) -> int:
    engine = _resolve_engine(args.policy)
    journal = Journal(args.journal)
    workspace = _workspace_of(args)

    with Session(engine, journal, cwd=str(Path.cwd()), workspace=str(workspace)) as session:
        guard = GuardedFileSystem(
            engine, journal, workspace=workspace, allow_review=args.allow_review
        )
        result = guard.delete(args.path)

    _report(
        result,
        engine=engine,
        journal_path=args.journal,
        session=session,
        detail=f"target:  {result.path} -> {result.resolved}",
    )
    if result.error:
        print(f"error:   {result.error}", file=sys.stderr)
    return _exit_for(result)


def _handle_fetch(args: argparse.Namespace) -> int:
    engine = _resolve_engine(args.policy)
    journal = Journal(args.journal)
    workspace = _workspace_of(args)

    with Session(engine, journal, cwd=str(Path.cwd()), workspace=str(workspace)) as session:
        guard = GuardedNetwork(
            engine,
            journal,
            allow_review=args.allow_review,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
        )
        result = guard.fetch(args.url, method=args.method)

    detail = f"url:     {result.url}"
    if result.status == "fetched":
        detail += (
            f"\nhttp:    {result.status_code} {result.content_type or ''}"
            f" ({result.bytes_received} bytes{', truncated' if result.truncated else ''})"
        )
        if result.location:
            detail += f"\nlocation: {result.location} (not followed; fetch it explicitly)"
    _report(result, engine=engine, journal_path=args.journal, session=session, detail=detail)
    if result.error:
        print(f"error:   {result.error}", file=sys.stderr)
    if result.body:
        sys.stdout.flush()
        sys.stdout.buffer.write(result.body)
        sys.stdout.buffer.flush()
    return _exit_for(result, failed=(result.status_code or 0) >= 400)


def _write_payload(args: argparse.Namespace) -> bytes:
    """The bytes to write: from ``--content``, from a file, or from stdin."""
    if args.content is not None:
        return str(args.content).encode("utf-8")
    if args.from_file is not None:
        try:
            return Path(args.from_file).read_bytes()
        except OSError as exc:
            raise SentinelError(f"cannot read --from-file {args.from_file}: {exc}") from exc
    return bytes(sys.stdin.buffer.read())


def _handle_approve(args: argparse.Namespace) -> int:
    journal = Journal(args.journal)
    action = _resolve_approved_action(journal, args)
    event = record_decision(
        journal,
        action=action,
        granted=not args.refuse,
        source=SOURCE_OPERATOR,
        note=args.note,
        request_seq=args.request_seq,
        expires_in_seconds=None if args.expires_in is None else args.expires_in * 60,
    )
    verdict = "refused" if args.refuse else "granted"
    print(
        f"recorded approval #{event.seq} ({verdict}) for "
        f"{action.kind.value} {action.subject}\n"
        f"fingerprint: {action.fingerprint()[:16]}"
    )
    return EXIT_OK


def _resolve_approved_action(journal: Journal, args: argparse.Namespace) -> Action:
    """Turn ``--request-seq`` or ``--command`` into the action being approved."""
    if args.request_seq is None:
        return Action(kind=ActionKind(args.kind), target=args.command)
    for request in approval_requests(journal):
        if request.seq == args.request_seq:
            return Action(kind=ActionKind(request.kind), target=request.command)
    raise SentinelError(f"{args.journal}: no approval request recorded as #{args.request_seq}")


def _handle_journal_pending(args: argparse.Namespace) -> int:
    pending = pending_requests(Journal(args.path))
    if not pending:
        print("no approvals pending")
        return EXIT_OK
    for request in pending:
        print(request.render())
        print(f"        to approve: sentinel approve {args.path} --request-seq {request.seq}")
    return EXIT_OK


def _handle_journal_show(args: argparse.Namespace) -> int:
    journal = Journal(args.path)
    events = journal.read() if args.limit <= 0 else journal.tail(args.limit)
    for event in events:
        if args.json:
            print(json.dumps(event.to_record(), ensure_ascii=False))
        else:
            print(event.render())
            message = event.payload.get("message")
            if message:
                print(f"      {message}")
    if not events:
        print(f"{args.path}: no events recorded")
    return EXIT_OK


def _handle_journal_verify(args: argparse.Namespace) -> int:
    journal = Journal(args.path)
    expected_key = public_key_from_file(args.key) if args.key else None
    if args.anchors:
        report = verify_with_anchors(journal, anchor_path=args.anchors, expected_key=expected_key)
    elif expected_key is not None:
        raise SentinelError(
            "--key pins the signer of an anchor file, so it needs --anchors to check against"
        )
    else:
        report = journal.verify()
    print(report.render())
    return EXIT_OK if report.ok else EXIT_ERROR


def _handle_journal_anchor(args: argparse.Namespace) -> int:
    journal = Journal(args.path)
    private_key = private_key_from_file(args.sign_with) if args.sign_with else None
    anchor = anchor_journal(journal, note=args.note, private_key=private_key)

    # The summary goes out first: a CI log that captured it still has the
    # evidence even if the command below fails.
    print(anchor.render())
    if args.file:
        append_anchor(args.file, anchor)
        print(f"appended to {args.file}", file=sys.stderr)

    if args.command:
        code = _run_anchor_command(args.command, anchor)
        if code:
            destination = args.file or "the printed line above"
            print(
                f"sentinel: the anchor command exited {code}; {destination} was still written",
                file=sys.stderr,
            )
            return EXIT_COMMAND_FAILED
    return EXIT_OK


def _run_anchor_command(command: str, anchor: Anchor) -> int:
    """Hand the anchor to a program on stdin, the way a CI log would receive it."""
    payload = canonical_dumps(anchor.as_dict()).encode("utf-8")
    try:
        completed = subprocess.run(  # noqa: S602 - the operator supplies the command
            command, shell=True, input=payload, check=False
        )
    except OSError as exc:
        raise SentinelError(f"cannot run the anchor command {command!r}: {exc}") from exc
    return completed.returncode


def _handle_journal_note(args: argparse.Namespace) -> int:
    event = Journal(args.path).note(args.message)
    print(f"recorded note as event #{event.seq} ({event.hash[:12]})")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        handler = args.handler
        return int(handler(args))
    except SentinelError as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("sentinel: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
