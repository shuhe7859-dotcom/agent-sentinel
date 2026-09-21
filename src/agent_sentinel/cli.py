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
import sys
from collections.abc import Sequence

from . import __version__
from .errors import SentinelError
from .guards.shell import GuardedRunner
from .journal import Journal
from .policy.engine import PolicyEngine
from .policy.loader import load_policy
from .policy.models import Action, ActionKind, Effect
from .policy.presets import available_presets, load_preset

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
        "--timeout", type=float, default=None, help="seconds before the command is killed"
    )
    run.add_argument(
        "--allow-review",
        action="store_true",
        help="treat 'review' as 'allow' (records the decision either way)",
    )
    run.add_argument("command", nargs=argparse.REMAINDER, help="the command, after '--'")
    run.set_defaults(handler=_handle_run)

    # ----------------------------------------------------------------- journal
    journal = subparsers.add_parser("journal", help="read and verify flight recorder files")
    journal_sub = journal.add_subparsers(dest="action", required=True)

    show = journal_sub.add_parser("show", help="print recorded events")
    show.add_argument("path")
    show.add_argument("--limit", type=int, default=20, help="how many trailing events (0 for all)")
    show.add_argument("--json", action="store_true", help="print raw records as JSON lines")
    show.set_defaults(handler=_handle_journal_show)

    verify = journal_sub.add_parser("verify", help="check the hash chain")
    verify.add_argument("path")
    verify.set_defaults(handler=_handle_journal_verify)

    note = journal_sub.add_parser("note", help="append a human annotation")
    note.add_argument("path")
    note.add_argument("message")
    note.set_defaults(handler=_handle_journal_note)

    version = subparsers.add_parser("version", help="print the version")
    version.set_defaults(handler=_handle_version)

    return parser


# ------------------------------------------------------------------ handlers
def _resolve_engine(engine_source: str) -> PolicyEngine:
    if engine_source in available_presets():
        return PolicyEngine(load_preset(engine_source))
    return PolicyEngine(load_policy(engine_source))


def _handle_version(args: argparse.Namespace) -> int:
    print(f"agent-sentinel {__version__}")
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
    runner = GuardedRunner(
        engine,
        journal,
        cwd=args.cwd,
        allow_review=args.allow_review,
        timeout=args.timeout,
    )
    result = runner.run(" ".join(command))

    print(result.decision.render(), file=sys.stderr)
    print(f"status:  {result.status}", file=sys.stderr)

    if result.stdout_preview:
        sys.stdout.write(result.stdout_preview)
    if result.stderr_preview:
        sys.stderr.write(result.stderr_preview)

    if result.status == "denied":
        return EXIT_DENY
    if result.status == "awaiting_approval":
        return EXIT_REVIEW
    if result.returncode:
        return EXIT_COMMAND_FAILED
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
    report = Journal(args.path).verify()
    print(report.render())
    return EXIT_OK if report.ok else EXIT_ERROR


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
