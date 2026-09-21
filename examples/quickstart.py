"""A five-minute tour of agent-sentinel.

Run it from a checkout::

    python examples/quickstart.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_sentinel import (
    Action,
    ActionKind,
    GuardedRunner,
    Journal,
    PolicyEngine,
    load_preset,
)


def main() -> None:
    engine = PolicyEngine(load_preset("standard"))
    journal = Journal(Path(".sentinel") / "quickstart.jsonl")
    runner = GuardedRunner(engine, journal)

    print("== what the policy says ==")
    for kind, target in [
        (ActionKind.SHELL, "pytest -q"),
        (ActionKind.SHELL, "git push --force origin main"),
        (ActionKind.SHELL, "rm -rf /"),
        (ActionKind.FILE_WRITE, "../outside.py"),
        (ActionKind.NETWORK, "pypi.org"),
    ]:
        decision = engine.evaluate(Action(kind=kind, target=target))
        print(f"  {decision.effect.value:<6} {kind.value:<11} {target}")

    print("\n== running one allowed command ==")
    result = runner.run(f'"{sys.executable}" -c "print(\'hello from a guarded shell\')"')
    print(f"  status: {result.status}, exit code: {result.returncode}")
    print(f"  stdout preview: {result.stdout_preview.strip()}")

    print("\n== one denied command ==")
    denied = runner.run("rm -rf /")
    print(f"  status: {denied.status}, rule: {denied.decision.rule_id}")

    print("\n== the flight recorder ==")
    for event in journal.read():
        print(f"  {event.render()}")

    report = journal.verify()
    print(f"\n{report.render()}")


if __name__ == "__main__":
    main()
