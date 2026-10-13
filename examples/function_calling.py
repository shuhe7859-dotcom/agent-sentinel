"""Handing the guarded tools to a function-calling agent.

Two halves, both offline:

1. the schemas you would give a model, in the shape OpenAI function calling
   takes -- the same shape several other frameworks accept;
2. dispatching the tool call the model hands back.

Nothing here talks to a model, because the interesting part is not the model:
it is that a model given these four tools has no other way to act. There is no
shell to fall back on, and every call lands in the journal.

Run it from a checkout::

    python examples/function_calling.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_sentinel import (
    Journal,
    PolicyEngine,
    SentinelTools,
    load_preset,
    openai_tools,
)

TOOL_CALLS = [
    # What a model would send back, one call at a time.
    {"name": "run_shell", "arguments": {"command": "echo hello from a tool call"}},
    {
        "name": "write_file",
        "arguments": {"path": "notes.md", "content": "written through the guardrail"},
    },
    {"name": "run_shell", "arguments": {"command": "rm -rf /"}},
    {"name": "delete_file", "arguments": {"path": "notes.md"}},
]


def main() -> None:
    print("== the tools you would give the model ==")
    for tool in openai_tools():
        function = tool["function"]
        required = function["parameters"].get("required", [])
        print(f"  {function['name']}({', '.join(required)})")

    with tempfile.TemporaryDirectory() as work:
        workspace = Path(work)
        journal = Journal(workspace / "session.jsonl")
        tools = SentinelTools(PolicyEngine(load_preset("standard")), journal, workspace=workspace)

        print("\n== dispatching what the model asked for ==")
        for call in TOOL_CALLS:
            result = tools.call(call["name"], call["arguments"])
            print(f"\n  {call['name']}({json.dumps(call['arguments'])})")
            print(f"  is_error: {result.is_error}")
            for line in result.text.splitlines():
                print(f"    {line}")

        print("\n== what the workspace looks like now ==")
        for path in sorted(workspace.rglob("*")):
            if path.is_file() and path.name != "session.jsonl":
                print(f"  {path.relative_to(workspace)}")

        print("\n== the journal, which is the same one the CLI writes ==")
        for event in journal.read():
            print(f"  {event.render()}")
        print()
        print(journal.verify().render())


if __name__ == "__main__":
    main()
