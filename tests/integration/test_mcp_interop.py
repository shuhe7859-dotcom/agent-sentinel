"""Interoperability with the official MCP client.

The unit tests prove the server emits the JSON-RPC we meant it to. This one
proves a real client agrees, which is a different claim: a hand-written
transport is only worth having if somebody else's implementation can drive it.

The SDK is a development dependency, not a runtime one, so this skips where it
is not installed. Run ``pip install -e ".[dev]"`` to include it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("anyio", reason="the MCP SDK is not installed")
pytest.importorskip("mcp", reason="the MCP SDK is not installed")

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from agent_sentinel.journal import Journal
from agent_sentinel.mcp_server import PROTOCOL_VERSIONS

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _parameters(journal: Path, workspace: Path) -> StdioServerParameters:
    """How a client would be told to start us."""
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agent_sentinel",
            "mcp",
            "--policy",
            "standard",
            "--journal",
            str(journal),
            "--workspace",
            str(workspace),
        ],
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
    )


async def _interrogate(journal: Path, workspace: Path) -> dict[str, Any]:
    with anyio.fail_after(20):
        async with (
            stdio_client(_parameters(journal, workspace)) as (read, write),
            ClientSession(read, write) as session,
        ):
            info = await session.initialize()
            tools = await session.list_tools()
            ran = await session.call_tool("run_shell", {"command": "echo interop"})
            refused = await session.call_tool("run_shell", {"command": "rm -rf /"})
            wrote = await session.call_tool(
                "write_file", {"path": "from-the-client.md", "content": "hello"}
            )
            return {
                "protocol": info.protocol_version,
                "server": info.server_info.name,
                "tools": sorted(tool.name for tool in tools.tools),
                "ran_error": ran.is_error,
                "ran_text": ran.content[0].text,
                "refused_error": refused.is_error,
                "refused_text": refused.content[0].text,
                "wrote_error": wrote.is_error,
            }


def test_a_real_client_can_drive_the_server(tmp_path: Path) -> None:
    summary = anyio.run(_interrogate, tmp_path / "session.jsonl", tmp_path)

    assert summary["protocol"] in PROTOCOL_VERSIONS
    assert summary["server"] == "agent-sentinel"
    assert summary["tools"] == ["delete_file", "fetch_url", "run_shell", "write_file"]

    assert summary["ran_error"] is False
    assert "interop" in summary["ran_text"]
    assert summary["refused_error"] is True
    assert "shell.rm-root" in summary["refused_text"]
    assert summary["wrote_error"] is False
    assert (tmp_path / "from-the-client.md").read_text(encoding="utf-8") == "hello"


def test_a_client_session_leaves_a_journal_this_project_can_read(tmp_path: Path) -> None:
    """The MCP session writes the same records the CLI does, framing included."""
    journal_path = tmp_path / "session.jsonl"

    anyio.run(_interrogate, journal_path, tmp_path)

    journal = Journal(journal_path)
    assert journal.verify().ok
    assert journal.read()[0].type.value == "session.start"
    assert journal.read()[-1].type.value == "session.end"
    assert journal.read()[0].payload["policy"] == "standard"
