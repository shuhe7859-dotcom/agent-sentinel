"""The MCP transport: JSON-RPC over lines, and the two rules that matter."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from agent_sentinel.journal import Journal
from agent_sentinel.mcp_server import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    LATEST_PROTOCOL_VERSION,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROTOCOL_VERSIONS,
    McpServer,
)
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.presets import load_preset
from agent_sentinel.tools import SentinelTools


def _server(tmp_path: Path, **kwargs: Any) -> McpServer:
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(load_preset("standard"))
    tools = SentinelTools(engine, journal, workspace=tmp_path, **kwargs)
    return McpServer(tools)


def _request(server: McpServer, method: str, params: Any = None, id: Any = 1) -> Any:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        message["params"] = params
    return server.handle(message)


# ----------------------------------------------------------------- handshake
def test_initialize_negotiates_the_version(tmp_path: Path) -> None:
    server = _server(tmp_path)

    result = _request(server, "initialize", {"protocolVersion": "2025-03-26"})["result"]

    assert result["protocolVersion"] == "2025-03-26"
    assert result["serverInfo"]["name"] == "agent-sentinel"
    assert result["serverInfo"]["version"]
    assert "tools" in result["capabilities"]
    assert result["instructions"]


def test_an_unknown_protocol_version_falls_back_to_the_newest(tmp_path: Path) -> None:
    server = _server(tmp_path)

    result = _request(server, "initialize", {"protocolVersion": "1999-01-01"})["result"]
    absent = _request(server, "initialize", {})["result"]

    assert result["protocolVersion"] == LATEST_PROTOCOL_VERSION
    assert absent["protocolVersion"] == LATEST_PROTOCOL_VERSION
    assert LATEST_PROTOCOL_VERSION in PROTOCOL_VERSIONS


@pytest.mark.parametrize("version", PROTOCOL_VERSIONS)
def test_every_version_we_name_is_one_a_client_may_ask_for(tmp_path: Path, version: str) -> None:
    server = _server(tmp_path)

    assert (
        _request(server, "initialize", {"protocolVersion": version})["result"]["protocolVersion"]
        == version
    )


def test_ping_is_answered(tmp_path: Path) -> None:
    assert _request(_server(tmp_path), "ping")["result"] == {}


# -------------------------------------------------------------- notifications
@pytest.mark.parametrize(
    "method", ["notifications/initialized", "notifications/cancelled", "notifications/whatever"]
)
def test_a_notification_is_never_answered(tmp_path: Path, method: str) -> None:
    """Replying to a notification is a protocol violation clients are strict about."""
    server = _server(tmp_path)

    assert server.handle({"jsonrpc": "2.0", "method": method}) is None
    assert server.handle({"jsonrpc": "2.0", "method": method, "params": {}}) is None


# --------------------------------------------------------------------- tools
def test_tools_list_describes_every_tool(tmp_path: Path) -> None:
    result = _request(_server(tmp_path), "tools/list")["result"]

    names = [tool["name"] for tool in result["tools"]]
    assert sorted(names) == ["delete_file", "fetch_url", "run_shell", "write_file"]
    assert all(tool["inputSchema"]["type"] == "object" for tool in result["tools"])


def test_tools_call_runs_a_tool(tmp_path: Path) -> None:
    result = _request(
        _server(tmp_path), "tools/call", {"name": "run_shell", "arguments": {"command": "echo hi"}}
    )["result"]

    assert result["isError"] is False
    assert result["content"][0]["type"] == "text"
    assert "executed" in result["content"][0]["text"]


def test_tools_call_reports_a_refusal_as_an_error_result(tmp_path: Path) -> None:
    result = _request(
        _server(tmp_path),
        "tools/call",
        {"name": "run_shell", "arguments": {"command": "rm -rf /"}},
    )["result"]

    assert result["isError"] is True
    assert "shell.rm-root" in result["content"][0]["text"]


def test_tools_call_with_an_unknown_tool_is_invalid_params(tmp_path: Path) -> None:
    response = _request(_server(tmp_path), "tools/call", {"name": "nope", "arguments": {}})

    assert response["error"]["code"] == INVALID_PARAMS
    assert "unknown tool" in response["error"]["message"]


def test_tools_call_with_bad_arguments_says_which_one(tmp_path: Path) -> None:
    response = _request(_server(tmp_path), "tools/call", {"name": "run_shell", "arguments": {}})

    assert response["error"]["code"] == INVALID_PARAMS
    assert "missing required argument" in response["error"]["message"]


def test_tools_call_needs_a_tool_name(tmp_path: Path) -> None:
    response = _request(_server(tmp_path), "tools/call", {"arguments": {}})

    assert response["error"]["code"] == INVALID_PARAMS


def test_tools_call_needs_an_arguments_object(tmp_path: Path) -> None:
    response = _request(_server(tmp_path), "tools/call", {"name": "run_shell", "arguments": 7})

    assert response["error"]["code"] == INVALID_PARAMS


def test_tools_call_without_arguments_is_read_as_empty(tmp_path: Path) -> None:
    response = _request(_server(tmp_path), "tools/call", {"name": "run_shell"})

    assert response["error"]["code"] == INVALID_PARAMS
    assert "missing required argument" in response["error"]["message"]


# -------------------------------------------------------------------- errors
def test_an_unknown_method_is_reported(tmp_path: Path) -> None:
    response = _request(_server(tmp_path), "resources/list")

    assert response["error"]["code"] == METHOD_NOT_FOUND
    assert "not implemented" in response["error"]["message"]


@pytest.mark.parametrize("message", ["a string", 7, None, []])
def test_a_message_that_is_not_an_object_is_invalid(tmp_path: Path, message: Any) -> None:
    assert _server(tmp_path).handle(message)["error"]["code"] == INVALID_REQUEST


def test_a_message_that_is_not_jsonrpc_is_invalid(tmp_path: Path) -> None:
    response = _server(tmp_path).handle({"id": 1, "method": "ping"})

    assert response["error"]["code"] == INVALID_REQUEST


def test_params_must_be_an_object(tmp_path: Path) -> None:
    response = _server(tmp_path).handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": []}
    )

    assert response["error"]["code"] == INVALID_PARAMS


def test_an_unexpected_failure_becomes_an_internal_error(tmp_path: Path, monkeypatch) -> None:
    server = _server(tmp_path)

    def explode(name: str, arguments: Any = None) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(server.tools, "call", explode)
    response = _request(server, "tools/call", {"name": "run_shell", "arguments": {"command": "x"}})

    assert response["error"]["code"] == -32603
    assert "RuntimeError" in response["error"]["message"]


# ------------------------------------------------------------------- serving
def _serve(tmp_path: Path, lines: list[str]) -> tuple[int, list[dict[str, Any]]]:
    server = _server(tmp_path)
    stdin = io.StringIO("\n".join(lines) + "\n")
    stdout = io.StringIO()
    code = server.serve(stdin, stdout)
    written = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    return code, written


def test_serving_answers_requests_and_ignores_notifications(tmp_path: Path) -> None:
    code, written = _serve(
        tmp_path,
        [
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            '{"jsonrpc":"2.0","id":2,"method":"ping"}',
            "",
        ],
    )

    assert code == 0
    assert [entry["id"] for entry in written] == [1, 2]


def test_serving_survives_a_parse_error(tmp_path: Path) -> None:
    code, written = _serve(
        tmp_path,
        [
            "this is not json",
            '{"jsonrpc":"2.0","id":9,"method":"ping"}',
        ],
    )

    assert code == 0
    assert written[0]["error"]["code"] == PARSE_ERROR
    assert written[0]["id"] is None
    assert written[1]["id"] == 9


def test_stdout_carries_nothing_but_jsonrpc(tmp_path: Path) -> None:
    """One stray print and the client sees a parse error, so this is worth pinning."""
    server = _server(tmp_path)
    stdin = io.StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        '"params":{"name":"run_shell","arguments":{"command":"echo hi"}}}\n'
    )
    stdout = io.StringIO()

    server.serve(stdin, stdout)

    for line in stdout.getvalue().splitlines():
        if line.strip():
            assert json.loads(line)["jsonrpc"] == "2.0"
