"""The guarded tools: what a model is allowed to reach, and what it gets back."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_sentinel.approvals import SOURCE_OPERATOR, record_decision
from agent_sentinel.errors import ToolError
from agent_sentinel.journal import Journal
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import parse_policy
from agent_sentinel.policy.models import Action, ActionKind
from agent_sentinel.policy.presets import load_preset
from agent_sentinel.tools import (
    SentinelTools,
    openai_tools,
    tool_specs,
    validate_arguments,
)

_EXAMPLES: dict[str, Any] = {"string": "value", "integer": 2, "boolean": True}


def _tools(
    tmp_path: Path, *, preset: str = "standard", workspace: Path | None = None
) -> tuple[SentinelTools, Journal]:
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(load_preset(preset))
    return SentinelTools(engine, journal, workspace=workspace or tmp_path), journal


# ------------------------------------------------------------------- schemas
def test_every_tool_is_described() -> None:
    for spec in tool_specs():
        assert spec.name
        assert spec.description
        assert spec.parameters["type"] == "object"
        assert spec.parameters["additionalProperties"] is False
        assert set(spec.parameters["required"]) <= set(spec.parameters["properties"])


def test_the_openai_shape_is_what_frameworks_expect() -> None:
    tools = openai_tools()

    assert {tool["type"] for tool in tools} == {"function"}
    assert {tool["function"]["name"] for tool in tools} == {
        "run_shell",
        "write_file",
        "delete_file",
        "fetch_url",
    }
    assert all(tool["function"]["parameters"]["type"] == "object" for tool in tools)


def test_the_mcp_shape_is_what_clients_expect() -> None:
    for spec in tool_specs():
        payload = spec.mcp()
        assert set(payload) == {"name", "description", "inputSchema"}
        assert payload["inputSchema"]["type"] == "object"


def test_the_validator_accepts_what_each_schema_describes() -> None:
    """The schemas and the checker are two descriptions of one thing."""
    for spec in tool_specs():
        arguments = {
            name: _EXAMPLES[str(prop["type"])]
            for name, prop in spec.parameters["properties"].items()
        }

        assert validate_arguments(spec, arguments) == arguments


def test_the_validator_insists_on_the_shape_it_declares() -> None:
    spec = tool_specs()[0]  # run_shell

    with pytest.raises(ToolError, match="unknown argument"):
        validate_arguments(spec, {"command": "echo", "bonus": "x"})
    with pytest.raises(ToolError, match="missing required argument"):
        validate_arguments(spec, {})
    with pytest.raises(ToolError, match="must be a string"):
        validate_arguments(spec, {"command": 7})


def test_a_boolean_is_not_an_integer() -> None:
    fetch = next(spec for spec in tool_specs() if spec.name == "fetch_url")

    with pytest.raises(ToolError, match="must be a integer"):
        validate_arguments(fetch, {"url": "https://example.com", "max_bytes": True})


# ------------------------------------------------------------------- calling
def test_an_unknown_tool_says_what_there_is(tmp_path: Path) -> None:
    tools, _ = _tools(tmp_path)

    with pytest.raises(ToolError, match="this server offers"):
        tools.call("rm_everything", {})


def test_run_shell_records_the_command_and_returns_it(tmp_path: Path) -> None:
    tools, journal = _tools(tmp_path)

    result = tools.call("run_shell", {"command": "echo tool-call-works"})

    assert not result.is_error
    assert "status: executed" in result.text
    assert "exit code: 0" in result.text
    assert "tool-call-works" in result.text
    assert [event.type.value for event in journal.read()] == [
        "action.proposed",
        "policy.decision",
        "action.result",
    ]
    assert journal.verify().ok


def test_a_refused_call_is_a_result_not_an_exception(tmp_path: Path) -> None:
    """A model told why can tell the user; a traceback teaches it nothing."""
    tools, journal = _tools(tmp_path)

    result = tools.call("run_shell", {"command": "rm -rf /"})

    assert result.is_error
    assert "rule: shell.rm-root" in result.text
    assert "recursive delete" in result.text
    assert "the action did NOT run" in result.text
    assert journal.read()[-1].payload["status"] == "denied"


def test_a_reviewed_call_asks_for_a_human_and_then_works(tmp_path: Path) -> None:
    tools, journal = _tools(tmp_path)

    first = tools.call("run_shell", {"command": "echo .netrc"})

    assert first.is_error
    assert "a human has to approve this" in first.text
    assert first.result is not None
    assert first.result.approval_request is not None
    request_seq = first.result.approval_request.seq
    assert request_seq > 0

    record_decision(
        journal,
        action=Action(kind=ActionKind.SHELL, target="echo .netrc"),
        granted=True,
        source=SOURCE_OPERATOR,
    )

    second = tools.call("run_shell", {"command": "echo .netrc"})

    assert not second.is_error
    assert "approved by event #" in second.text


def test_write_file_writes_inside_the_workspace(tmp_path: Path) -> None:
    tools, _ = _tools(tmp_path)

    result = tools.call("write_file", {"path": "notes.md", "content": "hello"})

    assert not result.is_error
    assert "wrote 5 bytes" in result.text
    assert (tmp_path / "notes.md").read_text(encoding="utf-8") == "hello"


def test_write_file_refuses_to_leave_the_workspace(tmp_path: Path) -> None:
    tools, _ = _tools(tmp_path)

    result = tools.call("write_file", {"path": "../escape.md", "content": "no"})

    assert result.is_error
    assert "outside the workspace" in result.text
    assert not (tmp_path.parent / "escape.md").exists()


def test_delete_file_removes_one_file(tmp_path: Path) -> None:
    (tmp_path / "junk.txt").write_text("bye", encoding="utf-8")
    tools, _ = _tools(tmp_path)

    result = tools.call("delete_file", {"path": "junk.txt"})

    assert not result.is_error
    assert "status: deleted" in result.text
    assert "deleted junk.txt" in result.text
    assert not (tmp_path / "junk.txt").exists()


def test_delete_file_refuses_a_directory(tmp_path: Path) -> None:
    (tmp_path / "build").mkdir()
    tools, _ = _tools(tmp_path)

    result = tools.call("delete_file", {"path": "build"})

    assert result.is_error
    assert "out of scope" in result.text
    assert (tmp_path / "build").is_dir()


def test_fetch_url_is_held_for_a_human_by_default(tmp_path: Path) -> None:
    """No network is needed: the default preset reviews every destination."""
    tools, _ = _tools(tmp_path)

    result = tools.call("fetch_url", {"url": "https://pypi.org/simple/"})

    assert result.is_error
    assert "rule: network.any" in result.text
    assert "a human has to approve this" in result.text


def test_fetch_url_only_takes_http_and_https(tmp_path: Path) -> None:
    tools, _ = _tools(tmp_path, preset="permissive")

    result = tools.call("fetch_url", {"url": "file:///etc/passwd"})

    assert result.is_error
    assert "only fetches http and https" in result.text


def test_an_allow_review_server_runs_without_asking(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(load_preset("standard"))
    tools = SentinelTools(engine, journal, workspace=tmp_path, allow_review=True)

    result = tools.call("run_shell", {"command": "echo .netrc"})

    assert not result.is_error
    decided = [event for event in journal.read() if event.type.value == "approval.decided"]
    assert decided[0].payload["source"] == "config"


def test_a_policy_that_denies_everything_denies_every_tool(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "session.jsonl")
    engine = PolicyEngine(parse_policy({"name": "closed", "default": "deny", "rules": []}))
    tools = SentinelTools(engine, journal, workspace=tmp_path)

    assert tools.call("write_file", {"path": "a.txt", "content": "x"}).is_error
    assert tools.call("run_shell", {"command": "echo hi"}).is_error
    assert not (tmp_path / "a.txt").exists()
