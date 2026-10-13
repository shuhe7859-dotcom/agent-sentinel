"""The guarded tools, in the shape an agent framework expects.

Handing a model a shell hands it everything. Handing it these four tools hands
it exactly four things, each of which goes through the policy, the approval flow
and the journal before anything happens. That is the whole point: a model that
only has these cannot route around the guardrail, because there is no other road.

This module knows nothing about JSON-RPC and nothing about any particular
framework. It describes tools, checks arguments against its own schemas, and
dispatches to the guards. The MCP server and the OpenAI-shaped export are two
ways of handing the same description out.

**A blocked action is a result, not an exception.** A model told "denied" can
tell the user why; a model that gets a traceback learns nothing and may retry
forever.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ToolError
from .guards.base import GuardResult
from .guards.filesystem import GuardedFileSystem
from .guards.network import DEFAULT_MAX_BYTES, GuardedNetwork
from .guards.shell import GuardedShell
from .journal import Journal
from .policy.engine import PolicyEngine

MAX_TEXT_CHARS = 8000
"""How much of anything we hand back to a model, before it becomes a token bill."""


@dataclass(frozen=True)
class ToolSpec:
    """One tool: what it is called, what it does, and what arguments it takes."""

    name: str
    description: str
    parameters: Mapping[str, Any]
    """A JSON Schema object. Flat, and only using the types listed below."""

    def openai(self) -> dict[str, Any]:
        """The shape OpenAI function calling takes."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": dict(self.parameters),
            },
        }

    def mcp(self) -> dict[str, Any]:
        """The shape MCP's ``tools/list`` takes."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": dict(self.parameters),
        }


@dataclass(frozen=True)
class ToolResult:
    """What a tool call produced, in a form either transport can carry."""

    tool: str
    text: str
    is_error: bool
    """True when the action did not achieve what was asked — including a refusal."""

    result: GuardResult | None = None
    """The guard's own result, for a caller that wants more than the text."""


_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="run_shell",
        description=(
            "Run a shell command through the policy. The command is recorded, and "
            "may be refused or held for a human. Returns the exit code and output."
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command line to run."}
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="write_file",
        description=(
            "Write a file inside the workspace. Paths outside the workspace are "
            "refused whatever the policy says, and writing to a file that holds "
            "credentials may be held for a human."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the workspace."},
                "content": {"type": "string", "description": "What to write."},
                "create_parents": {
                    "type": "boolean",
                    "description": "Create missing directories on the way. Default false.",
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="delete_file",
        description=(
            "Delete one file inside the workspace. Directories and symbolic links "
            "are refused: neither is ambiguous enough to guess at."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the workspace."}
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="fetch_url",
        description=(
            "Fetch an http or https URL. The policy matches the host, redirects are "
            "not followed, and the response body is returned to you."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch."},
                "method": {"type": "string", "description": "HTTP method. Default GET."},
                "max_bytes": {
                    "type": "integer",
                    "description": "How much of the body to read. Defaults to the server's.",
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    ),
)

_BY_NAME = {spec.name: spec for spec in _SPECS}

_TYPES: dict[str, type] = {"string": str, "integer": int, "boolean": bool}


def tool_specs() -> tuple[ToolSpec, ...]:
    """Every tool this project offers."""
    return _SPECS


def openai_tools() -> list[dict[str, Any]]:
    """The same tools, shaped for OpenAI function calling.

    Anything that accepts that shape — the Agents SDK, a plain chat-completions
    loop, several other frameworks — can take these without a wrapper.
    """
    return [spec.openai() for spec in _SPECS]


def validate_arguments(spec: ToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Check arguments against a tool's schema.

    Only the subset this project's schemas actually use: a flat object of
    string, integer or boolean properties, with required keys and nothing extra.
    It is **not** a general JSON Schema validator and does not pretend to be one.

    Raises:
        ToolError: a key is unknown or missing, or a value has the wrong type.
    """
    properties = spec.parameters.get("properties", {})
    known = set(properties)

    unknown = sorted(set(arguments) - known)
    if unknown:
        raise ToolError(
            f"{spec.name}: unknown argument(s) {', '.join(unknown)}; "
            f"this tool takes {', '.join(sorted(known))}"
        )

    missing = [name for name in spec.parameters.get("required", []) if name not in arguments]
    if missing:
        raise ToolError(f"{spec.name}: missing required argument(s) {', '.join(missing)}")

    checked: dict[str, Any] = {}
    for name, value in arguments.items():
        declared = str(properties[name].get("type", "string"))
        expected = _TYPES.get(declared, str)
        if not _is_instance(value, expected):
            raise ToolError(f"{spec.name}: '{name}' must be a {declared}")
        checked[name] = value
    return checked


def _is_instance(value: Any, expected: type) -> bool:
    if expected is bool:
        return isinstance(value, bool)
    if expected is int:
        # JSON has no separate integer type, but a float is not an int here.
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, expected)


class SentinelTools:
    """The four guarded tools, wired to one policy and one journal."""

    def __init__(
        self,
        engine: PolicyEngine,
        journal: Journal,
        *,
        workspace: str | Path | None = None,
        cwd: str | None = None,
        allow_review: bool = False,
        timeout: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self.engine = engine
        self.journal = journal
        self.workspace = Path(workspace).expanduser().resolve() if workspace else Path.cwd()
        self.cwd = cwd
        self.max_bytes = max_bytes
        self._shell = GuardedShell(
            engine, journal, cwd=cwd, allow_review=allow_review, timeout=timeout
        )
        self._files = GuardedFileSystem(
            engine, journal, workspace=self.workspace, allow_review=allow_review
        )
        self._network = GuardedNetwork(
            engine, journal, allow_review=allow_review, timeout=timeout, max_bytes=max_bytes
        )

    def call(self, name: str, arguments: Mapping[str, Any] | None = None) -> ToolResult:
        """Run one tool call.

        Raises:
            ToolError: the tool is unknown, or its arguments do not fit. A tool
                that *ran* and was refused is a result, not an error.
        """
        spec = _BY_NAME.get(name)
        if spec is None:
            raise ToolError(
                f"unknown tool {name!r}; this server offers {', '.join(sorted(_BY_NAME))}"
            )
        values = validate_arguments(spec, dict(arguments or {}))
        if name == "run_shell":
            return self._run_shell(values)
        if name == "write_file":
            return self._write_file(values)
        if name == "delete_file":
            return self._delete_file(values)
        return self._fetch_url(values)

    # ---------------------------------------------------------------- tools
    def _run_shell(self, values: Mapping[str, Any]) -> ToolResult:
        result = self._shell.run(str(values["command"]))
        lines = _outcome(result, self.journal)
        if result.status == "executed":
            lines.append(f"exit code: {result.returncode}")
            if result.stdout_preview:
                lines.append("output:\n" + _shorten(result.stdout_preview))
            if result.stderr_preview:
                lines.append("errors:\n" + _shorten(result.stderr_preview))
        return _result("run_shell", result, lines)

    def _write_file(self, values: Mapping[str, Any]) -> ToolResult:
        result = self._files.write(
            str(values["path"]),
            str(values["content"]),
            create_parents=bool(values.get("create_parents", False)),
        )
        lines = _outcome(result, self.journal)
        if result.status == "written":
            lines.append(f"wrote {result.bytes_written} bytes to {result.relative or result.path}")
        elif result.error:
            lines.append(result.error)
        return _result("write_file", result, lines)

    def _delete_file(self, values: Mapping[str, Any]) -> ToolResult:
        result = self._files.delete(str(values["path"]))
        lines = _outcome(result, self.journal)
        lines.append(
            f"deleted {result.relative or result.path}"
            if result.status == "deleted"
            else result.error
        )
        return _result("delete_file", result, lines)

    def _fetch_url(self, values: Mapping[str, Any]) -> ToolResult:
        extra: dict[str, Any] = {}
        if values.get("method") is not None:
            extra["method"] = str(values["method"])
        if values.get("max_bytes") is not None:
            extra["max_bytes"] = int(values["max_bytes"])
        result = self._network.fetch(str(values["url"]), **extra)

        lines = _outcome(result, self.journal)
        if result.status == "fetched":
            lines.append(f"http {result.status_code} {result.content_type or ''}".strip())
            if result.location:
                lines.append(
                    f"redirect to {result.location} (not followed; fetch it yourself if you mean to)"
                )
            if result.body:
                lines.append("body:\n" + _shorten(_decode(result.body)))
        elif result.error:
            lines.append(result.error)
        return _result("fetch_url", result, lines)


# ---------------------------------------------------------------- rendering
def _result(tool: str, result: GuardResult, lines: Sequence[str]) -> ToolResult:
    return ToolResult(
        tool=tool,
        text="\n".join(line for line in lines if line),
        is_error=not result.ok,
        result=result,
    )


def _outcome(result: GuardResult, journal: Journal) -> list[str]:
    """The first few lines of any result: what happened, and why."""
    decision = result.decision
    lines = [f"status: {result.status}"]
    if decision.matched:
        lines.append(f"rule: {decision.rule_id}")
    if decision.reason:
        lines.append(f"reason: {decision.reason}")
    if result.status in {"denied", "refused", "awaiting_approval"}:
        lines.append(f"the action did NOT run ({result.status})")
    if result.approval_request is not None:
        lines.append(
            "a human has to approve this. Ask them to run: "
            f"sentinel approve {journal.path} --request-seq {result.approval_request.seq}"
        )
    elif result.approval_seq is not None:
        lines.append(f"approved by event #{result.approval_seq}")
    return lines


def _decode(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def _shorten(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n... [{len(text) - limit} more characters not shown]"
