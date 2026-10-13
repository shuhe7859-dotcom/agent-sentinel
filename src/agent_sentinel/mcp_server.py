"""A minimal MCP server over stdio.

MCP is JSON-RPC 2.0 over a pipe, one message per line. This module implements
the part a tool server needs — ``initialize``, ``tools/list``, ``tools/call``,
``ping`` — and nothing else, so the runtime keeps its promise of importing only
the standard library.

Two rules matter more than the rest:

* **stdout belongs to the protocol.** One stray ``print`` and the client sees a
  parse error. Everything else goes to stderr.
* **A notification is never answered.** A message without an ``id`` is a
  notification; replying to one is a protocol violation, and clients are strict
  about it.

This is a subset on purpose: no resources, no prompts, no sampling, no HTTP
transport, no OAuth. ``docs/tools.md`` says so, and points at the official SDK
for the rest.
"""

from __future__ import annotations

import json
import sys
import traceback
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from ._version import __version__
from .errors import SentinelError, ToolError
from .events import canonical_dumps
from .tools import SentinelTools, tool_specs

PROTOCOL_VERSIONS: tuple[str, ...] = ("2024-11-05", "2025-03-26", "2025-06-18")
"""The protocol revisions this server knows. Anything else falls back to the newest."""

LATEST_PROTOCOL_VERSION = PROTOCOL_VERSIONS[-1]
SERVER_NAME = "agent-sentinel"

DEFAULT_INSTRUCTIONS = (
    "Every tool here runs through a policy and is written to a journal. A refused "
    "or review-held call is not a broken tool: read the reason it gives you and "
    "tell the user what it said."
)

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

Handler = Callable[[Mapping[str, Any]], dict[str, Any]]


def use_utf8_stdio() -> None:
    """Make standard input and output UTF-8, with plain newlines.

    Windows text streams default to the console code page and translate newlines
    on the way out; either one corrupts a JSON-RPC conversation. MCP is UTF-8 on
    stdio, so say so explicitly rather than hoping.
    """
    for stream in (sys.stdin, sys.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", newline="\n")


class McpServer:
    """Answers MCP requests about one set of guarded tools."""

    def __init__(
        self,
        tools: SentinelTools,
        *,
        name: str = SERVER_NAME,
        version: str = __version__,
        instructions: str = DEFAULT_INSTRUCTIONS,
    ) -> None:
        self.tools = tools
        self.name = name
        self.version = version
        self.instructions = instructions

    # ----------------------------------------------------------- one message
    def handle(self, message: Any) -> dict[str, Any] | None:
        """Answer one message, or return ``None`` when it needs no answer."""
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "a message must be a JSON object")

        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(request_id, INVALID_REQUEST, "not a JSON-RPC 2.0 request")

        # Notifications are never answered, even the ones we do not recognise.
        if request_id is None or method.startswith("notifications/"):
            return None

        params = message.get("params", {})
        if not isinstance(params, dict):
            return _error(request_id, INVALID_PARAMS, "params must be an object")

        handler = self._handlers().get(method)
        if handler is None:
            return _error(
                request_id,
                METHOD_NOT_FOUND,
                f"method {method!r} is not implemented by this server",
            )

        try:
            payload = handler(params)
        except ToolError as exc:
            return _error(request_id, INVALID_PARAMS, str(exc))
        except SentinelError as exc:
            return _error(request_id, INTERNAL_ERROR, str(exc))
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            return _error(request_id, INTERNAL_ERROR, f"unexpected error: {type(exc).__name__}")
        return {"jsonrpc": "2.0", "id": request_id, "result": payload}

    # ---------------------------------------------------------- the session
    def serve(self, stdin: TextIO, stdout: TextIO) -> int:
        """Read messages until end of input, answering the ones that ask."""
        for line in iter(stdin.readline, ""):
            raw = line.strip()
            if not raw:
                continue
            try:
                message = json.loads(raw)
            except json.JSONDecodeError as exc:
                self._write(stdout, _error(None, PARSE_ERROR, f"parse error: {exc.msg}"))
                continue
            response = self.handle(message)
            if response is not None:
                self._write(stdout, response)
        return 0

    def _write(self, stdout: TextIO, payload: Mapping[str, Any]) -> None:
        stdout.write(canonical_dumps(payload))
        stdout.write("\n")
        stdout.flush()

    # ------------------------------------------------------------ handlers
    def _handlers(self) -> dict[str, Handler]:
        return {
            "initialize": self._initialize,
            "ping": _no_params,
            "tools/list": self._list_tools,
            "tools/call": self._call_tool,
        }

    def _initialize(self, params: Mapping[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        chosen = requested if requested in PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        return {
            "protocolVersion": chosen,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.name, "version": self.version},
            "instructions": self.instructions,
        }

    def _list_tools(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return {"tools": [spec.mcp() for spec in tool_specs()]}

    def _call_tool(self, params: Mapping[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ToolError("tools/call needs a tool 'name'")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ToolError("tools/call 'arguments' must be an object")

        result = self.tools.call(name, arguments)
        return {"content": [{"type": "text", "text": result.text}], "isError": result.is_error}


def _no_params(params: Mapping[str, Any]) -> dict[str, Any]:
    return {}


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
