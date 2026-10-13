# Giving an agent the guarded tools

Handing a model a shell hands it everything. Handing it the four tools below
hands it exactly four things, each of which goes through the policy, the
approval flow and the journal first — so there is no road around the guardrail,
because there is no other road.

## The tools

| Tool | Arguments | Guard behind it |
| --- | --- | --- |
| `run_shell` | `command` | `GuardedShell` |
| `write_file` | `path`, `content`, `create_parents` | `GuardedFileSystem` |
| `delete_file` | `path` | `GuardedFileSystem` |
| `fetch_url` | `url`, `method`, `max_bytes` | `GuardedNetwork` |

Every call writes the same records the CLI writes — `action.proposed`,
`policy.decision`, `action.result` — so `journal replay`, `verify`, `export`
and anchoring all work on a session an agent produced, unchanged.

**A blocked call is a result, not an exception.** A model told *why* can tell
the user; a model that gets a traceback learns nothing and may retry forever:

```text
status: denied
rule: shell.rm-root
reason: recursive delete of a root or home directory
the action did NOT run (denied)
```

```text
status: awaiting_approval
rule: fs.secrets
reason: writing to a file that normally holds credentials
the action did NOT run (awaiting_approval)
a human has to approve this. Ask them to run:
  sentinel approve .sentinel/mcp.jsonl --request-seq 12
```

## Two shapes, one description

The tools are described once and handed out in whichever shape a caller wants.

```console
$ sentinel tools --format openai      # [{"type": "function", "function": {...}}]
$ sentinel tools --format mcp         # [{"name": ..., "inputSchema": {...}}]
```

The OpenAI function-calling shape is the lingua franca: the Agents SDK, a plain
chat-completions loop and several other frameworks accept it with no wrapper.
`examples/function_calling.py` shows the whole loop offline — schemas out, tool
calls dispatched back in.

```python
from agent_sentinel import Journal, PolicyEngine, SentinelTools, load_preset, openai_tools

tools = SentinelTools(
    PolicyEngine(load_preset("standard")),
    Journal(".sentinel/mcp.jsonl"),
    workspace=".",
)

# What you hand the model:
schemas = openai_tools()

# What you do with what it hands back:
result = tools.call("run_shell", {"command": "pytest -q"})
print(result.is_error, result.text)
```

## The MCP server

```console
$ sentinel mcp --policy standard --journal .sentinel/mcp.jsonl --workspace .
```

It speaks JSON-RPC 2.0 over stdin and stdout, one message per line. Point a
client at it:

```json
{
  "mcpServers": {
    "agent-sentinel": {
      "command": "sentinel",
      "args": [
        "mcp",
        "--policy", "standard",
        "--journal", ".sentinel/mcp.jsonl",
        "--workspace", "."
      ]
    }
  }
}
```

The server opens a session on start and closes it on exit, so the journal says
which policy was in force for the whole conversation, not just for one command.

### What is implemented

| Method | Behaviour |
| --- | --- |
| `initialize` | Negotiates the protocol version and advertises the `tools` capability. |
| `notifications/initialized` | Accepted and ignored, like every notification. |
| `tools/list` | The four tools, with their JSON Schemas. |
| `tools/call` | Runs a tool; `isError` is true whenever the action did not happen. |
| `ping` | Answers `{}`. |

Protocol versions `2024-11-05`, `2025-03-26` and `2025-06-18` are recognised. A
client asking for anything else is answered with the newest we know, which is
the negotiation the specification allows.

### What is not

Resources, prompts, sampling, elicitation, HTTP transports and OAuth. This is a
**tool server**, deliberately, and it is hand-written so the runtime keeps its
promise of importing only the standard library. If you need the rest, the
official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) is
the thing to reach for — the tool descriptions here are plain data and port
across in an afternoon.

That the subset actually works is not a claim, it is a test: the development
extra installs the official SDK purely as a *client*, and
`tests/integration/test_mcp_interop.py` points it at this server and drives it.

### Two rules worth knowing

**stdout belongs to the protocol.** One stray `print` and the client sees a
parse error. Every diagnostic goes to stderr, and a test pins that.

**A notification is never answered.** A message without an `id` is a
notification, and replying to one is a violation that strict clients object to.
An unknown notification is still not answered.

On Windows the streams are also switched to UTF-8 with plain newlines, because
the defaults are the console code page and CRLF, either of which corrupts a
JSON-RPC conversation.

## Choices the server makes for you

- **`--workspace` is the boundary.** Paths resolve against it and are refused
  outside it, whatever the policy says. This is the one argument worth getting
  right.
- **No `--interactive`.** The client is a program; there is no terminal to ask.
  A reviewed action comes back as "waiting for a human", and the human answers
  with `sentinel approve`, out of band — which is also what leaves the auditable
  record.
- **`--allow-review` exists and is honest about itself.** It runs reviewed
  actions without asking and records `source: config` next to each one, so the
  journal says plainly that nobody was asked.
- **Nothing else reaches the machine.** There is no shell to escape to, no
  filesystem outside the workspace, and `fetch_url` only speaks http and https.
