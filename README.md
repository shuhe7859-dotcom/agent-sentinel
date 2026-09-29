# agent-sentinel

**Guardrails and a flight recorder for coding agents.**

English | [简体中文](README.zh-CN.md)

[![CI](https://github.com/shuhe7859-dotcom/agent-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/shuhe7859-dotcom/agent-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/tests-224%20passing-brightgreen.svg)](tests/)

A coding agent edits your files, runs your commands and talks to the network.
Two questions follow, and together they are the whole project:

* **What is it allowed to do?** — decided *before* anything runs, by a policy that
  returns `allow`, `review` or `deny` and says why.
* **What did it actually do?** — written down as it happens, in a log that can
  prove afterwards that it was not edited.

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- git push --force origin main
REVIEW [standard] shell.git-force-push: force pushing rewrites shared history
       action: shell git push --force origin main
status:  awaiting_approval
```

The refusal is recorded, too. A blocked attempt is evidence.

## Two pillars, nothing else

| Pillar | Question | Module |
| --- | --- | --- |
| **Guardrails** | May this action run? | [`policy/`](src/agent_sentinel/policy) |
| **Flight recorder** | What was proposed, decided and observed? | [`journal.py`](src/agent_sentinel/journal.py) |

Everything else in the codebase is plumbing that puts those two on the path of
an actual action.

## Status

Early, but working. The record format, the policy engine, all three guarded
surfaces, the approval loop and the tamper-evidence toolkit are implemented and
covered by 224 tests.

| Area | State |
| --- | --- |
| Event format, canonical JSON, SHA-256 hash chain | implemented |
| Journal append / read / tail / verify | implemented |
| TOML policy loading and strict validation | implemented |
| Policy engine: priority ordering, reasoned decisions | implemented |
| `permissive` / `standard` / `strict` presets | implemented |
| Guarded shell execution (propose, decide, run, record) | implemented |
| Approvals as first-class, single-use, expirable records | implemented |
| Sessions that record which policy was in force | implemented |
| Guarded file writes and deletes, contained to a workspace root | implemented |
| Guarded HTTP egress, matched by host, redirects not followed | implemented |
| Anchors that catch a truncated tail and a replaced journal | implemented |
| Optional Ed25519 signatures over anchors | implemented |
| `sentinel` CLI with stable exit codes | implemented |
| MCP server, framework adapters, journal replay | planned (M4) |

See [`docs/roadmap.md`](docs/roadmap.md) for the milestone list.

## Try it in two minutes

No installation needed — the repository runs from a checkout:

```console
$ git clone https://github.com/shuhe7859-dotcom/agent-sentinel
$ cd agent-sentinel
$ python examples/quickstart.py
```

Or install it:

```console
$ python -m pip install -e ".[dev]"
```

### Ask the policy without running anything

```console
$ sentinel policy check --policy standard --target "rm -rf /"
DENY   [standard] shell.rm-root: recursive delete of a root or home directory
       action: shell rm -rf /
```

```console
$ sentinel policy check --policy standard --kind file.write --target "../outside.py"
DENY   [standard] fs.path-traversal: path escapes the workspace through '..'
       action: file.write ../outside.py
```

### Run something through the guardrail

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- pytest -q
ALLOW  [standard] (policy default): no rule matched; the policy default is 'allow'
       action: shell pytest -q
status:  executed
```

Every guarded run writes three records: what was proposed, what was decided, and
what happened.

### Read the flight recorder

```console
$ sentinel journal show .sentinel/session.jsonl
#1    2026-09-21T13:53:20.971Z agent    action.proposed  63584bb6f94e
#2    2026-09-21T13:53:20.982Z sentinel policy.decision  d6633472077d
#3    2026-09-21T13:53:21.070Z sentinel action.result    7bbfa1f0fcca
```

Change a line by hand and the chain notices:

```console
$ sentinel journal verify .sentinel/session.jsonl
journal: .sentinel/session.jsonl
records: 3
head:    7bbfa1f0fcca...
status:  BROKEN - 1 issue(s)
  - line 2 (seq 2): hash: record content no longer matches its digest
```

That is the point of the design: the log does not stop tampering, it makes
tampering visible.

### Approve something that was escalated

A `review` verdict does not just stop — the human answer is recorded too, scoped
to that one command:

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
status:  awaiting_approval
this is waiting for a human. to grant it:
  sentinel approve .sentinel/session.jsonl --request-seq 4
then run the command again

$ sentinel journal pending .sentinel/session.jsonl
#4    shell       echo .netrc
        shell.credential-access: reading credential material

$ sentinel approve .sentinel/session.jsonl --request-seq 4 --note "checked with the team"
recorded approval #7 (granted) for shell echo .netrc

$ sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
status:  executed
approval: granted by event #7
```

The policy still says `review` — the approval authorised one execution of one
action, and running it again asks again. Read
[`docs/approvals.md`](docs/approvals.md) for the rules.

### Guard files and the network too

The same policy governs three surfaces. Two of them carry a structural rule
that no policy can relax: a file path must resolve inside the workspace, and a
URL must be `http` or `https`.

```console
$ sentinel write --policy standard --journal .sentinel/session.jsonl --workspace . notes.md --content "hi"
status:  written
target:  notes.md -> /home/you/project/notes.md (2 bytes, sha256 0a1b2c3d4e5f)

$ sentinel write --policy standard --journal .sentinel/session.jsonl --workspace . ../escape.md --content "hi"
DENY   [standard] (policy default): '../escape.md' resolves to /home/you/escape.md,
       outside the workspace '/home/you/project'; the filesystem guard does not
       allow escapes (the policy had said allow)
status:  denied
$ echo $?
3
```

Network rules match the **host**, so an allow-list stays readable:

```console
$ sentinel fetch --policy examples/policies/workspace.toml https://pypi.org/simple/
status:  fetched
url:     https://pypi.org/simple/
http:    200 text/html; charset=utf-8 (21379 bytes)
```

The guard makes the request itself — a guard that only reported a verdict would
be easy to walk around — and a redirect is not followed, so the next hop goes
through the policy as a fresh action. Read [`docs/guards.md`](docs/guards.md).

### Make the log hard to lie about

A hash chain catches an edited record. It cannot catch a journal whose last
lines were deleted, or one replaced with a different but valid file. An
**anchor** — the head hash, written down somewhere else — can:

```console
$ sentinel journal anchor .sentinel/session.jsonl \
      --file .sentinel/anchors.jsonl --note "end of CI job"
anchor  seq 42  head 5f2c602b66bba94b  journal session.jsonl  session b21629681de4

$ sentinel journal verify .sentinel/session.jsonl --anchors .sentinel/anchors.jsonl
anchors: 1 checked, latest at seq 42
status:  ok - hash chain verified
```

Cut a few trailing records and the anchor notices:

```console
$ sentinel journal verify .sentinel/session.jsonl --anchors .sentinel/anchors.jsonl
status:  BROKEN - 1 issue(s)
  - anchor (seq 42): truncated: anchored at seq 42, but the journal now ends at
    seq 39: 3 records missing
```

Every anchor is a checkpoint, so a rewrite of an early record is caught by an
anchor taken before it. Anchors can be signed as well, so a third party without
the private key cannot forge one — see [`docs/anchoring.md`](docs/anchoring.md).

## Using the library

```python
from agent_sentinel import GuardedRunner, Journal, PolicyEngine, load_preset

engine = PolicyEngine(load_preset("standard"))
journal = Journal(".sentinel/session.jsonl")
runner = GuardedRunner(engine, journal, cwd=".", timeout=120)

result = runner.run("pytest -q")
if result.executed:
    print(result.returncode, result.stdout_preview)
else:
    print(f"not run: {result.status} ({result.decision.rule_id})")
```

Ask the policy directly when you only want a verdict:

```python
from agent_sentinel import Action, ActionKind, PolicyEngine, load_preset

engine = PolicyEngine(load_preset("standard"))
decision = engine.evaluate(Action(kind=ActionKind.SHELL, target="git push --force origin main"))

print(decision.effect.value)  # "review"
print(decision.rule_id)  # "shell.git-force-push"
print(decision.reason)  # "force pushing rewrites shared history"
```

## Writing a policy

Policies are TOML, parsed with the standard library — no extra dependency, no
service to run, and a file a reviewer can diff.

```toml
schema  = 1
name    = "team"
default = "review"            # unknown actions escalate to a human

[[rules]]
id       = "shell.tests"
kind     = "shell"
effect   = "allow"
priority = 10                 # lower numbers are checked first
pattern  = '''(?i)\b(?:pytest|ruff|mypy)\b'''
reason   = "the local quality tooling is always fine"

[[rules]]
id       = "shell.publish"
kind     = "shell"
effect   = "deny"
priority = 5                  # ...but publishing is never the agent's call
pattern  = '''(?i)\b(?:git\s+push|npm\s+publish|twine\s+upload)\b'''
reason   = "publishing is a human decision here"
```

**First match wins**, rules are sorted by ascending `priority`, and the
`default` applies when nothing matches. Full reference:
[`docs/policy-reference.md`](docs/policy-reference.md).

Three presets ship with the project:

| Preset | Default | Character |
| --- | --- | --- |
| `permissive` | `allow` | Blocks only the catastrophic. For a first run where you want a record more than control. |
| `standard` | `allow` | Blocks the catastrophic, escalates the risky. Recommended starting point. |
| `strict` | `review` | Ships no allow rules at all: nothing shell-shaped runs without a human. |

[`examples/policies/standard.toml`](examples/policies/standard.toml) is the
`standard` preset written out by hand — the intended way to start a
project-specific policy is to copy it and narrow it.

## CLI reference

| Command | Purpose |
| --- | --- |
| `sentinel policy presets` | List the built-in policies. |
| `sentinel policy check --policy P --kind K --target T [--json]` | Evaluate one action; run nothing. |
| `sentinel run --policy P --journal J [--cwd D] [--timeout S] [--allow-review] -- CMD…` | Run a command through the guardrail and record it. |
| `sentinel write --policy P --journal J [--workspace W] [--create-parents] PATH [--content T \| --from-file F]` | Write a file inside the workspace; reads stdin when no content is given. |
| `sentinel delete --policy P --journal J [--workspace W] PATH` | Remove a single file inside the workspace. |
| `sentinel fetch --policy P --journal J [--method M] [--timeout S] [--max-bytes N] URL` | Fetch a URL; the guard makes the request and the body goes to stdout. |
| `sentinel approve J --request-seq N [--expires-in MIN] [--note T] [--refuse]` | Record a human answer for an escalated action. |
| `sentinel journal show J [--limit N] [--json]` | Print recorded events. |
| `sentinel journal pending J` | List escalations that still need a human. |
| `sentinel journal verify J [--anchors A] [--key PUB]` | Verify the hash chain, and optionally check it against anchors. |
| `sentinel journal note J "text"` | Append a human annotation. |
| `sentinel journal anchor J [--file A] [--command CMD] [--note T] [--sign-with KEY]` | Write the head hash somewhere the journal cannot reach. |
| `sentinel keygen [--private P] [--public P] [--force]` | Generate an Ed25519 key pair for signing anchors. |
| `sentinel version` | Print the version. |

`--policy` accepts a preset name or a path to a `.toml` file.

Exit codes are stable, so `sentinel` can be used from scripts:

| Code | Meaning |
| --- | --- |
| `0` | allowed, or the guarded command succeeded |
| `1` | sentinel itself failed (bad policy, damaged journal) |
| `2` | the action needs review and was not run |
| `3` | the action was denied by policy |
| `4` | the action ran and failed: a command returned non-zero, an I/O error occurred, an HTTP status of 400 or above came back, or something timed out |

## Repository layout

```
agent-sentinel/
├── src/agent_sentinel/
│   ├── events.py            record format, canonical JSON, hashing
│   ├── journal.py           append-only file, chain verification
│   ├── approvals.py         human answers: scope, single use, expiry
│   ├── session.py           session.start / session.end framing
│   ├── anchors.py           head hashes written outside the journal
│   ├── signing.py           Ed25519 key files and signatures (the sign extra)
│   ├── errors.py            exception hierarchy
│   ├── cli.py               the `sentinel` command
│   ├── policy/
│   │   ├── models.py        Action, Rule, Policy, Decision, Effect
│   │   ├── loader.py        TOML parsing and validation
│   │   ├── engine.py        ordering, matching, verdict
│   │   └── presets.py       permissive / standard / strict
│   └── guards/
│       ├── base.py          the flow all three guards share
│       ├── shell.py         GuardedShell: run a command line
│       ├── filesystem.py    GuardedFileSystem: writes and deletes, contained
│       └── network.py       GuardedNetwork: HTTP, matched by host
├── tests/
│   ├── unit/                events, journal, policy
│   ├── integration/         the CLI end to end
│   └── fixtures/policies/   example policies used by tests
├── examples/
│   ├── quickstart.py        a five-minute tour
│   └── policies/            hand-written policy examples
├── docs/
│   ├── architecture.md      layers, data flow, extension points
│   ├── policy-reference.md  every key a policy can use
│   ├── approvals.md         how a human "yes" becomes evidence
│   ├── guards.md            the three surfaces and what each one refuses
│   ├── anchoring.md         truncation, rewrites, and what a signature proves
│   ├── event-schema.md      the on-disk record format
│   ├── threat-model.md      what this defends against, and what it does not
│   ├── roadmap.md           milestones
│   ├── development.md       setup, conventions, release process
│   ├── adr/                 architecture decision records
│   └── zh-CN/项目计划.md     中文项目计划
├── pyproject.toml
└── .github/workflows/ci.yml
```

## Design principles

* **The policy is data, not code.** A guardrail you cannot review is not a guardrail.
* **Every decision carries its reason.** The journal explains itself six months later.
* **The log is append-only and self-verifying.** Detection of tampering, not prevention.
* **Zero runtime dependencies.** A safety tool should not be its own supply-chain risk.
* **Summaries, not dumps.** Output is stored as a digest plus a truncated preview.
* **Small vocabulary.** Four action kinds, three effects. Fewer things to get wrong.

## What this is not

agent-sentinel is **not a sandbox**. It decides whether to start a process; it
does not confine one, and it detects journal tampering rather than preventing
it. A coding agent with an unrestricted shell can bypass a guardrail it does not
have to go through. The honest framing is defense in depth, and the assumptions
are written out in [`docs/threat-model.md`](docs/threat-model.md).

## Documentation

| Document | Read it when |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | You want to know how the pieces fit, or where to add a guard. |
| [`docs/policy-reference.md`](docs/policy-reference.md) | You are writing or reviewing a policy. |
| [`docs/approvals.md`](docs/approvals.md) | You are deciding how a human should answer an escalation. |
| [`docs/guards.md`](docs/guards.md) | You are embedding a guard, or wondering why a write was refused. |
| [`docs/anchoring.md`](docs/anchoring.md) | You want to know that nothing was quietly removed from a journal. |
| [`docs/event-schema.md`](docs/event-schema.md) | You want to read a journal without this library, or change the format. |
| [`docs/threat-model.md`](docs/threat-model.md) | You need to know what is in scope, and what is not. |
| [`docs/development.md`](docs/development.md) | You are setting up, contributing, or releasing. |
| [`docs/roadmap.md`](docs/roadmap.md) | You want to know what is coming next. |
| [`docs/zh-CN/项目计划.md`](docs/zh-CN/项目计划.md) | 你需要中文项目计划与验收要点。 |

## Contributing

Issues and pull requests are welcome. Start with
[`CONTRIBUTING.md`](CONTRIBUTING.md), which points at the conventions in
[`docs/development.md`](docs/development.md). Changes to a shipped preset or to
the record format have extra requirements, because other people's journals
depend on them.

## Security

Please report bypasses privately rather than in a public issue — see
[`SECURITY.md`](SECURITY.md). Because policies are pattern-based filters and not
sandboxes, "a regex missed an equivalent command" is a known and documented
limitation rather than a vulnerability; the threat model lists what is in scope.

## License

[MIT](LICENSE) © 2026 MI-Manchi
