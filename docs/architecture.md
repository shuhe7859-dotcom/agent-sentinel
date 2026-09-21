# Architecture

agent-sentinel exists because a coding agent is a process that edits your
files, runs your commands and talks to the network, and the humans responsible
for that machine need two things: a way to *bound* what it may do, and a way to
*know* what it did.

The project is built from two pillars, and deliberately nothing else.

| Pillar | Question it answers | Module |
| --- | --- | --- |
| Guardrails | May this action run? | `agent_sentinel.policy` |
| Flight recorder | What was proposed, decided and observed? | `agent_sentinel.journal` |

Everything else in the codebase is plumbing that puts those two on the path of
an actual action.

## Layered view

```
   ┌──────────────────────────────────────────────────────────────┐
   │  callers                                                     │
   │  CLI (sentinel run)   Python SDK   future: MCP / adapters    │
   └───────────────────────────┬──────────────────────────────────┘
                               │  a command, a path, a host
   ┌───────────────────────────▼──────────────────────────────────┐
   │  guards/            GuardedRunner: propose → decide → run    │
   └───────────┬──────────────────────────────────────┬───────────┘
               │ Action                               │ outcome
   ┌───────────▼───────────────┐         ┌────────────▼───────────┐
   │  policy/                  │         │  journal/              │
   │  Rule ─▶ Decision         │         │  hash-chained JSONL    │
   └───────────────────────────┘         └────────────────────────┘
               ▲                                      ▲
               │                                      │
   ┌───────────┴───────────────┐         ┌────────────┴───────────┐
   │  presets.toml / your.toml │         │  events.py (record     │
   │  loader.py validates      │         │  format + hashing)     │
   └───────────────────────────┘         └────────────────────────┘
```

## What happens to one command

```
agent:      "pytest -q"
              │
              ▼
  ①  journal.append(action.proposed)          ← recorded before anything else
              │
              ▼
  ②  engine.evaluate(Action)                  ← first matching rule wins
              │
      ┌───────┼───────────────┐
      ▼       ▼               ▼
   deny    review          allow
      │       │               │
      │       │               ▼
      │       │      ③ subprocess runs the command
      │       │               │
      ▼       ▼               ▼
  ④  journal.append(action.result, status=denied | awaiting_approval | executed)
              │
              ▼
  ⑤  exit code: 3 / 2 / 0
```

Two properties fall out of this ordering:

* the *intent* is recorded even when the command is refused, so a blocked
  attempt is still evidence;
* the *decision* is recorded next to the intent, so the log explains itself
  without needing the policy file that was in force at the time.

## Module map

| Path | Responsibility |
| --- | --- |
| `src/agent_sentinel/events.py` | The record format, canonical JSON, the hash function. |
| `src/agent_sentinel/journal.py` | Append-only file I/O, chain verification, reports. |
| `src/agent_sentinel/policy/models.py` | `Action`, `Rule`, `Policy`, `Decision`, `Effect`. |
| `src/agent_sentinel/policy/loader.py` | TOML parsing and validation into the model. |
| `src/agent_sentinel/policy/engine.py` | Rule ordering, matching, verdict. |
| `src/agent_sentinel/policy/presets.py` | The built-in `permissive`/`standard`/`strict` policies. |
| `src/agent_sentinel/guards/shell.py` | `GuardedRunner`: the guarded execution path. |
| `src/agent_sentinel/cli.py` | `sentinel` subcommands and exit codes. |
| `src/agent_sentinel/errors.py` | Exception hierarchy. |

## Design principles

**The policy is data, not code.** A guardrail you cannot read in a code review
is not a guardrail. Policies are TOML files that a reviewer can diff, and the
engine is small enough to audit in one sitting.

**Every decision carries its reason.** `Decision` names the rule that fired and
explains it in words. This is what makes a log useful six months later, when
nobody remembers why a rule exists.

**The log is append-only and self-verifying.** Records are never rewritten, and
each one hashes its predecessor, so tampering is detectable rather than
prevented. Prevention is the operating system's job; *detection* is ours.

**Stdlib-only core.** Policies use TOML, parsed by `tomllib`. The library adds
no runtime dependency, so it can be dropped into any environment without
turning into a supply-chain decision of its own.

**Record summaries, not everything.** Command output is stored as a SHA-256
digest plus a truncated preview. The log stays small and still lets you prove
what a command printed.

**Small vocabulary.** Four action kinds, three effects. If a policy needs more
expressive power than that, the answer is usually a narrower action kind rather
than a richer rule language.

## Extension points

*New action kind.* Add a member to `ActionKind`, then add rules with that
`kind`. Guards that actually intercept that surface are separate work — the
policy layer already understands a `network` action today, but nothing yet
produces one.

*New guard.* A guard is anything that (1) builds an `Action`, (2) asks the
engine, (3) records the outcome via a `Journal`. `GuardedRunner` is the
reference implementation; `guards/filesystem.py` and `guards/network.py` would
follow the same four steps.

*New adapter.* An adapter does not need to know about policy or journals. It
needs to route a proposal through a guard. The planned MCP server and framework
integrations are thin translations onto `GuardedRunner.run`.

*New policy source.* `parse_policy` takes a mapping and `load_policy` takes a
path. Any other source (a URL, a database row, a Python dict built in a test)
only has to produce the same mapping.

## State of the code

Implemented and covered by tests:

* the record format, hashing, canonical serialisation;
* append, read, tail, head and full-chain verification of a journal;
* TOML policy loading, validation and rule matching;
* the three presets;
* guarded shell execution with propose/decide/run/record;
* the `sentinel` CLI with stable exit codes.

Designed but not built yet (see [`roadmap.md`](roadmap.md)):

* guards for filesystem writes, deletes and network egress;
* an append-only *approval* record, so a human "yes" is itself auditable;
* `journal replay` and `journal export`;
* adapters for agent frameworks and an MCP server;
* signed journals and external anchoring of the head hash.

## Where the constraints live

| Concern | Enforced by |
| --- | --- |
| What may run | `policy/` |
| What is written down | `journal/` |
| Whether the record is intact | `journal.verify()` |
| Whether the machine is actually isolated | *not this project* — see [`threat-model.md`](threat-model.md) |

