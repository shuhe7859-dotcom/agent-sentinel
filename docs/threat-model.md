# Threat model

A guardrail that overstates itself is worse than no guardrail, because people
stop paying attention. This document says plainly what agent-sentinel defends
against, what it does not, and what has to be true for it to work at all.

## What is being protected

| Asset | Why it matters |
| --- | --- |
| The working tree | Uncommitted work is often the only copy. |
| The host machine | A coding agent usually has the user's full privileges. |
| Credentials | `.env`, SSH keys, cloud tokens, browser profiles. |
| Remote history | A force push to a shared branch destroys other people's work. |
| The audit trail | If the log can be edited, accountability disappears. |

## Who or what we are defending against

**A confident, wrong agent.** The realistic failure mode is not malice. It is an
agent that decides `git reset --hard` is the cleanest way out of a merge
conflict, or that piping a setup script into `sh` is the fastest way to install
a tool. Most of the shipped rules target this case.

**A prompt-injected agent.** An agent that reads a repository, an issue or a web
page it does not control may be steered by text inside that content. Here the
agent may be actively working against the user's interest, within the
permissions it was given.

**An after-the-fact question.** Weeks later: did the agent touch the deployment
configuration, and did anyone approve it? The flight recorder is aimed squarely
at this, and it is the part of the project that has to be right.

## In scope

* Refusing a proposed action that matches a `deny` rule.
* Stopping at `review` until a human or a configured reviewer callback approves.
* Recording the proposal, the verdict and the observed outcome of every guarded
  action.
* Keeping file writes and deletes inside a declared workspace, and HTTP egress
  on `http` and `https`, whatever a policy happens to say — a guard can tighten
  a verdict but never loosen it.
* Detecting that a journal was edited, truncated, reordered or spliced after the
  fact.
* Being readable and reviewable: a policy is a diffable file, the log is text.

## Out of scope

* **Isolation.** agent-sentinel is not a sandbox, a container, a VM or a seccomp
  filter. It does not confine a process; it decides whether to start one.
  Containers, `firejail`, AppArmor and dedicated users do that job, and they
  compose with this project rather than competing with it.
* **Kernel-level enforcement.** A process that is already running is not
  constrained by anything here.
* **Prevention of tampering.** The journal *detects* tampering; it does not
  prevent it. An attacker who can rewrite the whole file can produce a
  consistent chain from scratch. Detecting that needs the head hash written down
  somewhere else, and even then only if you ask for it — see
  [`anchoring.md`](anchoring.md).
* **Malware analysis, dependency scanning, secret scanning at rest.** Different
  tools, different problems.
* **Judging intent.** Patterns match text. `echo "rm -rf /"` and `rm -rf /` look
  the same to a regex.

## The load-bearing assumption

> agent-sentinel is only as strong as the claim that the agent cannot run
> commands except through it.

A coding agent with an unrestricted shell can simply execute `rm -rf /`
directly. If the guardrail is invoked from inside the same trust domain as the
thing it is guarding, it is a bump, not a wall. The honest framing is
**defense in depth**:

```
OS sandbox / container / unprivileged user     ← the actual boundary
    └── agent-sentinel policy                  ← bounds intent, explains refusals
            └── agent-sentinel journal         ← evidence of what was attempted
```

The strongest deployments put the guardrail on the only path to execution: a
CI runner, a wrapper around the agent's tool-calling layer, or an MCP server
that owns the tools. In those placements the assumption holds and the guardrail
does real work.

## Threats and the current answer

| Threat | Current answer | Residual risk |
| --- | --- | --- |
| Destructive command (`rm -rf /`, `mkfs`, `dd` to `/dev/`) | `deny` rules in every preset | A novel spelling the pattern misses |
| Remote code execution by convention (`curl … \| sh`) | `deny` rule | Obfuscated equivalents |
| Path escape via `..`, an absolute path, or a symbolic link | Resolved and compared against the workspace root by the filesystem guard; no policy can relax it | Time-of-check to time-of-use: a path component swapped for a link between the check and the write |
| Editing `.git` internals | `deny` rule on `file.write` / `file.delete` | Only applies to writes made through the guard |
| Force push / history rewrite | `review` | A human who rubber-stamps |
| Credential access or exfiltration | `review` rules, plus a default `review` for every network destination | Rules match text and hosts, not intent |
| Exfiltration by `file://` URL | The network guard refuses every scheme but `http` and `https`, before the policy is consulted | Direct filesystem reads outside the guard are not covered |
| An allow-listed host redirecting somewhere else | Redirects are not followed; the 3xx and its `Location` are recorded, and the next hop is a fresh action | The caller has to notice the 3xx and re-fetch deliberately |
| A secret leaking through the journal | File contents and response bodies are never recorded, only digests and byte counts | Command output *is* recorded as a preview, because that is the evidence of what a command did |
| Silently editing a journal record | Per-record digest | An attacker who recomputes the whole chain produces an internally consistent file |
| Truncating a journal | `sequence` and `link` checks | Truncating the *tail* looks exactly like a shorter session unless the head hash was anchored |
| Rewriting the whole journal, or truncating its tail | `sentinel journal verify --anchors`: every anchor is a checkpoint, and a missing or empty anchor file is an error | An anchor kept next to the journal does not stop someone with access to both; publish it somewhere else. Evidence nobody asked about can still be deleted |
| Forging an anchor | Ed25519 signature over the anchor, checked against a pinned public key | Signing is an optional extra, and an unpinned key only proves the anchor file was not edited by someone without the private key |
| Denial of service by a runaway command | `--timeout` kills the process and records `timeout` | Resource limits are the operating system's job |

The two that used to be open — tail truncation and a full rewrite — now have an
answer in [`anchoring.md`](anchoring.md). The honest caveat is that the answer
is opt-in: an anchor only helps if one was taken, and it only helps if you ask
about it, because absence of evidence you never expected is not something a
verifier can notice.

## Failure behaviour

The design preference is to fail loudly and conservatively:

* A policy that cannot be parsed is an error, never a silent fallback to
  "allow everything".
* An unknown `schema`, `effect` or `kind` is an error, not a guess.
* An unreadable journal record raises instead of being skipped, so a damaged log
  cannot look like a clean one.
* `deny` and `review` both record the proposal before refusing, so a refused
  action leaves evidence.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Please do not open a public issue for a
bypass.
