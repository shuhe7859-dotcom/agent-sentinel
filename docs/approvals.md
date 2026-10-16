# Context-bound approvals

A `review` decision waits for an explicit answer. Approvals bind **execution inputs**,
not the text used to match policy rules. The current approval context version is `2`.

## Approve the recorded request

```console
sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
sentinel journal pending .sentinel/session.jsonl
sentinel approve .sentinel/session.jsonl --request-seq 4 --expires-in 30 --note "checked context"
```

Use the request sequence printed by your run; it need not be 4. `pending` displays
the stored execution context. Repeat the original action, with the same parameters,
to use the grant. `--refuse` records a negative answer; `--expires-in` is in minutes.
A refusal is evidence, not a permanent ban. Multiple valid grants are used oldest first.

The deprecated `approve --command` syntax returns exit code 1 with guidance to use
`--request-seq`. A command string alone cannot identify an execution safely.

## What is bound

All contexts include the action kind, exact target, optional argv, and **policy
fingerprint**. Matching still uses the existing normalized subject; approval identity
uses the original execution inputs. Correlation IDs are excluded from that identity,
so retrying the exact action in a later session can consume its grant.

| Surface | Additional bound inputs |
| --- | --- |
| Shell | Resolved absolute working directory and effective timeout |
| File write/delete | Workspace, resolved target, prior content SHA-256 or missing/non-file state |
| File write | New content SHA-256, byte count, and create-parents setting |
| HTTP | Full URL, method, explicit header digest, body digest or absent marker, effective timeout and response-size limit |

Headers and bodies are copied before hashing and execution. File contents, request
bodies, and header values are not logged. URLs and command text are recorded: avoid
putting credentials in them. Digests are identifiers, not encryption of low-entropy secrets.

Before performing a file action, the guard resolves the path and checks file state
again. A change produces a fresh request and leaves the old grant unused; a path
that now escapes the workspace is denied. These checks are not OS-level protection
against a change between checking and opening a file. A shell grant does not bind
all resources the child process may subsequently read, or its inherited environment.

## Durable single-use claims

Each attempt has an `action_id`; sessions attach `session_id`. Requests preserve the
full action snapshot and versioned context so the CLI never reconstructs approval
from command text alone. An example lifecycle is:

```text
action.proposed -> policy.decision -> approval.requested -> action.result (waiting)
approval.decided
new action.proposed -> policy.decision -> approval.claimed -> action.result
```

A persistent `<journal>.lock` sidecar serializes cooperating writers on Windows and
POSIX. Chain-head read, sequence allocation, append and fsync occur under the lock.
The guard verifies the chain, selects an unexpired grant and durably writes
`approval.claimed` in one lock scope; execution happens **after releasing the lock**.
The sidecar is intentionally not deleted. Lock contention times out after 10 seconds.
Use a local filesystem with working OS locks; this is not a distributed lock service.

A claim remains consumed even if the process crashes or result logging fails. Reports
show a claim with no result as **outcome unknown / 结果未知**. Do not infer failure or
retry automatically: inspect the effects, then request a new approval. This guarantees
at-most-once use of a grant, not exactly-once execution of an external operation.

## Callbacks and unattended operation

`reviewer(action, decision)` receives the complete contextual action. Returning true
records a grant and still goes through the same atomic claim. `--interactive` prints
the context to stderr before asking; only `y` or `yes` approves. It requires a TTY
and is mutually exclusive with `--allow-review`. EOF or any other response refuses.

`allow_review=True` / `--allow-review` records approval with source `config`; it is
explicit unattended preauthorization, not a human answer. Operator CLI decisions
use source `operator`, and callbacks use `callback`.

Library callers should retain the action from `result.decision.action` (or restore
`result.approval_request.action` with `Action.from_dict`) when recording a decision.
Constructing a fresh Action from its target alone omits the execution context.

## Compatibility and boundary

The outer event envelope remains schema `1.0`; approval payloads carry
`context_version: 2`. New readers can inspect and verify historical logs. Historical
approvals without version 2 never authorize new execution. Run the desired action
again to obtain a current request; no automatic migration guesses missing inputs.
Old program versions cannot read the new `approval.claimed` event: upgrade all readers.

Claims coordinate cooperating guards, not processes that bypass them. They do not
establish a reviewer's authenticated identity. Hash chains detect edits; external,
optionally signed anchors provide evidence against truncation and complete rewrites.
