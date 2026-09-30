# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, changes to the record format or to a rule `id`
are still treated as breaking, because journals outlive code.

## [Unreleased]

### Added

- **Approvals as first-class records.** A `review` verdict now escalates, and the
  human answer is written into the same hash chain as the action it authorises.
  Approvals are scoped to one action (an action fingerprint covers the kind and
  the normalised command or path), single use (the execution records the
  `approval_seq` it consumed), and optionally expirable.
- **`sentinel approve`** records a grant or a refusal, either for a queued
  escalation (`--request-seq`) or directly (`--command`), with an optional
  `--expires-in` and `--note`.
- **`sentinel journal pending`** lists escalations that still need a human.
- **An escalation now says how to answer it.** A run that stops for review
  prints the exact `sentinel approve … --request-seq N` command to run.
- **Sessions.** `sentinel run` brackets every execution with `session.start` and
  `session.end`. `session.start` carries the policy name, its source, and a
  content fingerprint, so a journal can be tied to the exact rules that were in
  force. `Session` is available as a context manager for embedders, and
  `Policy.fingerprint()` / `Action.fingerprint()` are public.
- **A `refused` status**, for when a reviewer callback answers no, and an
  `approval_seq` field on executed results.
- **`reviewer` callbacks and `allow_review` documented and tested.** Both record
  who answered, and `approval.decided` carries a `source` of `operator`,
  `callback` or `config`.
- **`docs/approvals.md`**, a full account of the approval model and its limits.
- **Guarded filesystem access.** `GuardedFileSystem.write()` and `.delete()`
  work inside one workspace root, given at runtime. The target is resolved with
  `Path.resolve()`, so `..`, an absolute path and a symbolic link that points
  outside are all refused *before* the policy is consulted, and no policy can
  relax that. The journal records the path as written, the resolved path, the
  workspace-relative path and a digest — never the file's contents.
- **Guarded HTTP egress.** `GuardedNetwork.fetch()` makes the request itself, so
  an allow-list is enforced rather than suggested. Rules match the host
  (lower-cased, with `:port` when it is not the scheme's default); only `http`
  and `https` are fetched; redirects are not followed, so the next hop goes
  through the policy as a fresh action; response bodies go to the caller and not
  into the journal.
- **`sentinel write`, `sentinel delete` and `sentinel fetch`**, each writing a
  session frame and recording what they did. `--workspace` defaults to the
  current directory and is recorded in `session.start`; `sentinel run` gained the
  same flag so every command records it.
- **`guards/base.py`**, the propose → decide → escalate → act → record flow that
  all three guards share, so the single-use approval rule exists in one place.
- **`docs/guards.md`**, and `examples/policies/workspace.toml` showing a host
  allow-list next to file rules that lean on the guard for containment.
- **Anchors.** `sentinel journal anchor` writes the journal's head hash to an
  anchor file and/or hands the same JSON to an external command, printing a
  summary line for the CI log first so a later failure cannot hide it. Every
  anchor is a checkpoint.
- **Truncation and rewrite detection.** `sentinel journal verify --anchors`
  reports `truncated` when an anchor points past the end of the journal and
  `rewritten` when the record at an anchored position no longer matches. A
  missing or empty anchor file is an error, not a pass, so deleting the evidence
  is not the easiest attack.
- **Optional Ed25519 signatures over anchors.** `sentinel keygen` writes a key
  pair, `--sign-with` signs an anchor, and `--key` pins the expected signer,
  reporting `bad-signature` or `key-mismatch`. It lives behind the
  `agent-sentinel[sign]` extra, so the runtime core keeps importing nothing but
  the standard library.
- **`docs/anchoring.md`**, including an honest account of what anchoring cannot
  do: evidence nobody expected can still be deleted, and an anchor kept next to
  the journal does not stop someone with access to both.
- **`--interactive`** on `run`, `write`, `delete` and `fetch`: asks on the
  terminal before running a reviewed action, prompts on stderr so stdout stays
  the guarded command's, and treats anything but `y`/`yes` as no.
- **It refuses to guess without a terminal.** With `--interactive` and a
  non-TTY stdin, the command exits `1` before touching the journal and points at
  `sentinel approve` instead of hanging or deciding for you. `--interactive`
  and `--allow-review` are mutually exclusive, since one asks and the other
  presumes.
- **`GuardedFileSystem`, `GuardedNetwork`, `GuardedShell` and `Guard` take a
  `reviewer_note`**, so a journal can tell a live answer from a programmatic
  one. The CLI writes `answered at the terminal`.

### Changed

- `GuardedResult` gained `approval_seq` and `approval_request`.
- The version string moved to `agent_sentinel/_version.py` so that modules
  imported by the package root can read it without a circular import.
- `IntegrityIssue` gained a `source` field (`journal` or `anchor`) so a rendered
  problem says which file it is about.
- `VerifyReport` gained `anchors_checked`, `latest_anchor_seq` and `signer`, all
  defaulted, so existing construction and callers are unchanged.
- `dev` now includes `cryptography`, so CI covers the signing path.
- `GuardedRunner` is now `GuardedShell`, with `GuardedRunner` kept as an alias.
  `GuardedResult`, `GuardResult` and the existing fields are unchanged.
- An `OSError` while carrying an action out is now recorded as a `failed` result
  for every guard. The shell guard used to raise `GuardError`.
- `Session` takes a `workspace`, recorded in `session.start`.

### Fixed

- `sentinel run` exited `0` when a command hit its timeout, because the exit code
  was read from `returncode`, which is `None` in that case. A timeout now exits
  `4`, like any other attempt that failed.

### Known limitations

- A refusal is recorded but does not block: the action is escalated again on the
  next attempt.
- Approvals are not authenticated. Anyone who can write the journal can append a
  grant, and the chain will still verify, because it is a valid record.
- Anchoring is opt-in and only as external as the place you put the anchor. A
  journal nobody anchored, or an anchor file nobody asks about, cannot be
  checked. An unpinned signature proves very little, because the public key
  travels inside the anchor.
- Deleting a symbolic link is refused rather than guessed at, and directory
  deletion is out of scope for the filesystem guard; both go through the shell
  guard, where the command is recorded instead.
- Containment is checked and then used, so a path component swapped for a link
  in between is not caught. Closing that needs `openat`-style primitives the
  standard library does not expose portably.

## [0.1.0] - 2026-09-21

The foundation release: a working guardrail and a working flight recorder, with
one guarded surface.

### Added

- **Flight recorder.** Append-only JSON Lines journal with a SHA-256 hash chain.
  Records carry the digest of their predecessor, so an edited, deleted,
  reordered or spliced record is detectable.
- **Event format.** `Event`, `EventType`, `Actor`, canonical JSON serialisation
  and hashing, with verified round-tripping of records.
- **Journal API.** Append, read, tail, head, verify, plus a structured
  `VerifyReport` that reports every integrity issue with a line number and a
  reason rather than stopping at the first.
- **Policy engine.** `Action`, `Rule`, `Policy`, `Decision`, `Effect`; rules
  ordered by ascending priority with declaration order breaking ties; first
  match wins; every decision names the rule that fired and explains itself.
- **Policy files.** TOML policies parsed with the standard library, with strict
  validation: unknown schema, effect, kind, duplicate ids, non-integer
  priorities and patterns that do not compile are all errors, never guesses.
- **Presets.** `permissive`, `standard` and `strict`, covering destructive
  commands, remote-code-execution by convention, path traversal, `.git`
  tampering, force pushes, history rewrites, privilege escalation, dependency
  installation, credential access, data upload and network egress.
- **Guarded shell execution.** `GuardedRunner` records the proposal, the
  decision and the outcome of every command, storing output as a digest plus a
  truncated preview, with `--timeout` support.
- **CLI.** `sentinel policy presets|check`, `sentinel run`,
  `sentinel journal show|verify|note` and `sentinel version`, with stable exit
  codes (0 allowed, 1 error, 2 review, 3 denied, 4 command failed).
- **Documentation.** Architecture, policy reference, event schema, threat
  model, roadmap, development guide, two architecture decision records and a
  Chinese project plan.
- **Tooling.** `pyproject.toml` with a zero-dependency runtime, a `dev` extra,
  ruff and mypy configuration, pytest with coverage, pre-commit hooks, a
  Makefile and GitHub Actions CI on Linux and Windows across Python 3.11–3.13.

### Known limitations

- No guards yet for filesystem writes, deletes or network egress, so the
  corresponding policy rules have nothing to act on.
- A `review` verdict stops the action; the human approval is not yet itself
  recorded as an event.
- Tail truncation of a journal and a full rewrite of the file are not
  detectable without external anchoring of the head hash.

[Unreleased]: https://github.com/shuhe7859-dotcom/agent-sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/shuhe7859-dotcom/agent-sentinel/releases/tag/v0.1.0
