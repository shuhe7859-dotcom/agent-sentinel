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
- **A third `action.result` status, `refused`**, for when a reviewer callback
  answers no, and an `approval_seq` field on executed results.
- **`GuardedRunner(reviewer=...)` and `allow_review` are documented and tested.**
  Both record who answered, and `approval.decided` carries a `source` of
  `operator`, `callback` or `config`.
- **`docs/approvals.md`**, a full account of the approval model and its limits.

### Changed

- `GuardedResult` gained `approval_seq` and `approval_request`.
- The version string moved to `agent_sentinel/_version.py` so that modules
  imported by the package root can read it without a circular import.

### Known limitations

- A refusal is recorded but does not block: the action is escalated again on the
  next attempt.
- Approvals are not authenticated. Anyone who can write the journal can append a
  grant, and the chain will still verify, because it is a valid record.

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
