# Roadmap

Milestones are ordered by "what makes the tool honest", not by what is most fun
to build. Everything below M1 is a plan, not a promise.

## M0 — Foundation ✅

The skeleton a project can be built on.

- [x] Repository layout, tooling, CI, contribution guide
- [x] Record format, canonical JSON, hash chain
- [x] Journal append / read / tail / head / verify
- [x] Policy model, TOML loader with strict validation
- [x] Policy engine with priority ordering and reasoned decisions
- [x] `permissive`, `standard`, `strict` presets
- [x] Guarded shell execution recording proposal, decision and outcome
- [x] `sentinel` CLI with stable exit codes
- [x] 125 tests covering the above

## M1 — Close the loop on approvals ✅

A `review` verdict no longer merely stops. The human answer is written into the
same hash chain, scoped to one action, and spent when it is used.

- [x] `sentinel approve` to record an approval as a first-class, hash-chained event
- [x] `sentinel journal pending` to list escalations that still need a human
- [x] `GuardedRunner(reviewer=...)` and `allow_review`, both documented and tested,
      each leaving a record of who answered
- [x] A `session.start` / `session.end` pair written by the CLI, with the policy
      identity and its digest in the payload
- [x] Approvals that expire, and that are scoped to one action rather than one rule
- [ ] An interactive terminal reviewer (`sentinel run --interactive`)

## M2 — Guards for the other three surfaces ✅

All four action kinds now have a guard behind them, and the two that can be
constrained structurally are.

- [x] `guards/filesystem.py`: writes and deletes inside the workspace, with the
      resolved path recorded and a digest instead of the contents
- [x] `guards/network.py`: the guard makes the request, so the host allow-list is
      enforced rather than suggested
- [x] A workspace root given at runtime, so `..` and absolute paths are judged by
      resolving them rather than by matching text
- [x] Preset rules re-verified against the real subjects the new guards produce
- [x] The flow shared by all three guards extracted into `guards/base.py`
- [x] 168 tests, of which two symbolic-link cases are skipped where the platform
      will not create them

## M3 — Make the log hard to lie about

- [ ] Anchor the head hash outside the journal (CI log line, transparency log, or a
      second machine) and record the anchor
- [ ] Optional Ed25519 signing of each record, so a full rewrite by a third party is detectable
- [ ] Detect tail truncation by comparing the journal head with the last anchored value

## M4 — Make it usable where agents actually run

- [ ] `sentinel run --shell` as a drop-in wrapper for an existing workflow
- [ ] An MCP server exposing guarded tools, so a model cannot bypass the guardrail by construction
- [ ] Adapters for at least one agent framework
- [ ] `sentinel journal replay` and `sentinel journal export --format html|sarif`
- [ ] A policy test mode: fixtures of commands with their expected verdicts, run in CI

## Backlog / ideas

- YAML policies as an optional extra, for teams that prefer them
- Rule `kind` matching on a *structured* action (parsed argv) rather than a string
- A `sentinel doctor` command that reports the environment and which files are watched
- Per-rule counters in a session summary, so noisy rules are visible
- Documentation site built from `docs/`
