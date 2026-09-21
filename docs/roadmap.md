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
- [x] 79 tests covering the above

## M1 — Close the loop on approvals

Right now a `review` verdict simply stops. The missing piece is that the human
"yes" is itself evidence.

- [ ] `sentinel approve` to record an approval as a first-class, hash-chained event
- [ ] `GuardedRunner(reviewer=...)` documented and tested against an interactive prompt
- [ ] A `session.start` / `session.end` pair written by the CLI, with the policy
      identity and its digest in the payload
- [ ] An approval that expires: approving command X should not silently approve
      every later command matching the same rule

## M2 — Guards for the other three surfaces

The policy layer already understands `file.write`, `file.delete` and `network`.
Nothing produces those actions yet, which makes those rules decorative.

- [ ] `guards/filesystem.py`: path containment inside the workspace, recording writes and deletes
- [ ] `guards/network.py`: destination allow-list, recorded egress
- [ ] A workspace "root" concept, so `..` is judged against it rather than by text alone
- [ ] Preset rules re-verified against the real subjects the new guards produce

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
