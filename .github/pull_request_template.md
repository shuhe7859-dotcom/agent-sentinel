## What changed

<!-- One or two sentences. What does this do, and why now? -->

## Why

<!-- The problem this solves. Link an issue if there is one. -->

## How it was tested

<!--
Commands you ran, and what you saw. "python -m pytest" plus a note about any new
case is usually enough.
-->

## Checklist

- [ ] `make check` passes locally (ruff, mypy, pytest)
- [ ] New behaviour comes with a test, including a case that should *not* match
- [ ] Docs updated if a policy key, CLI flag, exit code or record field changed
- [ ] `CHANGELOG.md` updated under `Unreleased` for user-visible changes
- [ ] If a shipped preset changed: it is mirrored in `examples/policies/` and the
      widening of permissions is explained above
- [ ] If the record format changed: `SCHEMA_VERSION` bumped and
      `docs/event-schema.md` compatibility section updated

## Notes for the reviewer

<!-- Anything you are unsure about, or would like a second opinion on. -->

