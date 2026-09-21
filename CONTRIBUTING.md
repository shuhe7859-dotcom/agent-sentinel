# Contributing

Thanks for taking the time to look. This project is small enough that a good
issue report is often more valuable than a patch, so both are welcome.

## Getting set up

```console
$ python -m venv .venv
$ .venv\Scripts\activate            # Windows
$ source .venv/bin/activate         # macOS / Linux
$ python -m pip install -e ".[dev]"
$ python -m pre_commit install
$ python -m pytest
```

The full command list, conventions and the release process live in
[`docs/development.md`](docs/development.md).

## Before you open a pull request

```console
$ make check
```

which is `ruff check`, `ruff format --check`, `mypy` and `pytest --cov` in one
go. CI runs the same thing on Linux and Windows across Python 3.11, 3.12 and
3.13, so a local failure is a CI failure.

## What makes a change easy to accept

**It comes with a test.** For a bug, a test that fails before the fix. For a
rule, a test asserting the verdict for a realistic command string, plus a case
that should *not* match — a rule that blocks everything is easy to write and
useless in practice.

**It says why.** Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
`docs:`, `test:`, `refactor:`, `chore:`. Reviewers should be able to read the
log and understand intent, not just mechanics.

**It keeps the vocabulary small.** Four action kinds and three effects are
deliberate. If a change needs a fifth kind or a fourth effect, that is a design
discussion first — open an issue, and expect the answer to be a
[decision record](docs/adr/0001-record-architecture-decisions.md) rather than a
quick merge.

**It does not quietly widen permissions.** A preset rule that stops blocking
something is a security regression even when the diff is three characters.

## Changes with extra requirements

| Kind of change | Also required |
| --- | --- |
| A shipped preset rule | Mirror in `examples/policies/standard.toml` if it touches `standard`; a `CHANGELOG.md` entry |
| The record format, hashing, or a field's meaning | A `SCHEMA_VERSION` bump, an entry in the compatibility section of `docs/event-schema.md`, and a test that old journals still verify |
| A rule `id` | Prefer adding a new id over renaming; ids appear in journals people already have |
| A CLI exit code | Justify it in the pull request; these are consumed by scripts |

## Adding a rule that you think belongs in every preset

Probably not. Presets are a starting point, and every rule carries a false
positive cost for every user. A rule that is essential for one project usually
belongs in that project's `.sentinel/policy.toml`. The bar for `standard` is:
the action is either catastrophic, or so commonly dangerous that ignoring it
would make the default policy dishonest.

## Reporting a bug

Include:

* the command or API call;
* the policy in force (redact anything private);
* the relevant journal excerpt, and `sentinel journal verify` output if the
  report touches the log;
* the platform and Python version.

## Reporting a security bypass

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

