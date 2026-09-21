# Development

## Requirements

- Python 3.11 or newer (`tomllib` is used from the standard library)
- Git
- Optional: [`uv`](https://docs.astral.sh/uv/) for faster environment handling

There are no runtime dependencies. Everything in the `dev` extra is tooling.

## Setting up

With `uv`:

```console
$ uv venv
$ uv pip install -e ".[dev]"
```

With the standard library's venv:

```console
$ python -m venv .venv
$ .venv\Scripts\activate          # Windows
$ source .venv/bin/activate       # macOS / Linux
$ python -m pip install -e ".[dev]"
```

The test suite can also run straight from a checkout without installing
anything: `tests/conftest.py` puts `src/` on the path.

## Everyday commands

| Task | Command |
| --- | --- |
| Run the tests | `python -m pytest` |
| Run one file | `python -m pytest tests/unit/test_journal.py` |
| Run one test | `python -m pytest -k "tampering"` |
| Coverage | `python -m pytest --cov=agent_sentinel` |
| Lint | `python -m ruff check .` |
| Lint and fix | `python -m ruff check --fix .` |
| Format | `python -m ruff format .` |
| Type check | `python -m mypy` |
| Try it out | `python examples/quickstart.py` |
| Build a wheel | `python -m build` |

`make test` / `make lint` / `make fmt` / `make check` wrap the same commands if
you have `make` available.

## Pre-commit

```console
$ python -m pre_commit install
```

This runs whitespace and syntax checks, `ruff` (with fixes), `ruff format` and
`mypy` on staged files. Hooks should be fast; keep them that way.

## Project conventions

**Layout.** `src/` layout, so tests exercise the installed package rather than
the working directory. Tests mirror the source tree under `tests/unit` and
`tests/integration`.

**Style.** 100 columns, double quotes, enforced by `ruff format`. Rules from
`E`, `F`, `W`, `I`, `N`, `UP`, `B`, `C4`, `SIM`, `RET`, `RUF` and `S` (bandit)
are on. `S` matters here: this is a security tool, and a `# noqa` on an `S` rule
is a claim that deserves a reason in the comment.

**Types.** `mypy --strict` covers `src/`. Annotations are part of the interface:
a guard that returns `object` is a guard nobody can compose.

**Docstrings.** Modules explain *why the module exists* and what it guarantees,
not just what functions exist. Look at `journal.py` or `guards/shell.py` for the
register to aim for.

**Tests.** Test behaviour a user would notice, including the failure paths. A
journal test that only asserts "append worked" is half a test; the other half
asserts that an edited record is caught.

**Commits.** [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`. The subject line
completes the sentence *"applied, this commit will …"*.

**Branches.** `main` is always green. Work on `feat/<short-name>` or
`fix/<short-name>` and open a pull request. Direct pushes to `main` should be
for nothing more than a typo.

## Changing a shipped preset

Presets are part of the interface and appear in other people's logs.

1. Add or edit the rule in `policy/presets.py`.
2. Mirror the change in `examples/policies/standard.toml` when it touches
   `standard`.
3. Add a test in `tests/unit/test_policy_engine.py` asserting the verdict for a
   realistic command string, in both the positive and negative direction.
4. Note the change in `CHANGELOG.md`. A preset that quietly stops blocking
   something is a security regression, even if the diff looks small.

## Changing the record format

`docs/event-schema.md` is the specification; `events.py` implements it. Any
change to the hashing recipe, the field set, or the meaning of an existing field
requires:

1. a bump of `SCHEMA_VERSION`;
2. an entry in the compatibility section of the schema document;
3. a test proving that journals written under the previous version still
   verify, or an explicit statement that they do not.

## Releasing

1. Update `__version__` in `src/agent_sentinel/__init__.py` and `version` in
   `pyproject.toml`. `tests/unit/test_version.py` enforces that they agree.
2. Move the `Unreleased` section of `CHANGELOG.md` under the new version and
   date it.
3. Tag: `git tag -a vX.Y.Z -m "vX.Y.Z"` and push the tag.
4. `python -m build`, then inspect the wheel before uploading.

Versioning follows [Semantic Versioning](https://semver.org/). While the major
version is `0`, a change to the record format or to a rule `id` is still treated
as breaking, because journals outlive code.

## Getting help

Open an issue with the policy (redacted), the command, and the journal excerpt
around the problem. `sentinel journal verify` output is usually the fastest way
to make a report actionable.

