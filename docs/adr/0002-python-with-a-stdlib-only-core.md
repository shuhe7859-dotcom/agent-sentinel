# 2. Python, `src` layout, and a standard-library-only core

* Status: accepted
* Date: 2026-09-21

## Context

A guardrail sits on the path of someone else's build. It has to be installable
in the environments where coding agents actually run — a developer laptop, a CI
runner, a container image — without becoming a project of its own. Two questions
had to be settled before any code was written:

1. What language and layout?
2. How much of a dependency tree is acceptable for something whose entire
   purpose is to make a system's behaviour more predictable?

The tempting answers were to use YAML policies (friendlier to write) and to pull
in a policy engine, a rich console library and a structured logging stack.

## Decision

**Python 3.11+, `src/` layout, packaged with Hatchling.** The environment that
runs coding agents — CI runners included — has Python almost by definition, and
GitHub's own Python `.gitignore` template was already in the repository when
work started, so the inference was cheap to confirm.

**Zero runtime dependencies.** `tomllib` (3.11+) parses policies; `argparse`
handles the CLI; `hashlib` and `json` handle the record format; `subprocess`
runs commands. Nothing is imported that is not in the standard library.

**Policies are TOML.** TOML is in the standard library, has real types, handles
multi-line strings cleanly, and is already familiar from `pyproject.toml`.

**The journal is JSON Lines with a SHA-256 hash chain.** Plain text, one record
per line, canonical JSON, each record committing to its predecessor.

**`src/` layout** so tests import the installed package rather than a stray
directory, and so a missing `__init__.py` cannot hide in a distributed wheel.

## Consequences

Better:

* `pip install agent-sentinel` pulls nothing else, so adopting it is not itself
  a supply-chain decision.
* The core is small enough to audit — a few hundred lines cover the format, the
  chain, the engine and the guarded run.
* A journal is readable with `jq`, `grep` and `diff`, and readable in ten years.
* TOML string literals (`'''…'''`) are a good fit for regex-heavy policies.

Worse:

* YAML policies need an optional extra later; the loader is deliberately shaped
  so that a second format can be added without touching the engine.
* No rich CLI output, no colour, no progress bars.
* Hand-rolled policy matching is less expressive than a general policy engine
  such as OPA/Rego. Accepted: four action kinds and three effects are enough for
  this problem, and a small vocabulary is easier to reason about under pressure.
* Manual canonical JSON serialisation is easy to get subtly wrong, so it is
  pinned by tests asserting that key order does not change a digest.

## Alternatives considered

**YAML policies with PyYAML.** Nicer for hand-editing, but adds a dependency,
and YAML's implicit typing (the `no` → `False` problem) is a poor property for a
file that decides whether `rm -rf /` runs.

**JSON policies.** No dependency, but no comments and no multi-line strings — a
bad trade for a document humans must review.

**A general policy engine (OPA/Rego, CEL, Cedar).** More expressive and
battle-tested. Rejected for now: an external engine, an evaluation runtime and a
decision protocol is a large amount of machinery to introduce before the record
format itself is proven.

**Node.js or Go.** Go would ship a single static binary, which is genuinely
attractive for a guardrail. Python won on time-to-first-useful-version and on
being the language of the rest of this project's tooling.

**A flat top-level `agent_sentinel/` package.** Simpler to browse, but it lets
import-path accidents reach users. `src/` layout prevents that class of bug.

