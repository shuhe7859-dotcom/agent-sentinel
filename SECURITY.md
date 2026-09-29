# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or by contacting the maintainer listed in `pyproject.toml`.

Please include what you did, what you expected, and what happened. A journal
excerpt plus `sentinel journal verify` output is usually the fastest path to a
fix.

We aim to acknowledge a report within a few days. This is a small project
without a paid security team, so please allow reasonable time before
disclosing publicly.

## What counts as a vulnerability

In scope:

* a `deny` rule that does not fire for the command it obviously describes, where
  the mismatch is a bug in our pattern rather than a limitation of pattern
  matching;
* a journal that verifies as `ok` after being edited, truncated, reordered or
  spliced;
* a journal that verifies as `ok` under `--anchors` when an anchor says
  otherwise: a missed truncation, a missed rewrite, a signature that should not
  have verified, or a key mismatch that was not reported;
* a record whose stored hash does not match its content but is reported as
  valid;
* escaping a policy by way of the library's own API — for example a code path
  that executes without consulting the engine or writes without recording;
* a malformed policy or journal that crashes the process with a traceback, or
  worse, silently falls back to permissive behaviour.

## What is documented behaviour, not a vulnerability

agent-sentinel is a pattern-based policy layer, not a sandbox. The following are
known, intended limits, described in [`docs/threat-model.md`](docs/threat-model.md):

* **Equivalent spellings.** Patterns match text. A determined agent can rewrite
  a blocked command to avoid a pattern. This is a limitation of the approach,
  not of the implementation.
* **Bypass by not using it.** An agent with unrestricted shell access can run
  commands without going through a guard. Putting the guardrail on the only
  path to execution is the operator's job.
* **Full rewrite of a journal, or truncation of its tail.** The hash chain
  detects local edits, not a consistently recomputed file. Anchors are the
  answer, and they are opt-in: `sentinel journal verify --anchors` catches both
  a tail that was cut and a file that was replaced, *provided* an anchor was
  taken. See [`docs/anchoring.md`](docs/anchoring.md).
* **Evidence nobody asked about.** If no anchor was ever taken, or an anchor
  file is deleted and nobody verifies against it, its absence is not something a
  verifier can notice. Anchoring answers "was anything removed from a log I
  expected to be this long"; it cannot answer "was there a log I never knew
  about".
* **An anchor stored next to the journal.** A local anchor file protects against
  accidents and casual rewriting, not against someone with write access to both
  files. Publish it somewhere else — a CI log, another machine — for that.
* **An unpinned signature.** Without `--key`, a signature is checked against the
  public key carried inside the anchor, which proves very little: whoever can
  rewrite the anchor can swap the key. Pinning the key is what makes the check
  mean something.
* **Resource exhaustion.** A command that consumes all the memory is a job for
  the operating system. `--timeout` only bounds wall-clock time.

If you believe one of these is being described inaccurately in the
documentation, that is a documentation bug and worth an issue.

## Supported versions

The project is pre-1.0. Only the latest release on `main` is supported; fixes
land there rather than on a maintenance branch.
