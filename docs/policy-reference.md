# Policy reference

A policy is a TOML file that maps patterns of agent actions to one of three
effects. It is read, validated, then handed to a `PolicyEngine`.

## Where policies live

* **Presets** are built in: `permissive`, `standard`, `strict`.
* **Files** are wherever you keep them. `sentinel --policy` accepts either a
  preset name or a path, and a common convention is `.sentinel/policy.toml`
  checked into the repository so that changes to the guardrail are reviewed
  like any other change.

## Top-level keys

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema` | integer | no | Format version. Defaults to `1`. An unknown version is an error, never a guess. |
| `name` | string | **yes** | Identifier that appears in every decision and journal record. |
| `description` | string | no | One-line summary, shown by `sentinel policy presets`. |
| `default` | string | **yes** | `allow`, `deny` or `review`: the verdict when no rule matches. |
| `rules` | array of tables | no | Evaluated in priority order. An empty list is valid. |

## Rule keys

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | **yes** | Unique within the policy. Shows up in journals, so treat it as an API. |
| `effect` | string | **yes** | `allow`, `deny` or `review`. |
| `pattern` | string | **yes** | A regular expression, searched against the action's subject. |
| `reason` | string | no | Why this rule exists. Written into the journal verbatim. |
| `kind` | string or array | no | Restrict to one or more action kinds. Omit to match every kind. |
| `priority` | integer | no | Lower runs first. Default `100`. |
| `tags` | array of strings | no | Free-form labels for grouping and future reporting. |

## Effects

| Effect | Meaning | Typical use |
| --- | --- | --- |
| `allow` | Run it. | Your test runner, read-only git commands. |
| `review` | Stop and ask; run only if a human or reviewer callback says yes. | Force pushes, dependency installs, touching credentials, any network egress. |
| `deny` | Refuse. The action is recorded and never executed. | `rm -rf /`, piping a download into a shell, path traversal. |

There is intentionally no `warn` effect. A warning that does not change
behaviour is noise in a log; if something deserves attention, it deserves
`review`.

## Action kinds

| Kind | Subject is | Example target |
| --- | --- | --- |
| `shell` | The command line. | `git push --force origin main` |
| `file.write` | The destination path. | `src/agent_sentinel/cli.py` |
| `file.delete` | The path being removed. | `build/` |
| `network` | The host or URL. | `pypi.org` |

## Ordering and precedence

Rules are evaluated in ascending `priority`; ties keep the order they appear in
the file. The **first match wins** and evaluation stops there.

```
priority 10   deny  shell.rm-root                 ─┐
priority 10   deny  shell.pipe-remote-to-shell    │  checked first
priority 50   review shell.git-force-push         │
priority 90   review network.any                  ─┘
priority ---  (no rule matched) → default
```

That means a broad `allow` at priority `900` can act as an allow-list baseline
while narrow `deny` rules sit at low numbers and win over it.

## Matching semantics

* **Search, not full match.** `pattern` is applied with `re.search`, so
  `pytest` also matches `python -m pytest -q`.
* **Targets are normalised.** Backslashes are rewritten to forward slashes
  before matching, so `..\evil.py` and `../evil.py` are one pattern.
* **Case sensitivity is yours to choose.** Write `(?i)` at the start of a
  pattern to make it case-insensitive, as the presets do.
* **The subject is the whole command line.** For shell actions the subject is
  `argv` joined with spaces when `argv` is set, otherwise the raw `target`. A
  rule cannot see inside quoting: `echo "rm -rf /"` still looks like `rm -rf /`
  to a pattern. Treat patterns as a coarse filter, not a parser.
* **Patterns are Python regexes.** `tomllib` gives you literal strings, so use
  `'''...'''` TOML strings for patterns full of backslashes.

## Worked example

```toml
schema      = 1
name        = "team"
description = "A repository that must not publish by itself."
default     = "review"          # strict: unknown actions escalate

[[rules]]
id       = "shell.tests"
kind     = "shell"
effect   = "allow"
priority = 10                   # narrow allows sit at the top
pattern  = '''(?i)\b(?:pytest|ruff|mypy)\b'''
reason   = "the local quality tooling is always fine"

[[rules]]
id       = "shell.read-only-git"
kind     = "shell"
effect   = "allow"
priority = 20
pattern  = '''(?i)\bgit\s+(?:status|log|diff|show)\b'''
reason   = "read-only git commands change nothing"

[[rules]]
id       = "shell.publish"
kind     = "shell"
effect   = "deny"
priority = 5                    # ...but publishing is never the agent's call
pattern  = '''(?i)\b(?:git\s+push|npm\s+publish|twine\s+upload)\b'''
reason   = "publishing is a human decision here"
```

Check a policy without running anything:

```console
$ sentinel policy check --policy .sentinel/policy.toml --target "git push origin main"
DENY   [team] shell.publish: publishing is a human decision here
       action: shell git push origin main
```

## Built-in presets

| Preset | Default | Character |
| --- | --- | --- |
| `permissive` | `allow` | Blocks only the catastrophic. Use it when you want a record more than you want control. |
| `standard` | `allow` | Blocks the catastrophic, escalates the risky, allows the rest. Recommended starting point. |
| `strict` | `review` | Ships no allow rules at all: nothing shell-shaped runs without a human. Grow an allow list onto it. |

`examples/policies/standard.toml` is the `standard` preset written out by hand,
which is the intended way to start a project-specific policy: copy it, then
narrow it.

## Validation errors

`load_policy` fails loudly, never partially. You get a `PolicyError` for a
missing or unreadable file, invalid TOML, an unsupported `schema`, a missing
`name`, an unknown `default` or `effect`, an unknown `kind`, a duplicate rule
`id`, a non-integer `priority`, malformed `tags`, and patterns that do not
compile.

## Pitfalls worth knowing

* A rule with no `kind` matches *every* action kind. Useful for a catch-all
  `review`, dangerous as a catch-all `allow`.
* `deny` rules should be the most specific things in the file. A `deny` on the
  word `rm` will also block `rm -i scratch.txt`, which is fine, but it will
  also block a test named `test_rm_helpers.py` if the subject is a shell
  command that mentions it.
* Changing a rule `id` breaks continuity in old journals. Add a new id instead,
  and retire the old one.
* Patterns are not a sandbox. See [`threat-model.md`](threat-model.md) for what
  a policy cannot do.

