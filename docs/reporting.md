# Reading a journal back

A journal is JSON Lines, so `grep` and `jq` always work. Two commands go
further: `replay` turns it into the reading order a person wants, and `export`
turns it into something you can hand to somebody who does not have the file.

Neither of them executes anything. A journal is evidence, not a script.

## Replay

```console
$ sentinel journal replay .sentinel/session.jsonl
journal: .sentinel/session.jsonl
records: 16
head:    0c108425ad897152f65bec8a583fdf3ec76ee9060a8765b001ce38c42a932686
status:  ok

session 018bf710618f  policy standard (d8e95dff9ad0)  workspace /repos/demo
  #1   …Z sentinel session.start    410061b96cc6  policy standard (d8e95dff9ad0)
  #2   …Z agent    action.proposed  6f076e0032ad  shell echo from-dash-c
  #3   …Z sentinel policy.decision  66d8d1978f84  allow from (policy default)
  #4   …Z sentinel action.result    18758e3fb361  executed  returncode=0  duration_ms=19
  #5   …Z sentinel session.end      8200fcd71184  1 action(s), ok

session 9cfd414a02d2  policy standard (d8e95dff9ad0)  workspace /repos/demo
  #11  …Z sentinel session.start    ae929cae288d  policy standard (d8e95dff9ad0)
  #12  …Z agent    action.proposed  0269922082dc  shell rm -rf /
  #13  …Z sentinel policy.decision  a4ffca02548f  deny from shell.rm-root
  #14  …Z sentinel action.result    4f970351e78c  denied
  #15  …Z sentinel session.end      8b5f09dfeb2f  1 action(s), ok

(records outside any session)
  #16  …Z human    note             0c108425ad89  looked at this by hand
```

Records are grouped by the session they belong to. Anything written outside one
— a bare `sentinel journal note`, say — gets its own block rather than being
hidden: it is still evidence.

* **`--session ID`** narrows the transcript to one session. The id may be a
  prefix, because the rendering shows twelve characters and that is what people
  copy.
* **`--json`** prints the same thing as an object: the journal, its head, whether
  it verified, and one entry per session with its records. For a script that
  wants to act on the log rather than read it.
* **`--anchors`** checks against an anchor file on the way, so the transcript
  says whether the journal is complete, not just whether it is self-consistent.

A damaged line does not stop the transcript. `iter_events()` refuses to guess —
right for reading, wrong for reporting — so `replay` uses a tolerant scan and
lists what it could not read under **problems found**. A broken journal is
exactly when you most want something to look at.

## Export

```console
$ sentinel journal export .sentinel/session.jsonl --format html --out report.html
wrote html report to report.html
```

Without `--out` the report goes to standard output, so it pipes.

### HTML

One self-contained file: no scripts, no external assets, inline styles. A
summary table with the journal path, record count, head hash and verification
verdict; then one section per session, with a row per record and the verdicts
coloured by effect. `--anchors` and `--key` fold the anchor check into the
verdict, which makes the export a complete piece of evidence on its own.

Everything that came out of the journal is escaped on the way in. A journal
records what an agent typed, and an agent can type `<script>`.

### SARIF

For tools that consume findings — code scanning, review dashboards:

```console
$ sentinel journal export .sentinel/session.jsonl --format sarif
```

SARIF 2.1.0, one run, one **result** per verdict that is not `allow`:

| Journal | SARIF |
| --- | --- |
| a `deny` decision | a result at `error` |
| a `review` decision | a result at `warning` |
| the rule that fired | `ruleId`, or `policy-default` when the policy default decided |

`ruleId` is the rule's id, never its reason text, so a rule that is reworded
does not look like a new finding.

**The honest limitation:** an action is a command or a path, not a line in a
source file, so these results carry no file locations. They are repository-level
findings, not inline annotations — GitHub code scanning will show them against
the repository rather than against a line of code.

Problems with the journal itself — an unreadable line, a truncated tail, a
signature that does not verify — are **not** dressed up as findings about your
code. They go into `invocations[].toolExecutionNotifications`, which is what
SARIF has for "the tool could not do its job", and
`invocations[].executionSuccessful` is false.


## Contextual evidence timeline

HTML exports now group new actions by `action_id` and sessions by `session_id`,
including interleaved sessions. Expand a native `<details>` panel to see the proposed
inputs, policy, exact approval scope, durable claim and execution result. A claimed
action without a result is labelled **outcome unknown**; its approval remains spent.
Old events retain their sequential presentation and explicitly lack precise action
correlation. The report is a single file with no scripts, fonts, CDN or external assets.
All log-provided strings are escaped, including targets, policy reasons and contexts.

`journal export` remains diagnostic: it renders readable evidence even from damaged
logs and highlights BROKEN. Policy comparison below is stricter and rejects damaged
inputs rather than calculating apparently trustworthy statistics.

## Counterfactual policy comparison

```console
sentinel policy compare --journal .sentinel/session.jsonl --old standard --new strict --format text
sentinel policy compare --journal .sentinel/session.jsonl --old standard --new strict --format html --out comparison.html
sentinel policy compare --journal .sentinel/session.jsonl --old old.toml --new new.toml --format json --anchors anchors.jsonl
```

`--old` and `--new` accept preset names or TOML files. `--format` defaults to `text`;
`--out` is optional. `--key` pins an anchor signer and requires `--anchors`.
The output cannot overwrite one of the command's input paths.

Comparison takes one scanned snapshot, verifies it (and optional anchors), restores
**every** action proposal and evaluates both supplied policies. It never executes
commands, writes target files, fetches URLs or consumes approvals. It does not replay
runtime structural checks, machine state or human decisions. The supplied old policy
is a comparison baseline, not a claim that it was the historical effective policy.

Outputs include policy names/fingerprints, every decision with rule and reason,
a 3-by-3 allow/review/deny transition matrix, changed-decision count, changed-rule
count, review-action counts and rule hits. Every proposal is a sample; retries are
not deduplicated. Review counts are potential review workload, not actual human prompts.
JSON carries its own `schema: 1`, separate from journal and approval versions.

Success (including policy differences and zero proposals) exits 0. Missing files,
invalid policies, broken chains/anchors, or unrestorable action records exit 1; no
records are silently skipped. An existing empty journal produces zero counts.

## Reproducible offline experiments

```console
python examples/evidence_demo.py
```

This creates a fresh `.sentinel/evidence-*` directory on every run and prints the
path to `index.html`. It only writes demo files; no historical shell commands or
network calls are executed. The three scenes show changed-content approval rejection,
standard-versus-strict comparison, and a tampered copy. The original log and its
checkpoint remain intact. An additional simulated crash demonstrates an unknown result.

`examples/cases/evaluation.toml` contains 14 manually labelled teaching cases, including
normal actions and command variants. The demo writes `evaluation.html`, `.json` and
`.txt`. `compare_cases(cases, old, new)` is the library evaluation API.

| Metric | Numerator | Denominator |
| --- | --- | --- |
| unsafe_allow_rate | Expected review/deny but predicted allow | All expected review/deny cases |
| unnecessary_restriction_rate | Expected allow but predicted review/deny | All expected allow cases |
| review_rate | Predicted review | All cases |

JSON reports each numerator, denominator and fractional rate. Zero denominators
produce null, rendered as N/A / 不适用. The sample illustrates a tradeoff; it is not
representative evidence of general security effectiveness. Unlabelled real journals
have no accuracy metrics. Add held-out labelled cases before drawing broader conclusions.
