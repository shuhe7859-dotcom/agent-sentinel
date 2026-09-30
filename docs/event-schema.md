# Event schema

A journal is a UTF-8 text file with one canonical JSON object per line (JSON
Lines). Nothing about it requires this library: `grep`, `jq`, `diff` and a text
editor are all valid ways to read it.

```
{"actor":"agent","hash":"6358...","payload":{...},"prev_hash":"0000...","schema":"1.0","seq":1,"ts":"2026-09-21T13:53:20.971Z","type":"action.proposed"}
```

Keys are written in sorted order with no insignificant whitespace. That is not
cosmetic: the digest is computed over this exact rendering, so "canonical"
means "there is exactly one byte sequence for this record".

## Record fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Record format version. Currently `"1.0"`. |
| `seq` | integer | 1-based position in the chain. Must be contiguous. |
| `type` | string | See the event types below. |
| `actor` | string | `agent`, `human` or `sentinel` — who caused the record. |
| `ts` | string | UTC timestamp, ISO-8601, millisecond precision, `Z` suffix. |
| `payload` | object | Type-specific body. |
| `prev_hash` | string | SHA-256 of the previous record, or 64 zeros for the first. |
| `hash` | string | SHA-256 over this record's body, bound to `prev_hash`. |

## Event types

| Type | Actor | Payload |
| --- | --- | --- |
| `session.start` | sentinel | `session_id`, `policy`, `policy_fingerprint`, `policy_source`, `policy_default`, `rules`, `cwd`, `tool`, `metadata`. |
| `action.proposed` | agent | `kind`, `target`, optional `argv`, `cwd`, `metadata`. |
| `policy.decision` | sentinel | `effect`, `rule`, `reason`, `policy`. |
| `approval.requested` | sentinel | `fingerprint`, `kind`, `command`, `target`, `rule`, `reason`, `policy`. |
| `approval.decided` | human / sentinel | `granted`, `fingerprint`, `kind`, `command`, `request_seq`, `expires_at`, `source`, `note`. |
| `action.result` | sentinel | `status` plus what the guarded step observed, and `approval_seq` when an approval was consumed. |
| `note` | human / agent | `message`. |
| `session.end` | sentinel | `session_id`, `actions`, `outcome` (`ok` or `error`), `head`. |

### `session.start`

`policy_fingerprint` is a SHA-256 over the policy's content, and is independent
of where the file was loaded from. It is what ties a journal to the exact rules
that were in force: reload the policy revision you think was used, call
`Policy.fingerprint()`, and compare. `head` in `session.end` is the digest of
the last record written *before* the session closed, which is a convenient value
to publish somewhere else (see milestone M3).

### `approval.decided`

`source` says why an answer exists, and is one of:

| Source | Meaning |
| --- | --- |
| `operator` | Someone ran `sentinel approve`. |
| `callback` | A `reviewer` callback answered inside the run. `note` says which kind: `answered at the terminal` for `--interactive`, the default text for one an embedder supplied. |
| `config` | `allow_review` pre-approved the run. Nobody was asked. |

`fingerprint` is a digest of the action's kind and its normalised command or
path, so a grant authorises exactly one action. `expires_at`, when present, is
an ISO-8601 UTC instant after which the grant stops counting. See
[`approvals.md`](approvals.md) for the full rules.

### `action.result` statuses

| Status | Guard | Meaning | Extra fields |
| --- | --- | --- | --- |
| `executed` | shell | The command ran. | `returncode`, `duration_ms`, stdout/stderr digests, byte counts, previews |
| `timeout` | shell, network | Killed at the deadline, or gave up waiting. | `timeout_s`, `duration_ms`, digests |
| `written` | filesystem | The file was written. | `bytes_written`, `sha256`, `duration_ms` |
| `deleted` | filesystem | The file was removed. | `duration_ms` |
| `fetched` | network | A response came back; read `status_code`. | `status_code`, `content_type`, `location`, `bytes_received`, `sha256`, `truncated` |
| `denied` | all | Policy refused, or the guard did. | `rule`, `reason`, plus the guard's context |
| `awaiting_approval` | all | Policy asked for review and nobody has answered. | `rule`, `reason` |
| `refused` | all | A reviewer callback answered "no". | `rule`, `reason` |
| `failed` | filesystem, network | The attempt raised an I/O or transport error. | `error`, plus the guard's context |

Every guarded action's `action.result` also carries the context its guard
contributes: a `policy.decision` and an `action.result` for a filesystem action
both record `path`, `resolved` and `containment`, and both record `url` and
`method` for a network action. The verdict and its outcome therefore read as one
story without cross-referencing.

### Content is recorded deliberately, per guard

| Guard | What it writes to the journal |
| --- | --- |
| shell | Digest, byte count, **and a truncated preview** of stdout and stderr |
| filesystem | Digest and byte count only — never the file's contents |
| network | Status, content type, digest, byte count — never the response body |

A command's output is transient and is the first thing anyone reaches for when
reading a journal. A file or a response body is neither: it is persistent
elsewhere, its digest is enough to prove identity, and it frequently contains
secrets. A journal is meant to be shareable, so those two guards keep the
contents for the caller instead.

`approval_seq` is present whenever an approval authorised the execution. A
`sentinel journal verify`-style reader can therefore tell, for every execution,
which human decision let it happen -- and can mark that approval as spent.

## The hash chain

For every record:

```
body      = {schema, seq, type, actor, ts, payload, prev_hash}   # everything but `hash`
canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
hash      = sha256(f"{prev_hash}\n{canonical}".encode("utf-8")).hexdigest()
```

Because `prev_hash` is part of `body`, a record's digest transitively commits to
every record before it. The head hash is therefore a single value that
summarises the whole session.

```
seq 1  prev_hash = 0000…0000  hash = a1b2…
seq 2  prev_hash = a1b2…      hash = c3d4…
seq 3  prev_hash = c3d4…      hash = e5f6…   ← head
```

## What verification checks

`journal.verify()` walks the file and reports every problem it finds rather
than stopping at the first:

| Issue kind | Raised when |
| --- | --- |
| `malformed` | The line is not JSON, is not an object, fails validation, or has an unknown type/actor. |
| `sequence` | `seq` is not exactly one more than the previous record. |
| `link` | `prev_hash` does not equal the previous record's `hash`. |
| `hash` | The recomputed digest of the record does not match the stored `hash`. |

An empty or missing journal verifies as `ok` with `event_count == 0`. That is
deliberate: "nothing happened" is a valid and honest answer, distinct from
"the log is broken".

```
$ sentinel journal verify .sentinel/session.jsonl
journal: .sentinel/session.jsonl
records: 6
head:    5f2c602b66bba94b4818e428c1699b8d185811537ddd69f78f973e1d9c375710
status:  ok - hash chain verified
```

With a broken chain the last line becomes, for example:

```
status:  BROKEN - 1 issue(s)
  - line 2 (seq 2): hash: record content no longer matches its digest
```

## What is deliberately not stored

Full command output. A guarded command records the SHA-256 of stdout and stderr,
their byte counts, and the first 2000 characters. That keeps a chatty build from
inflating the log while still letting you prove later that a given output
matches the digest. Raise `DEFAULT_PREVIEW_CHARS` in
`agent_sentinel/guards/shell.py` if a project needs more verbatim output.

## Anchoring does not change any of this

An anchor is a separate JSON Lines file with its own `schema`, recording a `seq`
and the `hash` a journal had reached. The record format above does not move when
you start anchoring, and `SCHEMA_VERSION` stays where it is. See
[`anchoring.md`](anchoring.md) for that format, and for what it catches.

## Compatibility rules

* Adding an optional field to `payload` is backwards compatible.
* Adding a new `type` or a new `action.result` status is backwards compatible;
  readers must tolerate unknown values in `payload`, and this release errors on
  unknown *top-level* `type` values so that a chain cannot be silently
  misread.
* Changing the hashing recipe or renaming a top-level field requires bumping
  `schema` and shipping a migration. Old journals keep verifying under the
  schema version they were written with.

## Reading a journal without this library

```console
$ jq -r 'select(.type=="policy.decision") | "\(.seq)\t\(.payload.effect)\t\(.payload.rule)"' \
    .sentinel/session.jsonl
1       allow   (policy default)
2       deny    shell.rm-root
```
