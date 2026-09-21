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
| `session.start` | agent / human | Context for the session. |
| `action.proposed` | agent | `kind`, `target`, optional `argv`, `cwd`, `metadata`. |
| `policy.decision` | sentinel | `effect`, `rule`, `reason`, `policy`. |
| `action.result` | sentinel | `status` plus what the guarded step observed. |
| `note` | human / agent | `message`. |
| `session.end` | human | Summary of the session. |

### `action.result` statuses

| Status | Meaning | Extra fields |
| --- | --- | --- |
| `executed` | The command ran. | `returncode`, `duration_ms`, digests, byte counts, previews |
| `timeout` | The command was killed at the deadline. | `timeout_s`, `duration_ms`, digests |
| `denied` | Policy refused; nothing ran. | `rule`, `reason` |
| `awaiting_approval` | Policy asked for review and none was given. | `rule`, `reason` |

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
