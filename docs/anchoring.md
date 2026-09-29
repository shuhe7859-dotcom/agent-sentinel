# Anchoring

A hash chain proves a journal is *internally* consistent. It cannot prove the
journal is *complete*, because whoever can write the file can also delete its
last lines and leave a shorter chain that verifies perfectly. Two questions
stay open:

* did anything get removed from the end?
* was the whole file replaced with a different but valid one?

Both are answered by writing the head hash down **outside the journal**, in a
place the attacker is less likely to control. That written-down value is an
anchor.

## What an anchor is

One JSON object per line, in an anchor file of your choosing:

```json
{"schema":"1.0","seq":42,"hash":"5f2c602b66bba94b4818e428c1699b8d185811537ddd69f78f973e1d9c375710",
 "ts":"2026-09-29T09:14:02.118Z","journal":"session.jsonl","session":"b21629681de4",
 "note":"end of CI job","tool":"agent-sentinel 0.1.0","signature":null}
```

An anchor names a point the journal reached: record number `seq` had digest
`hash` at time `ts`. `session` is filled in when the anchored record was a
`session.end`, so a reader can see which session the anchor closes.

## Taking one

```console
$ sentinel journal anchor .sentinel/session.jsonl \
      --file .sentinel/anchors.jsonl --note "end of CI job"
anchor  seq 42  head 5f2c602b66bba94b  journal session.jsonl  session b21629681de4
```

The summary line goes to **stdout** before anything else happens, so a CI log
that captured it still holds the evidence even if the steps after it fail.

`--file` appends to an anchor file. `--command` hands the same JSON to a program
on its standard input, which is how you publish an anchor anywhere else — a
transparency log, another machine, a chat message. Use both, or either:

```console
$ sentinel journal anchor .sentinel/session.jsonl \
      --file .sentinel/anchors.jsonl \
      --command "ssh ci@keeper 'cat >> /var/log/agent-anchors.jsonl'"
```

If `--command` exits non-zero, `sentinel` exits `4` — but the file was already
written and the summary already printed, and it says so, because a failed
publisher should not look like a failed anchor.

## Checking against one

```console
$ sentinel journal verify .sentinel/session.jsonl --anchors .sentinel/anchors.jsonl
journal: .sentinel/session.jsonl
records: 42
head:    5f2c602b66bba94b4818e428c1699b8d185811537ddd69f78f973e1d9c375710
anchors: 1 checked, latest at seq 42
status:  ok - hash chain verified
```

An anchor file that is missing, or that holds no usable anchor, is an **error**
rather than a pass. That is the point: evidence that was supposed to exist and
does not is exactly what anchoring is for. If `--anchors` were optional in
spirit, deleting the anchor file would be the easiest attack of all.

Two new failure kinds come out of the comparison:

| Kind | Meaning |
| --- | --- |
| `truncated` | an anchor points past the end of the journal |
| `rewritten` | the record at an anchored position no longer has the anchored digest |

```
$ sentinel journal verify .sentinel/session.jsonl --anchors .sentinel/anchors.jsonl
status:  BROKEN - 1 issue(s)
  - anchor (seq 42): truncated: anchored at seq 42, but the journal now ends at
    seq 39: 3 records missing
```

## Anchor more than once

**Every anchor is a checkpoint.** Anchoring at seq 10 and again at seq 40 means
three separate things are pinned: the record at 10, the record at 40, and the
fact that the log was 40 records long. An attacker who rewrites record 12 has to
recompute everything after it, which changes the record at 40, which the later
anchor catches.

It also narrows what truncation looks like. Cutting a 40-record log back to 10
records matches the early anchor exactly and is invisible to it — but it is a
clear `truncated` to the anchor at 40. A single anchor can only speak for the
state it saw.

## Signing an anchor

An anchor says a journal reached a state. A signature says *who* said so.

```console
$ sentinel keygen --private .sentinel/keys/signing.key.json \
                  --public  .sentinel/keys/signing.pub.json
private key: .sentinel/keys/signing.key.json
public key:  .sentinel/keys/signing.pub.json
fingerprint: 7ef9de91727f88d8

$ sentinel journal anchor .sentinel/session.jsonl \
      --file .sentinel/anchors.jsonl --sign-with .sentinel/keys/signing.key.json
anchor  seq 42  head 5f2c602b66bba94b  journal session.jsonl  signed by 7ef9de91727f88d8

$ sentinel journal verify .sentinel/session.jsonl \
      --anchors .sentinel/anchors.jsonl --key .sentinel/keys/signing.pub.json
anchors: 1 checked, latest at seq 42, signed by 7ef9de91727f88d8
status:  ok - hash chain verified
```

The signature covers the anchor's canonical JSON with the `signature` field
removed, so changing any other field invalidates it. Two more failure kinds:

| Kind | Meaning |
| --- | --- |
| `bad-signature` | the signature does not match the anchor, **or** a key was supplied and an anchor is unsigned |
| `key-mismatch` | the anchor was signed by a different key than the one you pinned |

**Pin the key.** Without `--key`, a signature is checked against the public key
carried inside the anchor. That proves the anchor file has not been edited by
someone who lacks the private key, but not much else: whoever can rewrite the
anchor can swap the embedded key too. Passing `--key` is what makes the check
mean "signed by *this* key", and it is also what turns "unsigned" into a
failure rather than a shrug.

`--key` without `--anchors` is an error, since there is nothing to check it
against.

### Ed25519 is an optional extra

The runtime core of agent-sentinel imports nothing but the standard library, and
that is worth keeping. Ed25519 does need a real implementation, so it lives
behind an extra:

```console
$ pip install "agent-sentinel[sign]"
```

Without it, everything else works; only signing and signature checking raise,
with a message saying what to install.

### Looking after the private key

`sentinel keygen` writes to `.sentinel/keys/` by default, which `.gitignore`
already excludes, so a private key cannot be committed by accident. It refuses
to overwrite an existing key unless you pass `--force`, because losing a signing
key means losing the ability to vouch for anchors already published.

On POSIX the private key is written with mode `0600`. On Windows `chmod` cannot
express that, so `keygen` says so and expects you to place the file somewhere
only you can read. The public half is safe to publish; the private half is not.

## What anchoring still does not do

* **It cannot detect the absence of evidence you had no reason to expect.**
  If nobody anchors a journal, nobody can tell that records were dropped. The
  same goes for an anchor file that an attacker simply deletes and you never
  ask about: only asking, with `--anchors`, makes its absence an error.
* **It is only as external as the place you put it.** An anchor file next to the
  journal protects against accidents and casual rewriting, not against someone
  with write access to both. A CI log, another machine, or a service you do not
  control is what makes it bite.
* **A signature is not authentication of a person.** It says the holder of a
  private key signed. Deciding who holds that key, and whether they should have,
  is yours.
* **Nothing here makes a journal confidential.** It proves integrity and
  authorship. Contents are still whatever the guards decided to write down, and
  those are deliberately summaries rather than payloads.
