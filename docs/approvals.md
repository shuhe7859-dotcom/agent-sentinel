# Approvals

A `review` verdict stops an action. What it does not do, on its own, is leave a
trace of who said yes. That is what approvals are for.

## The problem with a bare "stop"

If a guardrail can only block, three questions stay unanswerable:

1. Who allowed this to run?
2. Was it allowed *this* time, or has a blanket permission existed all along?
3. Did someone say no, and did the agent try again anyway?

Approvals answer all three by writing the human decision into the same
hash-chained journal as the action it authorises.

## The shape of it

An escalated shell command produces this, in order:

```
#1  session.start        sentinel   which policy is in force
#2  action.proposed      agent      the command
#3  policy.decision      sentinel   review, because of rule X
#4  approval.requested   sentinel   waiting for a human
#5  action.result        sentinel   status: awaiting_approval
#6  session.end          sentinel
```

Someone then runs `sentinel approve`, which appends:

```
#7  approval.decided     human      granted, scoped to this command
```

Running the command again produces:

```
#8  session.start        ...
#9  action.proposed      agent
#10 policy.decision      sentinel   review again -- the policy has not changed
#11 action.result        sentinel   status: executed, approval_seq: 7
#12 session.end          sentinel
```

Note `#10`: the policy still says `review`. The approval did not rewrite the
policy, it authorised one execution of one action. And note `#11`: the execution
records which approval it consumed, which is how the next attempt at the same
command knows it has to ask again.

## A worked example

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
policy:  standard (fingerprint d8e95dff9ad0)
REVIEW [standard] shell.credential-access: reading credential material
       action: shell echo .netrc
status:  awaiting_approval
this is waiting for a human. to grant it:
  sentinel approve .sentinel/session.jsonl --request-seq 4
then run the command again
session: session b21629681de4 [standard d8e95dff9ad0] #1-#6: 1 action(s), closed
$ echo $?
2
```

```console
$ sentinel journal pending .sentinel/session.jsonl
#4    shell       echo .netrc
        shell.credential-access: reading credential material
        to approve: sentinel approve .sentinel/session.jsonl --request-seq 4
```

```console
$ sentinel approve .sentinel/session.jsonl --request-seq 4 --note "checked with the team"
recorded approval #7 (granted) for shell echo .netrc
fingerprint: ae005ae1eccadc44
```

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
REVIEW [standard] shell.credential-access: reading credential material
       action: shell echo .netrc
status:  executed
approval: granted by event #7
.netrc
```

Run it a third time and it waits again, because the approval was spent.

## The rules

**Scoped to one action.** An approval covers an action fingerprint: a digest of
the action's kind and its normalised command or path. Approving
`git push --force origin main` does not approve `git push --force origin dev`,
and it does not approve a `file.write` to the same path.

**Single use.** The execution records the approval it consumed as
`approval_seq`. An approval that appears in any `action.result` is spent.

**First in, first out.** When several usable grants exist for the same action,
the oldest is used, so grants cannot pile up invisibly behind each other.

**Expirable.** `--expires-in MINUTES` attaches a deadline. An expired grant is
ignored, and the escalation becomes pending again.

**A refusal is evidence, not a ban.** `--refuse` records an
`approval.decided` with `granted: false`, which is worth having in the log. It
does not permanently block the action: a later attempt is escalated again, and
the journal contains both. Making refusals sticky would mean inventing a
revocation mechanism, which is a bigger idea than this milestone.

## Approving without the CLI

An in-process reviewer answers the escalation while the run is happening, and
the answer is still recorded:

```python
from agent_sentinel import GuardedRunner, Journal, PolicyEngine, load_preset


def reviewer(action, decision):
    """Return True to allow, False to refuse. Ask a human here."""
    print(f"{decision.rule_id}: {decision.reason}")
    return input(f"run {action.subject!r}? [y/N] ").strip().lower() == "y"


runner = GuardedRunner(
    PolicyEngine(load_preset("standard")),
    Journal(".sentinel/session.jsonl"),
    reviewer=reviewer,
)
runner.run("git push --force origin main")
```

The record that comes out carries `"source": "callback"`, so the journal
distinguishes an answer given live from one given later with
`sentinel approve` (`"source": "operator"`).

For unattended runs, `GuardedRunner(..., allow_review=True)` pre-approves
everything the policy escalates. It records `"source": "config"` next to each
one, so a reader can tell that nobody was actually asked. It is a deliberate,
visible choice rather than a silent widening of permissions.

## What approvals are not

* **Not authentication.** The journal records that an approval was written, and
  by which actor. It does not verify *who* ran `sentinel approve`. Anyone who
  can write to the journal file can append a grant, and the chain will still
  verify, because it is a valid record. Tying an approval to a person needs
  signing, which is milestone M3.
* **Not a lock.** The runner consults the journal; an agent that runs commands
  outside the runner never sees any of this. See
  [`threat-model.md`](threat-model.md).
* **Not a queue of work.** Nothing blocks waiting for an approval. The run ends
  with status `awaiting_approval` and exit code 2, and the caller decides what
  to do about it.
