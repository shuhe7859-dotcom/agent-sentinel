# 1. Record architecture decisions

* Status: accepted
* Date: 2026-09-21

## Context

agent-sentinel makes claims about safety and about evidence. Those claims are
easy to undermine later by a reasonable-looking change: a rule merged into
another, a hash field renamed, a default relaxed from `review` to `allow`. The
reasoning behind such choices is invisible in a diff, and the person who
disagrees six months from now will not have the context.

## Decision

We keep architecture decision records in `docs/adr/`, one file per decision,
numbered sequentially. Each record states the context, the decision, its
consequences, and the alternatives that were rejected.

Format, following Michael Nygard's convention:

```markdown
# <number>. <short title>

* Status: proposed | accepted | superseded by [N](000N-....md)
* Date: YYYY-MM-DD

## Context
What is the situation, and what forces are at play?

## Decision
What we are doing, stated in the active voice.

## Consequences
What becomes easier, what becomes harder, what we are now committed to.

## Alternatives considered
What else was on the table, and why it lost.
```

Records are immutable once accepted. To change a decision, add a new record that
supersedes the old one and update the old record's status line. We do not edit
history here for the same reason we do not edit journals.

A decision deserves a record when it is expensive to reverse, when it constrains
the public interface (a rule `id`, a record field, an exit code), or when a
reasonable engineer would have chosen differently. We do not write records for
reversible local choices such as a helper function's name.

## Consequences

* The *why* behind load-bearing choices survives staff changes.
* Reviewers can point at a record instead of re-litigating a settled argument.
* Adding a decision costs a short document, which is a real but small tax.
* The ADR set becomes a place to check before proposing a change to the record
  format or to a shipped preset.

## Alternatives considered

**Comments in the code.** They drift, they are invisible from the outside, and
they cannot be superseded cleanly.

**A wiki or issue tracker.** Not versioned with the code, so a record can be
changed without review, and it disappears when the tracker is migrated.

**No written decisions.** Cheapest now, most expensive at the first disagreement
about whether the journal is allowed to change.

