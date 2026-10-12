"""Turning a journal into something a person or a tool can read.

Three renderings, all built from one tolerant scan:

* :func:`transcript` — the reading order a human wants: one block per session,
  the proposal, the verdict, the answer, the outcome;
* :func:`html_report` — the same, as one self-contained file, for somebody who
  does not have the journal;
* :func:`sarif_report` — the findings, in the shape code-scanning tools consume.

None of them executes anything. A journal is evidence, not a script, and a
command named "replay" that re-ran commands would be an unpleasant surprise.

Every value that came out of the journal is escaped before it reaches the HTML.
A journal records what an agent typed, and an agent can type ``<script>``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from ._version import __version__
from .anchors import verify_with_anchors
from .events import Event, EventType
from .journal import Journal, VerifyReport

_EFFECT_COLOURS = {"allow": "#1a7f37", "review": "#9a6700", "deny": "#b42318"}
_SARIF_LEVELS = {"deny": "error", "review": "warning"}


@dataclass(frozen=True)
class SessionBlock:
    """One session's worth of records, plus whatever was not inside a session."""

    session_id: str | None
    events: tuple[Event, ...]

    @property
    def start(self) -> Event | None:
        return _first(self.events, EventType.SESSION_START)

    @property
    def end(self) -> Event | None:
        return _first(self.events, EventType.SESSION_END)

    @property
    def policy(self) -> str:
        return _text(self.start.payload.get("policy")) if self.start else ""

    @property
    def fingerprint(self) -> str:
        return _text(self.start.payload.get("policy_fingerprint")) if self.start else ""

    @property
    def workspace(self) -> str:
        return _text(self.start.payload.get("workspace")) if self.start else ""

    @property
    def outcome(self) -> str:
        if self.end is None:
            return "open" if self.start is not None else ""
        return _text(self.end.payload.get("outcome"), "ok")

    def render_title(self) -> str:
        """The heading line for this block."""
        if self.start is None:
            return "(records outside any session)"
        parts = [f"session {(self.session_id or '')[:12]}"]
        if self.policy:
            parts.append(f"policy {self.policy} ({self.fingerprint[:12]})")
        if self.workspace:
            parts.append(f"workspace {self.workspace}")
        return "  ".join(parts)


def sessions(events: Sequence[Event]) -> list[SessionBlock]:
    """Group records into the sessions they belong to.

    Records before the first ``session.start`` — a bare ``journal note``, say —
    get a block of their own with no id. They are still evidence.
    """
    blocks: list[SessionBlock] = []
    pending: list[Event] = []
    session_id: str | None = None
    inside = False

    def flush() -> None:
        nonlocal pending, session_id, inside
        if pending:
            blocks.append(SessionBlock(session_id=session_id, events=tuple(pending)))
        pending = []
        session_id = None
        inside = False

    for event in events:
        if event.type is EventType.SESSION_START:
            flush()
            inside = True
            session_id = _optional_text(event.payload.get("session_id"))
            pending.append(event)
            continue
        pending.append(event)
        if event.type is EventType.SESSION_END and inside:
            flush()
    flush()
    return blocks


def build_report(
    journal: Journal,
    *,
    anchors: str | Path | None = None,
    key: bytes | None = None,
) -> VerifyReport:
    """Verify the journal, against its anchors when any were given."""
    if anchors is None:
        return journal.verify()
    return verify_with_anchors(journal, anchor_path=anchors, expected_key=key)


# ----------------------------------------------------------------- transcript
def transcript(
    journal: Journal,
    *,
    session: str | None = None,
    anchors: str | Path | None = None,
    key: bytes | None = None,
) -> str:
    """A readable account of what the journal holds.

    Args:
        session: Only show the session with this id, or this id as a prefix —
            the rendering shows twelve characters, so that is what people have.
    """
    scan = journal.scan()
    report = build_report(journal, anchors=anchors, key=key)
    blocks = sessions(scan.events)
    if session is not None:
        blocks = [block for block in blocks if (block.session_id or "").startswith(session)]

    lines = [
        f"journal: {journal.path}",
        f"records: {len(scan.events)}",
        f"head:    {report.head_hash or '(empty)'}",
    ]
    if report.anchors_checked:
        lines.append(f"anchors: {report.anchors_checked} checked")
    lines.append(f"status:  {'ok' if report.ok else 'BROKEN — ' + _issue_tally(report)}")

    if not blocks:
        lines.append("")
        lines.append("nothing to replay")
        return "\n".join(lines)

    for block in blocks:
        lines.append("")
        lines.append(block.render_title())
        for event in block.events:
            detail = _describe(event)
            line = f"  {event.render()}"
            if detail:
                line += f"  {detail}"
            lines.append(line)

    if report.issues:
        lines.append("")
        lines.append("problems found")
        lines.extend(f"  - {issue.render()}" for issue in report.issues)
    return "\n".join(lines)


def transcript_json(
    journal: Journal,
    *,
    session: str | None = None,
    anchors: str | Path | None = None,
    key: bytes | None = None,
) -> dict[str, Any]:
    """The same account, as something a program can consume."""
    scan = journal.scan()
    report = build_report(journal, anchors=anchors, key=key)
    blocks = sessions(scan.events)
    if session is not None:
        blocks = [block for block in blocks if (block.session_id or "").startswith(session)]

    return {
        "journal": str(journal.path),
        "records": len(scan.events),
        "head": report.head_hash,
        "ok": report.ok,
        "issues": [issue.render() for issue in report.issues],
        "sessions": [
            {
                "session_id": block.session_id,
                "policy": block.policy,
                "policy_fingerprint": block.fingerprint,
                "workspace": block.workspace,
                "outcome": block.outcome,
                "events": [event.to_record() for event in block.events],
            }
            for block in blocks
        ],
    }


# ----------------------------------------------------------------------- html
def html_report(
    journal: Journal,
    *,
    anchors: str | Path | None = None,
    key: bytes | None = None,
) -> str:
    """A single self-contained HTML file. No scripts, no external assets."""
    scan = journal.scan()
    report = build_report(journal, anchors=anchors, key=key)
    blocks = sessions(scan.events)

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>agent-sentinel journal</title>",
        f"<style>{_STYLESHEET}</style>",
        "</head><body>",
        "<h1>agent-sentinel journal</h1>",
        _html_summary(journal, report, len(scan.events)),
    ]

    for block in blocks:
        parts.append("<section>")
        parts.append(f"<h2>{escape(block.render_title())}</h2>")
        parts.append(
            "<table><thead><tr><th>seq</th><th>time</th><th>actor</th>"
            "<th>event</th><th>detail</th><th>hash</th></tr></thead><tbody>"
        )
        for event in block.events:
            parts.append(_html_row(event))
        parts.append("</tbody></table>")
        parts.append("</section>")

    if report.issues:
        parts.append("<section><h2>Problems found</h2><ul>")
        parts.extend(f"<li>{escape(issue.render())}</li>" for issue in report.issues)
        parts.append("</ul></section>")

    parts.append(
        f"<footer>generated by agent-sentinel {escape(__version__)}</footer></body></html>"
    )
    return "\n".join(parts)


def _html_summary(journal: Journal, report: VerifyReport, records: int) -> str:
    verdict = "ok" if report.ok else "BROKEN"
    rows = [
        ("journal", str(journal.path)),
        ("records", str(records)),
        ("head", report.head_hash or "(empty)"),
    ]
    if report.anchors_checked:
        anchor_line = f"{report.anchors_checked} checked, latest at seq {report.latest_anchor_seq}"
        if report.signer:
            anchor_line += f", signed by {report.signer}"
        rows.append(("anchors", anchor_line))
    rows.append(("status", verdict if report.ok else f"{verdict} — {_issue_tally(report)}"))

    body = "".join(
        f"<tr><th>{escape(name)}</th><td>{escape(value)}</td></tr>" for name, value in rows
    )
    status_class = "ok" if report.ok else "broken"
    return f'<table class="summary {status_class}"><tbody>{body}</tbody></table>'


def _html_row(event: Event) -> str:
    detail = _describe(event)
    css = ""
    if event.type is EventType.POLICY_DECISION:
        css = f' class="{escape(_text(event.payload.get("effect")))}"'
    elif event.type is EventType.ACTION_RESULT:
        status = _text(event.payload.get("status"))
        css = f' class="{escape(status)}"'
    return (
        "<tr>"
        f"<td>{event.seq}</td>"
        f"<td>{escape(event.ts)}</td>"
        f"<td>{escape(event.actor.value)}</td>"
        f"<td><code{css}>{escape(event.type.value)}</code></td>"
        f"<td>{escape(detail)}</td>"
        f"<td><code>{escape(event.hash[:12])}</code></td>"
        "</tr>"
    )


_STYLESHEET = """
body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem;
       color: #1f2328; line-height: 1.5; }
h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; margin-top: 1.5rem; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; font-size: 0.9rem; }
th, td { border: 1px solid #d0d7de; padding: 0.35rem 0.5rem; text-align: left;
         vertical-align: top; }
th { background: #f6f8fa; font-weight: 600; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
table.summary { width: auto; } table.summary th { width: 8rem; }
table.summary.broken td { color: #b42318; font-weight: 600; }
code.allow { color: #1a7f37; } code.review { color: #9a6700; } code.deny { color: #b42318; }
footer { margin-top: 2rem; color: #656d76; font-size: 0.8rem; }
""".strip()


# ---------------------------------------------------------------------- sarif
def sarif_report(
    journal: Journal,
    *,
    anchors: str | Path | None = None,
    key: bytes | None = None,
) -> dict[str, Any]:
    """Findings in SARIF 2.1.0.

    Every verdict that is not ``allow`` becomes one result. There are no file
    locations to point at — an action is a command or a path, not a line in a
    source file — so these are repository-level results, not inline annotations.
    Problems with the journal itself are reported as tool notifications rather
    than dressed up as findings about the code.
    """
    scan = journal.scan()
    report = build_report(journal, anchors=anchors, key=key)

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for event in scan.events:
        if event.type is not EventType.POLICY_DECISION:
            continue
        effect = _text(event.payload.get("effect"))
        if effect == "allow" or effect not in _SARIF_LEVELS:
            continue
        rule_id = _text(event.payload.get("rule")) or "policy-default"
        reason = _text(event.payload.get("reason"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": reason or rule_id},
                "properties": {"effect": effect, "policy": _text(event.payload.get("policy"))},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVELS[effect],
                "message": {
                    "text": f"{_text(event.payload.get('reason')) or rule_id} (seq {event.seq})"
                },
                "properties": {
                    "effect": effect,
                    "seq": event.seq,
                    "timestamp": event.ts,
                },
            }
        )

    notifications = [
        {
            "level": "error",
            "descriptor": {"id": issue.kind},
            "message": {"text": issue.render()},
            "properties": {"seq": issue.seq, "line": issue.line, "source": issue.source},
        }
        for issue in report.issues
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/shuhe7859-dotcom/agent-sentinel",
                        "rules": [rules[key_] for key_ in sorted(rules)],
                        "properties": {
                            "journal": str(journal.path),
                            "head": report.head_hash,
                            "anchorsChecked": report.anchors_checked,
                        },
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.ok,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
            }
        ],
    }


# ------------------------------------------------------------------ internals
def _describe(event: Event) -> str:
    """One line about a record, in the terms a reader cares about."""
    payload = event.payload
    if event.type is EventType.ACTION_PROPOSED:
        return f"{_text(payload.get('kind'))} {_text(payload.get('target'))}".strip()
    if event.type is EventType.POLICY_DECISION:
        rule = _text(payload.get("rule")) or "(policy default)"
        return f"{_text(payload.get('effect'))} from {rule}"
    if event.type is EventType.APPROVAL_REQUESTED:
        return f"waiting for a human: {_text(payload.get('command'))}"
    if event.type is EventType.APPROVAL_DECIDED:
        verdict = "granted" if payload.get("granted") else "refused"
        note = _text(payload.get("note"))
        return f"{verdict} by {event.actor.value}" + (f" — {note}" if note else "")
    if event.type is EventType.ACTION_RESULT:
        return _describe_result(payload)
    if event.type is EventType.NOTE:
        return _text(payload.get("message"))
    if event.type is EventType.SESSION_START:
        policy = _text(payload.get("policy"))
        if not policy:
            return ""
        return f"policy {policy} ({_text(payload.get('policy_fingerprint'))[:12]})"
    if event.type is EventType.SESSION_END:
        return f"{payload.get('actions', 0)} action(s), {_text(payload.get('outcome'), 'ok')}"
    return ""


def _describe_result(payload: Mapping[str, Any]) -> str:
    parts = [_text(payload.get("status"), "unknown")]
    for key in ("returncode", "status_code", "duration_ms"):
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            parts.append(f"{key}={value}")
    error = _text(payload.get("error"))
    if error:
        parts.append(error)
    return "  ".join(parts)


def _first(events: Sequence[Event], kind: EventType) -> Event | None:
    return next((event for event in events if event.type is kind), None)


def _issue_tally(report: VerifyReport) -> str:
    return f"{len(report.issues)} issue(s)"


def _text(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) and value else default


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def dumps(payload: Any) -> str:
    """JSON with the same settings the journal uses, so output stays comparable."""
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
