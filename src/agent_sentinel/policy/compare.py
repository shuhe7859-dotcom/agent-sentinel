"""Read-only counterfactual decisions and labelled evaluation. Never executes actions."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator, Sequence
from html import escape
from pathlib import Path
from typing import Any

from ..anchors import verify_with_anchors
from ..errors import SentinelError
from ..events import Event, EventType
from ..journal import Journal, JournalScan
from .cases import Case
from .engine import PolicyEngine
from .models import Action, Decision, Effect

DISCLAIMER = (
    "Policy-only counterfactuals: no actions are executed. Runtime constraints and human "
    "answers are not simulated. Unlabelled journal differences do not measure accuracy."
)


class _Snapshot(Journal):
    """Use the same scanned bytes for chain, anchor and action evaluation."""

    def __init__(self, scan: JournalScan) -> None:
        super().__init__(scan.path)
        self._scan = scan

    def scan(self) -> JournalScan:
        return self._scan

    def head(self) -> Event | None:
        return self._scan.events[-1] if self._scan.events else None

    def iter_events(self) -> Iterator[Event]:
        return iter(self._scan.events)


def _verdict(decision: Decision) -> dict[str, Any]:
    return {"effect": decision.effect.value, "rule": decision.rule_id, "reason": decision.reason}


def _row(action: Action, old: PolicyEngine, new: PolicyEngine) -> dict[str, Any]:
    before, after = old.evaluate(action), new.evaluate(action)
    return {
        "action": action.as_dict(),
        "old": _verdict(before),
        "new": _verdict(after),
        "changed": before.effect != after.effect,
        "rule_changed": before.rule_id != after.rule_id,
    }


def _summary(rows: list[dict[str, Any]], old: PolicyEngine, new: PolicyEngine) -> dict[str, Any]:
    effects = [effect.value for effect in Effect]
    matrix = {a: dict.fromkeys(effects, 0) for a in effects}
    for row in rows:
        matrix[row["old"]["effect"]][row["new"]["effect"]] += 1
    return {
        "schema": 1,
        "notice": DISCLAIMER,
        "policies": {
            "old": {"name": old.name, "fingerprint": old.policy.fingerprint()},
            "new": {"name": new.name, "fingerprint": new.policy.fingerprint()},
        },
        "summary": {
            "actions": len(rows),
            "changed": sum(row["changed"] for row in rows),
            "rule_changed": sum(row["rule_changed"] for row in rows),
            "transitions": matrix,
            "review_actions": {
                side: sum(r[side]["effect"] == "review" for r in rows) for side in ("old", "new")
            },
            "rule_hits": {
                side: dict(Counter(r[side]["rule"] or "(default)" for r in rows))
                for side in ("old", "new")
            },
        },
        "rows": rows,
    }


def compare_journal(
    journal: Journal,
    old: PolicyEngine,
    new: PolicyEngine,
    *,
    anchors: str | Path | None = None,
    key: bytes | None = None,
) -> dict[str, Any]:
    """Verify a journal, restore every proposal and evaluate two supplied policies."""
    if key is not None and anchors is None:
        raise SentinelError("--key requires --anchors")
    if not journal.path.is_file():
        raise SentinelError(f"journal does not exist: {journal.path}")
    try:
        snapshot = _Snapshot(journal.scan())
        integrity = snapshot.verify()
        if not integrity.ok:
            raise SentinelError(integrity.render())
        if anchors is not None:
            integrity = verify_with_anchors(snapshot, anchor_path=anchors, expected_key=key)
        if not integrity.ok:
            raise SentinelError(integrity.render())
        rows: list[dict[str, Any]] = []
        for event in snapshot.iter_events():
            if event.type is EventType.ACTION_PROPOSED:
                try:
                    action = Action.from_dict(event.payload)
                except ValueError as exc:
                    raise SentinelError(f"cannot restore action at seq {event.seq}: {exc}") from exc
                rows.append({"seq": event.seq, **_row(action, old, new)})
    except (OSError, UnicodeError) as exc:
        raise SentinelError(f"cannot read journal {journal.path}: {exc}") from exc
    result = _summary(rows, old, new)
    result.update(
        {
            "source": str(journal.path),
            "labelled": False,
            "integrity": {
                "head": integrity.head_hash,
                "records": integrity.event_count,
                "anchors_checked": integrity.anchors_checked,
                "latest_anchor_seq": integrity.latest_anchor_seq,
                "signer": integrity.signer,
            },
        }
    )
    return result


def compare_cases(cases: Sequence[Case], old: PolicyEngine, new: PolicyEngine) -> dict[str, Any]:
    """Measure a fixed labelled sample; rates are fractions, null means no denominator."""
    rows = [
        {"name": case.name, "expected": case.expect.value, **_row(case.build(), old, new)}
        for case in cases
    ]
    result = _summary(rows, old, new)
    metrics: dict[str, Any] = {}
    for side in ("old", "new"):
        restricted = [r for r in rows if r["expected"] != "allow"]
        allowed = [r for r in rows if r["expected"] == "allow"]
        metrics[side] = {
            "unsafe_allow_rate": _rate(
                sum(r[side]["effect"] == "allow" for r in restricted), len(restricted)
            ),
            "unnecessary_restriction_rate": _rate(
                sum(r[side]["effect"] != "allow" for r in allowed), len(allowed)
            ),
            "review_rate": _rate(sum(r[side]["effect"] == "review" for r in rows), len(rows)),
        }
    result.update(
        {
            "labelled": True,
            "metrics": metrics,
            "notice": DISCLAIMER
            + " Labelled rates describe only this fixed sample, not general security effectiveness.",
        }
    )
    return result


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


def _metric_text(metric: dict[str, Any]) -> str:
    value = metric["rate"]
    return (
        "不适用 / N/A"
        if value is None
        else f"{value:.1%} ({metric['numerator']}/{metric['denominator']})"
    )


def comparison_text(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        result["notice"],
        f"actions: {summary['actions']}; changed: {summary['changed']}",
        f"review actions: {summary['review_actions']['old']} -> {summary['review_actions']['new']}",
    ]
    for side, policy in result["policies"].items():
        lines.append(f"{side}: {policy['name']} ({policy['fingerprint']})")
    lines.append("transitions: " + json.dumps(summary["transitions"], ensure_ascii=False))
    lines.append("rule hits: " + json.dumps(summary["rule_hits"], ensure_ascii=False))
    for row in result["rows"]:
        lines.append(
            f"{row.get('seq', row.get('name', ''))}: {row['action']['kind']} {row['action']['target']}"
        )
        for side in ("old", "new"):
            verdict = row[side]
            lines.append(
                f"  {side}: {verdict['effect']} [{verdict['rule'] or '(default)'}] {verdict['reason']}"
            )
    for side, metrics in result.get("metrics", {}).items():
        lines.extend(f"{side} {name}: {_metric_text(value)}" for name, value in metrics.items())
    return "\n".join(lines)


def comparison_html(result: dict[str, Any]) -> str:
    """Single-file, script-free evidence report; all source text is escaped."""
    from ..report import html_document

    summary = result["summary"]
    parts = [
        f"<p>{escape(result['notice'])}</p>",
        '<div class="metrics">',
        f"<article><strong>{summary['actions']}</strong>Actions / 动作</article>",
        f"<article><strong>{summary['changed']}</strong>Changed / 判定变化</article>",
        f"<article><strong>{summary['review_actions']['old']} → {summary['review_actions']['new']}</strong>Review / 需审核</article></div>",
    ]
    for side, policy in result["policies"].items():
        parts.append(
            f"<p>{side}: <b>{escape(policy['name'])}</b> <code>{escape(policy['fingerprint'])}</code></p>"
        )
    if "integrity" in result:
        parts.append(
            "<details><summary>Source integrity / 来源完整性</summary><pre>"
            + escape(json.dumps(result["integrity"], indent=2))
            + "</pre></details>"
        )
    effects = [e.value for e in Effect]
    parts.append(
        "<h2>Transitions / 判定转换</h2><table><tr><th>Old → New</th>"
        + "".join(f"<th>{e}</th>" for e in effects)
        + "</tr>"
    )
    for effect, counts in summary["transitions"].items():
        parts.append(
            f"<tr><th>{escape(effect)}</th>"
            + "".join(f"<td>{counts[e]}</td>" for e in effects)
            + "</tr>"
        )
    parts.append(
        "</table><details><summary>Rule hits / 规则命中</summary>"
        "<table><tr><th>Rule</th><th>Old</th><th>New</th></tr>"
    )
    hits = summary["rule_hits"]
    for rule in sorted(set(hits["old"]) | set(hits["new"])):
        parts.append(
            f"<tr><th>{escape(rule)}</th><td>{hits['old'].get(rule, 0)}</td>"
            f"<td>{hits['new'].get(rule, 0)}</td></tr>"
        )
    parts.append("</table></details>")
    if result.get("labelled"):
        parts.append(
            "<h2>Labelled sample / 标注样本评测</h2><table><tr><th>Metric</th><th>Old</th><th>New</th></tr>"
        )
        for name in result["metrics"]["old"]:
            parts.append(
                f"<tr><th>{escape(name)}</th>"
                + "".join(
                    f"<td>{escape(_metric_text(result['metrics'][side][name]))}</td>"
                    for side in ("old", "new")
                )
                + "</tr>"
            )
        parts.append("</table>")
    parts.append("<h2>Actions / 逐动作证据</h2>")
    for row in result["rows"]:
        action = row["action"]
        parts.append(
            "<details><summary>"
            + escape(
                f"{row.get('seq', row.get('name', ''))} · {action['kind']} · {action['target']}"
            )
            + f" <b>{escape(row['old']['effect'])} → {escape(row['new']['effect'])}</b></summary>"
        )
        for side in ("old", "new"):
            verdict = row[side]
            parts.append(
                f"<p>{side}: {escape(verdict['rule'] or '(default)')} — {escape(verdict['reason'])}</p>"
            )
        if "expected" in row:
            parts.append(f"<p>Expected: {escape(row['expected'])}</p>")
        parts.append(
            "<pre>" + escape(json.dumps(action, ensure_ascii=False, indent=2)) + "</pre></details>"
        )
    return html_document("Policy comparison / 策略对比", "\n".join(parts))
