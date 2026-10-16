"""Offline evidence tour. Only writes files in a fresh output directory; no commands/network."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from html import escape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_sentinel.anchors import anchor_journal, append_anchor
from agent_sentinel.approvals import claim_grant, record_decision
from agent_sentinel.events import Actor, EventType
from agent_sentinel.guards import GuardedFileSystem
from agent_sentinel.journal import Journal
from agent_sentinel.policy import PolicyEngine, load_preset
from agent_sentinel.policy.cases import load_cases
from agent_sentinel.policy.compare import (
    compare_cases,
    compare_journal,
    comparison_html,
    comparison_text,
)
from agent_sentinel.policy.models import Action
from agent_sentinel.report import html_document, html_report
from agent_sentinel.session import Session


def build_demo(parent: Path) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="evidence-", dir=parent)).resolve()
    workspace = output / "workspace"
    workspace.mkdir()
    journal = Journal(output / "approval.jsonl")
    strict = PolicyEngine(load_preset("strict"))
    standard = PolicyEngine(load_preset("standard"))
    guard = GuardedFileSystem(strict, journal, workspace=workspace)
    with Session(strict, journal, workspace=str(workspace)):
        first = guard.write("note.txt", "approved version")
        assert first.awaiting_approval
        record_decision(
            journal,
            action=first.decision.action,
            granted=True,
            source="operator",
            request_seq=first.approval_request.seq if first.approval_request else None,
            note="Demo: approved this exact content and workspace",
        )
        changed = guard.write("note.txt", "unapproved replacement")
        assert changed.awaiting_approval and not (workspace / "note.txt").exists()
        same = guard.write("note.txt", "approved version")
        assert same.ok
        # A durable claim with no result is visibly unknown, not reported as successful.
        waiting = guard.write("unknown.txt", "never executed")
        record_decision(journal, action=waiting.decision.action, granted=True, source="operator")
        data = waiting.decision.action.as_dict() | {"action_id": "demo-crash-before-result"}
        action = Action.from_dict(data)
        journal.append(EventType.ACTION_PROPOSED, Actor.AGENT, data)
        assert claim_grant(journal, action) is not None
    anchors = output / "anchors.jsonl"
    append_anchor(anchors, anchor_journal(journal, note="offline demo checkpoint"))
    (output / "approval.html").write_text(html_report(journal, anchors=anchors), encoding="utf-8")

    cases = load_cases(Path(__file__).parent / "cases" / "evaluation.toml")
    history = Journal(output / "proposals.jsonl")
    with Session(standard, history):
        history.note("Synthetic labelled teaching cases; none of these proposals were executed.")
        for case in cases:
            history.append(EventType.ACTION_PROPOSED, Actor.AGENT, case.build().as_dict())
    comparison = compare_journal(history, standard, strict)
    (output / "comparison.html").write_text(comparison_html(comparison), encoding="utf-8")
    (output / "comparison.json").write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    benchmark = compare_cases(cases, standard, strict)
    (output / "evaluation.html").write_text(comparison_html(benchmark), encoding="utf-8")
    (output / "evaluation.json").write_text(
        json.dumps(benchmark, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output / "evaluation.txt").write_text(comparison_text(benchmark), encoding="utf-8")

    # Alter a copy only. Keep the original log and its checkpoint intact.
    damaged = Journal(output / "tampered-copy.jsonl")
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["payload"]["policy"] = "tampered-policy"
    lines[0] = json.dumps(record, ensure_ascii=False)
    damaged.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not damaged.verify().ok and journal.verify().ok
    (output / "tampered.html").write_text(html_report(damaged, anchors=anchors), encoding="utf-8")
    links = [
        (
            "approval.html",
            "01 / 上下文绑定审批",
            "改变写入内容后旧审批失效; 原内容获准执行; 崩溃占用显示结果未知。",
        ),
        (
            "comparison.html",
            "02 / 策略反事实回放",
            "同一组动作交给 standard 与 strict 重新判定, 不执行历史命令。",
        ),
        (
            "evaluation.html",
            "标注样本实验",
            "展示漏放、误拦和审核比例的取舍; 结果仅代表这 14 条教学样本。",
        ),
        (
            "tampered.html",
            "03 / 篡改检测",
            "仅修改日志副本, 校验显示 BROKEN; 原日志和锚点保留完整。",
        ),
    ]
    body = "<p>Agent Sentinel · Offline evidence lab</p><p>审批范围 → 执行证据 → 策略实验</p>"
    body += '<div class="metrics"><article><strong>3</strong>演示场景</article><article><strong>14</strong>固定标注样本</article><article><strong>0</strong>外部请求 / 历史命令执行</article></div>'
    for href, title, description in links:
        body += f'<section><h2><a href="{href}">{escape(title)}</a></h2><p>{escape(description)}</p></section>'
    body += "<p>所有数据来自本次演示生成的独立目录。文件内容与请求体不进入日志, 仅记录摘要。</p>"
    (output / "index.html").write_text(
        html_document("Agent Sentinel / 可验证的审批与审计", body), encoding="utf-8"
    )
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(".sentinel"),
        help="parent for a new isolated demo directory",
    )
    args = parser.parse_args()
    folder = build_demo(args.out)
    print(f"Demo ready: {folder / 'index.html'}")
    print("Changed content: awaiting_approval; exact content: written; tampered copy: BROKEN")
