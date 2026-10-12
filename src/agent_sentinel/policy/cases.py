"""Policy regression cases: actions paired with the verdicts they must get.

A policy is a set of rules, and rules drift. Someone narrows a pattern, someone
else changes a priority, and the thing you cared about quietly stops being
blocked. This module turns "this command must be reviewed" into a file a test
runner can check, so a policy change can be shown to be safe before it is
merged — the way the guards' own behaviour is pinned by the test suite.

Cases are TOML, the same format policies use, and the whole file is validated
before a single case runs: discovering that case seven is malformed after six
have already passed helps nobody.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import PolicyError
from .engine import PolicyEngine
from .models import Action, ActionKind, Decision, Effect, parse_action_kind, parse_effect

CASE_SCHEMA_VERSION = 1
"""The only case-file schema version this release understands."""


@dataclass(frozen=True)
class Case:
    """One action, and the verdict it must receive."""

    target: str
    expect: Effect
    kind: ActionKind = ActionKind.SHELL
    rule: str | None = None
    """When set, the verdict must come from this rule rather than the default."""

    name: str = ""

    def build(self) -> Action:
        """The action this case describes."""
        return Action(kind=self.kind, target=self.target)


@dataclass(frozen=True)
class CaseResult:
    """What the policy actually said about one case."""

    case: Case
    decision: Decision

    @property
    def ok(self) -> bool:
        """True when the policy said what the case asked for."""
        if self.decision.effect is not self.case.expect:
            return False
        return self.case.rule is None or self.decision.rule_id == self.case.rule

    @property
    def failure(self) -> str:
        """Why the case failed, in one line. Empty when it passed."""
        got = self.decision.effect.value
        rule = self.decision.rule_id or "(policy default)"
        if self.decision.effect is not self.case.expect:
            return f"expected {self.case.expect.value}, got {got} from {rule}"
        if self.case.rule is not None and self.decision.rule_id != self.case.rule:
            return f"expected rule {self.case.rule}, got {rule}"
        return ""

    def render(self) -> str:
        """One report line, with the reason underneath when it failed."""
        mark = "ok  " if self.ok else "FAIL"
        named = f"{self.case.name}: " if self.case.name else ""
        line = (
            f"{mark} {named}{self.case.kind.value} {self.case.target}"
            f" -> {self.decision.effect.value}"
        )
        if self.decision.rule_id:
            line += f" ({self.decision.rule_id})"
        if not self.ok:
            line += f"\n       {self.failure}"
        return line


def load_cases(path: str | Path) -> list[Case]:
    """Read every case in a file, validating all of them before returning any.

    Raises:
        PolicyError: the file is unreadable, is not valid TOML, carries an
            unknown schema, holds no cases, or a case is malformed.
    """
    case_path = Path(path)
    try:
        raw = case_path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read case file {case_path}: {exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{case_path} is not valid TOML: {exc}") from exc

    schema = data.get("schema", CASE_SCHEMA_VERSION)
    if schema != CASE_SCHEMA_VERSION:
        raise PolicyError(
            f"{case_path}: unsupported case schema {schema!r}; "
            f"this release reads schema {CASE_SCHEMA_VERSION}"
        )

    raw_cases = data.get("case")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise PolicyError(f"{case_path} has no cases; add at least one [[case]] table")
    return [
        _parse_case(entry, position=position, where=str(case_path))
        for position, entry in enumerate(raw_cases, start=1)
    ]


def run_cases(engine: PolicyEngine, cases: Iterable[Case]) -> list[CaseResult]:
    """Evaluate every case against a policy.

    Nothing is executed and nothing is recorded: this is the verdict only, the
    same question ``sentinel policy check`` asks.
    """
    return [CaseResult(case=case, decision=engine.evaluate(case.build())) for case in cases]


def summarise(results: Sequence[CaseResult]) -> str:
    """A one-line tally for the end of a run."""
    failed = sum(1 for result in results if not result.ok)
    passed = len(results) - failed
    if not failed:
        return f"{passed} passed"
    return f"{passed} passed, {failed} failed"


def _parse_case(raw: Any, *, position: int, where: str) -> Case:
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: case {position} must be a table")
    context = f"{where}: case {position}"

    name = raw.get("name", "")
    if not isinstance(name, str):
        raise PolicyError(f"{context} has a non-string 'name'")
    if name:
        context = f"{context} ({name})"

    target = raw.get("target")
    if not isinstance(target, str) or not target.strip():
        raise PolicyError(f"{context} needs a non-empty 'target'")

    if "expect" not in raw:
        raise PolicyError(f"{context} needs an 'expect' (allow, review or deny)")
    try:
        expect = parse_effect(raw["expect"])
    except ValueError as exc:
        raise PolicyError(f"{context} has {exc}") from exc

    kind = ActionKind.SHELL
    if raw.get("kind") is not None:
        try:
            kind = parse_action_kind(raw["kind"])
        except ValueError as exc:
            raise PolicyError(f"{context} has {exc}") from exc

    rule = raw.get("rule")
    if rule is not None and (not isinstance(rule, str) or not rule.strip()):
        raise PolicyError(f"{context} has an empty 'rule'")

    return Case(target=target, expect=expect, kind=kind, rule=rule or None, name=name)
