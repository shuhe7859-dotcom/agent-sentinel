"""Data model for the guardrail layer.

The vocabulary is deliberately small:

* an :class:`Action` is something an agent wants to do;
* a :class:`Rule` describes a pattern of actions to care about;
* a :class:`Decision` is the verdict the engine returns, with its reason.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from re import Pattern
from typing import Any

DEFAULT_PRIORITY = 100
"""Priority used when a rule does not declare one."""


class ActionKind(StrEnum):
    """The categories of action a policy can reason about."""

    SHELL = "shell"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    NETWORK = "network"


class Effect(StrEnum):
    """What the policy wants to happen to an action."""

    ALLOW = "allow"
    """Run it."""

    REVIEW = "review"
    """Stop and ask a human, or the configured reviewer, first."""

    DENY = "deny"
    """Refuse to run it."""


def normalize_target(target: str) -> str:
    """Normalise a target so the same policy works on every platform.

    Backslashes become forward slashes, which lets one pattern describe both
    ``..\\evil.py`` on Windows and ``../evil.py`` on POSIX.
    """
    return target.replace("\\", "/")


@dataclass(frozen=True)
class Action:
    """Something an agent wants to do."""

    kind: ActionKind
    target: str
    """A shell command line, a file path or a host name."""

    argv: tuple[str, ...] = ()
    """Optional tokenised form; when present it is what rules match against."""

    cwd: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def subject(self) -> str:
        """The normalised text that rule patterns are matched against."""
        text = " ".join(self.argv) if self.argv else self.target
        return normalize_target(text)

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"kind": self.kind.value, "target": self.target}
        if self.argv:
            data["argv"] = list(self.argv)
        if self.cwd:
            data["cwd"] = self.cwd
        if self.metadata:
            data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class Rule:
    """One pattern in a policy, plus what to do when it matches."""

    id: str
    effect: Effect
    pattern: Pattern[str]
    reason: str = ""
    kind: frozenset[ActionKind] | None = None
    """Restrict the rule to these action kinds; ``None`` means "any"."""

    priority: int = DEFAULT_PRIORITY
    tags: tuple[str, ...] = ()

    def matches(self, action: Action) -> bool:
        """True when this rule is interested in ``action``."""
        if self.kind is not None and action.kind not in self.kind:
            return False
        return self.pattern.search(action.subject) is not None


@dataclass(frozen=True)
class Policy:
    """A named, ordered set of rules plus a fallback effect."""

    name: str
    default_effect: Effect
    rules: tuple[Rule, ...] = ()
    description: str = ""
    version: int = 1
    source: str | None = None
    """Where the policy was loaded from, for error messages and audit records."""

    def ordered_rules(self) -> tuple[Rule, ...]:
        """Rules sorted by ascending priority, declaration order breaking ties.

        Lower numbers are evaluated first, the way firewall rulesets read.
        """
        return tuple(sorted(self.rules, key=lambda rule: rule.priority))


@dataclass(frozen=True)
class Decision:
    """The engine's verdict for one action."""

    effect: Effect
    action: Action
    rule_id: str | None = None
    reason: str = ""
    policy: str = ""

    @property
    def matched(self) -> bool:
        """True when a rule fired, rather than the policy default."""
        return self.rule_id is not None

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def denied(self) -> bool:
        return self.effect is Effect.DENY

    @property
    def requires_review(self) -> bool:
        return self.effect is Effect.REVIEW

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "rule": self.rule_id,
            "reason": self.reason,
            "policy": self.policy,
            "action": self.action.as_dict(),
        }

    def render(self) -> str:
        rule = self.rule_id or "(policy default)"
        return (
            f"{self.effect.value.upper():<6} [{self.policy}] {rule}: {self.reason}\n"
            f"       action: {self.action.kind.value} {self.action.subject}"
        )
