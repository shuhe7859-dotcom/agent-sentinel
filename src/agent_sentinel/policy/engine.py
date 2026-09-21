"""Evaluating actions against a policy."""

from __future__ import annotations

from .models import Action, Decision, Policy, Rule


class PolicyEngine:
    """Answers one question: may this action run?"""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._rules: tuple[Rule, ...] = policy.ordered_rules()

    @property
    def name(self) -> str:
        return self.policy.name

    @property
    def rules(self) -> tuple[Rule, ...]:
        """Rules in evaluation order."""
        return self._rules

    def evaluate(self, action: Action) -> Decision:
        """Return the first matching rule's verdict, or the policy default."""
        for rule in self._rules:
            if rule.matches(action):
                return Decision(
                    effect=rule.effect,
                    action=action,
                    rule_id=rule.id,
                    reason=rule.reason or f"matched rule {rule.id}",
                    policy=self.policy.name,
                )
        return Decision(
            effect=self.policy.default_effect,
            action=action,
            rule_id=None,
            reason=(f"no rule matched; the policy default is '{self.policy.default_effect.value}'"),
            policy=self.policy.name,
        )

    def explain(self, action: Action) -> str:
        """A readable, multi-line account of how a decision was reached."""
        decision = self.evaluate(action)
        lines = [
            f"policy:  {self.policy.name}",
            f"default: {self.policy.default_effect.value}",
            f"rules:   {len(self._rules)}",
            "",
            decision.render(),
        ]
        if not decision.matched:
            lines.append("")
            lines.append("no rule matched, so the policy default applied")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"PolicyEngine(name={self.name!r}, rules={len(self._rules)})"
