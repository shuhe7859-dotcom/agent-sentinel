"""Reading and validating policy documents.

Policies are TOML, parsed with the standard library, so guardrails do not add
a runtime dependency. The shape is small enough to read in one sitting::

    schema  = 1
    name    = "standard"
    default = "allow"

    [[rules]]
    id       = "shell.rm-root"
    kind     = "shell"
    effect   = "deny"
    pattern  = '''(?i)\\brm\\s+-[a-z]*[rf][a-z]*\\s+(?:/|~)(?:\\s|$)'''
    priority = 10
    reason   = "recursive delete of / or ~"
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..errors import PolicyError
from .models import DEFAULT_PRIORITY, ActionKind, Effect, Policy, Rule

SUPPORTED_SCHEMA = 1
"""The only policy schema version this release understands."""

_MISSING = object()


def load_policy(path: str | Path) -> Policy:
    """Read a TOML policy from disk.

    Raises:
        PolicyError: the file is unreadable, is not valid TOML, or fails
            validation.
    """
    policy_path = Path(path)
    try:
        raw = policy_path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {policy_path}: {exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{policy_path} is not valid TOML: {exc}") from exc
    return replace(parse_policy(data), source=str(policy_path))


def parse_policy(data: Mapping[str, Any]) -> Policy:
    """Validate an already-parsed policy mapping.

    Raises:
        PolicyError: any field is missing, unknown or inconsistent.
    """
    schema = data.get("schema", SUPPORTED_SCHEMA)
    if schema != SUPPORTED_SCHEMA:
        raise PolicyError(
            f"unsupported policy schema {schema!r}; this release reads schema {SUPPORTED_SCHEMA}"
        )

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyError("a policy needs a non-empty 'name'")

    default_effect = _parse_effect(data.get("default", _MISSING), where="the policy default")

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be an array of tables")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rules.append(_parse_rule(raw_rule, index=index, seen_ids=seen_ids))

    description = data.get("description", "")
    return Policy(
        name=name.strip(),
        default_effect=default_effect,
        rules=tuple(rules),
        description=str(description),
    )


def _parse_rule(raw_rule: Any, *, index: int, seen_ids: set[str]) -> Rule:
    if not isinstance(raw_rule, dict):
        raise PolicyError(f"rules[{index}] must be a table")

    rule_id = raw_rule.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyError(f"rules[{index}] needs a non-empty 'id'")
    rule_id = rule_id.strip()
    if rule_id in seen_ids:
        raise PolicyError(f"duplicate rule id {rule_id!r}")
    seen_ids.add(rule_id)

    pattern_source = raw_rule.get("pattern")
    if not isinstance(pattern_source, str) or not pattern_source:
        raise PolicyError(f"rule {rule_id!r} needs a non-empty 'pattern'")
    try:
        pattern = re.compile(pattern_source)
    except re.error as exc:
        raise PolicyError(f"rule {rule_id!r} has an invalid pattern: {exc}") from exc

    effect = _parse_effect(raw_rule.get("effect", _MISSING), where=f"rule {rule_id!r}")

    kind: frozenset[ActionKind] | None = None
    raw_kind = raw_rule.get("kind", _MISSING)
    if raw_kind is not _MISSING:
        kind = _parse_kinds(raw_kind, where=f"rule {rule_id!r}")

    priority = raw_rule.get("priority", DEFAULT_PRIORITY)
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise PolicyError(f"rule {rule_id!r} has a non-integer 'priority'")

    tags = raw_rule.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise PolicyError(f"rule {rule_id!r} has invalid 'tags'; expected an array of strings")

    reason = raw_rule.get("reason", "")
    return Rule(
        id=rule_id,
        effect=effect,
        pattern=pattern,
        reason=str(reason),
        kind=kind,
        priority=priority,
        tags=tuple(tags),
    )


def _parse_effect(value: Any, *, where: str) -> Effect:
    if value is _MISSING:
        raise PolicyError(f"{where} is missing an 'effect' (allow, deny or review)")
    try:
        return Effect(str(value).lower())
    except ValueError as exc:
        allowed = ", ".join(effect.value for effect in Effect)
        raise PolicyError(
            f"{where} has unknown effect {value!r}; expected one of {allowed}"
        ) from exc


def _parse_kinds(value: Any, *, where: str) -> frozenset[ActionKind]:
    raw_kinds = [value] if isinstance(value, str) else value
    if not isinstance(raw_kinds, list) or not raw_kinds:
        raise PolicyError(
            f"{where} has an invalid 'kind'; expected a string or an array of strings"
        )
    kinds: set[ActionKind] = set()
    for raw_kind in raw_kinds:
        try:
            kinds.add(ActionKind(str(raw_kind).lower()))
        except ValueError as exc:
            allowed = ", ".join(kind.value for kind in ActionKind)
            raise PolicyError(
                f"{where} has unknown kind {raw_kind!r}; expected one of {allowed}"
            ) from exc
    return frozenset(kinds)
