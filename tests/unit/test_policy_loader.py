"""Reading and validating policy documents."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_sentinel.errors import PolicyError
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.loader import load_policy, parse_policy
from agent_sentinel.policy.models import Action, ActionKind, Effect, Rule
from agent_sentinel.policy.presets import PRESET_NAMES, available_presets, load_preset

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "policies"


def _minimal(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": 1,
        "name": "test-policy",
        "default": "deny",
        "rules": [
            {
                "id": "shell.hello",
                "kind": "shell",
                "effect": "allow",
                "pattern": "hello",
                "reason": "greetings are fine",
            }
        ],
    }
    data.update(overrides)
    return data


def test_parse_a_minimal_policy() -> None:
    policy = parse_policy(_minimal())

    assert policy.name == "test-policy"
    assert policy.default_effect is Effect.DENY
    assert len(policy.rules) == 1
    assert policy.rules[0].matches(Action(kind=ActionKind.SHELL, target="echo hello"))


def test_schema_defaults_to_the_supported_version() -> None:
    data = _minimal()
    del data["schema"]

    assert parse_policy(data).version == 1


def test_kind_accepts_a_list() -> None:
    data = _minimal(
        rules=[
            {
                "id": "fs.any",
                "kind": ["file.write", "file.delete"],
                "effect": "review",
                "pattern": ".*",
            }
        ]
    )
    rule = parse_policy(data).rules[0]

    assert rule.matches(Action(kind=ActionKind.FILE_DELETE, target="x.py"))
    assert not rule.matches(Action(kind=ActionKind.SHELL, target="x.py"))


def test_a_rule_without_a_kind_matches_every_kind() -> None:
    data = _minimal(rules=[{"id": "any", "effect": "allow", "pattern": ".*"}])
    rule = parse_policy(data).rules[0]

    assert rule.matches(Action(kind=ActionKind.NETWORK, target="example.com"))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"name": ""}, "non-empty 'name'"),
        ({"schema": 2}, "unsupported policy schema"),
        ({"default": "maybe"}, "unknown effect"),
        ({"rules": "nope"}, "must be an array of tables"),
        ({"rules": [{"effect": "deny", "pattern": "x"}]}, "needs a non-empty 'id'"),
        ({"rules": [{"id": "a", "pattern": "x"}]}, "missing an 'effect'"),
        ({"rules": [{"id": "a", "effect": "deny", "pattern": ""}]}, "non-empty 'pattern'"),
        ({"rules": [{"id": "a", "effect": "deny", "pattern": "("}]}, "invalid pattern"),
        (
            {"rules": [{"id": "a", "effect": "deny", "pattern": "x", "kind": "nope"}]},
            "unknown kind",
        ),
        (
            {"rules": [{"id": "a", "effect": "deny", "pattern": "x", "priority": "high"}]},
            "non-integer 'priority'",
        ),
        (
            {"rules": [{"id": "a", "effect": "deny", "pattern": "x", "tags": "git"}]},
            "invalid 'tags'",
        ),
        (
            {
                "rules": [
                    {"id": "a", "effect": "deny", "pattern": "x"},
                    {"id": "a", "effect": "allow", "pattern": "y"},
                ]
            },
            "duplicate rule id",
        ),
    ],
)
def test_invalid_policies_are_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_policy(_minimal(**overrides))


def test_load_policy_reads_toml_and_records_the_source(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text(
        """
schema  = 1
name    = "from-disk"
default = "review"

[[rules]]
id      = "shell.hello"
kind    = "shell"
effect  = "allow"
pattern = "hello"
""",
        encoding="utf-8",
    )

    policy = load_policy(path)

    assert policy.name == "from-disk"
    assert policy.source == str(path)


def test_load_policy_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read policy file"):
        load_policy(tmp_path / "absent.toml")


def test_load_policy_reports_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "broken.toml"
    path.write_text("name = [unterminated", encoding="utf-8")

    with pytest.raises(PolicyError, match="not valid TOML"):
        load_policy(path)


def test_every_preset_loads() -> None:
    assert set(available_presets()) == set(PRESET_NAMES)
    for name in PRESET_NAMES:
        policy = load_preset(name)
        assert policy.name == name
        assert policy.rules


def test_unknown_preset_is_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown preset"):
        load_preset("yolo")


# ------------------------------------------------------- shipped policy files
def _signature(rule: Rule) -> tuple[object, ...]:
    kinds = tuple(sorted(kind.value for kind in rule.kind)) if rule.kind else None
    return (rule.id, kinds, rule.effect.value, rule.priority, rule.pattern.pattern, rule.tags)


def test_the_shipped_example_stays_in_step_with_the_standard_preset() -> None:
    """The example file is a copy people edit; drift would make it lie."""
    example = load_policy(PROJECT_ROOT / "examples" / "policies" / "standard.toml")
    preset = load_preset("standard")

    assert example.default_effect is preset.default_effect
    assert [_signature(rule) for rule in example.ordered_rules()] == [
        _signature(rule) for rule in preset.ordered_rules()
    ]


def test_the_team_fixture_behaves_as_its_comments_claim() -> None:
    engine = PolicyEngine(load_policy(FIXTURES / "team.toml"))
    shell = ActionKind.SHELL

    assert engine.evaluate(Action(kind=shell, target="pytest -q")).allowed
    assert engine.evaluate(Action(kind=shell, target="git log --oneline")).allowed
    assert engine.evaluate(Action(kind=shell, target="git push origin main")).denied
    assert engine.evaluate(Action(kind=shell, target="make deploy")).requires_review


def test_every_example_policy_loads() -> None:
    examples = sorted((PROJECT_ROOT / "examples" / "policies").glob("*.toml"))

    assert examples, "expected at least one example policy"
    for path in examples:
        policy = load_policy(path)
        assert policy.name
        assert policy.rules or policy.default_effect is not None


def test_the_workspace_example_judges_its_documented_cases() -> None:
    """The example claims two things; hold it to them."""
    engine = PolicyEngine(load_policy(PROJECT_ROOT / "examples" / "policies" / "workspace.toml"))

    # 1. In-workspace file work is allowed; containment is the guard's job.
    assert engine.evaluate(Action(kind=ActionKind.FILE_WRITE, target="src/app.py")).allowed
    assert engine.evaluate(Action(kind=ActionKind.FILE_DELETE, target="build/tmp.txt")).allowed

    # 2. The allow-listed hosts are allowed, everything else is reviewed.
    assert engine.evaluate(Action(kind=ActionKind.NETWORK, target="pypi.org")).allowed
    assert engine.evaluate(Action(kind=ActionKind.NETWORK, target="pypi.org:8443")).allowed
    assert engine.evaluate(Action(kind=ActionKind.NETWORK, target="example.com")).requires_review

    # Nothing outside the allow-list was loosened.
    assert engine.evaluate(Action(kind=ActionKind.SHELL, target="make deploy")).requires_review
