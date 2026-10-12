"""Policy regression cases: reading them, and reporting on them."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_sentinel.errors import PolicyError
from agent_sentinel.policy.cases import (
    Case,
    load_cases,
    run_cases,
    summarise,
)
from agent_sentinel.policy.engine import PolicyEngine
from agent_sentinel.policy.models import ActionKind, Effect
from agent_sentinel.policy.presets import load_preset

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "cases"


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "cases.toml"
    path.write_text(body, encoding="utf-8")
    return path


def _engine(*, default: str = "allow", rules: list[dict[str, object]] | None = None):
    from agent_sentinel.policy.loader import parse_policy

    return PolicyEngine(parse_policy({"name": "test", "default": default, "rules": rules or []}))


# -------------------------------------------------------------------- reading
def test_a_minimal_case_file_loads(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        'schema = 1\n\n[[case]]\ntarget = "pytest -q"\nexpect = "allow"\n',
    )

    cases = load_cases(path)

    assert len(cases) == 1
    assert cases[0].target == "pytest -q"
    assert cases[0].expect is Effect.ALLOW
    assert cases[0].kind is ActionKind.SHELL
    assert cases[0].rule is None
    assert cases[0].name == ""


def test_every_field_is_read(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        'schema = 1\n\n[[case]]\nname = "a force push"\nkind = "shell"\n'
        'target = "git push --force"\nexpect = "review"\nrule = "shell.git-force-push"\n',
    )

    case = load_cases(path)[0]

    assert case == Case(
        target="git push --force",
        expect=Effect.REVIEW,
        kind=ActionKind.SHELL,
        rule="shell.git-force-push",
        name="a force push",
    )


def test_the_schema_defaults_and_is_checked(tmp_path: Path) -> None:
    without = _write(tmp_path, '[[case]]\ntarget = "x"\nexpect = "allow"\n')
    assert len(load_cases(without)) == 1

    wrong = _write(tmp_path, 'schema = 2\n\n[[case]]\ntarget = "x"\nexpect = "allow"\n')
    with pytest.raises(PolicyError, match="unsupported case schema"):
        load_cases(wrong)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("schema = 1\n", "has no cases"),
        ("schema = 1\ncase = []\n", "has no cases"),
        ("schema = 1\ncase = [1]\n", "must be a table"),
        ('[[case]]\nexpect = "allow"\n', "needs a non-empty 'target'"),
        ('[[case]]\ntarget = "   "\nexpect = "allow"\n', "needs a non-empty 'target'"),
        ('[[case]]\ntarget = "x"\n', "needs an 'expect'"),
        ('[[case]]\ntarget = "x"\nexpect = "maybe"\n', "unknown effect"),
        ('[[case]]\ntarget = "x"\nexpect = "allow"\nkind = "nope"\n', "unknown kind"),
        ('[[case]]\ntarget = "x"\nexpect = "allow"\nrule = ""\n', "empty 'rule'"),
        ('[[case]]\ntarget = "x"\nexpect = "allow"\nname = 7\n', "non-string 'name'"),
    ],
)
def test_a_malformed_case_stops_the_whole_file(tmp_path: Path, body: str, message: str) -> None:
    """Nothing runs until everything parses: a half-finished run helps nobody."""
    with pytest.raises(PolicyError, match=message):
        load_cases(_write(tmp_path, body))


def test_a_missing_or_unreadable_case_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read case file"):
        load_cases(tmp_path / "absent.toml")

    broken = _write(tmp_path, "this is not toml")
    with pytest.raises(PolicyError, match="not valid TOML"):
        load_cases(broken)


# ------------------------------------------------------------------- running
def test_running_cases_against_a_policy() -> None:
    engine = _engine(
        default="deny",
        rules=[{"id": "ok", "effect": "allow", "pattern": "pytest", "reason": "tests"}],
    )
    cases = [
        Case(target="pytest -q", expect=Effect.ALLOW),
        Case(target="rm -rf /", expect=Effect.ALLOW),
    ]

    results = run_cases(engine, cases)

    assert [result.ok for result in results] == [True, False]
    assert results[0].failure == ""
    assert "expected allow, got deny" in results[1].failure
    assert summarise(results) == "1 passed, 1 failed"


def test_a_case_can_pin_the_rule_that_must_fire() -> None:
    engine = _engine(rules=[{"id": "a", "effect": "deny", "pattern": "rm"}])

    assert run_cases(engine, [Case(target="rm -rf /", expect=Effect.DENY, rule="a")])[0].ok
    mismatched = run_cases(
        engine, [Case(target="rm -rf /", expect=Effect.DENY, rule="somewhere-else")]
    )[0]
    assert not mismatched.ok
    assert "expected rule somewhere-else, got a" in mismatched.failure


def test_render_shows_the_verdict_and_the_rule() -> None:
    engine = _engine(rules=[{"id": "a", "effect": "deny", "pattern": "rm"}])

    passing = run_cases(engine, [Case(target="rm", expect=Effect.DENY, name="delete")])[0]
    failing = run_cases(engine, [Case(target="rm", expect=Effect.ALLOW)])[0]

    assert passing.render().startswith("ok  ")
    assert "delete" in passing.render()
    assert "(a)" in passing.render()
    assert failing.render().startswith("FAIL")
    assert "expected allow" in failing.render()


def test_summarise_counts_everything_as_passing_when_it_does() -> None:
    engine = _engine()
    assert summarise(run_cases(engine, [Case(target="x", expect=Effect.ALLOW)])) == "1 passed"


# ------------------------------------------------------- the shipped examples
def test_the_shipped_cases_match_the_standard_preset() -> None:
    """The example file is documentation that has to stay true."""
    cases = load_cases(EXAMPLES / "standard.toml")

    assert len(cases) >= 10
    results = run_cases(PolicyEngine(load_preset("standard")), cases)
    assert [result.render() for result in results if not result.ok] == []


@pytest.mark.parametrize("preset", ["permissive", "standard", "strict"])
def test_the_shipped_cases_load_against_every_preset(preset: str) -> None:
    """Loading is preset-independent; running them against others is a choice."""
    cases = load_cases(EXAMPLES / "standard.toml")

    assert run_cases(PolicyEngine(load_preset(preset)), cases)
