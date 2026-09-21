"""Keep the packaged version and the reported version in step."""

from __future__ import annotations

import tomllib
from pathlib import Path

import agent_sentinel

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_pyproject_version_matches_the_package() -> None:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == agent_sentinel.__version__


def test_console_script_points_at_main() -> None:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["sentinel"] == "agent_sentinel.cli:main"
