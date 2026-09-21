"""Execution wrappers that put the policy engine on the critical path."""

from __future__ import annotations

from .shell import GuardedResult, GuardedRunner

__all__ = ["GuardedResult", "GuardedRunner"]
