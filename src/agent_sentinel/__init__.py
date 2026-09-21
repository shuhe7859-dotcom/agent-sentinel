"""agent-sentinel: guardrails and a flight recorder for coding agents.

The package is built around two ideas:

* :mod:`agent_sentinel.policy` decides whether an action may run.
* :mod:`agent_sentinel.journal` writes down what was proposed, decided and observed,
  as an append-only hash chain that can be verified afterwards.
"""

from __future__ import annotations

from ._version import __version__
from .approvals import (
    SOURCE_CALLBACK,
    SOURCE_CONFIG,
    SOURCE_OPERATOR,
    Approval,
    ApprovalRequest,
    approvals,
    find_grant,
    pending_requests,
    record_decision,
    request_approval,
)
from .errors import (
    ConfigError,
    GuardError,
    JournalError,
    JournalIntegrityError,
    PolicyError,
    SentinelError,
)
from .events import GENESIS_HASH, Actor, Event, EventType
from .guards.shell import GuardedResult, GuardedRunner
from .journal import IntegrityIssue, Journal, VerifyReport, read_events, verify_file
from .policy.engine import PolicyEngine
from .policy.loader import load_policy, parse_policy
from .policy.models import Action, ActionKind, Decision, Effect, Policy, Rule
from .policy.presets import PRESET_NAMES, available_presets, load_preset
from .session import Session, SessionInfo

__all__ = [
    "GENESIS_HASH",
    "PRESET_NAMES",
    "SOURCE_CALLBACK",
    "SOURCE_CONFIG",
    "SOURCE_OPERATOR",
    "Action",
    "ActionKind",
    "Actor",
    "Approval",
    "ApprovalRequest",
    "ConfigError",
    "Decision",
    "Effect",
    "Event",
    "EventType",
    "GuardError",
    "GuardedResult",
    "GuardedRunner",
    "IntegrityIssue",
    "Journal",
    "JournalError",
    "JournalIntegrityError",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "Rule",
    "SentinelError",
    "Session",
    "SessionInfo",
    "VerifyReport",
    "__version__",
    "approvals",
    "available_presets",
    "find_grant",
    "load_policy",
    "load_preset",
    "parse_policy",
    "pending_requests",
    "read_events",
    "record_decision",
    "request_approval",
    "verify_file",
]
