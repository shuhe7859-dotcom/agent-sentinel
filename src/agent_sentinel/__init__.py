"""agent-sentinel: guardrails and a flight recorder for coding agents.

The package is built around two ideas:

* :mod:`agent_sentinel.policy` decides whether an action may run.
* :mod:`agent_sentinel.journal` writes down what was proposed, decided and observed,
  as an append-only hash chain that can be verified afterwards.
"""

from __future__ import annotations

from ._version import __version__
from .anchors import (
    ANCHOR_SCHEMA_VERSION,
    Anchor,
    AnchorFile,
    anchor_journal,
    append_anchor,
    compare_anchors,
    read_anchor_file,
    sign_anchor,
    verify_with_anchors,
)
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
    SigningError,
)
from .events import GENESIS_HASH, Actor, Event, EventType
from .guards import (
    FileSystemResult,
    Guard,
    GuardedFileSystem,
    GuardedNetwork,
    GuardedResult,
    GuardedRunner,
    GuardedShell,
    GuardResult,
    NetworkResult,
)
from .journal import IntegrityIssue, Journal, VerifyReport, read_events, verify_file
from .policy.engine import PolicyEngine
from .policy.loader import load_policy, parse_policy
from .policy.models import Action, ActionKind, Decision, Effect, Policy, Rule
from .policy.presets import PRESET_NAMES, available_presets, load_preset
from .session import Session, SessionInfo
from .signing import (
    KeyPair,
    Signature,
    generate_keypair,
    private_key_from_file,
    public_key_from_file,
    write_keypair,
)

__all__ = [
    "ANCHOR_SCHEMA_VERSION",
    "GENESIS_HASH",
    "PRESET_NAMES",
    "SOURCE_CALLBACK",
    "SOURCE_CONFIG",
    "SOURCE_OPERATOR",
    "Action",
    "ActionKind",
    "Actor",
    "Anchor",
    "AnchorFile",
    "Approval",
    "ApprovalRequest",
    "ConfigError",
    "Decision",
    "Effect",
    "Event",
    "EventType",
    "FileSystemResult",
    "Guard",
    "GuardError",
    "GuardResult",
    "GuardedFileSystem",
    "GuardedNetwork",
    "GuardedResult",
    "GuardedRunner",
    "GuardedShell",
    "IntegrityIssue",
    "Journal",
    "JournalError",
    "JournalIntegrityError",
    "KeyPair",
    "NetworkResult",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "Rule",
    "SentinelError",
    "Session",
    "SessionInfo",
    "Signature",
    "SigningError",
    "VerifyReport",
    "__version__",
    "anchor_journal",
    "append_anchor",
    "approvals",
    "available_presets",
    "compare_anchors",
    "find_grant",
    "generate_keypair",
    "load_policy",
    "load_preset",
    "parse_policy",
    "pending_requests",
    "private_key_from_file",
    "public_key_from_file",
    "read_anchor_file",
    "read_events",
    "record_decision",
    "request_approval",
    "sign_anchor",
    "verify_file",
    "verify_with_anchors",
    "write_keypair",
]
