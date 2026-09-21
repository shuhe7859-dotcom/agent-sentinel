"""Ready-made policies, so a project can start guarding on day one.

Three presets are shipped:

``permissive``
    Allow by default; block only the genuinely catastrophic. Good for a first
    run, where the goal is a record of what happened rather than control.
``standard``
    The recommended starting point: block catastrophic actions, escalate the
    risky-but-sometimes-legitimate ones to a human, allow the rest.
``strict``
    Review by default and ship no allow rules, so nothing shell-shaped runs
    without a human saying yes. Good for unattended runs on a machine you care
    about, and the right base to grow a narrow allow list onto.
"""

from __future__ import annotations

import copy
from typing import Any

from ..errors import PolicyError
from .loader import parse_policy
from .models import Policy

_CATASTROPHIC: list[dict[str, Any]] = [
    {
        "id": "shell.rm-root",
        "kind": "shell",
        "effect": "deny",
        "priority": 10,
        "pattern": r"(?i)\brm\s+(?:-[^\s]+\s+)*(?:/|/\*|~|\$HOME)(?:\s|$)",
        "reason": "recursive delete of a root or home directory",
        "tags": ["destructive"],
    },
    {
        "id": "shell.pipe-remote-to-shell",
        "kind": "shell",
        "effect": "deny",
        "priority": 10,
        "pattern": r"(?i)\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
        "reason": "piping a downloaded script straight into a shell",
        "tags": ["supply-chain"],
    },
    {
        "id": "shell.disk-destroy",
        "kind": "shell",
        "effect": "deny",
        "priority": 10,
        "pattern": r"(?i)\b(?:mkfs(?:\.[a-z0-9]+)?\s|dd\s+if=[^\s]+\s+of=/dev/|shred\s+/dev/)",
        "reason": "writing to a raw disk device",
        "tags": ["destructive"],
    },
    {
        "id": "shell.host-power",
        "kind": "shell",
        "effect": "deny",
        "priority": 10,
        "pattern": r"(?i)(?:^|[;&|]\s*)(?:shutdown|reboot|halt|poweroff)\b",
        "reason": "powering the machine off",
        "tags": ["destructive"],
    },
    {
        "id": "fs.path-traversal",
        "kind": ["file.write", "file.delete"],
        "effect": "deny",
        "priority": 10,
        "pattern": r"(?:^|/)\.\.(?:/|$)",
        "reason": "path escapes the workspace through '..'",
        "tags": ["filesystem", "escape"],
    },
    {
        "id": "fs.git-internals",
        "kind": ["file.write", "file.delete"],
        "effect": "deny",
        "priority": 10,
        "pattern": r"(?:^|/)\.git/",
        "reason": "editing git internals directly instead of using git",
        "tags": ["filesystem"],
    },
]

_RISKY: list[dict[str, Any]] = [
    {
        "id": "shell.git-force-push",
        "kind": "shell",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?i)\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?\b|\s-f(?:\s|$))",
        "reason": "force pushing rewrites shared history",
        "tags": ["git"],
    },
    {
        "id": "shell.git-history-rewrite",
        "kind": "shell",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?i)\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s|branch\s+-D\b)",
        "reason": "this discards uncommitted or unreferenced work",
        "tags": ["git", "destructive"],
    },
    {
        "id": "shell.privilege-escalation",
        "kind": "shell",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?i)(?:^|[;&|]\s*)(?:sudo|doas|runas)\b",
        "reason": "escalating privileges",
        "tags": ["privilege"],
    },
    {
        "id": "shell.package-install",
        "kind": "shell",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?i)\b(?:pip|pip3|npm|pnpm|yarn|apt(?:-get)?|brew|choco|winget)\s+(?:install|add|i)\b",
        "reason": "installing a dependency changes the build environment",
        "tags": ["supply-chain"],
    },
    {
        "id": "fs.secrets",
        "kind": "file.write",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?:^|/)(?:\.env(?:\.[^/]*)?|id_rsa|id_ed25519|\.netrc|\.aws/credentials)(?:$|/)",
        "reason": "writing to a file that normally holds credentials",
        "tags": ["secrets"],
    },
    {
        "id": "shell.credential-access",
        "kind": "shell",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?i)(?:id_rsa|id_ed25519|\.ssh/|\.aws/credentials|\.netrc|security\s+find-generic-password)",
        "reason": "reading credential material",
        "tags": ["secrets"],
    },
    {
        "id": "shell.data-upload",
        "kind": "shell",
        "effect": "review",
        "priority": 50,
        "pattern": r"(?i)\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n]*(?:--data\b|-d\s|--upload-file\b|-T\s|--post-file\b|-F\s)",
        "reason": "uploading data to a remote endpoint",
        "tags": ["exfiltration"],
    },
    {
        "id": "network.any",
        "kind": "network",
        "effect": "review",
        "priority": 90,
        "pattern": r"(?s).+",
        "reason": "every network destination is reviewed by default",
        "tags": ["network"],
    },
]


def _preset(
    name: str, default: str, description: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "schema": 1,
        "name": name,
        "description": description,
        "default": default,
        "rules": rules,
    }


PRESETS: dict[str, dict[str, Any]] = {
    "permissive": _preset(
        "permissive",
        "allow",
        "Allow by default, block only the catastrophic. Intended for a first run "
        "where the goal is a record rather than control.",
        copy.deepcopy(_CATASTROPHIC),
    ),
    "standard": _preset(
        "standard",
        "allow",
        "Block the catastrophic, escalate the risky, allow the rest. The recommended "
        "starting point for a supervised coding agent.",
        copy.deepcopy(_CATASTROPHIC + _RISKY),
    ),
    "strict": _preset(
        "strict",
        "review",
        "Review by default. Nothing runs without an explicit allow rule or a human saying yes.",
        copy.deepcopy(_CATASTROPHIC + _RISKY),
    ),
}
"""Built-in policies, keyed by preset name."""

PRESET_NAMES: tuple[str, ...] = tuple(PRESETS)


def available_presets() -> dict[str, str]:
    """Map preset name to its one-line description."""
    return {name: str(preset.get("description", "")) for name, preset in PRESETS.items()}


def load_preset(name: str) -> Policy:
    """Validate and return a built-in policy.

    Raises:
        PolicyError: no preset goes by that name.
    """
    try:
        preset = PRESETS[name]
    except KeyError as exc:
        known = ", ".join(PRESET_NAMES)
        raise PolicyError(f"unknown preset {name!r}; available presets: {known}") from exc
    return parse_policy(copy.deepcopy(preset))
