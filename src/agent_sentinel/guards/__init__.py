"""Execution wrappers that put the policy engine on the critical path.

Each guard covers one surface an agent can act on: the shell, the filesystem,
and the network. They share their flow -- propose, decide, escalate, act,
record -- and differ only in what they describe and how they carry it out.
"""

from __future__ import annotations

from .base import Guard, GuardResult, Performed, Performer, Reviewer
from .filesystem import FileSystemResult, GuardedFileSystem, normalize_path
from .network import DEFAULT_MAX_BYTES, GuardedNetwork, NetworkResult, host_of
from .shell import DEFAULT_PREVIEW_CHARS, GuardedResult, GuardedRunner, GuardedShell

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_PREVIEW_CHARS",
    "FileSystemResult",
    "Guard",
    "GuardResult",
    "GuardedFileSystem",
    "GuardedNetwork",
    "GuardedResult",
    "GuardedRunner",
    "GuardedShell",
    "NetworkResult",
    "Performed",
    "Performer",
    "Reviewer",
    "host_of",
    "normalize_path",
]
