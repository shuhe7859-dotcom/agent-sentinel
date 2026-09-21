"""The exception hierarchy raised by agent-sentinel.

Every error the library raises on purpose inherits from :class:`SentinelError`,
so embedders can guard a whole integration with a single ``except``.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for every deliberate agent-sentinel failure."""


class ConfigError(SentinelError):
    """Configuration could not be read or is invalid."""


class PolicyError(ConfigError):
    """A policy document is malformed or internally inconsistent."""


class JournalError(SentinelError):
    """The flight recorder could not be read or written."""


class JournalIntegrityError(JournalError):
    """A journal record is unreadable or the hash chain does not hold."""


class GuardError(SentinelError):
    """A guarded action could not be prepared or executed."""
