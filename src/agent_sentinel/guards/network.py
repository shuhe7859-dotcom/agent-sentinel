"""Guarded HTTP egress: the guard makes the request, so the allow-list means something.

A check that only reports a verdict is easy to walk around -- the caller simply
issues the request anyway. So this guard performs the request itself, with the
standard library's :mod:`urllib.request`, after the policy has had its say.

Three structural rules hold regardless of policy:

* only ``http`` and ``https`` are fetched. ``file://`` would otherwise read
  local files and walk straight past the filesystem guard;
* the policy matches the **host**, lower-cased, with ``:port`` appended when the
  port is not the scheme's default. Allow-lists stay readable;
* redirects are **not** followed. A 3xx is recorded with its ``Location`` and
  handed back, so the next hop goes through the policy as a fresh action rather
  than being smuggled through on the first host's permission.

Response bodies are handed to the caller and are not written to the journal:
only the status, the content type, the byte count and a digest are. A journal is
meant to be shareable.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from typing import Any
from urllib.parse import SplitResult, urlsplit

from ..approvals import ApprovalRequest
from ..journal import Journal
from ..policy.engine import PolicyEngine
from ..policy.models import Action, ActionKind, Decision, Effect
from .base import (
    Guard,
    GuardResult,
    Performed,
    Reviewer,
    as_int,
    as_optional_int,
    as_optional_text,
    as_text,
)

DEFAULT_MAX_BYTES = 1_048_576
"""How much of a response body to read, by default."""

SUPPORTED_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class NetworkResult(GuardResult):
    """What happened to one guarded request."""

    url: str = ""
    host: str = ""
    status_code: int | None = None
    content_type: str | None = None
    location: str | None = None
    """The ``Location`` header of a 3xx response, which is not followed."""

    body: bytes = b""
    """The response body, handed to the caller and never written to the journal."""

    bytes_received: int = 0
    sha256: str | None = None
    truncated: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        """True when a response came back with a status below 400."""
        return self.status == "fetched" and (self.status_code or 0) < 400


def host_of(url: str) -> str:
    """The host a URL addresses, as a policy pattern sees it.

    Lower-cased, with the port appended when it is not the scheme's default, so
    ``https://PyPI.org/x`` matches ``pypi.org`` and ``http://example.com:8080/``
    matches ``example.com:8080``.
    """
    parts = urlsplit(url)
    return _host_of_parts(parts, parts.scheme.lower())


def _host_of_parts(parts: SplitResult, scheme: str) -> str:
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{host}:{port}"
    return host


def _unsupported_reason(parts: SplitResult, scheme: str) -> str | None:
    """Why this URL cannot be fetched, or ``None`` when it can."""
    if not scheme:
        return "the URL has no scheme; the network guard only fetches http and https"
    if scheme not in SUPPORTED_SCHEMES:
        return (
            f"the network guard only fetches http and https, not '{scheme}'; "
            f"a {scheme}:// URL reads the local disk, which is the filesystem guard's business"
        )
    if not (parts.hostname or ""):
        return f"the URL '{parts.geturl()}' has no host to check against the policy"
    try:
        _ = parts.port
    except ValueError as exc:
        return f"the URL has an unusable port ({exc})"
    return None


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    return isinstance(getattr(exc, "reason", None), TimeoutError)


def _describe(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    detail = reason if reason is not None else exc
    return f"{type(detail).__name__}: {detail}"


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects, so every hop is checked on its own."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _opener() -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.ProxyHandler())
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(_NoRedirects())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


class GuardedNetwork(Guard[NetworkResult]):
    """Fetches URLs, but only after the policy has allowed the host."""

    def __init__(
        self,
        engine: PolicyEngine,
        journal: Journal,
        *,
        allow_review: bool = False,
        reviewer: Reviewer | None = None,
        reviewer_note: str | None = None,
        timeout: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        super().__init__(
            engine,
            journal,
            allow_review=allow_review,
            reviewer=reviewer,
            reviewer_note=reviewer_note,
        )
        self.timeout = timeout
        self.max_bytes = max_bytes

    # ------------------------------------------------------------------ public
    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> NetworkResult:
        """Ask the policy about ``url`` and, if it agrees, fetch it."""
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = _host_of_parts(parts, scheme)
        metadata: dict[str, Any] = {
            "url": url,
            "scheme": scheme,
            "method": method.upper(),
        }
        problem = _unsupported_reason(parts, scheme)
        if problem is not None:
            metadata["constraint"] = problem
        action = Action(kind=ActionKind.NETWORK, target=host or url, metadata=metadata)
        return self.guard(
            action,
            partial(
                self._request,
                headers=dict(headers or {}),
                body=body,
                timeout=timeout,
                max_bytes=max_bytes,
            ),
        )

    # ------------------------------------------------------------------- hooks
    def _context(self, action: Action, decision: Decision) -> Mapping[str, Any]:
        context: dict[str, Any] = {
            "url": action.metadata.get("url"),
            "method": action.metadata.get("method"),
        }
        if action.metadata.get("constraint") is not None:
            context["constraint"] = action.metadata["constraint"]
        return context

    def _constrain(self, action: Action, decision: Decision) -> Decision:
        """Refuse anything the guard cannot fetch safely, whatever the policy says."""
        problem = action.metadata.get("constraint")
        if problem is None:
            return decision
        return Decision(
            effect=Effect.DENY,
            action=action,
            rule_id=decision.rule_id,
            reason=f"{problem} (the policy had said {decision.effect.value})",
            policy=decision.policy,
        )

    def _result(
        self,
        action: Action,
        decision: Decision,
        recorded: Mapping[str, Any],
        private: Mapping[str, Any],
        *,
        approval_seq: int | None = None,
        approval_request: ApprovalRequest | None = None,
    ) -> NetworkResult:
        body = private.get("body")
        return NetworkResult(
            decision=decision,
            status=as_text(recorded.get("status"), "failed"),
            url=as_text(recorded.get("url"), as_text(action.metadata.get("url"))),
            host=action.target,
            status_code=as_optional_int(recorded.get("status_code")),
            content_type=as_optional_text(recorded.get("content_type")),
            location=as_optional_text(recorded.get("location")),
            body=body if isinstance(body, bytes) else b"",
            bytes_received=as_int(recorded.get("bytes_received")),
            sha256=as_optional_text(recorded.get("sha256")),
            truncated=bool(recorded.get("truncated")),
            error=as_text(recorded.get("error")),
            approval_seq=approval_seq,
            approval_request=approval_request,
        )

    # ---------------------------------------------------------------- internals
    def _request(
        self,
        action: Action,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float | None,
        max_bytes: int | None,
    ) -> Performed:
        url = str(action.metadata["url"])
        method = str(action.metadata["method"])
        limit = self.max_bytes if max_bytes is None else max_bytes
        deadline = timeout if timeout is not None else self.timeout
        # S310: the scheme is checked by _unsupported_reason before we get here.
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers=dict(headers), method=method
        )

        try:
            response: Any = _opener().open(request, timeout=deadline)
        except urllib.error.HTTPError as exc:
            # A 3xx (we do not follow) or a 4xx/5xx is still a response.
            response = exc
        except OSError as exc:
            failure: dict[str, Any] = {
                "status": "timeout" if _is_timeout(exc) else "failed",
                "error": _describe(exc),
            }
            if deadline is not None:
                failure["timeout_s"] = deadline
            return Performed(recorded=failure)

        with response:
            raw = response.read(limit + 1)
            truncated = len(raw) > limit
            chunk = raw[:limit]
            recorded: dict[str, Any] = {
                "status": "fetched",
                "url": url,
                "status_code": getattr(response, "status", None) or getattr(response, "code", None),
                "content_type": response.headers.get("Content-Type"),
                "location": response.headers.get("Location"),
                "bytes_received": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
                "truncated": truncated,
            }
        return Performed(recorded=recorded, private={"body": chunk})
