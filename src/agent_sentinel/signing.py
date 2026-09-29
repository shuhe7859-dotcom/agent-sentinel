"""Ed25519 signatures for anchors.

Signing is optional on purpose. Everything else in agent-sentinel imports
nothing but the standard library, and that is worth keeping: a safety tool
should not be its own supply-chain risk. Ed25519 does need a real
implementation, though, so it lives behind an extra::

    pip install "agent-sentinel[sign]"

The ``cryptography`` import is deferred to call time, so importing this module
costs nothing, and a missing package becomes a
:class:`~agent_sentinel.errors.SigningError` that says what to install rather
than an ``ImportError`` from three frames down.

What a signature buys is worth stating plainly: it says *who* wrote an anchor.
It says nothing about whether everything was written down, which is the anchor's
job. See ``docs/anchoring.md``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._version import __version__
from .errors import SigningError
from .events import canonical_dumps, utc_now_iso

KEY_SCHEMA_VERSION = "1.0"
"""Version of the on-disk key file format."""

ALGORITHM = "ed25519"
DEFAULT_KEY_DIR = Path(".sentinel") / "keys"
DEFAULT_PRIVATE_KEY = "sentinel-signing.key.json"
DEFAULT_PUBLIC_KEY = "sentinel-signing.pub.json"
_KEY_BYTES = 32
_SIGNATURE_BYTES = 64


def _ed25519() -> Any:
    """The Ed25519 primitives, or a clear error saying what to install."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - reached only without the extra
        raise SigningError(
            "Ed25519 signing needs the 'cryptography' package. Install it with "
            'pip install "agent-sentinel[sign]"'
        ) from exc
    return ed25519


@dataclass(frozen=True)
class Signature:
    """A detached Ed25519 signature over one anchor."""

    public_key: str
    """The signer's public key, base64 of the raw 32 bytes."""

    signature: str
    """The signature itself, base64 of the raw 64 bytes."""

    algorithm: str = ALGORITHM

    def as_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    @property
    def fingerprint(self) -> str:
        """A short, stable name for the signer."""
        return fingerprint_of_base64(self.public_key)


@dataclass(frozen=True)
class KeyPair:
    """Where a freshly generated key pair was written."""

    private_path: Path
    public_path: Path
    public_key: str
    fingerprint: str
    permissions_enforced: bool
    """False when the platform cannot restrict a file to its owner."""


def to_base64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def from_base64(text: str) -> bytes:
    """Decode base64, reporting a :class:`SigningError` rather than a traceback."""
    try:
        return base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise SigningError(f"not valid base64: {exc}") from exc


def fingerprint(public_key: bytes) -> str:
    """A short, stable name for a public key."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def fingerprint_of_base64(public_key: str) -> str:
    """The same, starting from the base64 form stored in an anchor."""
    try:
        return fingerprint(from_base64(public_key))
    except SigningError:
        return ""


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_key, public_key)``, both raw 32-byte values."""
    ed25519 = _ed25519()
    private = ed25519.Ed25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def sign(message: bytes, private_key: bytes) -> bytes:
    """Sign ``message`` with a raw private key."""
    ed25519 = _ed25519()
    try:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    except ValueError as exc:
        raise SigningError(f"not a usable Ed25519 private key: {exc}") from exc
    return bytes(key.sign(message))


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """True when ``signature`` is ``message``'s, under ``public_key``."""
    ed25519 = _ed25519()
    from cryptography.exceptions import InvalidSignature

    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        return False
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def create_signature(message: bytes, private_key: bytes) -> Signature:
    """Sign ``message`` and package the result with the matching public key."""
    ed25519 = _ed25519()
    try:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    except ValueError as exc:
        raise SigningError(f"not a usable Ed25519 private key: {exc}") from exc
    public = key.public_key().public_bytes_raw()
    return Signature(public_key=to_base64(public), signature=to_base64(key.sign(message)))


# ------------------------------------------------------------------- key files
def write_keypair(
    private_path: str | Path,
    public_path: str | Path,
    *,
    force: bool = False,
) -> KeyPair:
    """Generate a key pair and write it out.

    Refuses to overwrite an existing file unless ``force`` is set: losing a
    signing key means losing the ability to vouch for anchors already published.
    """
    private_path = Path(private_path)
    public_path = Path(public_path)
    existing = [str(path) for path in (private_path, public_path) if path.exists()]
    if existing and not force:
        raise SigningError(
            f"refusing to overwrite {', '.join(existing)}; pass force=True (--force) "
            "if the old key is genuinely disposable"
        )

    private_raw, public_raw = generate_keypair()
    created = utc_now_iso()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(
        canonical_dumps(
            {
                "schema": KEY_SCHEMA_VERSION,
                "algorithm": ALGORITHM,
                "created": created,
                "tool": f"agent-sentinel {__version__}",
                "private_key": to_base64(private_raw),
                "public_key": to_base64(public_raw),
            }
        ),
        encoding="utf-8",
    )
    public_path.write_text(
        canonical_dumps(
            {
                "schema": KEY_SCHEMA_VERSION,
                "algorithm": ALGORITHM,
                "created": created,
                "tool": f"agent-sentinel {__version__}",
                "public_key": to_base64(public_raw),
            }
        ),
        encoding="utf-8",
    )
    return KeyPair(
        private_path=private_path,
        public_path=public_path,
        public_key=to_base64(public_raw),
        fingerprint=fingerprint(public_raw),
        permissions_enforced=_restrict(private_path),
    )


def _restrict(path: Path) -> bool:
    """Try to make a file readable only by its owner.

    Windows has no equivalent of ``chmod 0600``: the call only toggles the
    read-only bit, so the honest answer there is "not enforced", and the caller
    is told to use an ACL instead.
    """
    if os.name == "nt":
        return False
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - unusual filesystems
        return False
    return True


def read_key_file(path: str | Path) -> dict[str, Any]:
    """Read and sanity-check a key file."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SigningError(f"cannot read key file {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SigningError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != KEY_SCHEMA_VERSION:
        raise SigningError(f"{path} is not a key file this release understands")
    if data.get("algorithm") != ALGORITHM:
        raise SigningError(
            f"{path} uses algorithm {data.get('algorithm')!r}; expected {ALGORITHM!r}"
        )
    return data


def private_key_from_file(path: str | Path) -> bytes:
    """The raw private key in ``path``."""
    data = read_key_file(path)
    value = data.get("private_key")
    if not isinstance(value, str):
        raise SigningError(f"{path} has no private key; is it the public half?")
    raw = from_base64(value)
    if len(raw) != _KEY_BYTES:
        raise SigningError(f"{path} holds a {len(raw)}-byte private key; expected {_KEY_BYTES}")
    return raw


def public_key_from_file(path: str | Path) -> bytes:
    """The raw public key in ``path``."""
    data = read_key_file(path)
    value = data.get("public_key")
    if not isinstance(value, str):
        raise SigningError(f"{path} has no public key")
    raw = from_base64(value)
    if len(raw) != _KEY_BYTES:
        raise SigningError(f"{path} holds a {len(raw)}-byte public key; expected {_KEY_BYTES}")
    return raw


def public_key_bytes(base64_key: str) -> bytes:
    """Decode a public key carried inside a signature."""
    raw = from_base64(base64_key)
    if len(raw) != _KEY_BYTES:
        raise SigningError(f"expected a {_KEY_BYTES}-byte public key, got {len(raw)}")
    return raw


def signature_bytes(base64_signature: str) -> bytes:
    """Decode a signature carried inside an anchor."""
    raw = from_base64(base64_signature)
    if len(raw) != _SIGNATURE_BYTES:
        raise SigningError(f"expected a {_SIGNATURE_BYTES}-byte signature, got {len(raw)}")
    return raw
