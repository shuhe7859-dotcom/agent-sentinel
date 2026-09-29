"""Ed25519 keys and signatures, and what happens without the extra installed."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from agent_sentinel import signing
from agent_sentinel.errors import SigningError
from agent_sentinel.signing import (
    ALGORITHM,
    KEY_SCHEMA_VERSION,
    create_signature,
    fingerprint,
    from_base64,
    generate_keypair,
    private_key_from_file,
    public_key_from_file,
    to_base64,
    verify,
    write_keypair,
)


def _keys() -> tuple[bytes, bytes]:
    return generate_keypair()


# --------------------------------------------------------------------- crypto
def test_generate_keypair_returns_raw_32_byte_keys() -> None:
    private, public = _keys()

    assert len(private) == 32
    assert len(public) == 32
    assert private != public


def test_a_signature_verifies_with_its_own_key() -> None:
    private, public = _keys()

    signature = signing.sign(b"the message", private)

    assert len(signature) == 64
    assert verify(b"the message", signature, public)


def test_a_signature_does_not_verify_for_another_message() -> None:
    private, public = _keys()
    signature = signing.sign(b"the message", private)

    assert not verify(b"another message", signature, public)


def test_a_signature_does_not_verify_for_another_key() -> None:
    private, _ = _keys()
    _, other_public = _keys()
    signature = signing.sign(b"the message", private)

    assert not verify(b"the message", signature, other_public)


def test_verify_rejects_a_public_key_of_the_wrong_length() -> None:
    private, _ = _keys()
    signature = signing.sign(b"the message", private)

    assert not verify(b"the message", signature, b"too short")


def test_create_signature_carries_the_signer() -> None:
    private, public = _keys()

    signature = create_signature(b"payload", private)

    assert signature.algorithm == ALGORITHM
    assert from_base64(signature.public_key) == public
    assert signature.fingerprint == fingerprint(public)
    assert verify(b"payload", from_base64(signature.signature), public)


def test_base64_round_trip() -> None:
    raw = bytes(range(32))

    assert from_base64(to_base64(raw)) == raw


def test_base64_helpers_reject_rubbish() -> None:
    with pytest.raises(SigningError, match="not valid base64"):
        from_base64("not base64!!")
    with pytest.raises(SigningError, match="expected a 32-byte public key"):
        signing.public_key_bytes(to_base64(b"short"))
    with pytest.raises(SigningError, match="expected a 64-byte signature"):
        signing.signature_bytes(to_base64(b"short"))


def test_fingerprint_is_short_and_stable() -> None:
    _, public = _keys()

    assert fingerprint(public) == fingerprint(public)
    assert len(fingerprint(public)) == 16
    assert signing.fingerprint_of_base64(to_base64(public)) == fingerprint(public)


def test_fingerprint_of_unusable_base64_is_empty() -> None:
    assert signing.fingerprint_of_base64("not base64!!") == ""


def test_a_bad_private_key_is_reported() -> None:
    with pytest.raises(SigningError, match="not a usable Ed25519 private key"):
        signing.sign(b"message", b"too short")


def test_a_missing_cryptography_install_explains_what_to_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def refuse_cryptography(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("cryptography"):
            raise ImportError("No module named 'cryptography'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", refuse_cryptography)

    with pytest.raises(SigningError, match=r"agent-sentinel\[sign\]"):
        generate_keypair()


# ------------------------------------------------------------------- key files
def test_write_keypair_writes_both_halves(tmp_path: Path) -> None:
    private_path = tmp_path / "keys" / "signing.key.json"
    public_path = tmp_path / "keys" / "signing.pub.json"

    pair = write_keypair(private_path, public_path)

    assert private_path.is_file()
    assert public_path.is_file()
    assert pair.fingerprint == fingerprint(public_key_from_file(public_path))
    assert private_key_from_file(private_path) != public_key_from_file(public_path)

    private_data = json.loads(private_path.read_text(encoding="utf-8"))
    assert private_data["schema"] == KEY_SCHEMA_VERSION
    assert private_data["algorithm"] == ALGORITHM
    assert "private_key" in private_data

    public_data = json.loads(public_path.read_text(encoding="utf-8"))
    assert "private_key" not in public_data


def test_keygen_refuses_to_overwrite_a_key(tmp_path: Path) -> None:
    private_path = tmp_path / "signing.key.json"
    public_path = tmp_path / "signing.pub.json"
    write_keypair(private_path, public_path)
    before = private_path.read_text(encoding="utf-8")

    with pytest.raises(SigningError, match="refusing to overwrite"):
        write_keypair(private_path, public_path)

    assert private_path.read_text(encoding="utf-8") == before


def test_keygen_overwrites_when_told_to(tmp_path: Path) -> None:
    private_path = tmp_path / "signing.key.json"
    public_path = tmp_path / "signing.pub.json"
    first = write_keypair(private_path, public_path)

    second = write_keypair(private_path, public_path, force=True)

    assert second.fingerprint != first.fingerprint


def test_reading_the_public_half_as_a_private_key_is_refused(tmp_path: Path) -> None:
    _, public_path = _write_pair(tmp_path)

    with pytest.raises(SigningError, match="is it the public half"):
        private_key_from_file(public_path)


def test_a_key_file_of_an_unknown_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "odd.json"
    path.write_text(json.dumps({"schema": "9.9", "public_key": "x"}), encoding="utf-8")

    with pytest.raises(SigningError, match="not a key file this release understands"):
        public_key_from_file(path)


def test_a_key_file_with_another_algorithm_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "odd.json"
    path.write_text(
        json.dumps({"schema": KEY_SCHEMA_VERSION, "algorithm": "rsa", "public_key": "x"}),
        encoding="utf-8",
    )

    with pytest.raises(SigningError, match="uses algorithm 'rsa'"):
        public_key_from_file(path)


def test_a_missing_key_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(SigningError, match="cannot read key file"):
        public_key_from_file(tmp_path / "absent.json")


def test_a_key_file_that_is_not_json_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(SigningError, match="is not valid JSON"):
        public_key_from_file(path)


def _write_pair(tmp_path: Path) -> tuple[Path, Path]:
    private_path = tmp_path / "signing.key.json"
    public_path = tmp_path / "signing.pub.json"
    write_keypair(private_path, public_path)
    return private_path, public_path
