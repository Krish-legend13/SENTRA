"""Tests for the standalone Ed25519 crypto package."""

import hashlib
import os
import re

import pytest

from crypto import (
    canonical_bytes,
    deserialize_public_key,
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    serialize_public_key,
    sign,
    verify,
)


def test_generate_sign_and_verify() -> None:
    private_key, public_key = generate_keypair()
    data = canonical_bytes("message", 1, b"payload")

    signature = sign(private_key, data)

    assert verify(public_key, signature, data)


def test_empty_data_can_be_signed_and_verified() -> None:
    private_key, public_key = generate_keypair()
    signature = sign(private_key, b"")

    assert verify(public_key, signature, b"")


def test_tampered_data_does_not_verify() -> None:
    private_key, public_key = generate_keypair()
    signature = sign(private_key, b"original")

    assert not verify(public_key, signature, b"tampered")


def test_signature_does_not_verify_with_different_public_key() -> None:
    private_key, _ = generate_keypair()
    _, different_public_key = generate_keypair()
    signature = sign(private_key, b"message")

    assert not verify(different_public_key, signature, b"message")


def test_private_key_round_trips_without_password(tmp_path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "private.pem"

    save_private_key(private_key, path)

    loaded_key = load_private_key(path)
    assert loaded_key.private_bytes_raw() == private_key.private_bytes_raw()


def test_private_key_round_trips_with_password_and_rejects_wrong_password(
    tmp_path,
) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "private-encrypted.pem"

    save_private_key(private_key, path, password=b"correct password")

    loaded_key = load_private_key(path, password=b"correct password")
    assert loaded_key.private_bytes_raw() == private_key.private_bytes_raw()
    with pytest.raises(ValueError):
        load_private_key(path, password=b"wrong password")


def test_public_key_round_trips_through_pem(tmp_path) -> None:
    _, public_key = generate_keypair()
    path = tmp_path / "public.pem"

    save_public_key(public_key, path)

    loaded_key = load_public_key(path)
    assert serialize_public_key(loaded_key) == serialize_public_key(public_key)
    assert deserialize_public_key(serialize_public_key(public_key)).public_bytes_raw() == (
        public_key.public_bytes_raw()
    )


def test_fingerprint_is_stable_and_has_documented_format(tmp_path) -> None:
    _, public_key = generate_keypair()
    path = tmp_path / "public.pem"
    save_public_key(public_key, path)

    loaded_key = load_public_key(path)
    value = fingerprint(public_key)

    assert value == fingerprint(loaded_key)
    groups = value.split("-")
    assert len(groups) >= 8
    assert all(re.fullmatch(r"[0-9A-F]{4}", group) for group in groups)
    assert value == "-".join(
        hashlib.sha256(serialize_public_key(public_key)).hexdigest().upper()[index : index + 4]
        for index in range(0, 64, 4)
    )


def test_canonical_bytes_prevent_ambiguous_concatenation() -> None:
    assert canonical_bytes("ab", "c") != canonical_bytes("a", "bc")


@pytest.mark.parametrize(
    "signature",
    [b"", os.urandom(10), b"garbage bytes"],
)
def test_invalid_signatures_return_false(signature: bytes) -> None:
    _, public_key = generate_keypair()

    assert not verify(public_key, signature, b"")
