"""Tests for signed message envelope creation, verification, and conversion."""

import base64
import json
import os
from dataclasses import FrozenInstanceError

import pytest

from auth import create_response, generate_challenge
from crypto import canonical_bytes, generate_keypair, sign
from signing import (
    SignedEnvelope,
    build_signing_input,
    envelope_from_dict,
    envelope_to_dict,
    sign_envelope,
    verify_envelope,
)


def _signed_envelope() -> tuple[object, object, SignedEnvelope]:
    private_key, public_key = generate_keypair()
    envelope = sign_envelope(
        private_key,
        "alice",
        "bob",
        "message-1",
        1,
        "2026-09-25T12:00:00Z",
        "ciphertext",
    )
    return private_key, public_key, envelope


def test_sign_and_verify_happy_path() -> None:
    _, public_key, envelope = _signed_envelope()

    assert verify_envelope(public_key, envelope)


def test_signing_input_is_canonical_and_domain_separated() -> None:
    signing_input = build_signing_input("alice", "bob", "m", 1, "t", "c")

    assert isinstance(signing_input, bytes)
    assert b"SENTRA-MSG-v1" in signing_input
    assert signing_input == canonical_bytes(
        "SENTRA-MSG-v1",
        "alice",
        "bob",
        "m",
        1,
        "t",
        "c",
    )


def test_json_round_trip_preserves_verifiable_envelope() -> None:
    _, public_key, envelope = _signed_envelope()

    serialized = json.dumps(envelope_to_dict(envelope))
    restored = envelope_from_dict(json.loads(serialized))

    assert restored == envelope
    assert verify_envelope(public_key, restored)


@pytest.mark.parametrize(
    "field, replacement",
    [
        ("sender", "mallory"),
        ("recipient", "mallory"),
        ("message_id", "message-2"),
        ("timestamp", "2026-09-25T12:01:00Z"),
        ("sequence", 2),
        ("ciphertext_b64", "tampered"),
    ],
)
def test_tampering_any_signed_field_fails(
    field: str,
    replacement: str | int,
) -> None:
    _, public_key, envelope = _signed_envelope()
    values = envelope_to_dict(envelope)
    values[field] = replacement
    tampered = envelope_from_dict(values)

    assert not verify_envelope(public_key, tampered)


def test_different_signing_key_fails_verification() -> None:
    _, public_key, envelope = _signed_envelope()
    _, different_public_key = generate_keypair()

    assert not verify_envelope(different_public_key, envelope)
    assert verify_envelope(public_key, envelope)


def test_authentication_signature_cannot_verify_as_message_signature() -> None:
    private_key, public_key = generate_keypair()
    challenge = generate_challenge()
    auth_signature = create_response(private_key, challenge)
    envelope = SignedEnvelope(
        message_id="message-1",
        sender="alice",
        recipient="bob",
        timestamp="2026-09-25T12:00:00Z",
        sequence=1,
        ciphertext_b64="ciphertext",
        signature_b64=base64.b64encode(auth_signature).decode("ascii"),
    )

    assert not verify_envelope(public_key, envelope)


@pytest.mark.parametrize(
    "signature_b64",
    ["not base64!!!", "", base64.b64encode(os.urandom(10)).decode("ascii")],
)
def test_invalid_signature_encoding_fails(signature_b64: str) -> None:
    _, public_key, envelope = _signed_envelope()
    invalid = SignedEnvelope(
        message_id=envelope.message_id,
        sender=envelope.sender,
        recipient=envelope.recipient,
        timestamp=envelope.timestamp,
        sequence=envelope.sequence,
        ciphertext_b64=envelope.ciphertext_b64,
        signature_b64=signature_b64,
    )

    assert not verify_envelope(public_key, invalid)


@pytest.mark.parametrize(
    "missing_field",
    [
        "message_id",
        "sender",
        "recipient",
        "timestamp",
        "sequence",
        "ciphertext_b64",
        "signature_b64",
    ],
)
def test_missing_envelope_fields_raise_value_error(missing_field: str) -> None:
    data = envelope_to_dict(_signed_envelope()[2])
    del data[missing_field]

    with pytest.raises(ValueError, match=f"Missing envelope field: {missing_field}"):
        envelope_from_dict(data)


def test_envelope_from_dict_rejects_string_sequence() -> None:
    data = envelope_to_dict(_signed_envelope()[2])
    data["sequence"] = "1"

    with pytest.raises(ValueError, match="sequence"):
        envelope_from_dict(data)


def test_envelope_from_dict_ignores_extra_keys() -> None:
    envelope = _signed_envelope()[2]
    data = envelope_to_dict(envelope)
    data["future_field"] = "ignored"

    restored = envelope_from_dict(data)

    assert restored == envelope


def test_signed_envelope_is_frozen() -> None:
    envelope = _signed_envelope()[2]

    with pytest.raises(FrozenInstanceError):
        envelope.sender = "mallory"


def test_sign_envelope_rejects_empty_sender() -> None:
    private_key, _ = generate_keypair()

    with pytest.raises(ValueError):
        sign_envelope(private_key, "", "bob", "m", 1, "t", "c")


def test_sign_envelope_rejects_negative_sequence() -> None:
    private_key, _ = generate_keypair()

    with pytest.raises(ValueError):
        sign_envelope(private_key, "alice", "bob", "m", -1, "t", "c")


def test_zero_sequence_is_valid() -> None:
    private_key, public_key = generate_keypair()
    envelope = sign_envelope(private_key, "alice", "bob", "m", 0, "t", "c")

    assert envelope.sequence == 0
    assert verify_envelope(public_key, envelope)


def test_canonical_signing_input_disambiguates_field_boundaries() -> None:
    first = build_signing_input("A", "B", "m", 1, "t", "c")
    second = build_signing_input("AB", "", "m", 1, "t", "c")

    assert first != second


def test_envelope_to_dict_has_exactly_seven_keys() -> None:
    envelope = _signed_envelope()[2]

    assert set(envelope_to_dict(envelope)) == {
        "message_id",
        "sender",
        "recipient",
        "timestamp",
        "sequence",
        "ciphertext_b64",
        "signature_b64",
    }
