"""Canonical signing and serialization for signed message envelopes."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crypto.signatures import canonical_bytes, sign, verify

DOMAIN_STRING = "SENTRA-MSG-v1"

_ENVELOPE_FIELDS = (
    "message_id",
    "sender",
    "recipient",
    "timestamp",
    "sequence",
    "ciphertext_b64",
    "signature_b64",
)
_SIGNED_FIELDS = (
    "sender",
    "recipient",
    "message_id",
    "sequence",
    "timestamp",
    "ciphertext_b64",
)


@dataclass(frozen=True)
class SignedEnvelope:
    """Represent a signed routed message envelope.

    Attributes:
        message_id: Unique message identifier.
        sender: Sender identity.
        recipient: Recipient identity.
        timestamp: Message creation timestamp.
        sequence: Non-negative sender sequence number.
        ciphertext_b64: Base64-encoded ciphertext payload.
        signature_b64: Base64-encoded Ed25519 signature.
    """

    message_id: str
    sender: str
    recipient: str
    timestamp: str
    sequence: int
    ciphertext_b64: str
    signature_b64: str


def _validate_text_type(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    return value


def _validate_sequence_type(sequence: Any) -> int:
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise TypeError("sequence must be an integer")
    return sequence


def _validate_signing_fields(
    sender: str,
    recipient: str,
    message_id: str,
    sequence: int,
    timestamp: str,
    ciphertext_b64: str,
) -> None:
    text_fields = (
        ("sender", sender),
        ("recipient", recipient),
        ("message_id", message_id),
        ("timestamp", timestamp),
        ("ciphertext_b64", ciphertext_b64),
    )
    for field_name, value in text_fields:
        _validate_text_type(value, field_name)
        if not value:
            raise ValueError(f"{field_name} must not be empty")
    sequence_value = _validate_sequence_type(sequence)
    if sequence_value < 0:
        raise ValueError("sequence must be non-negative")


def build_signing_input(
    sender: str,
    recipient: str,
    message_id: str,
    sequence: int,
    timestamp: str,
    ciphertext_b64: str,
) -> bytes:
    """Build the canonical byte string signed for an envelope.

    Args:
        sender: Sender identity.
        recipient: Recipient identity.
        message_id: Unique message identifier.
        sequence: Non-negative sender sequence number.
        timestamp: Message creation timestamp.
        ciphertext_b64: Base64-encoded ciphertext payload.

    Returns:
        bytes: Canonical, domain-separated signing input.

    Raises:
        TypeError: If a field has an invalid type.
    """
    return canonical_bytes(
        DOMAIN_STRING,
        _validate_text_type(sender, "sender"),
        _validate_text_type(recipient, "recipient"),
        _validate_text_type(message_id, "message_id"),
        _validate_sequence_type(sequence),
        _validate_text_type(timestamp, "timestamp"),
        _validate_text_type(ciphertext_b64, "ciphertext_b64"),
    )


def sign_envelope(
    private_key: Ed25519PrivateKey,
    sender: str,
    recipient: str,
    message_id: str,
    sequence: int,
    timestamp: str,
    ciphertext_b64: str,
) -> SignedEnvelope:
    """Sign the six routing and payload fields into an immutable envelope.

    Args:
        private_key: Ed25519 private key used for signing.
        sender: Sender identity.
        recipient: Recipient identity.
        message_id: Unique message identifier.
        sequence: Non-negative sender sequence number.
        timestamp: Message creation timestamp.
        ciphertext_b64: Base64-encoded ciphertext payload.

    Returns:
        SignedEnvelope: The populated envelope with a base64 signature.

    Raises:
        TypeError: If private_key or a field has an invalid type.
        ValueError: If a text field is empty or sequence is negative.
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    _validate_signing_fields(
        sender,
        recipient,
        message_id,
        sequence,
        timestamp,
        ciphertext_b64,
    )
    signing_input = build_signing_input(
        sender,
        recipient,
        message_id,
        sequence,
        timestamp,
        ciphertext_b64,
    )
    signature = sign(private_key, signing_input)
    return SignedEnvelope(
        message_id=message_id,
        sender=sender,
        recipient=recipient,
        timestamp=timestamp,
        sequence=sequence,
        ciphertext_b64=ciphertext_b64,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_envelope(
    public_key: Ed25519PublicKey,
    envelope: SignedEnvelope,
) -> bool:
    """Verify an envelope signature over all signed envelope fields.

    Args:
        public_key: Ed25519 public key used for verification.
        envelope: Signed envelope to verify.

    Returns:
        bool: True when the signature matches every signed field; otherwise
            False.

    Raises:
        TypeError: If public_key is not an Ed25519PublicKey, envelope is not a
            SignedEnvelope, or an envelope field has an invalid type.
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    if not isinstance(envelope, SignedEnvelope):
        raise TypeError("envelope must be a SignedEnvelope")

    _validate_text_type(envelope.sender, "sender")
    _validate_text_type(envelope.recipient, "recipient")
    _validate_text_type(envelope.message_id, "message_id")
    _validate_sequence_type(envelope.sequence)
    _validate_text_type(envelope.timestamp, "timestamp")
    _validate_text_type(envelope.ciphertext_b64, "ciphertext_b64")
    _validate_text_type(envelope.signature_b64, "signature_b64")
    if (
        not envelope.sender
        or not envelope.recipient
        or not envelope.message_id
        or not envelope.timestamp
        or not envelope.ciphertext_b64
        or envelope.sequence < 0
    ):
        return False

    signing_input = build_signing_input(
        envelope.sender,
        envelope.recipient,
        envelope.message_id,
        envelope.sequence,
        envelope.timestamp,
        envelope.ciphertext_b64,
    )
    try:
        signature = base64.b64decode(
            envelope.signature_b64.encode("ascii"),
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError, TypeError):
        return False
    return verify(public_key, signature, signing_input)


def envelope_to_dict(envelope: SignedEnvelope) -> dict[str, str | int]:
    """Convert a signed envelope to its JSON-serializable dictionary form.

    Args:
        envelope: Envelope to convert.

    Returns:
        dict[str, str | int]: Dictionary containing exactly seven envelope
            fields.

    Raises:
        TypeError: If envelope is not a SignedEnvelope.
    """
    if not isinstance(envelope, SignedEnvelope):
        raise TypeError("envelope must be a SignedEnvelope")
    return {
        "message_id": envelope.message_id,
        "sender": envelope.sender,
        "recipient": envelope.recipient,
        "timestamp": envelope.timestamp,
        "sequence": envelope.sequence,
        "ciphertext_b64": envelope.ciphertext_b64,
        "signature_b64": envelope.signature_b64,
    }


def envelope_from_dict(data: dict) -> SignedEnvelope:
    """Create a signed envelope from a dictionary representation.

    Args:
        data: Dictionary containing envelope fields. Unknown keys are ignored.

    Returns:
        SignedEnvelope: Parsed immutable envelope.

    Raises:
        TypeError: If data is not a dictionary.
        ValueError: If a required field is missing or has the wrong type.
    """
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")
    values: dict[str, Any] = {}
    for field_name in _ENVELOPE_FIELDS:
        if field_name not in data:
            raise ValueError(f"Missing envelope field: {field_name}")
        values[field_name] = data[field_name]

    text_fields = (
        "message_id",
        "sender",
        "recipient",
        "timestamp",
        "ciphertext_b64",
        "signature_b64",
    )
    for field_name in text_fields:
        if not isinstance(values[field_name], str):
            raise ValueError(f"Envelope field {field_name} must be a string")
    if (
        not isinstance(values["sequence"], int)
        or isinstance(values["sequence"], bool)
    ):
        raise ValueError("Envelope field sequence must be an integer")

    return SignedEnvelope(
        message_id=values["message_id"],
        sender=values["sender"],
        recipient=values["recipient"],
        timestamp=values["timestamp"],
        sequence=values["sequence"],
        ciphertext_b64=values["ciphertext_b64"],
        signature_b64=values["signature_b64"],
    )
