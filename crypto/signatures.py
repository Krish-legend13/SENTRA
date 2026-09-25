"""Ed25519 signing and deterministic canonical serialization helpers."""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_bytes(*fields: str | int | bytes) -> bytes:
    """Serialize heterogeneous fields deterministically with type and length prefixes.

    Args:
        *fields: Values to serialize; each must be a str, int, or bytes.

    Returns:
        bytes: A canonical byte string containing a field-count prefix and one
            type-tagged length-prefixed value per field.

    Raises:
        TypeError: If a field is not str, int, or bytes.
        OverflowError: If an integer cannot be represented by its canonical
            encoding.
    """
    encoded_fields = bytearray(struct.pack(">Q", len(fields)))
    for field in fields:
        if type(field) is str:
            type_tag = b"s"
            value = field.encode("utf-8")
        elif type(field) is int:
            type_tag = b"i"
            value = str(field).encode("ascii")
        elif type(field) is bytes:
            type_tag = b"b"
            value = field
        else:
            raise TypeError("fields must contain only str, int, or bytes")

        encoded_fields.extend(type_tag)
        encoded_fields.extend(struct.pack(">Q", len(value)))
        encoded_fields.extend(value)
    return bytes(encoded_fields)


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign data with an Ed25519 private key.

    Args:
        private_key: Ed25519 private key used for signing.
        data: Byte string to sign.

    Returns:
        bytes: The 64-byte Ed25519 signature.

    Raises:
        TypeError: If private_key is not an Ed25519PrivateKey or data is not
            bytes.
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return private_key.sign(data)


def verify(
    public_key: Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify an Ed25519 signature without raising for invalid signatures.

    Args:
        public_key: Ed25519 public key used for verification.
        signature: Signature bytes to verify.
        data: Original signed data.

    Returns:
        bool: True when the signature is valid; otherwise False.

    Raises:
        TypeError: If public_key is not an Ed25519PublicKey or data is not
            bytes.
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(signature, bytes):
        return False
    try:
        public_key.verify(signature, data)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
