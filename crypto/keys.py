"""Ed25519 key generation, PEM serialization, loading, and fingerprinting."""

from __future__ import annotations

import hashlib
from os import PathLike
from pathlib import Path
from typing import TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PathType: TypeAlias = str | PathLike[str]


def _require_private_key(private_key: Ed25519PrivateKey) -> Ed25519PrivateKey:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    return private_key


def _require_public_key(public_key: Ed25519PublicKey) -> Ed25519PublicKey:
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    return public_key


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate and return a fresh Ed25519 private/public key pair.

    Returns:
        tuple[Ed25519PrivateKey, Ed25519PublicKey]: The new key pair.

    Raises:
        No standard-library exceptions are expected for valid operation.
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_private_key(
    private_key: Ed25519PrivateKey,
    path: PathType,
    password: bytes | None = None,
) -> None:
    """Write an Ed25519 private key to a PKCS8 PEM file.

    Args:
        private_key: Ed25519 private key to serialize.
        path: Destination filesystem path.
        password: Optional password used for PEM encryption.

    Raises:
        TypeError: If the key or password has an invalid type.
        OSError: If the destination cannot be written.
    """
    key = _require_private_key(private_key)
    if password is not None and not isinstance(password, bytes):
        raise TypeError("password must be bytes or None")

    encryption = (
        serialization.NoEncryption()
        if password is None
        else serialization.BestAvailableEncryption(password)
    )
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    Path(path).write_bytes(pem_bytes)


def save_public_key(public_key: Ed25519PublicKey, path: PathType) -> None:
    """Write an Ed25519 public key as SubjectPublicKeyInfo PEM.

    Args:
        public_key: Ed25519 public key to serialize.
        path: Destination filesystem path.

    Raises:
        TypeError: If public_key is not an Ed25519PublicKey.
        OSError: If the destination cannot be written.
    """
    key = _require_public_key(public_key)
    pem_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(path).write_bytes(pem_bytes)


def load_private_key(
    path: PathType,
    password: bytes | None = None,
) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PKCS8 PEM file.

    Args:
        path: Source filesystem path.
        password: Password for an encrypted PEM file, if applicable.

    Returns:
        Ed25519PrivateKey: The loaded private key.

    Raises:
        FileNotFoundError: If path does not exist.
        ValueError: If the PEM is invalid, encrypted with the wrong password,
            or contains a non-Ed25519 private key.
        TypeError: If password has an invalid type.
    """
    if password is not None and not isinstance(password, bytes):
        raise TypeError("password must be bytes or None")
    loaded_key = serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=password,
    )
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise ValueError("PEM does not contain an Ed25519 private key")
    return loaded_key


def load_public_key(path: PathType) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a SubjectPublicKeyInfo PEM file.

    Args:
        path: Source filesystem path.

    Returns:
        Ed25519PublicKey: The loaded public key.

    Raises:
        FileNotFoundError: If path does not exist.
        ValueError: If the PEM is invalid or contains a non-Ed25519 key.
    """
    loaded_key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(loaded_key, Ed25519PublicKey):
        raise ValueError("PEM does not contain an Ed25519 public key")
    return loaded_key


def serialize_public_key(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to SubjectPublicKeyInfo PEM bytes.

    Args:
        public_key: Ed25519 public key to serialize.

    Returns:
        bytes: PEM-encoded public-key bytes.

    Raises:
        TypeError: If public_key is not an Ed25519PublicKey.
    """
    key = _require_public_key(public_key)
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes) -> Ed25519PublicKey:
    """Deserialize an Ed25519 public key from SubjectPublicKeyInfo PEM bytes.

    Args:
        pem_bytes: PEM-encoded public-key bytes.

    Returns:
        Ed25519PublicKey: The deserialized public key.

    Raises:
        TypeError: If pem_bytes is not bytes.
        ValueError: If the PEM is invalid or contains a non-Ed25519 key.
    """
    if not isinstance(pem_bytes, bytes):
        raise TypeError("pem_bytes must be bytes")
    loaded_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(loaded_key, Ed25519PublicKey):
        raise ValueError("PEM does not contain an Ed25519 public key")
    return loaded_key


def fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return an uppercase, hyphen-separated SHA-256 public-key fingerprint.

    Args:
        public_key: Ed25519 public key to fingerprint.

    Returns:
        str: The SHA-256 digest of the PEM public-key bytes, formatted as
            groups of four uppercase hexadecimal characters.

    Raises:
        TypeError: If public_key is not an Ed25519PublicKey.
    """
    digest = hashlib.sha256(serialize_public_key(public_key)).hexdigest().upper()
    return "-".join(
        digest[index : index + 4] for index in range(0, len(digest), 4)
    )
