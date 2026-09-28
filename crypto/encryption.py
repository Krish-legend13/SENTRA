"""End-to-end payload encryption for SENTRA.

The server routes the opaque ciphertext and never receives plaintext.
Each message uses a fresh ephemeral X25519 key, HKDF-SHA256, and AES-256-GCM.
The existing Ed25519 identity is deterministically converted to an X25519
key pair, so no second long-term private-key file is required.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.signatures import canonical_bytes

VERSION = b"SENTRA-ENC-v1"
HKDF_INFO_PREFIX = b"SENTRA-PAYLOAD-v1"
EPHEMERAL_PUBLIC_KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
HEADER_BYTES = len(VERSION) + EPHEMERAL_PUBLIC_KEY_BYTES + SALT_BYTES + NONCE_BYTES
P = 2**255 - 19


def _ed25519_private_to_x25519(private_key: Ed25519PrivateKey) -> X25519PrivateKey:
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    scalar = bytearray(hashlib.sha512(seed).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(scalar))


def ed25519_public_to_x25519(public_key: Ed25519PublicKey) -> X25519PublicKey:
    """Convert an Ed25519 public key to the corresponding X25519 public key."""
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    y_bytes = bytearray(raw)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        raise ValueError("invalid Ed25519 public key encoding")
    denominator = (1 - y) % P
    if denominator == 0:
        raise ValueError("invalid Ed25519 public key for X25519 conversion")
    u = ((1 + y) * pow(denominator, P - 2, P)) % P
    return X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))


def _aad(sender: str, recipient: str, message_id: str) -> bytes:
    return canonical_bytes(
        HKDF_INFO_PREFIX,
        sender,
        recipient,
        message_id,
    )


def _derive_key(shared_secret: bytes, salt: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        info=aad,
    ).derive(shared_secret)


def encrypt_payload(
    plaintext: str,
    sender: str,
    recipient: str,
    message_id: str,
    recipient_public_key: Ed25519PublicKey,
) -> str:
    """Encrypt a plaintext message for a recipient."""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    aad = _aad(sender, recipient, message_id)
    recipient_x25519 = ed25519_public_to_x25519(recipient_public_key)
    ephemeral_private = X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(recipient_x25519)
    salt = os.urandom(SALT_BYTES)
    key = _derive_key(shared_secret, salt, aad)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        aad,
    )
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    payload = VERSION + ephemeral_public + salt + nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt_payload(
    ciphertext_b64: str,
    recipient_private_key: Ed25519PrivateKey,
    sender: str,
    recipient: str,
    message_id: str,
) -> str:
    """Decrypt and authenticate a SENTRA payload."""
    try:
        payload = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("payload is not valid base64") from exc

    if len(payload) < HEADER_BYTES + TAG_BYTES or not payload.startswith(VERSION):
        raise ValueError("unsupported or truncated encrypted payload")

    offset = len(VERSION)
    ephemeral_raw = payload[offset:offset + EPHEMERAL_PUBLIC_KEY_BYTES]
    offset += EPHEMERAL_PUBLIC_KEY_BYTES
    salt = payload[offset:offset + SALT_BYTES]
    offset += SALT_BYTES
    nonce = payload[offset:offset + NONCE_BYTES]
    offset += NONCE_BYTES
    ciphertext = payload[offset:]

    if len(ciphertext) < TAG_BYTES:
        raise ValueError("encrypted payload is truncated")

    recipient_x25519 = _ed25519_private_to_x25519(recipient_private_key)
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_raw)
    shared_secret = recipient_x25519.exchange(ephemeral_public)
    aad = _aad(sender, recipient, message_id)
    key = _derive_key(shared_secret, salt, aad)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError("payload authentication failed") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("payload is not valid UTF-8") from exc
