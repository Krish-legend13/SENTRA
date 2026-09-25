"""Ed25519 key, signature, and fingerprint helpers for SENTRA."""

from .keys import (
    deserialize_public_key,
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    serialize_public_key,
)
from .signatures import canonical_bytes, sign, verify
from .vault import (
    load_key_from_vault,
    save_key_to_vault,
    validate_passphrase,
    vault_exists,
)

__all__ = [
    "canonical_bytes",
    "deserialize_public_key",
    "fingerprint",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "save_private_key",
    "save_public_key",
    "serialize_public_key",
    "sign",
    "verify",
    "load_key_from_vault",
    "save_key_to_vault",
    "validate_passphrase",
    "vault_exists",
]
