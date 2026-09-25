"""Password-protected at-rest storage for Ed25519 private keys."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .keys import PathType, _require_private_key
from .signatures import canonical_bytes

VAULT_VERSION = 1
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
MIN_PASSPHRASE_LENGTH = 8
GCM_TAG_BYTES = 16


def validate_passphrase(passphrase: str) -> None:
    """Validate a vault passphrase before any cryptographic operation.

    Args:
        passphrase: Passphrase used to protect or unlock a vault.

    Returns:
        None: The function returns when the passphrase is valid.

    Raises:
        TypeError: If passphrase is not a string.
        ValueError: If passphrase is shorter than eight characters or contains
            only whitespace.
    """
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters"
        )
    if not passphrase.strip():
        raise ValueError("passphrase must not be empty or whitespace")


def _derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=KEY_BYTES,
        maxmem=128 * n * r * 2,
    )


def _aad(
    version: int,
    kdf_algorithm: str,
    n: int,
    r: int,
    p: int,
    salt: bytes,
    cipher_algorithm: str,
    nonce: bytes,
) -> bytes:
    return canonical_bytes(
        version,
        kdf_algorithm,
        n,
        r,
        p,
        salt,
        cipher_algorithm,
        nonce,
    )


def _encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_bytes(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"Vault field {field_name!r} must be a base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"Vault field {field_name!r} is not valid base64") from exc


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Vault field {field_name!r} must be an object")
    return value


def _required(mapping: dict[str, Any], key: str) -> Any:
    if key not in mapping:
        raise ValueError(f"Vault file is missing required key: {key}")
    return mapping[key]


def save_key_to_vault(
    private_key: Ed25519PrivateKey,
    path: PathType,
    passphrase: str,
) -> None:
    """Encrypt and atomically save an Ed25519 private key in a versioned vault.

    Args:
        private_key: Ed25519 private key to protect.
        path: Destination vault path.
        passphrase: Passphrase used for scrypt key derivation.

    Returns:
        None: The encrypted vault is written to path.

    Raises:
        TypeError: If private_key or passphrase has an invalid type.
        ValueError: If passphrase is invalid.
        OSError: If the vault cannot be written.
    """
    validate_passphrase(passphrase)
    key = _require_private_key(private_key)
    target_path = Path(path)
    temporary_path = Path(f"{target_path}.tmp")

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    derived_key = _derive_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    aad = _aad(
        VAULT_VERSION,
        "scrypt",
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        salt,
        "AES-256-GCM",
        nonce,
    )
    plaintext = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(nonce),
    ).encryptor()
    encryptor.authenticate_additional_data(aad)
    encrypted = encryptor.update(plaintext) + encryptor.finalize()
    ciphertext = encrypted + encryptor.tag

    vault_data = {
        "version": VAULT_VERSION,
        "kdf": {
            "algorithm": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": _encode_bytes(salt),
        },
        "cipher": {
            "algorithm": "AES-256-GCM",
            "nonce": _encode_bytes(nonce),
            "ciphertext": _encode_bytes(ciphertext),
        },
    }

    try:
        temporary_path.write_text(
            json.dumps(vault_data, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_path, target_path)
        try:
            os.chmod(target_path, 0o600)
        except (OSError, NotImplementedError):
            pass
    except Exception:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise


def load_key_from_vault(path: PathType, passphrase: str) -> Ed25519PrivateKey:
    """Load and decrypt an Ed25519 private key from a vault file.

    Args:
        path: Source vault path.
        passphrase: Passphrase used to derive the decryption key.

    Returns:
        Ed25519PrivateKey: The decrypted private key.

    Raises:
        FileNotFoundError: If path does not exist.
        TypeError: If passphrase is not a string.
        ValueError: If the passphrase, JSON, vault structure, algorithms,
            ciphertext, authentication tag, or decrypted PEM is invalid.
    """
    validate_passphrase(passphrase)
    try:
        raw_text = Path(path).read_text(encoding="utf-8")
        vault_data = json.loads(raw_text)
    except FileNotFoundError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Vault file is not valid JSON") from exc

    root = _require_mapping(vault_data, "root")
    version = _required(root, "version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("Vault version must be an integer")
    if version != VAULT_VERSION:
        raise ValueError(f"Unsupported vault version: {version}")

    kdf = _require_mapping(_required(root, "kdf"), "kdf")
    cipher = _require_mapping(_required(root, "cipher"), "cipher")
    kdf_algorithm = _required(kdf, "algorithm")
    n = _required(kdf, "n")
    r = _required(kdf, "r")
    p = _required(kdf, "p")
    salt = _decode_bytes(_required(kdf, "salt"), "kdf.salt")
    cipher_algorithm = _required(cipher, "algorithm")
    nonce = _decode_bytes(_required(cipher, "nonce"), "cipher.nonce")
    ciphertext = _decode_bytes(_required(cipher, "ciphertext"), "cipher.ciphertext")

    if kdf_algorithm != "scrypt":
        raise ValueError(f"Unsupported KDF algorithm: {kdf_algorithm}")
    if cipher_algorithm != "AES-256-GCM":
        raise ValueError(f"Unsupported cipher algorithm: {cipher_algorithm}")
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (n, r, p)):
        raise ValueError("Vault scrypt parameters must be integers")
    if (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise ValueError("Unsupported vault scrypt parameters")
    if len(salt) != SALT_BYTES:
        raise ValueError("Vault salt has an invalid length")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("Vault nonce has an invalid length")
    if len(ciphertext) <= GCM_TAG_BYTES:
        raise ValueError("Vault ciphertext is truncated")

    aad = _aad(
        version,
        kdf_algorithm,
        n,
        r,
        p,
        salt,
        cipher_algorithm,
        nonce,
    )
    derived_key = _derive_key(passphrase, salt, n, r, p)
    tag = ciphertext[-GCM_TAG_BYTES:]
    encrypted = ciphertext[:-GCM_TAG_BYTES]

    try:
        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(nonce, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(encrypted) + decryptor.finalize()
    except InvalidTag as exc:
        raise ValueError(
            "Vault decryption failed: wrong passphrase or corrupted file"
        ) from exc

    try:
        loaded_key = serialization.load_pem_private_key(
            plaintext,
            password=None,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Vault plaintext is not a valid private key") from exc
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise ValueError("Vault plaintext is not an Ed25519 private key")
    return loaded_key


def vault_exists(path: PathType) -> bool:
    """Return whether path identifies an existing vault file.

    Args:
        path: Filesystem path to inspect.

    Returns:
        bool: True for an existing regular file, otherwise False.

    Raises:
        TypeError: If path cannot be interpreted as a filesystem path.
    """
    return Path(path).is_file()
