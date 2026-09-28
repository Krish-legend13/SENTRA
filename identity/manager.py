"""Vault-backed Ed25519 identity management and session identity access."""

from __future__ import annotations

import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crypto.keys import (
    PathType,
    fingerprint,
    generate_keypair,
    serialize_public_key,
)
from crypto.signatures import sign as sign_data
from crypto.signatures import verify as verify_data
from crypto.encryption import decrypt_payload as decrypt_encrypted_payload
from crypto.vault import (
    load_key_from_vault,
    save_key_to_vault,
    vault_exists,
)

DEFAULT_DATA_ROOT = "."
VAULT_FILENAME = "identity.vault"
DATA_DIR_PREFIX = "data_"

_SESSION_LOCK = threading.Lock()
_SESSION_IDENTITY: IdentityManager | None = None


def _safe_username(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(
            "username must contain at least one alphanumeric, hyphen, or "
            "underscore character"
        )
    safe = "".join(character for character in raw if character.isalnum() or character in "-_")
    if not safe:
        raise ValueError(
            "username must contain at least one alphanumeric, hyphen, or "
            "underscore character"
        )
    return safe


class IdentityManager:
    """Manage one user's vault-protected Ed25519 identity for a session."""

    def __init__(
        self,
        username: str,
        private_key: Ed25519PrivateKey,
        vault_path: PathType,
    ) -> None:
        """Create an identity manager from an already-loaded private key.

        Args:
            username: Non-empty normalized identity username.
            private_key: Ed25519 private key for the identity.
            vault_path: Filesystem path of the identity vault.

        Raises:
            TypeError: If username, private_key, or vault_path has an invalid
                type.
            ValueError: If username is empty.
        """
        if not isinstance(username, str):
            raise TypeError("username must be a string")
        if not username:
            raise ValueError("username must not be empty")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        try:
            normalized_vault_path = Path(vault_path)
        except TypeError as exc:
            raise TypeError("vault_path must be path-like") from exc

        self._username = username
        self._private_key = private_key
        self._vault_path = normalized_vault_path
        self._public_key: Ed25519PublicKey | None = None

    @classmethod
    def load_or_create(
        cls,
        username: str,
        passphrase: str,
        data_root: PathType = DEFAULT_DATA_ROOT,
    ) -> IdentityManager:
        """Load an existing identity vault or create a new one.

        Args:
            username: Raw username to sanitize for the identity directory.
            passphrase: Vault passphrase.
            data_root: Root directory containing per-user identity folders.

        Returns:
            IdentityManager: Manager backed by the user's vault.

        Raises:
            ValueError: If username is invalid or the vault passphrase is
                invalid or incorrect.
            TypeError: If data_root is not path-like.
            OSError: If the vault directory or file cannot be accessed.
        """
        safe_username = _safe_username(username)
        try:
            root = Path(data_root)
        except TypeError as exc:
            raise TypeError("data_root must be path-like") from exc
        vault_path = root / f"{DATA_DIR_PREFIX}{safe_username}" / VAULT_FILENAME
        vault_path.parent.mkdir(parents=True, exist_ok=True)

        if vault_exists(vault_path):
            private_key = load_key_from_vault(vault_path, passphrase)
        else:
            private_key, _ = generate_keypair()
            save_key_to_vault(private_key, vault_path, passphrase)
        return cls(safe_username, private_key, vault_path)

    @property
    def username(self) -> str:
        """Return the normalized username for this identity.

        Returns:
            str: The sanitized identity username.
        """
        return self._username

    @property
    def public_key(self) -> Ed25519PublicKey:
        """Return this identity's Ed25519 public key.

        Returns:
            Ed25519PublicKey: The public key derived from the private key.
        """
        if self._public_key is None:
            self._public_key = self._private_key.public_key()
        return self._public_key

    @property
    def fingerprint(self) -> str:
        """Return the stable fingerprint of this identity's public key.

        Returns:
            str: Uppercase, hyphen-separated SHA-256 fingerprint.
        """
        return fingerprint(self.public_key)

    @property
    def vault_path(self) -> Path:
        """Return the path of this identity's vault file.

        Returns:
            Path: Identity vault path.
        """
        return self._vault_path

    def public_key_pem(self) -> bytes:
        """Serialize this identity's public key as PEM bytes.

        Returns:
            bytes: SubjectPublicKeyInfo PEM bytes.
        """
        return serialize_public_key(self.public_key)

    def sign(self, data: bytes) -> bytes:
        """Sign bytes with this identity's private key.

        Domain separation is not added here; callers must use the appropriate
        domain-separated helper such as the authentication or message signing
        modules when a protocol context requires one.

        Args:
            data: Bytes to sign.

        Returns:
            bytes: The Ed25519 signature.

        Raises:
            TypeError: If data is not bytes.
        """
        return sign_data(self._private_key, data)

    def decrypt_payload(
        self,
        ciphertext_b64: str,
        sender: str,
        recipient: str,
        message_id: str,
    ) -> str:
        """Decrypt a payload for this identity without exposing its key."""
        return decrypt_encrypted_payload(
            ciphertext_b64=ciphertext_b64,
            recipient_private_key=self._private_key,
            sender=sender,
            recipient=recipient,
            message_id=message_id,
        )

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature using this manager's own public key.

        This is a convenience for self-verification. Peer signatures should
        normally be verified with the peer's public key directly.

        Args:
            signature: Signature bytes to verify.
            data: Original signed bytes.

        Returns:
            bool: True if the signature is valid; otherwise False.

        Raises:
            TypeError: If data is not bytes.
        """
        return verify_data(self.public_key, signature, data)


def set_session_identity(manager: IdentityManager | None) -> None:
    """Set or clear the process session identity.

    Args:
        manager: Identity manager to store, or None to clear the slot.

    Returns:
        None: The session slot is updated.

    Raises:
        TypeError: If manager is neither IdentityManager nor None.
    """
    if manager is not None and not isinstance(manager, IdentityManager):
        raise TypeError("manager must be an IdentityManager or None")
    global _SESSION_IDENTITY
    with _SESSION_LOCK:
        _SESSION_IDENTITY = manager


def get_session_identity() -> IdentityManager | None:
    """Return the current process session identity, if one is set.

    Returns:
        IdentityManager | None: The stored manager or None.
    """
    with _SESSION_LOCK:
        return _SESSION_IDENTITY
