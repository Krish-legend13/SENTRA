"""Ed25519 challenge-response authentication and single-use challenge storage."""

from __future__ import annotations

import secrets
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crypto.signatures import canonical_bytes, sign, verify

CHALLENGE_BYTES = 32
DEFAULT_TTL_SECONDS = 30
DOMAIN_STRING = "SENTRA-AUTH-v1"


def generate_challenge() -> bytes:
    """Generate a cryptographically random authentication challenge.

    Returns:
        bytes: A 32-byte random challenge.

    Raises:
        No standard-library exceptions are expected for valid operation.
    """
    return secrets.token_bytes(CHALLENGE_BYTES)


def create_response(
    private_key: Ed25519PrivateKey,
    challenge: bytes,
) -> bytes:
    """Sign a domain-separated authentication challenge.

    Args:
        private_key: Ed25519 private key used to sign the challenge.
        challenge: Challenge bytes received from the authenticator.

    Returns:
        bytes: The 64-byte Ed25519 signature.

    Raises:
        TypeError: If private_key is not an Ed25519PrivateKey or challenge is
            not bytes.
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if not isinstance(challenge, bytes):
        raise TypeError("challenge must be bytes")
    return sign(private_key, canonical_bytes(DOMAIN_STRING, challenge))


def verify_response(
    public_key: Ed25519PublicKey,
    challenge: bytes,
    response: bytes,
) -> bool:
    """Verify a domain-separated signed authentication challenge.

    Args:
        public_key: Ed25519 public key used to verify the response.
        challenge: Original challenge bytes.
        response: Candidate Ed25519 signature.

    Returns:
        bool: True if response authenticates challenge; otherwise False.

    Raises:
        TypeError: If public_key is not an Ed25519PublicKey.
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    if not isinstance(challenge, bytes) or not isinstance(response, bytes):
        return False
    return verify(
        public_key,
        response,
        canonical_bytes(DOMAIN_STRING, challenge),
    )


class ChallengeStore:
    """Thread-safe, single-use store for time-limited authentication challenges."""

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        """Create a challenge store with a positive monotonic-clock TTL.

        Args:
            ttl_seconds: Number of seconds before an issued challenge expires.

        Raises:
            TypeError: If ttl_seconds is not an integer.
            ValueError: If ttl_seconds is zero or negative.
        """
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise TypeError("ttl_seconds must be an integer")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl_seconds = ttl_seconds
        self._challenges: dict[str, tuple[str, bytes, float]] = {}
        self._lock = threading.Lock()

    def issue(self, username: str) -> tuple[str, bytes]:
        """Issue and store a challenge for a username.

        Args:
            username: Username associated with the challenge.

        Returns:
            tuple[str, bytes]: A unique challenge ID and challenge bytes.

        Raises:
            TypeError: If username is not a string.
            ValueError: If username is empty or only whitespace.
        """
        if not isinstance(username, str):
            raise TypeError("username must be a string")
        normalized_username = username.strip()
        if not normalized_username:
            raise ValueError("Username must not be empty")

        challenge = generate_challenge()
        issued_at = time.monotonic()
        with self._lock:
            challenge_id = secrets.token_hex(16)
            while challenge_id in self._challenges:
                challenge_id = secrets.token_hex(16)
            self._challenges[challenge_id] = (
                normalized_username,
                challenge,
                issued_at,
            )
        return challenge_id, challenge

    def consume(self, challenge_id: str) -> bytes | None:
        """Consume a challenge once, returning None when absent or expired.

        Args:
            challenge_id: ID returned by issue().

        Returns:
            bytes | None: The unexpired challenge bytes, or None.

        Raises:
            No standard-library exceptions are expected for valid operation.
        """
        with self._lock:
            entry = self._challenges.pop(challenge_id, None)
        if entry is None:
            return None
        _, challenge, issued_at = entry
        if time.monotonic() - issued_at > self._ttl_seconds:
            return None
        return challenge

    def __len__(self) -> int:
        """Return the number of pending, unconsumed challenges.

        Returns:
            int: Number of entries currently held by the store.
        """
        with self._lock:
            return len(self._challenges)
