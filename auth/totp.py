"""RFC 6238 TOTP primitives and a thread-safe replay guard.

TOTP secrets are credentials and should be encrypted at rest by the caller.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import threading
import time
from collections import OrderedDict
from urllib.parse import quote

TOTP_DIGITS = 6
TOTP_STEP_SECONDS = 30
TOTP_SECRET_BYTES = 20
DEFAULT_WINDOW = 1


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    if not secret:
        raise ValueError("secret must not be empty")
    return secret


def _resolve_timestamp(timestamp: float | None) -> float:
    if timestamp is None:
        return time.time()
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        raise TypeError("timestamp must be a number or None")
    if timestamp < 0:
        raise ValueError("timestamp must not be negative")
    return float(timestamp)


def _validate_window(window: int) -> int:
    if not isinstance(window, int) or isinstance(window, bool):
        raise TypeError("window must be an integer")
    if window < 0:
        raise ValueError("window must be non-negative")
    return window


def _counter_for_timestamp(timestamp: float | None) -> int:
    return int(_resolve_timestamp(timestamp)) // TOTP_STEP_SECONDS


def generate_totp_secret() -> bytes:
    """Generate a cryptographically random 20-byte TOTP secret.

    Returns:
        bytes: A random secret suitable for HMAC-SHA1 TOTP.

    Raises:
        No standard-library exceptions are expected for valid operation.
    """
    return secrets.token_bytes(TOTP_SECRET_BYTES)


def secret_to_base32(secret: bytes) -> str:
    """Encode a TOTP secret as unpadded RFC 4648 Base32.

    Args:
        secret: Non-empty TOTP secret bytes.

    Returns:
        str: Uppercase Base32 without trailing padding.

    Raises:
        TypeError: If secret is not bytes.
        ValueError: If secret is empty.
    """
    return base64.b32encode(_validate_secret(secret)).decode("ascii").rstrip("=")


def base32_to_secret(secret_b32: str) -> bytes:
    """Decode padded or unpadded RFC 4648 Base32 into a TOTP secret.

    Args:
        secret_b32: Base32 secret with or without ``=`` padding.

    Returns:
        bytes: The decoded non-empty secret.

    Raises:
        TypeError: If secret_b32 is not a string.
        ValueError: If the input is invalid Base32 or decodes to empty bytes.
    """
    if not isinstance(secret_b32, str):
        raise TypeError("secret_b32 must be a string")
    if not secret_b32:
        raise ValueError("secret_b32 must not be empty")
    unpadded = secret_b32.rstrip("=")
    padding = "=" * (-len(unpadded) % 8)
    try:
        secret = base64.b32decode(
            (unpadded + padding).encode("ascii"),
            casefold=True,
        )
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("secret_b32 is not valid Base32") from exc
    if not secret:
        raise ValueError("secret_b32 must not decode to an empty secret")
    return secret


def build_otpauth_uri(
    secret_b32: str,
    account_name: str,
    issuer: str = "SENTRA",
) -> str:
    """Build a Google Authenticator-compatible TOTP enrollment URI.

    Args:
        secret_b32: Base32-encoded TOTP secret.
        account_name: Account label shown by the authenticator.
        issuer: Issuer label shown by the authenticator.

    Returns:
        str: An ``otpauth://totp/`` URI using SHA1, six digits, and 30 seconds.

    Raises:
        TypeError: If an argument has an invalid type.
        ValueError: If secret_b32, account_name, or issuer is empty.
    """
    if not isinstance(secret_b32, str):
        raise TypeError("secret_b32 must be a string")
    if not isinstance(account_name, str):
        raise TypeError("account_name must be a string")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a string")
    if not secret_b32:
        raise ValueError("secret_b32 must not be empty")
    if not account_name:
        raise ValueError("account_name must not be empty")
    if not issuer:
        raise ValueError("issuer must not be empty")
    encoded_issuer = quote(issuer, safe="")
    encoded_account = quote(account_name, safe="")
    return (
        f"otpauth://totp/{encoded_issuer}:{encoded_account}"
        f"?secret={quote(secret_b32, safe='')}"
        f"&issuer={encoded_issuer}&algorithm=SHA1&digits={TOTP_DIGITS}"
        f"&period={TOTP_STEP_SECONDS}"
    )


def generate_totp(secret: bytes, timestamp: float | None = None) -> str:
    """Generate a six-digit RFC 6238 TOTP code.

    Args:
        secret: Non-empty HMAC secret bytes.
        timestamp: Unix timestamp, or the current time when omitted.

    Returns:
        str: A zero-padded six-digit TOTP code.

    Raises:
        TypeError: If secret or timestamp has an invalid type.
        ValueError: If secret is empty or timestamp is negative.
    """
    secret = _validate_secret(secret)
    counter = _counter_for_timestamp(timestamp)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary_code = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return str(binary_code % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def find_matching_counter(
    secret: bytes,
    code: str,
    timestamp: float | None = None,
    window: int = DEFAULT_WINDOW,
) -> int | None:
    """Find the TOTP counter matching a code within a time window.

    Args:
        secret: Non-empty HMAC secret bytes.
        code: Candidate six-digit code.
        timestamp: Unix timestamp, or the current time when omitted.
        window: Number of steps before and after the current step to check.

    Returns:
        int | None: Matching counter, or None for an invalid/non-matching code.

    Raises:
        TypeError: If secret, timestamp, or window has an invalid type.
        ValueError: If secret is empty, timestamp is negative, or window is
            negative.
    """
    secret = _validate_secret(secret)
    window = _validate_window(window)
    if not isinstance(code, str) or len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    base_counter = _counter_for_timestamp(timestamp)
    for counter in range(base_counter - window, base_counter + window + 1):
        if counter < 0:
            continue
        candidate = generate_totp(secret, counter * TOTP_STEP_SECONDS)
        if hmac.compare_digest(candidate, code):
            return counter
    return None


def verify_totp(
    secret: bytes,
    code: str,
    timestamp: float | None = None,
    window: int = DEFAULT_WINDOW,
) -> bool:
    """Verify a TOTP code within the configured time window.

    Args:
        secret: Non-empty HMAC secret bytes.
        code: Candidate six-digit code.
        timestamp: Unix timestamp, or the current time when omitted.
        window: Number of steps before and after the current step to check.

    Returns:
        bool: True if a matching counter is found, otherwise False.

    Raises:
        TypeError: If secret, timestamp, or window has an invalid type.
        ValueError: If secret is empty, timestamp is negative, or window is
            negative.
    """
    return find_matching_counter(secret, code, timestamp, window) is not None


class TOTPReplayGuard:
    """Thread-safe bounded tracker of the highest consumed TOTP counter."""

    def __init__(self, max_identities: int = 10000) -> None:
        """Create a replay guard with a positive identity capacity.

        Args:
            max_identities: Maximum number of identities to retain.

        Raises:
            TypeError: If max_identities is not an integer.
            ValueError: If max_identities is zero or negative.
        """
        if not isinstance(max_identities, int) or isinstance(max_identities, bool):
            raise TypeError("max_identities must be an integer")
        if max_identities <= 0:
            raise ValueError("max_identities must be positive")
        self._max_identities = max_identities
        self._counters: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_record(self, identity: str, counter: int) -> bool:
        """Accept and record a strictly newer counter for an identity.

        Args:
            identity: Identity associated with the TOTP counter.
            counter: Non-negative TOTP counter.

        Returns:
            bool: True when recorded as newer; False for replay or older input.

        Raises:
            TypeError: If identity or counter has an invalid type.
            ValueError: If identity is empty or counter is negative.
        """
        if not isinstance(identity, str):
            raise TypeError("identity must be a string")
        if not identity:
            raise ValueError("identity must not be empty")
        if not isinstance(counter, int) or isinstance(counter, bool):
            raise TypeError("counter must be an integer")
        if counter < 0:
            raise ValueError("counter must be non-negative")
        with self._lock:
            previous = self._counters.get(identity)
            if previous is not None and counter <= previous:
                return False
            self._counters[identity] = counter
            self._counters.move_to_end(identity)
            if len(self._counters) > self._max_identities:
                self._counters.popitem(last=False)
            return True

    def forget(self, identity: str) -> None:
        """Forget an identity's recorded counter if present.

        Args:
            identity: Identity to remove.

        Returns:
            None: The identity is removed when present.

        Raises:
            TypeError: If identity is not a string.
        """
        if not isinstance(identity, str):
            raise TypeError("identity must be a string")
        with self._lock:
            self._counters.pop(identity, None)

    def __len__(self) -> int:
        """Return the number of identities currently tracked.

        Returns:
            int: Number of tracked identities.
        """
        with self._lock:
            return len(self._counters)


def verify_with_replay_guard(
    secret_b32: str,
    code: str,
    identity: str,
    guard: TOTPReplayGuard,
    timestamp: float | None = None,
    window: int = DEFAULT_WINDOW,
) -> tuple[bool, str]:
    """Verify a TOTP code with per-identity replay protection.

    Decodes the stored Base32 secret, locates the matching counter, and only
    accepts a counter that the replay guard has not already consumed for this
    identity. The guard's state is mutated only when a counter matches; an
    invalid code leaves it untouched.

    Args:
        secret_b32: Base32-encoded TOTP secret as stored in the registry.
        code: Candidate six-digit TOTP code.
        identity: Identity the replay guard tracks (typically the username).
        guard: Shared, thread-safe replay guard.
        timestamp: Unix timestamp, or the current time when omitted.
        window: Number of steps before and after the current step to check.

    Returns:
        tuple[bool, str]: ``(True, "ok")`` on success, otherwise
            ``(False, reason)`` where reason is ``"invalid_stored_secret"``,
            ``"invalid_code"``, or ``"replayed_code"``.

    Raises:
        TypeError: If secret_b32 or code is not a string.
        ValueError: If the secret is empty, the timestamp is negative, or the
            window is negative.
    """
    if not isinstance(secret_b32, str):
        raise TypeError("secret_b32 must be a string")
    if not isinstance(code, str):
        raise TypeError("code must be a string")
    try:
        secret = base32_to_secret(secret_b32)
    except ValueError:
        return (False, "invalid_stored_secret")
    counter = find_matching_counter(secret, code, timestamp, window)
    if counter is None:
        return (False, "invalid_code")
    if not guard.check_and_record(identity, counter):
        return (False, "replayed_code")
    return (True, "ok")
