"""Recovery-code generation, scrypt hashing, verification, and consumption."""

from __future__ import annotations

import hashlib
import hmac
import secrets

DEFAULT_RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_LENGTH = 12
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECOVERY_SALT_BYTES = 16
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32


def _validate_code(code: str) -> str:
    if not isinstance(code, str):
        raise TypeError("code must be a string")
    normalized = code.upper()
    if not normalized:
        raise ValueError("code must not be empty")
    return normalized


def _derive_digest(code: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        code.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=128 * SCRYPT_N * SCRYPT_R * 2,
    )


def generate_recovery_codes(
    count: int = DEFAULT_RECOVERY_CODE_COUNT,
) -> list[str]:
    """Generate distinct random recovery codes.

    Args:
        count: Number of codes to generate.

    Returns:
        list[str]: Distinct codes using RECOVERY_ALPHABET.

    Raises:
        TypeError: If count is not an integer.
        ValueError: If count is zero or negative.
    """
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError("count must be an integer")
    if count <= 0:
        raise ValueError("count must be positive")
    codes: set[str] = set()
    while len(codes) < count:
        codes.add(
            "".join(
                secrets.choice(RECOVERY_ALPHABET)
                for _ in range(RECOVERY_CODE_LENGTH)
            )
        )
    return list(codes)


def hash_recovery_code(code: str, salt: bytes | None = None) -> str:
    """Hash a recovery code with scrypt and a hexadecimal salt.

    Codes are uppercased before hashing; whitespace is not stripped.

    Args:
        code: Recovery code to hash.
        salt: Optional 16-byte salt; random when omitted.

    Returns:
        str: ``salt_hex:digest_hex`` encoded hash.

    Raises:
        TypeError: If code is not a string or salt is not bytes or None.
        ValueError: If code is empty or salt is not exactly 16 bytes.
    """
    normalized_code = _validate_code(code)
    if salt is None:
        salt = secrets.token_bytes(RECOVERY_SALT_BYTES)
    elif not isinstance(salt, bytes):
        raise TypeError("salt must be bytes or None")
    elif len(salt) != RECOVERY_SALT_BYTES:
        raise ValueError("salt must be exactly 16 bytes")
    digest = _derive_digest(normalized_code, salt)
    return f"{salt.hex()}:{digest.hex()}"


def _parse_stored_hash(stored_hash: str) -> tuple[bytes, bytes] | None:
    if stored_hash.count(":") != 1:
        return None
    salt_hex, digest_hex = stored_hash.split(":", 1)
    if (
        len(salt_hex) != RECOVERY_SALT_BYTES * 2
        or len(digest_hex) != SCRYPT_DKLEN * 2
    ):
        return None
    try:
        salt = bytes.fromhex(salt_hex)
        digest = bytes.fromhex(digest_hex)
    except ValueError:
        return None
    if len(salt) != RECOVERY_SALT_BYTES or len(digest) != SCRYPT_DKLEN:
        return None
    return salt, digest


def verify_recovery_code(stored_hash: str, presented_code: str) -> bool:
    """Verify a recovery code against a stored scrypt hash.

    Codes are uppercased before verification; whitespace is not stripped.

    Args:
        stored_hash: Stored ``salt_hex:digest_hex`` value.
        presented_code: Candidate recovery code.

    Returns:
        bool: True when the code matches; False for malformed hashes or a
            mismatch.

    Raises:
        TypeError: If stored_hash or presented_code is not a string.
    """
    if not isinstance(stored_hash, str) or not isinstance(presented_code, str):
        raise TypeError("stored_hash and presented_code must be strings")
    parsed = _parse_stored_hash(stored_hash)
    if parsed is None or not presented_code:
        return False
    salt, expected_digest = parsed
    actual_digest = _derive_digest(presented_code.upper(), salt)
    return hmac.compare_digest(actual_digest, expected_digest)


def consume_recovery_code(
    stored_hashes: list[str],
    presented_code: str,
) -> tuple[bool, list[str]]:
    """Verify and remove the first matching recovery-code hash.

    Args:
        stored_hashes: List of stored recovery-code hashes.
        presented_code: Candidate recovery code.

    Returns:
        tuple[bool, list[str]]: Whether a code was consumed and the remaining
            hashes. On failure, the original list is returned unchanged.

    Raises:
        TypeError: If stored_hashes is not a list of strings or presented_code
            is not a string.
    """
    if not isinstance(stored_hashes, list):
        raise TypeError("stored_hashes must be a list")
    if any(not isinstance(stored_hash, str) for stored_hash in stored_hashes):
        raise TypeError("stored_hashes must contain only strings")
    if not isinstance(presented_code, str):
        raise TypeError("presented_code must be a string")
    for index, stored_hash in enumerate(stored_hashes):
        if verify_recovery_code(stored_hash, presented_code):
            return True, stored_hashes[:index] + stored_hashes[index + 1 :]
    return False, stored_hashes
