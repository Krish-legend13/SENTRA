"""Authorized-user registry and challenge-response authentication helpers."""

from .challenge import (
    ChallengeStore,
    create_response,
    generate_challenge,
    verify_response,
)
from .registry import (
    UserRecord,
    get_user,
    init_registry,
    list_users,
    register_user,
    set_user_status,
)
from .recovery import (
    consume_recovery_code,
    generate_recovery_codes,
    hash_recovery_code,
    verify_recovery_code,
)
from .totp import (
    TOTPReplayGuard,
    base32_to_secret,
    build_otpauth_uri,
    find_matching_counter,
    generate_totp,
    generate_totp_secret,
    secret_to_base32,
    verify_totp,
)

__all__ = [
    "ChallengeStore",
    "UserRecord",
    "create_response",
    "generate_challenge",
    "get_user",
    "init_registry",
    "list_users",
    "register_user",
    "set_user_status",
    "verify_response",
    "TOTPReplayGuard",
    "base32_to_secret",
    "build_otpauth_uri",
    "find_matching_counter",
    "generate_totp",
    "generate_totp_secret",
    "secret_to_base32",
    "verify_totp",
    "consume_recovery_code",
    "generate_recovery_codes",
    "hash_recovery_code",
    "verify_recovery_code",
]
