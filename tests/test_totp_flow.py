"""Tests for verify_with_replay_guard."""

import pytest

from auth import (
    TOTPReplayGuard,
    generate_totp,
    secret_to_base32,
    verify_with_replay_guard,
)

RFC_SECRET = b"12345678901234567890"
RFC_SECRET_B32 = secret_to_base32(RFC_SECRET)
TIMESTAMP = 1234567890


def test_verify_valid_code_returns_ok() -> None:
    guard = TOTPReplayGuard()
    code = generate_totp(RFC_SECRET, TIMESTAMP)

    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "alice", guard, timestamp=TIMESTAMP)
        == (True, "ok")
    )


def test_invalid_code_returns_invalid_code() -> None:
    guard = TOTPReplayGuard()

    assert (
        verify_with_replay_guard(RFC_SECRET_B32, "000000", "alice", guard, timestamp=TIMESTAMP)
        == (False, "invalid_code")
    )


def test_same_valid_code_twice_is_replayed() -> None:
    guard = TOTPReplayGuard()
    code = generate_totp(RFC_SECRET, TIMESTAMP)

    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "alice", guard, timestamp=TIMESTAMP)
        == (True, "ok")
    )
    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "alice", guard, timestamp=TIMESTAMP)
        == (False, "replayed_code")
    )


def test_two_identities_with_same_counter_are_independent() -> None:
    guard = TOTPReplayGuard()
    code = generate_totp(RFC_SECRET, TIMESTAMP)

    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "alice", guard, timestamp=TIMESTAMP)
        == (True, "ok")
    )
    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "bob", guard, timestamp=TIMESTAMP)
        == (True, "ok")
    )


def test_malformed_secret_b32_returns_invalid_stored_secret() -> None:
    guard = TOTPReplayGuard()

    assert (
        verify_with_replay_guard("not-valid!", "000000", "alice", guard, timestamp=TIMESTAMP)
        == (False, "invalid_stored_secret")
    )


@pytest.mark.parametrize("code", ["", "abc"])
def test_invalid_code_strings_return_invalid_code(code: str) -> None:
    guard = TOTPReplayGuard()

    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "alice", guard, timestamp=TIMESTAMP)
        == (False, "invalid_code")
    )


def test_non_string_secret_raises_type_error() -> None:
    guard = TOTPReplayGuard()

    with pytest.raises(TypeError):
        verify_with_replay_guard(
            b"not-a-string", "000000", "alice", guard, timestamp=TIMESTAMP
        )


def test_invalid_code_does_not_consume_counter() -> None:
    guard = TOTPReplayGuard()
    code = generate_totp(RFC_SECRET, TIMESTAMP)

    assert (
        verify_with_replay_guard(RFC_SECRET_B32, "000000", "alice", guard, timestamp=TIMESTAMP)
        == (False, "invalid_code")
    )
    assert (
        verify_with_replay_guard(RFC_SECRET_B32, code, "alice", guard, timestamp=TIMESTAMP)
        == (True, "ok")
    )
