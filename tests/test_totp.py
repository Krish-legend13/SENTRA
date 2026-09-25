"""Tests for RFC 6238 TOTP helpers and replay protection."""

import base64

import pytest

from auth import (
    TOTPReplayGuard,
    base32_to_secret,
    build_otpauth_uri,
    find_matching_counter,
    generate_totp,
    generate_totp_secret,
    secret_to_base32,
    verify_totp,
)


RFC_SECRET = b"12345678901234567890"


@pytest.mark.parametrize(
    "timestamp, expected_eight_digits",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_sha1_vectors(
    timestamp: int,
    expected_eight_digits: str,
) -> None:
    assert generate_totp(RFC_SECRET, timestamp) == expected_eight_digits[-6:]


def test_totp_is_deterministic() -> None:
    codes = {generate_totp(RFC_SECRET, 1234567890.0) for _ in range(100)}

    assert codes == {generate_totp(RFC_SECRET, 1234567890.0)}


def test_totp_format_and_step_change() -> None:
    first = generate_totp(RFC_SECRET, 1234567890)
    second = generate_totp(RFC_SECRET, 1234567920)

    assert len(first) == 6
    assert first.isdigit()
    assert first != second


def test_verify_current_code() -> None:
    code = generate_totp(RFC_SECRET, 1234567890)

    assert verify_totp(RFC_SECRET, code, 1234567890)
    assert find_matching_counter(RFC_SECRET, code, 1234567890) == 41152263


def test_totp_window_behavior() -> None:
    timestamp = 1234567890
    previous = generate_totp(RFC_SECRET, timestamp - 30)
    current = generate_totp(RFC_SECRET, timestamp)
    next_code = generate_totp(RFC_SECRET, timestamp + 30)
    two_away = generate_totp(RFC_SECRET, timestamp + 60)

    assert not verify_totp(RFC_SECRET, previous, timestamp, window=0)
    assert not verify_totp(RFC_SECRET, next_code, timestamp, window=0)
    assert verify_totp(RFC_SECRET, previous, timestamp, window=1)
    assert verify_totp(RFC_SECRET, current, timestamp, window=1)
    assert verify_totp(RFC_SECRET, next_code, timestamp, window=1)
    assert not verify_totp(RFC_SECRET, two_away, timestamp, window=1)
    assert find_matching_counter(RFC_SECRET, previous, timestamp, 1) == 41152262
    assert find_matching_counter(RFC_SECRET, next_code, timestamp, 1) == 41152264


def test_unmatched_code_has_no_counter() -> None:
    assert find_matching_counter(RFC_SECRET, "000000", 1234567890, 0) is None


@pytest.mark.parametrize(
    "code",
    ["", "12345", "1234567", "abcdef", "12 456", None],
)
def test_invalid_codes_return_false(code: str | None) -> None:
    assert not verify_totp(RFC_SECRET, code, 1234567890)


def test_invalid_secret_types_and_empty_secrets() -> None:
    with pytest.raises(TypeError):
        generate_totp("secret", 0)
    with pytest.raises(ValueError):
        generate_totp(b"", 0)
    with pytest.raises(TypeError):
        verify_totp("secret", "000000", 0)


def test_base32_round_trip_and_padding() -> None:
    encoded = secret_to_base32(RFC_SECRET)
    padded = base64.b32encode(RFC_SECRET).decode("ascii")

    assert base32_to_secret(encoded) == RFC_SECRET
    assert base32_to_secret(padded) == RFC_SECRET


def test_invalid_base32_is_rejected() -> None:
    with pytest.raises(ValueError):
        base32_to_secret("not-valid!")


def test_otpauth_uri_contains_expected_parameters() -> None:
    secret_b32 = secret_to_base32(RFC_SECRET)
    uri = build_otpauth_uri(secret_b32, "alice@example.com", "SENTRA")

    assert uri.startswith("otpauth://totp/")
    assert "alice%40example.com" in uri
    assert "secret=" + secret_b32 in uri
    assert "issuer=SENTRA" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_generate_secret_length() -> None:
    assert len(generate_totp_secret()) == 20


def test_replay_guard_tracks_newer_counters() -> None:
    guard = TOTPReplayGuard()

    assert guard.check_and_record("alice", 100)
    assert not guard.check_and_record("alice", 100)
    assert not guard.check_and_record("alice", 99)
    assert guard.check_and_record("alice", 101)


def test_replay_guard_identities_are_independent() -> None:
    guard = TOTPReplayGuard()

    assert guard.check_and_record("alice", 100)
    assert guard.check_and_record("bob", 100)
    assert len(guard) == 2


def test_replay_guard_evicts_oldest_identity() -> None:
    guard = TOTPReplayGuard(max_identities=2)
    guard.check_and_record("alice", 100)
    guard.check_and_record("bob", 100)
    guard.check_and_record("carol", 100)

    assert len(guard) == 2
    assert guard.check_and_record("alice", 100)


def test_replay_guard_forget_and_invalid_capacity() -> None:
    guard = TOTPReplayGuard()
    guard.check_and_record("alice", 100)
    guard.forget("alice")
    guard.forget("unknown")

    assert len(guard) == 0
    with pytest.raises(ValueError):
        TOTPReplayGuard(max_identities=0)
