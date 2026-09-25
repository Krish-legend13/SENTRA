"""Tests for recovery-code generation, hashing, and single-use consumption."""

import pytest

from auth import (
    consume_recovery_code,
    generate_recovery_codes,
    hash_recovery_code,
    verify_recovery_code,
)
from auth.recovery import RECOVERY_ALPHABET


def test_generated_recovery_codes_are_distinct_and_valid() -> None:
    codes = generate_recovery_codes()

    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert all(
        len(code) == 12 and all(character in RECOVERY_ALPHABET for character in code)
        for code in codes
    )


def test_zero_recovery_code_count_is_rejected() -> None:
    with pytest.raises(ValueError):
        generate_recovery_codes(0)


def test_explicit_salt_hash_is_deterministic_and_random_salt_differs() -> None:
    salt = b"\x01" * 16

    first = hash_recovery_code("AbCdEf123456", salt)
    second = hash_recovery_code("abcdef123456", salt)
    random_first = hash_recovery_code("AbCdEf123456")
    random_second = hash_recovery_code("AbCdEf123456")

    assert first == second
    assert random_first != random_second


def test_recovery_code_verification_is_case_insensitive() -> None:
    stored_hash = hash_recovery_code("AbCdEf123456", b"\x02" * 16)

    assert verify_recovery_code(stored_hash, "ABCDEF123456")
    assert verify_recovery_code(stored_hash, "abcdef123456")


@pytest.mark.parametrize("stored_hash", ["garbage", "abc:", ":def", "zz:zz"])
def test_malformed_stored_hash_returns_false(stored_hash: str) -> None:
    assert not verify_recovery_code(stored_hash, "ABCDEF123456")


def test_consume_recovery_code_removes_matching_hash() -> None:
    codes = generate_recovery_codes(2)
    stored_hashes = [hash_recovery_code(code) for code in codes]

    consumed, remaining = consume_recovery_code(stored_hashes, codes[0].lower())

    assert consumed
    assert len(remaining) == 1
    assert stored_hashes[0] not in remaining


def test_consume_unknown_code_preserves_original_list() -> None:
    code = generate_recovery_codes(1)[0]
    stored_hashes = [hash_recovery_code(code)]

    consumed, remaining = consume_recovery_code(stored_hashes, "ZZZZZZZZZZZZ")

    assert not consumed
    assert remaining == stored_hashes


def test_consuming_same_code_twice_fails() -> None:
    code = generate_recovery_codes(1)[0]
    stored_hashes = [hash_recovery_code(code)]

    first_consumed, remaining = consume_recovery_code(stored_hashes, code)
    second_consumed, second_remaining = consume_recovery_code(remaining, code)

    assert first_consumed
    assert not second_consumed
    assert second_remaining == []
