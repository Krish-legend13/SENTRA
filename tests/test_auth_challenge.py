"""Tests for challenge-response authentication primitives."""

import os
import time

import pytest

from auth import (
    ChallengeStore,
    create_response,
    generate_challenge,
    verify_response,
)
from crypto import canonical_bytes, generate_keypair, sign


def test_challenge_response_happy_path() -> None:
    private_key, public_key = generate_keypair()
    challenge = generate_challenge()

    response = create_response(private_key, challenge)

    assert len(response) == 64
    assert verify_response(public_key, challenge, response)


def test_tampered_challenge_does_not_verify() -> None:
    private_key, public_key = generate_keypair()
    challenge = generate_challenge()
    response = create_response(private_key, challenge)
    tampered = bytes([challenge[0] ^ 1]) + challenge[1:]

    assert not verify_response(public_key, tampered, response)


def test_response_from_different_key_does_not_verify() -> None:
    private_key, _ = generate_keypair()
    _, different_public_key = generate_keypair()
    challenge = generate_challenge()
    response = create_response(private_key, challenge)

    assert not verify_response(different_public_key, challenge, response)


@pytest.mark.parametrize(
    "response",
    [b"", os.urandom(10), sign(generate_keypair()[0], b"different data")],
)
def test_invalid_responses_return_false(response: bytes) -> None:
    _, public_key = generate_keypair()
    challenge = generate_challenge()

    assert not verify_response(public_key, challenge, response)


def test_domain_separation_rejects_wrong_domain_signature() -> None:
    private_key, public_key = generate_keypair()
    challenge = generate_challenge()
    response = sign(
        private_key,
        canonical_bytes("WRONG-DOMAIN", challenge),
    )

    assert not verify_response(public_key, challenge, response)


def test_create_response_rejects_non_bytes_challenge() -> None:
    private_key, _ = generate_keypair()

    with pytest.raises(TypeError):
        create_response(private_key, "challenge")


def test_verify_response_rejects_wrong_key_type() -> None:
    challenge = generate_challenge()

    with pytest.raises(TypeError):
        verify_response(None, challenge, b"")


def test_generate_challenge_values_are_distinct() -> None:
    challenges = {generate_challenge() for _ in range(100)}

    assert len(challenges) == 100


def test_challenge_store_issue_and_consume() -> None:
    store = ChallengeStore()
    challenge_id, challenge = store.issue("alice")

    assert len(store) == 1
    assert store.consume(challenge_id) == challenge
    assert len(store) == 0
    assert store.consume(challenge_id) is None


def test_challenge_store_unknown_id_returns_none() -> None:
    assert ChallengeStore().consume("unknown") is None


def test_challenge_store_ids_are_distinct() -> None:
    store = ChallengeStore()
    first_id, _ = store.issue("alice")
    second_id, _ = store.issue("alice")

    assert first_id != second_id
    assert len(store) == 2


def test_challenge_store_expires_entries() -> None:
    store = ChallengeStore(ttl_seconds=1)
    challenge_id, _ = store.issue("alice")

    time.sleep(1.1)

    assert store.consume(challenge_id) is None
    assert len(store) == 0


@pytest.mark.parametrize("ttl_seconds", [0, -1])
def test_challenge_store_requires_positive_ttl(ttl_seconds: int) -> None:
    with pytest.raises(ValueError):
        ChallengeStore(ttl_seconds=ttl_seconds)
