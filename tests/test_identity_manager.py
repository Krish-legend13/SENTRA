"""Tests for session-scoped vault-backed identity management."""

from pathlib import Path
import threading

import pytest

from crypto import deserialize_public_key, fingerprint, generate_keypair, verify
from identity import (
    IdentityManager,
    get_session_identity,
    set_session_identity,
)


PASSPHRASE = "correct horse battery staple"


def test_load_or_create_creates_working_identity(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    assert manager.username == "alice"
    assert manager.vault_path.exists()
    signature = manager.sign(b"identity data")
    assert verify(manager.public_key, signature, b"identity data")


def test_load_or_create_same_passphrase_reloads_same_identity(
    tmp_path: Path,
) -> None:
    first = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)
    second = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    assert first.fingerprint == second.fingerprint


def test_load_or_create_wrong_passphrase_fails(tmp_path: Path) -> None:
    IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    with pytest.raises(ValueError):
        IdentityManager.load_or_create("alice", "wrong passphrase", tmp_path)


def test_load_or_create_short_passphrase_fails(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        IdentityManager.load_or_create("alice", "123", tmp_path)


def test_different_usernames_get_different_identities(tmp_path: Path) -> None:
    alice = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)
    bob = IdentityManager.load_or_create("bob", PASSPHRASE, tmp_path)

    assert alice.fingerprint != bob.fingerprint
    assert alice.vault_path != bob.vault_path


def test_username_is_sanitized_inside_data_root(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("../evil", PASSPHRASE, tmp_path)

    assert manager.username == "evil"
    assert manager.vault_path.resolve().is_relative_to(tmp_path.resolve())


@pytest.mark.parametrize("username", ["", "   ", "///"])
def test_invalid_usernames_are_rejected(
    tmp_path: Path,
    username: str,
) -> None:
    with pytest.raises(ValueError):
        IdentityManager.load_or_create(username, PASSPHRASE, tmp_path)


def test_fingerprint_matches_crypto_helper(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    assert manager.fingerprint == fingerprint(manager.public_key)


def test_public_key_pem_round_trips(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    restored = deserialize_public_key(manager.public_key_pem())

    assert restored.public_bytes_raw() == manager.public_key.public_bytes_raw()


def test_sign_and_verify_data(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    signature = manager.sign(b"payload")

    assert verify(manager.public_key, signature, b"payload")
    assert not verify(manager.public_key, signature, b"tampered")


def test_empty_data_can_be_signed(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)
    signature = manager.sign(b"")

    assert manager.verify(signature, b"")


def test_sign_rejects_non_bytes(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    with pytest.raises(TypeError):
        manager.sign("not bytes")


def test_manager_verify_handles_valid_and_invalid_signatures(
    tmp_path: Path,
) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    assert manager.verify(manager.sign(b"x"), b"x")
    assert not manager.verify(b"wrong", b"x")


def test_session_identity_set_get_and_clear(tmp_path: Path) -> None:
    manager = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)

    set_session_identity(manager)
    assert get_session_identity() is manager
    set_session_identity(None)
    assert get_session_identity() is None


def test_session_identity_thread_safety_smoke(tmp_path: Path) -> None:
    first = IdentityManager.load_or_create("alice", PASSPHRASE, tmp_path)
    second = IdentityManager.load_or_create("bob", PASSPHRASE, tmp_path)
    errors: list[BaseException] = []

    def worker(manager: IdentityManager) -> None:
        try:
            for _ in range(100):
                set_session_identity(manager)
                assert get_session_identity() in (first, second)
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(first,)),
        threading.Thread(target=worker, args=(second,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    set_session_identity(None)


def test_constructor_rejects_empty_username(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()

    with pytest.raises(ValueError):
        IdentityManager("", private_key, tmp_path / "identity.vault")


def test_constructor_rejects_non_ed25519_key(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        IdentityManager("alice", "not a key", tmp_path / "identity.vault")
