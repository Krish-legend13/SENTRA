"""Tests for the SQLite-backed authorized-user registry."""

from pathlib import Path

import pytest

from auth import (
    UserRecord,
    get_user,
    init_registry,
    list_users,
    register_user,
    set_user_status,
)
from crypto import generate_keypair, sign, verify


def test_register_and_get_user_round_trip(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"

    init_registry(db_path)
    register_user(db_path, " alice ", public_key)

    record = get_user(db_path, "alice")
    assert isinstance(record, UserRecord)
    assert record.username == "alice"
    assert record.status == "AUTHORIZED"
    signature = sign(private_key, b"registry identity")
    assert verify(record.public_key, signature, b"registry identity")
    assert record.created_at.endswith("+00:00")


def test_duplicate_registration_raises_value_error(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)

    with pytest.raises(ValueError, match="Username already registered: alice"):
        register_user(db_path, " alice ", public_key)


@pytest.mark.parametrize("username", ["", "   "])
def test_empty_usernames_are_rejected(
    tmp_path: Path,
    username: str,
) -> None:
    _, public_key = generate_keypair()

    with pytest.raises(ValueError, match="Username must not be empty"):
        register_user(tmp_path / "auth.sqlite3", username, public_key)


def test_non_string_username_is_rejected(tmp_path: Path) -> None:
    _, public_key = generate_keypair()

    with pytest.raises(TypeError):
        register_user(tmp_path / "auth.sqlite3", None, public_key)


def test_unknown_user_returns_none(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    init_registry(db_path)

    assert get_user(db_path, "unknown") is None


def test_set_status_revokes_user(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)

    set_user_status(db_path, " alice ", "REVOKED")

    record = get_user(db_path, "alice")
    assert record is not None
    assert record.status == "REVOKED"


def test_set_status_unknown_user_raises_key_error(tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        set_user_status(tmp_path / "auth.sqlite3", "unknown", "REVOKED")


def test_invalid_status_is_rejected(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"

    with pytest.raises(ValueError):
        register_user(db_path, "alice", public_key, "BANNED")

    register_user(db_path, "alice", public_key)
    with pytest.raises(ValueError):
        set_user_status(db_path, "alice", "BANNED")


def test_list_users_can_filter_by_status(tmp_path: Path) -> None:
    _, alice_key = generate_keypair()
    _, bob_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", alice_key)
    register_user(db_path, "bob", bob_key)
    set_user_status(db_path, "bob", "REVOKED")

    all_users = list_users(db_path)
    authorized = list_users(db_path, status="AUTHORIZED")
    revoked = list_users(db_path, status="REVOKED")

    assert [user.username for user in all_users] == ["alice", "bob"]
    assert [user.username for user in authorized] == ["alice"]
    assert [user.username for user in revoked] == ["bob"]


def test_init_registry_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"

    init_registry(db_path)
    init_registry(db_path)

    assert list_users(db_path) == []
