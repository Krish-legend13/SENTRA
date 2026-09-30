"""Tests for the registry's TOTP-secret extensions."""

import base64
import sqlite3
from pathlib import Path

import pytest

from auth import (
    clear_totp_secret,
    get_totp_secret,
    get_user,
    init_registry,
    register_user,
    set_totp_secret,
)
from auth.totp import generate_totp_secret, secret_to_base32
from crypto import generate_keypair, serialize_public_key


def _fresh_secret() -> str:
    return secret_to_base32(generate_totp_secret())


def _columns(db_path: Path) -> set[str]:
    connection = sqlite3.connect(db_path)
    try:
        return {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    finally:
        connection.close()


def test_init_registry_creates_totp_secret_column(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"

    init_registry(db_path)

    assert "totp_secret" in _columns(db_path)


def test_migration_adds_column_without_losing_rows(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"

    # Create a database using the pre-TOTP schema and insert one row.
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                public_key_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        pem_b64 = base64.b64encode(serialize_public_key(public_key)).decode("ascii")
        connection.execute(
            "INSERT INTO users (username, public_key_pem, status, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("alice", pem_b64, "AUTHORIZED", "2026-01-01T00:00:00+00:00"),
        )
        connection.commit()
    finally:
        connection.close()

    init_registry(db_path)

    assert "totp_secret" in _columns(db_path)
    assert get_user(db_path, "alice") is not None
    assert get_totp_secret(db_path, "alice") is None


def test_init_registry_twice_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"

    init_registry(db_path)
    init_registry(db_path)

    assert "totp_secret" in _columns(db_path)


def test_set_then_get_totp_secret_round_trips(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)
    secret = _fresh_secret()

    set_totp_secret(db_path, "alice", secret)

    assert get_totp_secret(db_path, "alice") == secret


def test_get_totp_secret_none_for_registered_user_without_secret(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)

    assert get_totp_secret(db_path, "alice") is None


def test_get_totp_secret_none_for_unregistered_user(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    init_registry(db_path)

    assert get_totp_secret(db_path, "unknown") is None


def test_set_totp_secret_raises_key_error_for_unknown_user(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    init_registry(db_path)

    with pytest.raises(KeyError):
        set_totp_secret(db_path, "unknown", _fresh_secret())


def test_set_totp_secret_raises_value_error_for_empty_secret(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)

    with pytest.raises(ValueError):
        set_totp_secret(db_path, "alice", "")


def test_set_totp_secret_raises_type_error_for_non_string_secret(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)

    with pytest.raises(TypeError):
        set_totp_secret(db_path, "alice", b"not-a-string")


def test_clear_totp_secret_sets_value_back_to_none(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)
    set_totp_secret(db_path, "alice", _fresh_secret())

    clear_totp_secret(db_path, "alice")

    assert get_totp_secret(db_path, "alice") is None


def test_clear_totp_secret_raises_key_error_for_unknown_user(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    init_registry(db_path)

    with pytest.raises(KeyError):
        clear_totp_secret(db_path, "unknown")


def test_enrolling_second_secret_overwrites_first(tmp_path: Path) -> None:
    _, public_key = generate_keypair()
    db_path = tmp_path / "auth.sqlite3"
    register_user(db_path, "alice", public_key)

    set_totp_secret(db_path, "alice", _fresh_secret())
    second = _fresh_secret()
    set_totp_secret(db_path, "alice", second)

    assert get_totp_secret(db_path, "alice") == second
