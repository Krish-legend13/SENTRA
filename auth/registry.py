"""SQLite-backed registry of authorized Ed25519 public keys."""

from __future__ import annotations

import base64
import binascii
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from crypto.keys import (
    PathType,
    deserialize_public_key,
    serialize_public_key,
)

AUTHORIZED = "AUTHORIZED"
REVOKED = "REVOKED"
VALID_STATUSES = frozenset({AUTHORIZED, REVOKED})


@dataclass(frozen=True)
class UserRecord:
    """Represent one registered username and its public identity key.

    Attributes:
        username: Normalized, case-sensitive username.
        public_key: Registered Ed25519 public key.
        status: Either ``AUTHORIZED`` or ``REVOKED``.
        created_at: ISO-8601 UTC creation timestamp.
    """

    username: str
    public_key: Ed25519PublicKey
    status: str
    created_at: str


def _connect(db_path: PathType) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise TypeError("username must be a string")
    normalized = username.strip()
    if not normalized:
        raise ValueError("Username must not be empty")
    return normalized


def _validate_status(status: str) -> str:
    if not isinstance(status, str) or status not in VALID_STATUSES:
        raise ValueError(f"Invalid user status: {status}")
    return status


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )


def _record_from_row(
    row: tuple[str, str, str, str],
) -> UserRecord:
    username, public_key_pem, status, created_at = row
    try:
        public_key_bytes = base64.b64decode(public_key_pem.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Stored public key is not valid base64") from exc
    public_key = deserialize_public_key(public_key_bytes)
    return UserRecord(username, public_key, status, created_at)


def init_registry(db_path: PathType) -> None:
    """Create the registry schema if it does not already exist.

    Args:
        db_path: SQLite database path.

    Returns:
        None: The registry database is initialized.

    Raises:
        OSError: If the database cannot be opened or written.
        sqlite3.Error: If SQLite cannot create the schema.
    """
    connection = _connect(db_path)
    try:
        with connection:
            _ensure_schema(connection)
    finally:
        connection.close()


def register_user(
    db_path: PathType,
    username: str,
    public_key: Ed25519PublicKey,
    status: str = AUTHORIZED,
) -> None:
    """Register a username and Ed25519 public key in the registry.

    Args:
        db_path: SQLite database path.
        username: Case-sensitive username; surrounding whitespace is removed.
        public_key: Ed25519 public key to register.
        status: Initial status, either ``AUTHORIZED`` or ``REVOKED``.

    Returns:
        None: The user is inserted into the registry.

    Raises:
        TypeError: If username or public_key has an invalid type.
        ValueError: If username or status is invalid, or username is already
            registered.
        OSError: If the database cannot be opened or written.
        sqlite3.Error: If SQLite reports another database error.
    """
    normalized_username = _normalize_username(username)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    validated_status = _validate_status(status)
    pem_b64 = base64.b64encode(serialize_public_key(public_key)).decode("ascii")
    created_at = datetime.now(timezone.utc).isoformat()

    connection = _connect(db_path)
    try:
        with connection:
            _ensure_schema(connection)
            try:
                connection.execute(
                    """
                    INSERT INTO users
                        (username, public_key_pem, status, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (normalized_username, pem_b64, validated_status, created_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    f"Username already registered: {normalized_username}"
                ) from exc
    finally:
        connection.close()


def get_user(db_path: PathType, username: str) -> UserRecord | None:
    """Retrieve a registered user by normalized, case-sensitive username.

    Args:
        db_path: SQLite database path.
        username: Username to look up; surrounding whitespace is removed.

    Returns:
        UserRecord | None: The matching user, or None when not registered.

    Raises:
        TypeError: If username is not a string.
        ValueError: If username is empty or stored key data is invalid.
        OSError: If the database cannot be opened or read.
        sqlite3.Error: If SQLite reports a database error.
    """
    normalized_username = _normalize_username(username)
    init_registry(db_path)
    connection = _connect(db_path)
    try:
        row = connection.execute(
            """
            SELECT username, public_key_pem, status, created_at
            FROM users
            WHERE username = ?
            """,
            (normalized_username,),
        ).fetchone()
    finally:
        connection.close()
    return None if row is None else _record_from_row(row)


def set_user_status(db_path: PathType, username: str, status: str) -> None:
    """Update the status of a registered user.

    Args:
        db_path: SQLite database path.
        username: Username to update; surrounding whitespace is removed.
        status: New status, either ``AUTHORIZED`` or ``REVOKED``.

    Returns:
        None: The user's status is updated.

    Raises:
        TypeError: If username is not a string.
        ValueError: If username is empty or status is invalid.
        KeyError: If username is not registered.
        OSError: If the database cannot be opened or written.
        sqlite3.Error: If SQLite reports another database error.
    """
    normalized_username = _normalize_username(username)
    validated_status = _validate_status(status)
    init_registry(db_path)
    connection = _connect(db_path)
    try:
        with connection:
            cursor = connection.execute(
                "UPDATE users SET status = ? WHERE username = ?",
                (validated_status, normalized_username),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Unknown username: {normalized_username}")
    finally:
        connection.close()


def list_users(
    db_path: PathType,
    status: str | None = None,
) -> list[UserRecord]:
    """List registered users, optionally filtered by status.

    Args:
        db_path: SQLite database path.
        status: Optional status filter, either ``AUTHORIZED`` or ``REVOKED``.

    Returns:
        list[UserRecord]: Matching records ordered by username.

    Raises:
        ValueError: If status is invalid or stored key data is invalid.
        OSError: If the database cannot be opened or read.
        sqlite3.Error: If SQLite reports a database error.
    """
    if status is not None:
        status = _validate_status(status)
    init_registry(db_path)
    connection = _connect(db_path)
    try:
        if status is None:
            rows = connection.execute(
                """
                SELECT username, public_key_pem, status, created_at
                FROM users
                ORDER BY username
                """
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT username, public_key_pem, status, created_at
                FROM users
                WHERE status = ?
                ORDER BY username
                """,
                (status,),
            ).fetchall()
    finally:
        connection.close()
    return [_record_from_row(row) for row in rows]
