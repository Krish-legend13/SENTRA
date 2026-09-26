"""Persistent offline message queue.

When a CHAT_MESSAGE is routed to a recipient who has no active session, the
server stores the full signed envelope here instead of dropping it. The
queue is drained (in order, and deleted) the next time that recipient
successfully authenticates. Storage is SQLite so queued messages survive a
server restart.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from crypto.keys import PathType

_lock = threading.Lock()


def _connect(db_path: PathType) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS offline_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            message_id TEXT NOT NULL,
            envelope_json TEXT NOT NULL,
            queued_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_offline_queue_recipient ON offline_queue(recipient)"
    )


def init_queue(db_path: PathType) -> None:
    """Create the offline-queue schema if it does not already exist."""
    connection = _connect(db_path)
    try:
        with connection:
            _ensure_schema(connection)
    finally:
        connection.close()


def enqueue(db_path: PathType, recipient: str, envelope: dict) -> None:
    """Persist one signed envelope for later delivery to ``recipient``."""
    with _lock:
        connection = _connect(db_path)
        try:
            with connection:
                _ensure_schema(connection)
                connection.execute(
                    """
                    INSERT INTO offline_queue (recipient, message_id, envelope_json, queued_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        recipient,
                        envelope.get("message_id", ""),
                        json.dumps(envelope, separators=(",", ":")),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
        finally:
            connection.close()


def drain(db_path: PathType, recipient: str) -> list[dict]:
    """Return and permanently remove every queued envelope for ``recipient``,
    oldest first."""
    with _lock:
        connection = _connect(db_path)
        try:
            with connection:
                _ensure_schema(connection)
                rows = connection.execute(
                    "SELECT id, envelope_json FROM offline_queue WHERE recipient = ? ORDER BY id ASC",
                    (recipient,),
                ).fetchall()
                if rows:
                    connection.execute(
                        "DELETE FROM offline_queue WHERE recipient = ?", (recipient,)
                    )
        finally:
            connection.close()
    return [json.loads(envelope_json) for _, envelope_json in rows]


def pending_count(db_path: PathType, recipient: str) -> int:
    """Return the number of envelopes currently queued for ``recipient``."""
    connection = _connect(db_path)
    try:
        with connection:
            _ensure_schema(connection)
        (count,) = connection.execute(
            "SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", (recipient,)
        ).fetchone()
        return count
    finally:
        connection.close()
