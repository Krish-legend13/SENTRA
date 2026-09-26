"""Multi-session registry.

A single user (username) may hold several simultaneously authenticated
connections at once (laptop + phone, two tabs, etc). Each TCP connection
that completes AUTH_RESULT=OK becomes one Session, keyed by a random
session_id, and is registered under its username. Routing a message to a
user means fanning it out to every live session registered for that
username.
"""

from __future__ import annotations

import dataclasses
import secrets
import threading
import time


@dataclasses.dataclass
class Session:
    session_id: str
    username: str
    sock: object  # ssl.SSLSocket
    peer_addr: str
    connected_at: float = dataclasses.field(default_factory=time.monotonic)
    last_pong_at: float = dataclasses.field(default_factory=time.monotonic)
    send_lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)


class SessionManager:
    """Thread-safe registry of username -> {session_id: Session}."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_user: dict[str, dict[str, Session]] = {}

    def new_session_id(self) -> str:
        return secrets.token_hex(16)

    def register(self, username: str, sock, peer_addr: str) -> Session:
        """Create and register a new session for ``username``."""
        session = Session(
            session_id=self.new_session_id(),
            username=username,
            sock=sock,
            peer_addr=peer_addr,
        )
        with self._lock:
            self._by_user.setdefault(username, {})[session.session_id] = session
        return session

    def touch_pong(self, username: str, session_id: str) -> None:
        with self._lock:
            session = self._by_user.get(username, {}).get(session_id)
            if session is not None:
                session.last_pong_at = time.monotonic()

    def unregister(self, username: str, session_id: str) -> None:
        with self._lock:
            sessions = self._by_user.get(username)
            if sessions is not None:
                sessions.pop(session_id, None)
                if not sessions:
                    del self._by_user[username]

    def sessions_for(self, username: str) -> list[Session]:
        with self._lock:
            return list(self._by_user.get(username, {}).values())

    def is_online(self, username: str) -> bool:
        with self._lock:
            return bool(self._by_user.get(username))

    def session_count(self, username: str) -> int:
        with self._lock:
            return len(self._by_user.get(username, {}))

    def all_sessions(self) -> list[Session]:
        with self._lock:
            return [s for sessions in self._by_user.values() for s in sessions.values()]
