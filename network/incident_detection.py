"""Backend incident detection for SENTRA.

Tracks per-actor behaviour over sliding time windows and flags three classes
of suspicious activity described in the project brief:

* Repeated authentication failures (credential stuffing / brute force)
* Message flooding (a session sending far more than a normal chat rate)
* Replay attempts (a signed envelope re-sent with a stale/duplicate sequence
  number, or a challenge_id reused after being consumed)

Every detection is reported through ``network.security_events`` so it lands
in the structured audit log. Callers (the server) decide what action to take
(disconnect, temp-ban) based on the returned verdict; this module only
observes and judges.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from network.security_events import log_event

# Tunables. Kept as module constants so they're easy to find and adjust.
AUTH_FAILURE_WINDOW_SECONDS = 60
AUTH_FAILURE_THRESHOLD = 5          # >=5 failures in the window -> lockout

MESSAGE_FLOOD_WINDOW_SECONDS = 10
MESSAGE_FLOOD_THRESHOLD = 30        # >=30 messages in 10s from one session -> flood

LOCKOUT_DURATION_SECONDS = 300


class IncidentDetector:
    """Thread-safe sliding-window detector shared by all connections."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)
        self._message_times: dict[str, deque[float]] = defaultdict(deque)
        self._last_sequence: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}

    # ---- lockouts -----------------------------------------------------

    def is_locked_out(self, key: str) -> bool:
        """Return True if ``key`` (typically an IP address) is under lockout."""
        with self._lock:
            expiry = self._locked_until.get(key)
            if expiry is None:
                return False
            if time.monotonic() >= expiry:
                del self._locked_until[key]
                return False
            return True

    def _trigger_lockout(self, key: str, reason: str, peer_addr: str | None) -> None:
        with self._lock:
            self._locked_until[key] = time.monotonic() + LOCKOUT_DURATION_SECONDS
        log_event(
            "LOCKOUT_TRIGGERED",
            severity="CRITICAL",
            actor=key,
            peer_addr=peer_addr,
            detail={"reason": reason, "duration_seconds": LOCKOUT_DURATION_SECONDS},
        )

    # ---- authentication failures ---------------------------------------

    def record_auth_failure(self, key: str, peer_addr: str | None = None) -> bool:
        """Record a failed authentication attempt for ``key`` (IP or username).

        Returns:
            bool: True if this failure tripped the lockout threshold.
        """
        now = time.monotonic()
        with self._lock:
            window = self._auth_failures[key]
            window.append(now)
            while window and now - window[0] > AUTH_FAILURE_WINDOW_SECONDS:
                window.popleft()
            tripped = len(window) >= AUTH_FAILURE_THRESHOLD
        log_event(
            "AUTH_FAILURE",
            severity="WARNING",
            actor=key,
            peer_addr=peer_addr,
            detail={"failures_in_window": len(window)},
        )
        if tripped:
            self._trigger_lockout(key, "repeated_auth_failure", peer_addr)
        return tripped

    def clear_auth_failures(self, key: str) -> None:
        """Reset the failure window for ``key`` after a successful auth."""
        with self._lock:
            self._auth_failures.pop(key, None)

    # ---- message flooding -----------------------------------------------

    def record_message(self, session_id: str, peer_addr: str | None = None) -> bool:
        """Record one inbound chat message for a session.

        Returns:
            bool: True if the session exceeded the flood threshold.
        """
        now = time.monotonic()
        with self._lock:
            window = self._message_times[session_id]
            window.append(now)
            while window and now - window[0] > MESSAGE_FLOOD_WINDOW_SECONDS:
                window.popleft()
            flooded = len(window) >= MESSAGE_FLOOD_THRESHOLD
        if flooded:
            log_event(
                "MESSAGE_FLOOD_DETECTED",
                severity="CRITICAL",
                actor=session_id,
                peer_addr=peer_addr,
                detail={"messages_in_window": len(window), "window_seconds": MESSAGE_FLOOD_WINDOW_SECONDS},
            )
        return flooded

    # ---- replay detection -------------------------------------------------

    def check_sequence(self, sender: str, sequence: int, peer_addr: str | None = None) -> bool:
        """Validate a per-sender monotonic sequence number.

        Returns:
            bool: True if ``sequence`` is valid (strictly greater than the
                last one seen from this sender). False means replay/reorder.
        """
        with self._lock:
            last = self._last_sequence.get(sender)
            if last is not None and sequence <= last:
                is_replay = True
            else:
                is_replay = False
                self._last_sequence[sender] = sequence
        if is_replay:
            log_event(
                "MESSAGE_REPLAY_DETECTED",
                severity="CRITICAL",
                actor=sender,
                peer_addr=peer_addr,
                detail={"received_sequence": sequence, "last_seen_sequence": last},
            )
        return not is_replay

    def record_challenge_reuse(self, username: str, peer_addr: str | None = None) -> None:
        """Log an attempt to answer an already-consumed or unknown challenge."""
        log_event(
            "AUTH_CHALLENGE_REPLAY",
            severity="CRITICAL",
            actor=username,
            peer_addr=peer_addr,
            detail={"reason": "challenge_id not found or already consumed"},
        )
