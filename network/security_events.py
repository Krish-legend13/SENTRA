"""Structured, machine-parseable security event logging for SENTRA.

Every security-relevant occurrence (auth success/failure, registration,
connection lifecycle, heartbeat timeout, message routing, replay/flood
detection, lockouts) is emitted as a single JSON line so it can be tailed,
shipped to a SIEM, or grepped during an investigation without a custom
parser.

Format (one JSON object per line)::

    {
      "ts": "2026-09-25T10:15:03.482Z",
      "event": "AUTH_FAILURE",
      "severity": "WARNING",
      "actor": "alice",
      "peer_addr": "127.0.0.1:51422",
      "session_id": "b3f1...",
      "detail": {"reason": "signature_mismatch"}
    }
"""

from __future__ import annotations

import datetime
import json
import threading
from pathlib import Path
from typing import Any

SEVERITIES = ("INFO", "WARNING", "CRITICAL")

DEFAULT_LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "security_events.log"

_lock = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SecurityEventLogger:
    """Thread-safe append-only structured event logger."""

    def __init__(self, log_path: Path | str = DEFAULT_LOG_PATH, echo_to_stdout: bool = True) -> None:
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._echo = echo_to_stdout

    def emit(
        self,
        event: str,
        severity: str = "INFO",
        actor: str | None = None,
        peer_addr: str | None = None,
        session_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write one structured event record and return it.

        Raises:
            ValueError: If severity is not one of SEVERITIES.
        """
        if severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")
        record = {
            "ts": _utc_now_iso(),
            "event": event,
            "severity": severity,
            "actor": actor,
            "peer_addr": peer_addr,
            "session_id": session_id,
            "detail": detail or {},
        }
        line = json.dumps(record, separators=(",", ":"))
        with _lock:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self._echo:
            print(f"[{record['severity']}] {record['event']} {line}")
        return record


# Module-level default instance so callers can just `from network.security_events import log_event`
_default_logger = SecurityEventLogger()


def log_event(
    event: str,
    severity: str = "INFO",
    actor: str | None = None,
    peer_addr: str | None = None,
    session_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _default_logger.emit(
        event, severity=severity, actor=actor, peer_addr=peer_addr, session_id=session_id, detail=detail
    )
