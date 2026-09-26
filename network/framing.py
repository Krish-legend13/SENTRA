"""Length-prefixed JSON framing for SENTRA sockets.

Every packet on the wire is a 4-byte unsigned big-endian length prefix
followed by a UTF-8 JSON payload, per PROTOCOL.md. This module is
transport-agnostic: it works identically over a plain ``socket.socket`` or
an ``ssl.SSLSocket`` (mTLS), since both expose ``recv``/``sendall``.
"""

from __future__ import annotations

import json
import struct

MAX_FRAME_BYTES = 1024 * 1024  # 1 MiB
_LENGTH_STRUCT = struct.Struct(">I")


class FrameError(Exception):
    """Raised when a peer sends a malformed or oversized frame."""


class ConnectionClosed(Exception):
    """Raised when the peer closes the connection cleanly mid-read."""


def _recv_exact(sock, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionClosed("Peer closed connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_packet(sock, packet: dict) -> None:
    """Encode ``packet`` as JSON and send it length-prefixed.

    Raises:
        FrameError: If the encoded payload exceeds MAX_FRAME_BYTES.
        OSError: If the underlying socket write fails.
    """
    payload = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise FrameError(f"Packet too large: {len(payload)} bytes")
    sock.sendall(_LENGTH_STRUCT.pack(len(payload)) + payload)


def recv_packet(sock) -> dict:
    """Block for one full length-prefixed frame and return the parsed JSON.

    Raises:
        ConnectionClosed: If the peer closes the connection.
        FrameError: If the length prefix is oversized or the payload is not
            valid UTF-8 JSON, or is not a JSON object.
    """
    header = _recv_exact(sock, _LENGTH_STRUCT.size)
    (length,) = _LENGTH_STRUCT.unpack(header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise FrameError(f"Invalid frame length: {length}")
    raw = _recv_exact(sock, length)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FrameError("Frame payload is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FrameError("Frame payload is not valid JSON") from exc
    if not isinstance(data, dict) or "type" not in data:
        raise FrameError("Frame payload must be a JSON object with a 'type' field")
    return data
