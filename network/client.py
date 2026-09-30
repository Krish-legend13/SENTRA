"""SENTRA network client.

Connects over mTLS, authenticates with Ed25519 challenge-response, maintains
heartbeat/reconnect behavior, and performs end-to-end payload encryption.

Payload confidentiality is client-side: each message uses X25519 + HKDF +
AES-256-GCM from ``crypto.encryption``. The server only routes the opaque
ciphertext and still verifies the Ed25519 signature over that ciphertext.
"""

from __future__ import annotations

import base64
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone

from auth.challenge import DOMAIN_STRING as AUTH_DOMAIN_STRING
from crypto.encryption import encrypt_payload
from crypto.keys import PathType, deserialize_public_key, serialize_public_key
from crypto.signatures import canonical_bytes
from identity.manager import IdentityManager
from network.framing import ConnectionClosed, FrameError, recv_packet, send_packet
from network.tls_config import build_client_context
from signing.envelope import (
    build_signing_input,
    envelope_from_dict,
    envelope_to_dict,
    verify_envelope,
)
from signing.envelope import SignedEnvelope

HEARTBEAT_INTERVAL_SECONDS = 15
HEARTBEAT_TIMEOUT_SECONDS = 40
RECONNECT_BASE_DELAY_SECONDS = 1
RECONNECT_MAX_DELAY_SECONDS = 30


class SentraClient:
    def __init__(
        self,
        host: str,
        port: int,
        certfile: PathType,
        keyfile: PathType,
        cafile: PathType,
        identity: IdentityManager,
        on_message=None,
        on_event=None,
        on_totp_required=None,
    ) -> None:
        self.host = host
        self.port = port
        self.tls_context = build_client_context(certfile, keyfile, cafile)
        self.identity = identity
        self.on_message = on_message or (lambda sender, text: print(f"[{sender}] {text}"))
        self.on_event = on_event or (lambda msg: print(f"-- {msg}"))
        self.on_totp_required = on_totp_required or (lambda: input("Enter 6-digit 2FA code: "))

        self._sock: ssl.SSLSocket | None = None
        self._send_lock = threading.Lock()
        self._sequence = int(time.time_ns())

        self._peer_keys: dict[str, object] = {}
        self._pending_key_waiters: dict[str, threading.Event] = {}
        self._pending_messages: dict[str, list[dict]] = {}
        self._peer_keys_lock = threading.Lock()

        self._last_pong_at = time.monotonic()
        self._stop = threading.Event()
        self._connected = threading.Event()

    def run_forever(self) -> None:
        """Connect, authenticate, and keep reconnecting until stop() is called."""
        attempt = 0
        while not self._stop.is_set():
            try:
                self._connect_and_authenticate()
                attempt = 0
                self._connected.set()
                self.on_event(f"Connected and authenticated as {self.identity.username}")
                self._session_loop()
            except (ConnectionClosed, FrameError, OSError, ssl.SSLError) as exc:
                self.on_event(f"Connection lost ({exc!r}); will retry")
            finally:
                self._connected.clear()
                self._close_socket()

            if self._stop.is_set():
                break
            delay = min(RECONNECT_BASE_DELAY_SECONDS * (2 ** attempt), RECONNECT_MAX_DELAY_SECONDS)
            self.on_event(f"Reconnecting in {delay:.0f}s (secure reconnect: full re-auth)")
            self._stop.wait(delay)
            attempt += 1

    def stop(self) -> None:
        self._stop.set()
        self._close_socket()

    def wait_until_connected(self, timeout: float | None = None) -> bool:
        return self._connected.wait(timeout)

    def send_message(self, recipient: str, plaintext: str) -> str:
        """Encrypt, sign, and send a chat message."""
        recipient_key = self.request_identity(recipient)
        if recipient_key is None:
            raise ValueError(f"recipient identity unavailable: {recipient}")

        message_id = uuid.uuid4().hex
        self._sequence += 1
        timestamp = datetime.now(timezone.utc).isoformat()

        ciphertext_b64 = encrypt_payload(
            plaintext=plaintext,
            sender=self.identity.username,
            recipient=recipient,
            message_id=message_id,
            recipient_public_key=recipient_key,
        )
        envelope = self._sign_envelope(recipient, message_id, timestamp, ciphertext_b64)
        packet = envelope_to_dict(envelope)
        packet["type"] = "CHAT_MESSAGE"
        self._send(packet)
        return message_id

    def request_identity(self, target_username: str, timeout: float = 5.0):
        """Fetch and cache a peer's registered Ed25519 public key."""
        with self._peer_keys_lock:
            if target_username in self._peer_keys:
                return self._peer_keys[target_username]
            event = self._pending_key_waiters.setdefault(target_username, threading.Event())

        self._send({"type": "IDENTITY_REQUEST", "target_username": target_username})
        event.wait(timeout)

        with self._peer_keys_lock:
            return self._peer_keys.get(target_username)

    def _sign_envelope(self, recipient, message_id, timestamp, ciphertext_b64) -> SignedEnvelope:
        signing_input = build_signing_input(
            sender=self.identity.username,
            recipient=recipient,
            message_id=message_id,
            sequence=self._sequence,
            timestamp=timestamp,
            ciphertext_b64=ciphertext_b64,
        )
        signature = self.identity.sign(signing_input)
        return SignedEnvelope(
            message_id=message_id,
            sender=self.identity.username,
            recipient=recipient,
            timestamp=timestamp,
            sequence=self._sequence,
            ciphertext_b64=ciphertext_b64,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def _sign_auth_challenge(self, challenge: bytes) -> bytes:
        signing_input = canonical_bytes(AUTH_DOMAIN_STRING, challenge)
        return self.identity.sign(signing_input)

    def _connect_and_authenticate(self) -> None:
        raw_sock = socket.create_connection((self.host, self.port), timeout=10)
        self._sock = self.tls_context.wrap_socket(raw_sock, server_hostname="localhost")
        self._sock.settimeout(None)

        self._register_if_needed()

        self._send({"type": "AUTH_REQUEST", "username": self.identity.username})
        challenge_packet = recv_packet(self._sock)
        if challenge_packet.get("type") != "AUTH_CHALLENGE":
            raise ConnectionClosed(
                f"Unexpected packet during auth: {challenge_packet.get('type')}"
            )

        challenge = base64.b64decode(challenge_packet["challenge_b64"])
        signature = self._sign_auth_challenge(challenge)
        self._send(
            {
                "type": "AUTH_RESPONSE",
                "challenge_id": challenge_packet["challenge_id"],
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            }
        )

        packet = recv_packet(self._sock)
        if packet.get("type") == "TOTP_CHALLENGE":
            code = self.on_totp_required()
            if not isinstance(code, str) or not code.strip():
                raise ConnectionClosed("TOTP code not provided")
            self._send({"type": "TOTP_RESPONSE", "code": code.strip()})
            packet = recv_packet(self._sock)
        result_packet = packet
        if result_packet.get("type") != "AUTH_RESULT" or result_packet.get("status") != "OK":
            raise ConnectionClosed(
                f"Authentication failed: {result_packet.get('reason')}"
            )

        self._last_pong_at = time.monotonic()

    def _register_if_needed(self) -> None:
        pem_bytes = serialize_public_key(self.identity.public_key)
        self._send(
            {
                "type": "REGISTER_IDENTITY",
                "username": self.identity.username,
                "public_key_pem_b64": base64.b64encode(pem_bytes).decode("ascii"),
                "fingerprint": self.identity.fingerprint,
            }
        )
        ack = recv_packet(self._sock)
        if ack.get("type") == "REGISTER_IDENTITY_ACK" and ack.get("status") == "REJECTED":
            reason = ack.get("reason", "")
            if "already registered" not in reason.lower():
                self.on_event(f"Registration rejected: {reason}")

    def _session_loop(self) -> None:
        heartbeat_stop = threading.Event()
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(heartbeat_stop,),
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            while not self._stop.is_set():
                packet = recv_packet(self._sock)
                self._dispatch(packet)
        finally:
            heartbeat_stop.set()

    def _heartbeat_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
            if time.monotonic() - self._last_pong_at > HEARTBEAT_TIMEOUT_SECONDS:
                self.on_event("Heartbeat timeout waiting for server; forcing reconnect")
                self._close_socket()
                return
            try:
                self._send({"type": "HEARTBEAT_PING", "nonce": uuid.uuid4().hex})
            except OSError:
                return

    def _dispatch(self, packet: dict) -> None:
        packet_type = packet.get("type")

        if packet_type == "HEARTBEAT_PING":
            self._send({"type": "HEARTBEAT_PONG", "nonce": packet.get("nonce")})
        elif packet_type == "HEARTBEAT_PONG":
            self._last_pong_at = time.monotonic()
        elif packet_type == "SESSION_INFO":
            self.on_event(
                f"Session {packet.get('session_id')} "
                f"({packet.get('active_sessions')} active session(s) for this account)"
            )
        elif packet_type == "IDENTITY_RESPONSE":
            self._handle_identity_response(packet)
        elif packet_type == "CHAT_MESSAGE":
            self._handle_chat_message(packet)
        elif packet_type == "DELIVERY_STATUS":
            self.on_event(
                f"Message {packet.get('message_id')}: {packet.get('status')}"
            )
        elif packet_type == "MESSAGE_ACK":
            self.on_event(
                f"Message {packet.get('message_id')} acknowledged by "
                f"{packet.get('acked_by')}"
            )
        elif packet_type == "ERROR":
            self.on_event(
                f"Server error: {packet.get('reason')} {packet.get('detail', '')}"
            )
        else:
            self.on_event(f"Unhandled packet type: {packet_type}")

    def _handle_identity_response(self, packet: dict) -> None:
        target = packet.get("target_username")
        pem_b64 = packet.get("public_key_pem_b64")
        replayable: list[dict] = []

        with self._peer_keys_lock:
            if pem_b64:
                self._peer_keys[target] = deserialize_public_key(
                    base64.b64decode(pem_b64)
                )
            event = self._pending_key_waiters.pop(target, None)
            replayable = self._pending_messages.pop(target, [])

        if event is not None:
            event.set()

        for pending_packet in replayable:
            self._process_chat_message(pending_packet)

    def _handle_chat_message(self, packet: dict) -> None:
        try:
            envelope = envelope_from_dict(packet)
        except ValueError:
            self.on_event("Received malformed message envelope; dropped")
            return

        with self._peer_keys_lock:
            have_key = envelope.sender in self._peer_keys
            if not have_key:
                already_requested = envelope.sender in self._pending_messages
                self._pending_messages.setdefault(envelope.sender, []).append(packet)

        if not have_key:
            if not already_requested:
                self._send(
                    {
                        "type": "IDENTITY_REQUEST",
                        "target_username": envelope.sender,
                    }
                )
            return

        self._process_chat_message(packet)

    def _process_chat_message(self, packet: dict) -> None:
        envelope = envelope_from_dict(packet)

        with self._peer_keys_lock:
            sender_key = self._peer_keys.get(envelope.sender)

        if sender_key is None or not verify_envelope(sender_key, envelope):
            self.on_event(
                f"Signature verification FAILED for message from "
                f"{envelope.sender}; dropped"
            )
            return

        try:
            plaintext = self.identity.decrypt_payload(
                ciphertext_b64=envelope.ciphertext_b64,
                sender=envelope.sender,
                recipient=envelope.recipient,
                message_id=envelope.message_id,
            )
        except ValueError as exc:
            self.on_event(
                f"Payload decryption FAILED for message from "
                f"{envelope.sender}: {exc}"
            )
            return

        self.on_message(envelope.sender, plaintext)
        self._send(
            {"type": "MESSAGE_ACK", "message_id": envelope.message_id}
        )

    def _send(self, packet: dict) -> None:
        with self._send_lock:
            send_packet(self._sock, packet)

    def _close_socket(self) -> None:
        if self._sock is not None:
            sock, self._sock = self._sock, None
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
