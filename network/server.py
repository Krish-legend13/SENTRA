"""SENTRA network server.

Ties the existing security modules (auth.registry, auth.challenge,
signing.envelope) to a real mTLS transport and adds everything the wire
protocol proposal left open: heartbeats, message acknowledgement, multi
-session routing, an offline queue, structured security-event logging, and
backend incident detection.

Design notes:
    * The server NEVER decrypts ciphertext_b64. It only verifies the
      Ed25519 signature over the envelope and routes it. Payload
      confidentiality is a client-side concern (out of scope for this
      module; see PROTOCOL.md open questions).
    * mTLS (transport identity) and the Ed25519 challenge-response
      (application identity) are independent layers. Both must pass.
    * One Python thread per connection, plus one heartbeat thread per
      *authenticated* connection. All socket writes for a given connection
      go through Session.send_lock to keep frames from interleaving.
"""

from __future__ import annotations

import base64
import socket
import ssl
import threading
import time
import uuid

from auth.challenge import ChallengeStore, verify_response
from auth.registry import AUTHORIZED, get_totp_secret, get_user, init_registry, register_user
from auth.totp import TOTPReplayGuard, verify_with_replay_guard
from crypto.keys import deserialize_public_key, fingerprint
from network import offline_queue
from network.framing import ConnectionClosed, FrameError, recv_packet, send_packet
from network.incident_detection import IncidentDetector
from network.security_events import log_event
from network.sessions import Session, SessionManager
from network.tls_config import build_server_context
from signing.envelope import envelope_from_dict, verify_envelope

HEARTBEAT_INTERVAL_SECONDS = 15
HEARTBEAT_TIMEOUT_SECONDS = 40  # ~2.5 missed beats before we give up
PENDING_ACK_TTL_SECONDS = 300


def _fmt_addr(addr) -> str:
    return f"{addr[0]}:{addr[1]}"


class SentraServer:
    def __init__(
        self,
        host: str,
        port: int,
        certfile: str,
        keyfile: str,
        cafile: str,
        registry_db: str,
        offline_db: str,
    ) -> None:
        self.host = host
        self.port = port
        self.tls_context = build_server_context(certfile, keyfile, cafile)
        self.registry_db = registry_db
        self.offline_db = offline_db
        init_registry(registry_db)
        offline_queue.init_queue(offline_db)

        self.sessions = SessionManager()
        self.challenges = ChallengeStore()
        self.totp_guard = TOTPReplayGuard()
        self.incidents = IncidentDetector()

        # message_id -> sender username, so a MESSAGE_ACK from the recipient
        # can be relayed back to whoever sent the original message.
        self._pending_acks: dict[str, tuple[str, float]] = {}
        self._pending_acks_lock = threading.Lock()

        self._server_socket: socket.socket | None = None
        self._stop = threading.Event()

    # ---- lifecycle -----------------------------------------------------

    def start(self) -> None:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_socket.bind((self.host, self.port))
        raw_socket.listen()
        self._server_socket = raw_socket
        log_event("SERVER_STARTED", detail={"host": self.host, "port": self.port})
        print(f"SENTRA server listening on {self.host}:{self.port} (mTLS required)")

        try:
            while not self._stop.is_set():
                try:
                    client_sock, addr = raw_socket.accept()
                except OSError:
                    break
                threading.Thread(
                    target=self._handle_connection, args=(client_sock, addr), daemon=True
                ).start()
        finally:
            raw_socket.close()

    def stop(self) -> None:
        self._stop.set()
        if self._server_socket is not None:
            self._server_socket.close()

    # ---- per-connection handling ---------------------------------------

    def _handle_connection(self, raw_sock: socket.socket, addr) -> None:
        peer_addr = _fmt_addr(addr)
        client_ip = addr[0]

        if self.incidents.is_locked_out(client_ip):
            log_event("CONNECTION_REJECTED_LOCKOUT", severity="WARNING", peer_addr=peer_addr)
            raw_sock.close()
            return

        try:
            tls_sock = self.tls_context.wrap_socket(raw_sock, server_side=True)
        except ssl.SSLError as exc:
            log_event(
                "TLS_HANDSHAKE_FAILURE",
                severity="CRITICAL",
                peer_addr=peer_addr,
                detail={"error": str(exc)},
            )
            raw_sock.close()
            return

        client_cert = tls_sock.getpeercert()
        cert_cn = None
        if client_cert:
            for rdn in client_cert.get("subject", ()):
                for key, value in rdn:
                    if key == "commonName":
                        cert_cn = value
        log_event(
            "TLS_HANDSHAKE_OK",
            peer_addr=peer_addr,
            detail={"client_cert_cn": cert_cn},
        )

        username = self._authenticate(tls_sock, peer_addr, client_ip)
        if username is None:
            tls_sock.close()
            return

        session = self.sessions.register(username, tls_sock, peer_addr)
        log_event(
            "AUTH_SUCCESS",
            actor=username,
            peer_addr=peer_addr,
            session_id=session.session_id,
            detail={"active_sessions_for_user": self.sessions.session_count(username)},
        )
        # Session is registered and routable *before* the peer is told it
        # succeeded, and before SESSION_INFO/offline-queue delivery.
        self._send(session, {"type": "AUTH_RESULT", "status": "OK", "reason": "authenticated"})
        self._send(session, {
            "type": "SESSION_INFO",
            "session_id": session.session_id,
            "active_sessions": self.sessions.session_count(username),
        })

        heartbeat_stop = threading.Event()
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, args=(session, heartbeat_stop), daemon=True
        )
        heartbeat_thread.start()

        self._deliver_offline_queue(session)

        try:
            self._authenticated_loop(session)
        finally:
            heartbeat_stop.set()
            self.sessions.unregister(username, session.session_id)
            try:
                tls_sock.close()
            except OSError:
                pass
            log_event(
                "CONNECTION_CLOSED",
                actor=username,
                peer_addr=peer_addr,
                session_id=session.session_id,
            )

    # ---- registration + challenge-response auth -------------------------

    def _authenticate(self, sock, peer_addr: str, client_ip: str) -> str | None:
        """Run REGISTER_IDENTITY (optional) then AUTH_REQUEST/RESPONSE.

        Returns the authenticated username, or None if the connection
        should be dropped.
        """
        try:
            packet = recv_packet(sock)
        except (ConnectionClosed, FrameError, OSError):
            return None

        if packet.get("type") == "REGISTER_IDENTITY":
            self._handle_register(sock, packet, peer_addr)
            try:
                packet = recv_packet(sock)
            except (ConnectionClosed, FrameError, OSError):
                return None

        if packet.get("type") != "AUTH_REQUEST":
            self._send_raw(sock, {"type": "ERROR", "reason": "expected_auth_request"})
            return None

        username = packet.get("username")
        if not isinstance(username, str) or not username.strip():
            self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": "invalid_username"})
            return None
        username = username.strip()

        user_record = get_user(self.registry_db, username)
        if user_record is None or user_record.status != AUTHORIZED:
            self.incidents.record_auth_failure(client_ip, peer_addr)
            self.incidents.record_auth_failure(username, peer_addr)
            self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": "unknown_or_revoked_user"})
            return None

        challenge_id, challenge = self.challenges.issue(username)
        self._send_raw(sock, {
            "type": "AUTH_CHALLENGE",
            "challenge_id": challenge_id,
            "challenge_b64": base64.b64encode(challenge).decode("ascii"),
        })

        try:
            response_packet = recv_packet(sock)
        except (ConnectionClosed, FrameError, OSError):
            return None

        if response_packet.get("type") != "AUTH_RESPONSE":
            self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": "expected_auth_response"})
            return None

        resp_challenge_id = response_packet.get("challenge_id")
        signature_b64 = response_packet.get("signature_b64")
        challenge_bytes = self.challenges.consume(resp_challenge_id) if isinstance(resp_challenge_id, str) else None

        if challenge_bytes is None:
            self.incidents.record_challenge_reuse(username, peer_addr)
            self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": "challenge_expired_or_unknown"})
            return None

        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except Exception:
            signature = b""

        if not verify_response(user_record.public_key, challenge_bytes, signature):
            tripped = self.incidents.record_auth_failure(client_ip, peer_addr)
            self.incidents.record_auth_failure(username, peer_addr)
            self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": "signature_mismatch"})
            if tripped:
                pass  # lockout already logged by incidents.record_auth_failure
            return None

        self.incidents.clear_auth_failures(client_ip)
        self.incidents.clear_auth_failures(username)

        # Optional second factor: only users with a registered TOTP secret
        # are challenged. Everyone else continues through Ed25519 alone.
        totp_secret_b32 = get_totp_secret(self.registry_db, username)
        if totp_secret_b32 is not None:
            if not self._run_totp_step(sock, username, totp_secret_b32, peer_addr, client_ip):
                return None

        # AUTH_RESULT:OK is sent by the caller only after the session is
        # registered, so a peer never receives "you're authenticated" before
        # the server can actually route messages to it (closes a race where
        # a sender could get DELIVERY_STATUS:OFFLINE for an online peer).
        return username

    def _run_totp_step(
        self,
        sock,
        username: str,
        secret_b32: str,
        peer_addr: str,
        client_ip: str,
    ) -> bool:
        """Challenge and verify a TOTP code for an Ed25519-authenticated user.

        Returns True if the code verifies and is not a replay, otherwise False.
        """
        self._send_raw(sock, {"type": "TOTP_CHALLENGE", "required": True})
        try:
            packet = recv_packet(sock)
        except (ConnectionClosed, FrameError, OSError):
            return False

        if packet.get("type") != "TOTP_RESPONSE":
            self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": "expected_totp_response"})
            return False

        code = packet.get("code")
        if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
            code = ""

        ok, reason = verify_with_replay_guard(secret_b32, code, username, self.totp_guard)
        if ok:
            self.incidents.clear_auth_failures(client_ip)
            self.incidents.clear_auth_failures(username)
            log_event("TOTP_SUCCESS", actor=username, peer_addr=peer_addr)
            return True

        self.incidents.record_auth_failure(client_ip, peer_addr)
        self.incidents.record_auth_failure(username, peer_addr)
        log_event(
            "TOTP_FAILURE",
            severity="WARNING",
            actor=username,
            peer_addr=peer_addr,
            detail={"reason": reason},
        )
        self._send_raw(sock, {"type": "AUTH_RESULT", "status": "FAILED", "reason": reason})
        return False

    def _handle_register(self, sock, packet: dict, peer_addr: str) -> None:
        username = packet.get("username")
        pubkey_b64 = packet.get("public_key_pem_b64")
        claimed_fingerprint = packet.get("fingerprint")

        try:
            if not isinstance(username, str) or not username.strip():
                raise ValueError("invalid_username")
            pem_bytes = base64.b64decode(pubkey_b64, validate=True)
            public_key = deserialize_public_key(pem_bytes)
            if fingerprint(public_key) != claimed_fingerprint:
                raise ValueError("fingerprint_mismatch")
            register_user(self.registry_db, username.strip(), public_key)
        except ValueError as exc:
            reason = str(exc) if str(exc) else "registration_rejected"
            self._send_raw(sock, {"type": "REGISTER_IDENTITY_ACK", "status": "REJECTED", "reason": reason})
            log_event("REGISTER_REJECTED", severity="WARNING", actor=username, peer_addr=peer_addr, detail={"reason": reason})
            return
        except Exception as exc:  # malformed base64/PEM etc.
            self._send_raw(sock, {"type": "REGISTER_IDENTITY_ACK", "status": "REJECTED", "reason": "malformed_request"})
            log_event("REGISTER_REJECTED", severity="WARNING", actor=username, peer_addr=peer_addr, detail={"reason": str(exc)})
            return

        self._send_raw(sock, {"type": "REGISTER_IDENTITY_ACK", "status": "OK", "reason": "registered"})
        log_event("REGISTER_SUCCESS", actor=username, peer_addr=peer_addr)

    # ---- authenticated message loop -------------------------------------

    def _authenticated_loop(self, session: Session) -> None:
        while True:
            try:
                packet = recv_packet(session.sock)
            except (ConnectionClosed, FrameError, OSError):
                return

            packet_type = packet.get("type")

            if packet_type == "HEARTBEAT_PING":
                self._send(session, {"type": "HEARTBEAT_PONG", "nonce": packet.get("nonce")})
            elif packet_type == "HEARTBEAT_PONG":
                self.sessions.touch_pong(session.username, session.session_id)
            elif packet_type == "IDENTITY_REQUEST":
                self._handle_identity_request(session, packet)
            elif packet_type == "CHAT_MESSAGE":
                self._handle_chat_message(session, packet)
            elif packet_type == "MESSAGE_ACK":
                self._handle_message_ack(session, packet)
            else:
                log_event("UNKNOWN_PACKET_TYPE", severity="WARNING", actor=session.username,
                          peer_addr=session.peer_addr, session_id=session.session_id,
                          detail={"type": packet_type})
                self._send(session, {"type": "ERROR", "reason": "unknown_packet_type", "detail": str(packet_type)})

    def _handle_identity_request(self, session: Session, packet: dict) -> None:
        target = packet.get("target_username")
        record = get_user(self.registry_db, target) if isinstance(target, str) else None
        if record is None or record.status != AUTHORIZED:
            self._send(session, {
                "type": "IDENTITY_RESPONSE", "target_username": target,
                "public_key_pem_b64": None, "status": "NOT_FOUND",
            })
            return
        from crypto.keys import serialize_public_key
        pem_b64 = base64.b64encode(serialize_public_key(record.public_key)).decode("ascii")
        self._send(session, {
            "type": "IDENTITY_RESPONSE", "target_username": target,
            "public_key_pem_b64": pem_b64, "status": "OK",
        })

    def _handle_chat_message(self, session: Session, packet: dict) -> None:
        peer_addr = session.peer_addr

        if self.incidents.record_message(session.session_id, peer_addr):
            self._send(session, {"type": "ERROR", "reason": "rate_limited"})
            return

        try:
            envelope = envelope_from_dict(packet)
        except ValueError as exc:
            self._send(session, {"type": "ERROR", "reason": "malformed_envelope", "detail": str(exc)})
            return

        if envelope.sender != session.username:
            log_event("SENDER_SPOOF_ATTEMPT", severity="CRITICAL", actor=session.username,
                       peer_addr=peer_addr, session_id=session.session_id,
                       detail={"claimed_sender": envelope.sender})
            self._send(session, {"type": "ERROR", "reason": "sender_mismatch"})
            return

        if not self.incidents.check_sequence(envelope.sender, envelope.sequence, peer_addr):
            self._send(session, {"type": "ERROR", "reason": "replay_detected", "detail": envelope.message_id})
            return

        sender_record = get_user(self.registry_db, envelope.sender)
        if sender_record is None or not verify_envelope(sender_record.public_key, envelope):
            log_event("SIGNATURE_INVALID", severity="CRITICAL", actor=envelope.sender,
                       peer_addr=peer_addr, session_id=session.session_id,
                       detail={"message_id": envelope.message_id})
            self._send(session, {"type": "ERROR", "reason": "signature_invalid", "detail": envelope.message_id})
            return

        self._remember_pending_ack(envelope.message_id, envelope.sender)

        recipient_sessions = self.sessions.sessions_for(envelope.recipient)
        envelope_dict = packet  # already the wire-format dict; forward as-is
        if recipient_sessions:
            for recipient_session in recipient_sessions:
                self._send(recipient_session, envelope_dict)
            self._send(session, {"type": "DELIVERY_STATUS", "message_id": envelope.message_id, "status": "DELIVERED"})
            log_event("MESSAGE_ROUTED", actor=envelope.sender, peer_addr=peer_addr, session_id=session.session_id,
                      detail={"recipient": envelope.recipient, "message_id": envelope.message_id,
                              "fanout": len(recipient_sessions)})
        else:
            offline_queue.enqueue(self.offline_db, envelope.recipient, envelope_dict)
            self._send(session, {"type": "DELIVERY_STATUS", "message_id": envelope.message_id, "status": "OFFLINE"})
            log_event("MESSAGE_QUEUED_OFFLINE", actor=envelope.sender, peer_addr=peer_addr,
                      session_id=session.session_id,
                      detail={"recipient": envelope.recipient, "message_id": envelope.message_id})

    def _handle_message_ack(self, session: Session, packet: dict) -> None:
        message_id = packet.get("message_id")
        with self._pending_acks_lock:
            entry = self._pending_acks.pop(message_id, None) if isinstance(message_id, str) else None
        if entry is None:
            log_event("ACK_UNMATCHED", severity="WARNING", actor=session.username,
                      peer_addr=session.peer_addr, detail={"message_id": message_id})
            return
        original_sender, _ = entry
        for sender_session in self.sessions.sessions_for(original_sender):
            self._send(sender_session, {
                "type": "MESSAGE_ACK", "message_id": message_id, "acked_by": session.username,
            })

    def _remember_pending_ack(self, message_id: str, sender: str) -> None:
        now = time.monotonic()
        with self._pending_acks_lock:
            self._pending_acks[message_id] = (sender, now)
            # Opportunistic cleanup of stale entries so this dict can't grow forever.
            stale = [mid for mid, (_, ts) in self._pending_acks.items() if now - ts > PENDING_ACK_TTL_SECONDS]
            for mid in stale:
                del self._pending_acks[mid]

    # ---- offline queue delivery ------------------------------------------

    def _deliver_offline_queue(self, session: Session) -> None:
        queued = offline_queue.drain(self.offline_db, session.username)
        if not queued:
            return
        for envelope_dict in queued:
            self._send(session, envelope_dict)
        log_event("OFFLINE_QUEUE_DELIVERED", actor=session.username, session_id=session.session_id,
                  detail={"count": len(queued)})

    # ---- heartbeat --------------------------------------------------------

    def _heartbeat_loop(self, session: Session, stop_event: threading.Event) -> None:
        while not stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
            elapsed = time.monotonic() - session.last_pong_at
            if elapsed > HEARTBEAT_TIMEOUT_SECONDS:
                log_event("HEARTBEAT_TIMEOUT", severity="WARNING", actor=session.username,
                          peer_addr=session.peer_addr, session_id=session.session_id,
                          detail={"seconds_since_last_pong": round(elapsed, 1)})
                try:
                    # shutdown() operates at the raw socket layer (it is not
                    # overridden by SSLSocket), so it's safe to call from a
                    # different thread than the one blocked in recv() on
                    # this same socket -- unlike unwrap(), which would touch
                    # TLS state concurrently with that blocked read. This is
                    # what reliably wakes the per-connection thread and
                    # sends the peer a FIN instead of leaving it hung until
                    # its own timeout.
                    session.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    session.sock.close()
                except OSError:
                    pass
                return
            try:
                self._send(session, {"type": "HEARTBEAT_PING", "nonce": uuid.uuid4().hex})
            except OSError:
                return

    # ---- socket write helpers ---------------------------------------------

    def _send(self, session: Session, packet: dict) -> None:
        with session.send_lock:
            send_packet(session.sock, packet)

    def _send_raw(self, sock, packet: dict) -> None:
        """Send on a not-yet-authenticated (session-less) socket."""
        send_packet(sock, packet)
