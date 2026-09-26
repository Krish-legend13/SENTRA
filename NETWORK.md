# SENTRA Network Layer

This document covers everything added under `network/`, plus `run_server.py`,
`run_client.py`, and `scripts/generate_dev_certs.py`. It implements the
network/backend engineer's half of SENTRA: a real mTLS transport wired to the
existing `auth`/`crypto`/`identity`/`signing` modules, plus heartbeat,
acknowledgement, reconnect, multi-session, offline queueing, structured
security logging, and backend incident detection.

## Why two layers of identity

Every connection is authenticated twice, independently:

1. **mTLS (transport identity).** The server requires a client certificate
   signed by the same CA (`network/tls_config.py`); the client verifies the
   server's certificate. This proves "this socket belongs to a holder of an
   issued certificate" before a single byte of application data is trusted.
2. **Ed25519 challenge-response (application identity).** After the TLS
   handshake, the client still has to prove it holds the private key
   registered for its username, via `auth.registry` + `auth.challenge`
   (unchanged from the existing security module).

Neither layer substitutes for the other. A stolen/shared client certificate
still can't forge a signed `AUTH_RESPONSE`; a leaked Ed25519 private key
still can't get through the door without a valid client certificate.

## Files

| File | Responsibility |
|---|---|
| `network/framing.py` | 4-byte length-prefix + JSON framing, per `PROTOCOL.md` |
| `network/tls_config.py` | Builds the server/client `ssl.SSLContext` for mTLS |
| `network/sessions.py` | Thread-safe registry of `username -> {session_id: Session}` (multi-session) |
| `network/offline_queue.py` | SQLite-backed per-recipient message queue |
| `network/security_events.py` | Structured (JSON-lines) security event logger |
| `network/incident_detection.py` | Sliding-window auth-failure / flood / replay detector |
| `network/server.py` | Ties it all together: `SentraServer` |
| `network/client.py` | `SentraClient`: connect, auth, heartbeat, reconnect, send/receive |
| `scripts/generate_dev_certs.py` | Dev-only CA + server + per-user client certs |
| `scripts/integration_check.py` | Scripted end-to-end smoke test of every feature |
| `run_server.py` / `run_client.py` | CLI entry points for a manual demo |

## Feature-by-feature

**mTLS.** `network/tls_config.py`. `CERT_REQUIRED` on the server side;
`check_hostname=True` + `load_cert_chain` on the client side. TLS 1.2 floor.

**Heartbeat / ping-pong.** Both peers send `HEARTBEAT_PING` every 15s
(`HEARTBEAT_INTERVAL_SECONDS`) and reply to the other's ping with
`HEARTBEAT_PONG`. If either side goes 40s (`HEARTBEAT_TIMEOUT_SECONDS`,
~2.5 missed beats) without a pong, it closes the connection from its side.

**Message acknowledgement.** Two levels, intentionally distinct:
`DELIVERY_STATUS` (server → sender, "I could/couldn't hand this to a live
session") and `MESSAGE_ACK` (recipient → server → sender, "I actually
received and signature-verified it"). The server tracks
`message_id -> original_sender` in memory (`_pending_acks`, TTL-cleaned) just
long enough to relay the ack back.

**Secure reconnect.** `SentraClient.run_forever()` never resumes a session.
On any disconnect it waits with exponential backoff (1s → 30s cap) and then
repeats the *entire* handshake: fresh TLS handshake, fresh
`REGISTER_IDENTITY` (harmless no-op if already registered), fresh
`AUTH_REQUEST` → `AUTH_CHALLENGE` → `AUTH_RESPONSE`. There is no resumable
session token to steal.

**Multi-session support.** `network/sessions.py`. A username maps to a
*set* of sessions, not one socket. Routing a `CHAT_MESSAGE` fans it out to
every session registered for the recipient (verified in
`scripts/integration_check.py` Test 3: one account, two simultaneous
connections, both receive the message).

**Offline message queue.** `network/offline_queue.py`. If a `CHAT_MESSAGE`'s
recipient has zero live sessions, the server stores the full signed envelope
in SQLite and replies `DELIVERY_STATUS: OFFLINE` to the sender. The queue is
drained (and deleted) for a user the moment their next connection finishes
authenticating — see `_deliver_offline_queue` in `server.py`.

**Structured security events.** `network/security_events.py`. Every
security-relevant occurrence is one JSON line:
`{"ts", "event", "severity", "actor", "peer_addr", "session_id", "detail"}`,
written to `data/security_events.log` and echoed to stdout. Events emitted:
`SERVER_STARTED`, `TLS_HANDSHAKE_OK/FAILURE`, `REGISTER_SUCCESS/REJECTED`,
`AUTH_SUCCESS/FAILURE`, `AUTH_CHALLENGE_REPLAY`, `SESSION`/`CONNECTION_CLOSED`,
`HEARTBEAT_TIMEOUT`, `MESSAGE_ROUTED`, `MESSAGE_QUEUED_OFFLINE`,
`MESSAGE_REPLAY_DETECTED`, `MESSAGE_FLOOD_DETECTED`, `SIGNATURE_INVALID`,
`SENDER_SPOOF_ATTEMPT`, `LOCKOUT_TRIGGERED`, `CONNECTION_REJECTED_LOCKOUT`.

**Backend incident detection.** `network/incident_detection.py`, sliding
windows, no external dependency:
- **Repeated auth failures:** ≥5 failures in 60s (tracked by both client IP
  and claimed username) triggers a 5-minute lockout; the *next* connection
  attempt from that IP is refused before the TLS handshake even starts.
- **Message flooding:** ≥30 `CHAT_MESSAGE` packets in 10s on one session
  gets that message rate-limited (`ERROR: rate_limited`).
- **Replay attempts:** every sender must send strictly increasing `sequence`
  numbers (already part of the signed envelope); a repeated/lower sequence
  is rejected and logged as `MESSAGE_REPLAY_DETECTED` *before* signature
  verification even runs. A consumed/expired/unknown `challenge_id` at auth
  time is logged as `AUTH_CHALLENGE_REPLAY`.

All of the above is exercised in `scripts/integration_check.py`.

## What's deliberately NOT here: payload encryption

`signing.envelope.SignedEnvelope.ciphertext_b64` is signed and routed, but
never decrypted, by anything in `network/`. That's correct separation of
concerns — the server should never need to decrypt a message it's just
relaying, and the wire protocol's own open questions list ("should session
keys use X25519 + HKDF, and where should key rotation occur?") assign that
to the crypto/security module. `network/client.py`'s `_seal`/`_open`
functions are an explicit, documented placeholder (base64 of the plaintext)
so the transport is testable end-to-end today; swap those two functions for
real AEAD encryption once that module exists and nothing else changes.

## Running it

```bash
pip install -r requirements.txt

# one-time: dev CA + server cert + a client cert per user
python scripts/generate_dev_certs.py --clients alice bob

# terminal 1
python run_server.py

# terminal 2
python run_client.py alice
# terminal 3
python run_client.py bob
# in either prompt: @<other_username> <message>
```

Or run the scripted end-to-end check (spins up a real server + multiple
real clients on a throwaway port, no manual typing):

```bash
python scripts/integration_check.py
```

## Known gaps / next steps

- **Payload encryption** (see above) — blocked on the crypto module's
  X25519/HKDF design.
- **Dev PKI only.** `scripts/generate_dev_certs.py` is explicitly not a real
  CA workflow (no revocation, no intermediate CA, 825-day dev certs). Fine
  for coursework/demo; would need real issuance for anything beyond that.
- **In-memory replay/flood/lockout state** resets on server restart. Fine for
  a single-process demo; a production deployment would want this in shared
  storage (Redis, etc.) if the server ever runs as more than one process.
- **No log rotation** on `data/security_events.log`.
