> **Status: DRAFT PROPOSAL**
> This document is a proposal from the security module author. It is not ratified.
> The network engineer owns the wire protocol. Adopt, revise, or reject as appropriate.
> Version: 0.1-draft
> Last updated: 2026-09-25

# SENTRA Wire Protocol Proposal

## Purpose and scope

This proposal defines packet shapes and security-related message flows for identity registration, public-key discovery, challenge-response authentication, and signed chat messages. It defines application-level framing and JSON fields, but not encryption algorithms, socket lifecycle management, persistence schemas, or a ratified production protocol.

## Transport

The demo transport is TCP on `127.0.0.1:65432`, matching the current prototype. In a deployment environment, TLS 1.3 should wrap the transport; whether mutual TLS is enabled remains an open question.

## Framing

Each packet is framed as a 4-byte unsigned big-endian length prefix followed by a UTF-8 JSON payload. The declared payload length must not exceed 1 MiB (`1024 * 1024`). Receivers must reject incomplete frames, invalid UTF-8, invalid JSON, and payloads above the maximum size.

## Packet envelope

Every packet is a JSON object containing at least a `type` field. Packet-specific fields are top-level properties. Unknown fields should be ignored where safe to support forward compatibility; required fields and field types must be validated before processing.

## Packet types

| Type | Direction | Required fields | Purpose |
|---|---|---|---|
| `REGISTER_IDENTITY` | client → server | `username`, `public_key_pem_b64`, `fingerprint` | Register a username and Ed25519 public identity key |
| `REGISTER_IDENTITY_ACK` | server → client | `status`, `reason` | Report registration acceptance or rejection |
| `IDENTITY_REQUEST` | client → server | `target_username` | Request a peer's registered public identity |
| `IDENTITY_RESPONSE` | server → client | `target_username`, `public_key_pem_b64`, `status` | Return a public key or indicate lookup failure |
| `AUTH_REQUEST` | client → server | `username` | Start challenge-response authentication |
| `AUTH_CHALLENGE` | server → client | `challenge_id`, `challenge_b64` | Deliver a single-use server challenge |
| `AUTH_RESPONSE` | client → server | `challenge_id`, `signature_b64` | Return the signature over the authentication challenge |
| `AUTH_RESULT` | server → client | `status`, `reason` | Report authentication success or failure |
| `CHAT_MESSAGE` | client → client, routed via server | `message_id`, `sender`, `recipient`, `timestamp`, `sequence`, `ciphertext_b64`, `signature_b64` | Carry an encrypted, signed message envelope |
| `DELIVERY_STATUS` | server → client | `message_id`, `status` | Report `DELIVERED` or `OFFLINE` |
| `ERROR` | server → client | `reason`; optional `detail` | Report a protocol or processing error |

### `REGISTER_IDENTITY`

Client to server. The client sends `username`, the Base64-encoded PEM public key in `public_key_pem_b64`, and the client-computed `fingerprint`. The server validates the key, username policy, and registration state before storing the identity.

### `REGISTER_IDENTITY_ACK`

Server to client. `status` is either `"OK"` or `"REJECTED"`. `reason` explains the outcome and is present for both outcomes.

### `IDENTITY_REQUEST`

Client to server. `target_username` identifies the peer whose registered Ed25519 public key is needed for signature verification.

### `IDENTITY_RESPONSE`

Server to client. `target_username` echoes the lookup target. `public_key_pem_b64` contains the Base64-encoded PEM public key on success and is `null` when unavailable. `status` identifies the lookup result.

### `AUTH_REQUEST`

Client to server. `username` identifies the registered identity attempting authentication.

### `AUTH_CHALLENGE`

Server to client. `challenge_id` identifies the single-use challenge-store entry, and `challenge_b64` contains the random challenge bytes encoded with standard Base64.

### `AUTH_RESPONSE`

Client to server. `challenge_id` identifies the challenge being answered, and `signature_b64` contains the Ed25519 signature over the domain-separated canonical challenge input.

### `AUTH_RESULT`

Server to client. `status` is `"OK"` or `"FAILED"`. `reason` describes authentication success or failure without exposing private key material.

### `CHAT_MESSAGE`

Client to client, routed via the server. The packet carries the seven fields of `signing.envelope.SignedEnvelope`: `message_id`, `sender`, `recipient`, `timestamp`, `sequence`, `ciphertext_b64`, and `signature_b64`. The recipient verifies the signature before decrypting the ciphertext.

### `DELIVERY_STATUS`

Server to client. `message_id` identifies the routed message. `status` is `"DELIVERED"` when the recipient accepted the packet for delivery or `"OFFLINE"` when the recipient is unavailable.

### `ERROR`

Server to client. `reason` is a stable error category or message. `detail` is optional diagnostic context and must not contain secrets.

## Authentication flow

1. The client sends `AUTH_REQUEST` with its registered `username`.
2. The server verifies that the username is registered and authorized, issues a single-use challenge through `auth.challenge.ChallengeStore`, and sends `AUTH_CHALLENGE` with `challenge_id` and `challenge_b64`.
3. The client signs `canonical_bytes("SENTRA-AUTH-v1", challenge)` with its Ed25519 private key and sends the Base64 signature in `AUTH_RESPONSE`.
4. The server consumes the challenge, loads the registered public key, and verifies the signature with the same canonical input.
5. The server sends `AUTH_RESULT` with `"OK"` on success or `"FAILED"` with a reason otherwise. A consumed or expired challenge cannot be reused.

## Signed message flow

1. Before verifying a peer message, the recipient requests the sender's registered identity with `IDENTITY_REQUEST`.
2. The server returns `IDENTITY_RESPONSE` containing the sender's PEM public key or `null` if unavailable.
3. The sender constructs the six-field input in the fixed order `sender`, `recipient`, `message_id`, `sequence`, `timestamp`, `ciphertext_b64` and signs `canonical_bytes("SENTRA-MSG-v1", sender, recipient, message_id, sequence, timestamp, ciphertext_b64)`.
4. The sender sends a `CHAT_MESSAGE` carrying the six signed fields plus `signature_b64`; the server routes it without changing signed fields.
5. The recipient verifies the signature against the sender's registered public key before decrypting the ciphertext. Any field change, including routing, timestamp, sequence, or ciphertext changes, invalidates the signature.
6. The server reports `DELIVERY_STATUS` for the message when delivery succeeds or the recipient is offline.

## Domain separation

Authentication signatures use `SENTRA-AUTH-v1`; message signatures use `SENTRA-MSG-v1`. These domain strings are distinct and are part of each canonical signing input. A signature generated in one context must never verify in the other context.

## Open questions

- Should offline messages be queued, and how should that interact with forward secrecy?
  **Resolved (network layer):** yes. See `network/offline_queue.py` — a SQLite-backed queue
  keyed by recipient, drained in order on next successful authentication. Forward secrecy is
  unaffected because queuing operates on the opaque `ciphertext_b64` blob; whatever
  confidentiality/forward-secrecy properties the payload encryption layer provides are preserved
  end-to-end regardless of how long a message sits in the queue.
- Should session keys use X25519 plus HKDF, and where should key rotation occur?
  **Still open** — owned by the crypto/security module, not the network layer. The network layer
  treats `ciphertext_b64` as an opaque blob it never decrypts; see `NETWORK.md` for the current
  placeholder used to keep the transport testable end-to-end in the meantime.
- Is TLS in scope for the demo or only for deployment?
  **Resolved:** mutual TLS 1.2+ is required for every connection, demo included. See
  `network/tls_config.py` and `scripts/generate_dev_certs.py` for the dev PKI.
- Will mutual TLS (mTLS) be implemented in addition to application-level Ed25519 authentication?
  **Resolved: yes, both.** mTLS authenticates the transport (holder of a CA-issued cert); the
  Ed25519 challenge-response in `auth.challenge` independently authenticates the application
  identity. Neither layer substitutes for the other.

## Network-layer packet type additions

The following packet types were added by the network layer on top of the types above. They are
documented here because they're part of the same wire format (length-prefixed JSON) and flow
through the same connections, even though they weren't in the original proposal.

| Type | Direction | Fields | Purpose |
|---|---|---|---|
| `HEARTBEAT_PING` | either direction | `nonce` | Liveness probe; sent every 15s by both peers |
| `HEARTBEAT_PONG` | either direction | `nonce` | Echoes the ping's nonce; absence for >40s closes the connection |
| `SESSION_INFO` | server → client | `session_id`, `active_sessions` | Sent right after `AUTH_RESULT:OK`; tells the client its session id and how many sessions (devices) this account currently has open |
| `MESSAGE_ACK` | client → server → original sender | `message_id` (client→server); `message_id`, `acked_by` (server→sender) | Application-level "the recipient actually received and verified this message," distinct from `DELIVERY_STATUS` which only reports whether the server could hand the packet to a live session |

See `NETWORK.md` for the full network-layer design (session lifecycle, incident detection
thresholds, structured event log format, and how to run a local demo).

## Change log

- `0.1-draft` — initial proposal
- `0.2` — network layer implemented: mTLS transport, heartbeat/ACK/reconnect/multi-session/offline
  queue packet types and behavior, structured security events, backend incident detection. See
  `NETWORK.md`.
