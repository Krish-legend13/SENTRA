# SENTRA — Secure Messaging Application

SENTRA is a Python secure messaging application prototype with a modular security layer.

## Status

The cryptographic, authentication, signing, and identity modules are complete and tested.
`main.py` is the original prototype and is not yet wired to the new modules; integration
is in progress. The repository is under active development by a four-person team.

## Features implemented

- **`crypto/`**
  - Ed25519 key generation, PEM serialization, signatures, and fingerprints.
  - Password-protected encrypted key vault using scrypt and AES-256-GCM.
- **`auth/`**
  - SQLite-backed authorized-user registry.
  - Challenge-response authentication.
  - RFC 6238 TOTP two-factor authentication.
  - Recovery-code generation, hashing, verification, and consumption.
- **`signing/`**
  - Canonical signed message envelopes covering sender, recipient, message ID,
    timestamp, sequence, and ciphertext.
- **`identity/`**
  - Vault-backed per-user identity management with session caching.

## Installation

```text
pip install -r requirements.txt
```

## Running the tests

```text
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

Current test status: **139 passed, 1 skipped**.

## Project structure

```text
.
├── auth/       Authorized-user registry and authentication primitives
├── crypto/     Ed25519 primitives and encrypted private-key vault
├── identity/   Session-scoped vault-backed identity management
├── signing/    Signed message envelope implementation
├── tests/      Pytest coverage for the security modules
├── main.py     Original RSA-OAEP secure messaging prototype
└── PROTOCOL.md Draft wire-protocol proposal
```

## Documentation

See [`PROTOCOL.md`](PROTOCOL.md) for the draft wire-protocol proposal.

## Security notes

- Private keys are stored encrypted at rest in vault files and must never be committed.
- The server is designed as a blind relay and does not decrypt end-to-end encrypted
  message content.
- Do not run with production data; this is an internship prototype.
