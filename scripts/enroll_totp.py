"""Enroll a registered SENTRA user in TOTP two-factor authentication.

Generates a fresh RFC 6238 TOTP secret, stores it in the SQLite registry, and
prints the enrollment URI plus the raw Base32 secret for manual entry.

This is a DEV-ONLY tool. The TOTP secret is stored plaintext in the registry
for the demo; a production deployment must encrypt it at rest.

Usage:
    python scripts/enroll_totp.py SENDER
    python scripts/enroll_totp.py SENDER --reset
    python scripts/enroll_totp.py SENDER --db data/registry.db --issuer SENTRA
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from auth.registry import AUTHORIZED, get_totp_secret, get_user, set_totp_secret
from auth.totp import build_otpauth_uri, generate_totp_secret, secret_to_base32

DEFAULT_DB = BASE / "data" / "registry.db"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Registered username to enroll.")
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help="Path to the registry SQLite database (default: data/registry.db).",
    )
    parser.add_argument(
        "--issuer",
        default="SENTRA",
        help="Issuer label embedded in the otpauth:// URI.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Re-enroll even if a TOTP secret already exists.",
    )
    args = parser.parse_args()

    username = args.username.strip()
    if not username:
        print("Error: username must not be empty.", file=sys.stderr)
        sys.exit(1)

    db = Path(args.db)

    record = get_user(db, username)
    if record is None:
        print(f"Error: user '{username}' is not registered.", file=sys.stderr)
        sys.exit(1)
    if record.status != AUTHORIZED:
        print(
            f"Error: user '{username}' is not authorized (status: {record.status}).",
            file=sys.stderr,
        )
        sys.exit(1)

    if get_totp_secret(db, username) is not None and not args.reset:
        print(
            f"Error: user '{username}' already has TOTP enrolled. "
            "Re-run with --reset to re-enroll.",
            file=sys.stderr,
        )
        sys.exit(1)

    secret = generate_totp_secret()
    b32 = secret_to_base32(secret)
    uri = build_otpauth_uri(b32, username, issuer=args.issuer)

    set_totp_secret(db, username, b32)

    print(f"otpauth:// URI: {uri}")
    print(f"Base32 secret: {b32}")
    print(f"Enrolled TOTP secret for '{username}' in {db}.")
    print(
        "WARNING: The TOTP secret is stored in plaintext in the SQLite "
        "registry. This is a demo limitation; a production deployment must "
        "encrypt secrets at rest."
    )
    print(
        "Note: --reset re-enrolls and invalidates any existing authenticator "
        "entry."
    )


if __name__ == "__main__":
    main()
