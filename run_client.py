"""Run a SENTRA chat client.

Usage:
    python scripts/generate_dev_certs.py --clients alice bob   # once
    python run_server.py                                       # in another terminal
    python run_client.py alice
    python run_client.py bob
Then type "@bob hello" from alice's prompt (or "@alice hi" from bob's).
"""

from __future__ import annotations

import argparse
import getpass
import threading
from pathlib import Path

from identity.manager import IdentityManager
from network.client import SentraClient

BASE = Path(__file__).resolve().parent
CERTS = BASE / "certs"
DATA = BASE / "data"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    args = parser.parse_args()

    passphrase = getpass.getpass(f"Vault passphrase for {args.username}: ")
    identity = IdentityManager.load_or_create(args.username, passphrase, data_root=str(DATA))

    client = SentraClient(
        host=args.host,
        port=args.port,
        certfile=str(CERTS / f"client_{args.username}.crt"),
        keyfile=str(CERTS / f"client_{args.username}.key"),
        cafile=str(CERTS / "ca.crt"),
        identity=identity,
    )

    thread = threading.Thread(target=client.run_forever, daemon=True)
    thread.start()
    client.wait_until_connected(timeout=10)

    print("Type '@<recipient> <message>' to send, or Ctrl+C to quit.")
    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            if line.startswith("@"):
                recipient, _, text = line[1:].partition(" ")
                if recipient and text:
                    client.send_message(recipient, text)
                else:
                    print("Format: @recipient your message")
            else:
                print("Format: @recipient your message")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.stop()


if __name__ == "__main__":
    main()
