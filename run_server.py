"""Run the SENTRA mTLS server.

Usage:
    python scripts/generate_dev_certs.py --clients alice bob   # once
    python run_server.py
"""

from __future__ import annotations

import argparse
from pathlib import Path

from network.server import SentraServer

BASE = Path(__file__).resolve().parent
CERTS = BASE / "certs"
DATA = BASE / "data"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    args = parser.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)

    server = SentraServer(
        host=args.host,
        port=args.port,
        certfile=str(CERTS / "server.crt"),
        keyfile=str(CERTS / "server.key"),
        cafile=str(CERTS / "ca.crt"),
        registry_db=str(DATA / "registry.db"),
        offline_db=str(DATA / "offline_queue.db"),
    )
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
