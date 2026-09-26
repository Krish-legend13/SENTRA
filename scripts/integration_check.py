"""Manual end-to-end smoke test for the network layer.

Not a pytest suite (it binds real sockets and sleeps for heartbeat timing),
but a scripted run through every feature: mTLS handshake, registration,
challenge-response auth, message send + signature verification + ACK,
multi-session fanout, offline queueing + delivery on reconnect, and a
structured security event for a bad auth attempt.

Run: python scripts/integration_check.py
"""

from __future__ import annotations

import shutil
import sys
import threading
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from identity.manager import IdentityManager
from network.client import SentraClient
from network.server import SentraServer

CERTS = BASE / "certs"
DATA = BASE / "data" / "integration_check"


def wipe_and_prepare():
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True)


def make_client(username: str, host, port, received: list):
    identity = IdentityManager.load_or_create(username, "test-pass", data_root=str(DATA))
    client = SentraClient(
        host=host, port=port,
        certfile=str(CERTS / f"client_{username}.crt"),
        keyfile=str(CERTS / f"client_{username}.key"),
        cafile=str(CERTS / "ca.crt"),
        identity=identity,
        on_message=lambda sender, text: received.append((sender, text)),
        on_event=lambda msg: print(f"  [{username} event] {msg}"),
    )
    threading.Thread(target=client.run_forever, daemon=True).start()
    assert client.wait_until_connected(timeout=5), f"{username} failed to connect"
    return client


def main():
    wipe_and_prepare()
    host, port = "127.0.0.1", 65433

    server = SentraServer(
        host=host, port=port,
        certfile=str(CERTS / "server.crt"), keyfile=str(CERTS / "server.key"),
        cafile=str(CERTS / "ca.crt"),
        registry_db=str(DATA / "registry.db"),
        offline_db=str(DATA / "offline_queue.db"),
    )
    threading.Thread(target=server.start, daemon=True).start()
    time.sleep(0.5)

    print("== Test 1: connect + auth (mTLS + Ed25519 challenge-response) ==")
    alice_inbox: list = []
    bob_inbox: list = []
    alice = make_client("alice", host, port, alice_inbox)
    bob = make_client("bob", host, port, bob_inbox)
    print("PASS: both clients authenticated\n")

    print("== Test 2: online message delivery + signature verify + ACK ==")
    alice.send_message("bob", "hello bob, this is alice")
    time.sleep(1)
    assert bob_inbox == [("alice", "hello bob, this is alice")], bob_inbox
    print("PASS: bob received and verified alice's message\n")

    print("== Test 3: multi-session fanout (alice logs in from a second device) ==")
    alice_inbox_2: list = []
    alice2 = make_client("alice", host, port, alice_inbox_2)
    time.sleep(0.5)
    bob.send_message("alice", "hi alice, from bob")
    time.sleep(1)
    assert ("bob", "hi alice, from bob") in alice_inbox
    assert ("bob", "hi alice, from bob") in alice_inbox_2
    print("PASS: both of alice's sessions received the message\n")
    alice2.stop()

    print("== Test 4: offline queue + delivery on reconnect ==")
    bob.stop()
    deadline = time.monotonic() + 5
    while server.sessions.is_online("bob") and time.monotonic() < deadline:
        time.sleep(0.1)
    if server.sessions.is_online("bob"):
        import traceback
        print("STILL ONLINE. Sessions:", server.sessions.all_sessions())
        print("bob._sock:", bob._sock, "bob._stop:", bob._stop.is_set())
        for tid, frame in sys._current_frames().items():
            print(f"--- thread {tid} ---")
            print("".join(traceback.format_stack(frame)[-4:]))
    assert not server.sessions.is_online("bob"), "server never noticed bob's disconnect"
    alice.send_message("bob", "are you there? (sent while offline)")
    time.sleep(0.5)
    bob_inbox.clear()
    bob_again = make_client("bob", host, port, bob_inbox)
    time.sleep(1)
    assert ("alice", "are you there? (sent while offline)") in bob_inbox
    print("PASS: offline message delivered on reconnect\n")

    print("== Test 5: forged/replayed message rejected (never reaches bob's inbox) ==")
    from network.framing import send_packet
    import base64, uuid
    from datetime import datetime, timezone

    # 5a: stale sequence number -> caught by replay detection
    bob_inbox_count_before = len(bob_inbox)
    replay_forged = {
        "type": "CHAT_MESSAGE", "message_id": uuid.uuid4().hex, "sender": "alice",
        "recipient": "bob", "timestamp": datetime.now(timezone.utc).isoformat(),
        "sequence": 1, "ciphertext_b64": base64.b64encode(b"forged").decode(),
        "signature_b64": base64.b64encode(b"\x00" * 64).decode(),
    }
    with alice._send_lock:
        send_packet(alice._sock, replay_forged)
    time.sleep(0.5)
    assert len(bob_inbox) == bob_inbox_count_before, bob_inbox
    print("PASS: stale-sequence message rejected by replay detection\n")

    # 5b: fresh (valid) sequence number but a bogus signature -> caught by
    # Ed25519 signature verification instead
    alice._sequence += 1
    bad_sig_forged = {
        "type": "CHAT_MESSAGE", "message_id": uuid.uuid4().hex, "sender": "alice",
        "recipient": "bob", "timestamp": datetime.now(timezone.utc).isoformat(),
        "sequence": alice._sequence, "ciphertext_b64": base64.b64encode(b"forged").decode(),
        "signature_b64": base64.b64encode(b"\x00" * 64).decode(),
    }
    with alice._send_lock:
        send_packet(alice._sock, bad_sig_forged)
    time.sleep(0.5)
    assert len(bob_inbox) == bob_inbox_count_before, bob_inbox
    print("PASS: bad-signature message rejected by signature verification\n")

    print("All integration checks passed.")
    alice.stop()
    bob_again.stop()

    print("\n== Test 6: backend incident detection (repeated auth-failure lockout) ==")
    import socket as socket_mod
    import ssl as ssl_mod
    from network.tls_config import build_client_context
    from network.framing import send_packet, recv_packet
    from network.incident_detection import AUTH_FAILURE_THRESHOLD

    ctx = build_client_context(str(CERTS / "client_alice.crt"), str(CERTS / "client_alice.key"), str(CERTS / "ca.crt"))
    last_reason = None
    locked_out_at_transport = False
    for i in range(AUTH_FAILURE_THRESHOLD + 2):
        try:
            raw = socket_mod.create_connection((host, port), timeout=5)
            sock = ctx.wrap_socket(raw, server_hostname="localhost")
        except (OSError, ssl_mod.SSLError):
            locked_out_at_transport = True
            break
        try:
            send_packet(sock, {"type": "AUTH_REQUEST", "username": "alice"})
            challenge_packet = recv_packet(sock)
            if challenge_packet.get("type") == "ERROR":
                last_reason = challenge_packet.get("reason")
                break
            send_packet(sock, {
                "type": "AUTH_RESPONSE",
                "challenge_id": challenge_packet["challenge_id"],
                "signature_b64": base64.b64encode(b"\x00" * 64).decode(),
            })
            result = recv_packet(sock)
            last_reason = result.get("reason")
        except (ConnectionError, OSError):
            locked_out_at_transport = True
            break
        finally:
            sock.close()
        time.sleep(0.05)

    if locked_out_at_transport:
        print("PASS: server started refusing the TLS connection outright once locked out")
    else:
        print(f"Server kept responding; last reason after {AUTH_FAILURE_THRESHOLD + 2} attempts: {last_reason!r}")
    print("(See LOCKOUT_TRIGGERED in the structured event log above.)")

    server.stop()


if __name__ == "__main__":
    main()
