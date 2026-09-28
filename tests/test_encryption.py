from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto.encryption import decrypt_payload, ed25519_public_to_x25519, encrypt_payload


def test_ed25519_to_x25519_conversion_matches_private_derivation():
    alice = Ed25519PrivateKey.generate()
    assert (
        ed25519_public_to_x25519(alice.public_key()).public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        == __import__(
            "crypto.encryption", fromlist=["_ed25519_private_to_x25519"]
        )._ed25519_private_to_x25519(alice).public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def test_encrypt_decrypt_round_trip():
    alice = Ed25519PrivateKey.generate()
    bob = Ed25519PrivateKey.generate()

    ciphertext = encrypt_payload(
        "hello bob — encrypted end to end",
        "alice",
        "bob",
        "message-1",
        bob.public_key(),
    )

    assert decrypt_payload(
        ciphertext,
        bob,
        "alice",
        "bob",
        "message-1",
    ) == "hello bob — encrypted end to end"


def test_different_recipient_private_key_cannot_decrypt():
    bob = Ed25519PrivateKey.generate()
    mallory = Ed25519PrivateKey.generate()

    ciphertext = encrypt_payload(
        "secret for bob",
        "alice",
        "bob",
        "message-1",
        bob.public_key(),
    )

    try:
        decrypt_payload(ciphertext, mallory, "alice", "bob", "message-1")
    except ValueError:
        pass
    else:
        raise AssertionError("a different recipient private key decrypted the payload")


def test_each_message_uses_fresh_ephemeral_ciphertext():
    bob = Ed25519PrivateKey.generate()

    first = encrypt_payload("same", "alice", "bob", "message-1", bob.public_key())
    second = encrypt_payload("same", "alice", "bob", "message-2", bob.public_key())

    assert first != second


def test_tampering_or_wrong_context_is_rejected():
    alice = Ed25519PrivateKey.generate()
    bob = Ed25519PrivateKey.generate()

    ciphertext = encrypt_payload(
        "secret",
        "alice",
        "bob",
        "message-1",
        bob.public_key(),
    )

    bad = ciphertext[:-2] + ("AA" if ciphertext[-2:] != "AA" else "BB")
    try:
        decrypt_payload(bad, bob, "alice", "bob", "message-1")
    except ValueError:
        pass
    else:
        raise AssertionError("tampered ciphertext was accepted")

    try:
        decrypt_payload(ciphertext, bob, "alice", "mallory", "message-1")
    except ValueError:
        pass
    else:
        raise AssertionError("wrong recipient context was accepted")
