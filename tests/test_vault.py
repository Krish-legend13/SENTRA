"""Tests for password-protected Ed25519 private-key vaults."""

import base64
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from crypto import (
    generate_keypair,
    load_key_from_vault,
    save_key_to_vault,
    sign,
    validate_passphrase,
    vault_exists,
    verify,
)


PASSPHRASE = "correct horse battery staple"


def _read_vault(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_vault(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def test_round_trip_key_can_sign_and_verify(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair()
    path = tmp_path / "identity.vault"

    save_key_to_vault(private_key, path, PASSPHRASE)
    loaded_key = load_key_from_vault(path, PASSPHRASE)
    signature = sign(loaded_key, b"vault payload")

    assert verify(public_key, signature, b"vault payload")


def test_wrong_passphrase_has_documented_error(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"
    save_key_to_vault(private_key, path, PASSPHRASE)

    with pytest.raises(
        ValueError,
        match="^Vault decryption failed: wrong passphrase or corrupted file$",
    ):
        load_key_from_vault(path, "wrong passphrase")


def test_tampered_ciphertext_is_rejected(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"
    save_key_to_vault(private_key, path, PASSPHRASE)
    data = _read_vault(path)

    ciphertext = bytearray(base64.b64decode(data["cipher"]["ciphertext"]))
    ciphertext[0] ^= 1
    data["cipher"]["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    _write_vault(path, data)

    with pytest.raises(ValueError):
        load_key_from_vault(path, PASSPHRASE)


def test_tampered_header_is_rejected_by_authentication(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"
    save_key_to_vault(private_key, path, PASSPHRASE)
    data = _read_vault(path)
    data["kdf"]["n"] = 16384
    _write_vault(path, data)

    with pytest.raises(ValueError):
        load_key_from_vault(path, PASSPHRASE)


def test_truncated_file_is_rejected(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"
    save_key_to_vault(private_key, path, PASSPHRASE)
    content = path.read_text(encoding="utf-8")
    path.write_text(content[: len(content) // 2], encoding="utf-8")

    with pytest.raises(ValueError):
        load_key_from_vault(path, PASSPHRASE)


def test_non_json_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "identity.vault"
    path.write_text("not json", encoding="utf-8")

    with pytest.raises(ValueError, match="Vault file is not valid JSON"):
        load_key_from_vault(path, PASSPHRASE)


def test_missing_kdf_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "identity.vault"
    _write_vault(path, {"version": 1, "cipher": {}})

    with pytest.raises(ValueError, match="kdf"):
        load_key_from_vault(path, PASSPHRASE)


def test_unsupported_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "identity.vault"
    _write_vault(path, {"version": 99, "kdf": {}, "cipher": {}})

    with pytest.raises(ValueError, match="Unsupported vault version: 99"):
        load_key_from_vault(path, PASSPHRASE)


def test_consecutive_saves_use_different_salt_and_nonce(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"

    save_key_to_vault(private_key, path, PASSPHRASE)
    first = _read_vault(path)
    save_key_to_vault(private_key, path, PASSPHRASE)
    second = _read_vault(path)

    assert first["kdf"]["salt"] != second["kdf"]["salt"]
    assert first["cipher"]["nonce"] != second["cipher"]["nonce"]


@pytest.mark.parametrize("passphrase", ["", "short", "       "])
def test_invalid_passphrases_are_rejected(passphrase: str) -> None:
    with pytest.raises(ValueError):
        validate_passphrase(passphrase)


def test_eight_character_passphrase_is_accepted() -> None:
    validate_passphrase("12345678")


def test_vault_exists_reflects_saved_file(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"

    assert not vault_exists(path)
    save_key_to_vault(private_key, path, PASSPHRASE)
    assert vault_exists(path)


def test_successful_save_leaves_no_tmp_file(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"

    save_key_to_vault(private_key, path, PASSPHRASE)

    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions only")
def test_vault_file_permissions_are_owner_only(tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    path = tmp_path / "identity.vault"

    save_key_to_vault(private_key, path, PASSPHRASE)

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
