"""Generate a local development CA plus a server certificate and one or more
client certificates, all signed by that CA, for mutual TLS testing.

This is a DEV-ONLY tool. It exists so the network layer can be exercised
end-to-end without a real PKI. Do not ship these keys or reuse this script
for production issuance.

Usage:
    python scripts/generate_dev_certs.py --clients alice bob
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"
VALIDITY_DAYS = 825


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _self_signed_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _new_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "SENTRA Dev CA")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf_cert(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    san_dns: list[str] | None = None,
    san_ip: list[str] | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _new_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    san_entries: list[x509.GeneralName] = [x509.DNSName(n) for n in (san_dns or [])]
    san_entries += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in (san_ip or [])]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _dump_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _dump_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clients",
        nargs="*",
        default=["alice", "bob"],
        help="Usernames to issue client certificates for.",
    )
    args = parser.parse_args()

    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = _self_signed_ca()
    _write(CERTS_DIR / "ca.key", _dump_key(ca_key))
    _write(CERTS_DIR / "ca.crt", _dump_cert(ca_cert))
    print(f"Wrote CA: {CERTS_DIR / 'ca.crt'}")

    server_key, server_cert = _leaf_cert(
        "sentra-server",
        ca_key,
        ca_cert,
        san_dns=["localhost"],
        san_ip=["127.0.0.1"],
    )
    _write(CERTS_DIR / "server.key", _dump_key(server_key))
    _write(CERTS_DIR / "server.crt", _dump_cert(server_cert))
    print(f"Wrote server cert: {CERTS_DIR / 'server.crt'}")

    for username in args.clients:
        client_key, client_cert = _leaf_cert(username, ca_key, ca_cert)
        _write(CERTS_DIR / f"client_{username}.key", _dump_key(client_key))
        _write(CERTS_DIR / f"client_{username}.crt", _dump_cert(client_cert))
        print(f"Wrote client cert: {CERTS_DIR / f'client_{username}.crt'}")

    print(
        "\nDev PKI ready. The client's certificate CN is only used for the "
        "mTLS handshake (transport identity); application-level identity "
        "still goes through auth.registry + Ed25519 challenge-response."
    )


if __name__ == "__main__":
    main()
