"""Mutual TLS context builders.

The server requires and verifies a client certificate before any
application data (including the Ed25519 challenge-response handshake) is
exchanged. The client verifies the server's certificate and presents its
own. TLS 1.2 is the floor; the ssl module negotiates the highest mutually
supported version above that (TLS 1.3 where available).

Note: mTLS establishes *transport*-level trust (this socket belongs to a
holder of a CA-issued certificate). It is layered underneath, and does not
replace, the application-level Ed25519 identity/challenge-response system
in auth.challenge and auth.registry -- a compromised or shared client
certificate still can't forge a signed AUTH_RESPONSE.
"""

from __future__ import annotations

import ssl

from crypto.keys import PathType


def build_server_context(certfile: PathType, keyfile: PathType, cafile: PathType) -> ssl.SSLContext:
    """Build a server-side SSLContext that requires a valid client certificate.

    Raises:
        ssl.SSLError: If the certificate/key files are invalid or mismatched.
        FileNotFoundError: If any path does not exist.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.load_verify_locations(cafile=str(cafile))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def build_client_context(certfile: PathType, keyfile: PathType, cafile: PathType) -> ssl.SSLContext:
    """Build a client-side SSLContext that verifies the server and presents
    a client certificate for mutual authentication.

    Raises:
        ssl.SSLError: If the certificate/key files are invalid or mismatched.
        FileNotFoundError: If any path does not exist.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(cafile))
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.check_hostname = True
    return context
