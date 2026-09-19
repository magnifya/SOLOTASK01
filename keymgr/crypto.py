"""Cryptographic key generation for supported algorithms."""

import base64
import os
from typing import NamedTuple, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SUPPORTED_ALGORITHMS = ("AES256", "RSA2048")


class GeneratedKey(NamedTuple):
    """Result of generating a key.

    public_material is PEM (SubjectPublicKeyInfo) for RSA, None for AES.
    private_material stays server-side only (PEM for RSA, base64 for AES).
    """

    public_material: Optional[str]
    private_material: str


def _generate_aes256() -> GeneratedKey:
    """Generate a 256-bit AES key (no public component)."""
    raw = os.urandom(32)
    return GeneratedKey(
        public_material=None,
        private_material=base64.b64encode(raw).decode("ascii"),
    )


def _generate_rsa2048() -> GeneratedKey:
    """Generate a 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return GeneratedKey(
        public_material=public_pem,
        private_material=private_pem,
    )


def generate_key(algorithm: str) -> GeneratedKey:
    """Generate a new key for the given algorithm name."""
    if algorithm == "AES256":
        return _generate_aes256()
    if algorithm == "RSA2048":
        return _generate_rsa2048()
    raise ValueError("unsupported algorithm: %r" % (algorithm,))
