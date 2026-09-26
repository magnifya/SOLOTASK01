"""Cryptographic key generation for supported algorithms."""

import base64
import os
from typing import NamedTuple, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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


def rsa2048_sign(private_key, message: bytes) -> bytes:
    """Sign ``message`` with RSASSA-PKCS1-v1_5 / SHA-256 (deterministic).

    ``private_key`` must be a 2048-bit RSA private key (the store layer has
    already validated the loaded material). The signature never leaves the
    service except as the base64 response field.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey) or (
        private_key.key_size != 2048
    ):
        raise ValueError("signing requires a 2048-bit RSA private key")
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def rsa2048_verify(public_pem: str, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 / SHA-256 signature against a PEM public key.

    Uses only the stored public material. A mismatching signature returns
    False; a stored public key that is not a usable 2048-bit RSA PEM raises
    ValueError (a backend inconsistency, surfaced as 503 by the caller).
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_pem.encode("utf-8")
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(
            "stored RSA2048 public key is not a PEM public key"
        ) from exc
    if not isinstance(public_key, rsa.RSAPublicKey) or (
        public_key.key_size != 2048
    ):
        raise ValueError("stored RSA2048 public key is not a 2048-bit RSA key")
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True
