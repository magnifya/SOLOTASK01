"""RSA-2048 digital signatures: RSASSA-PKCS1-v1_5 with SHA-256.

Signing is deterministic: the same private key version and message always
yield the same signature, so retries need no idempotency machinery. Only
RSA2048 versions can sign; verification needs solely the version's public
key (PEM, already stored on the key record), so a signature can still be
verified against an old version after a restart, rotation or migration --
and even while that version's KMS/HSM provider is unavailable.
"""

import base64
import binascii

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_RSA_KEY_SIZE = 2048
#: Byte length of an RSASSA-PKCS1-v1_5 signature over a 2048-bit RSA key.
SIGNATURE_BYTES = _RSA_KEY_SIZE // 8
#: RSASSA-PKCS1-v1_5/SHA-256: deterministic, no randomness or nonce.
_PKCS1_PADDING = padding.PKCS1v15()
_SHA256 = hashes.SHA256()


class SigningError(ValueError):
    """Malformed signing material (a backend inconsistency, never a 400)."""


def b64_decode_field(value, field: str) -> bytes:
    """Strictly decode canonical standard base64 (empty string allowed).

    Raises ValueError naming the request field on any non-string or
    non-canonical input.
    """
    if not isinstance(value, str):
        raise ValueError("field %s must be a base64 string" % field)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("field %s is not valid base64" % field) from exc


def b64_encode(raw: bytes) -> str:
    """Canonical standard base64 used for every signature."""
    return base64.b64encode(raw).decode("ascii")


def rsa_sign(private_key, message: bytes) -> bytes:
    """Sign ``message`` with RSASSA-PKCS1-v1_5/SHA-256 (deterministic)."""
    return private_key.sign(message, _PKCS1_PADDING, _SHA256)


def rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    """Return True only when ``signature`` verifies under ``public_key``.

    Any mismatch (or a malformed signature value) is one answer: False. The
    caller turns that into ``200 {"valid": false}``; a bad signature is a
    normal verification result, never an error.
    """
    try:
        public_key.verify(signature, message, _PKCS1_PADDING, _SHA256)
    except InvalidSignature:
        return False
    except ValueError:
        # Wrong length/encoding for PKCS1v15 verification.
        return False
    return True


def load_rsa_public_key(public_pem) -> rsa.RSAPublicKey:
    """Parse and validate a stored 2048-bit RSA public key (PEM SPKI).

    The PEM is system-generated alongside the version, so a missing or
    unparseable value is a backend data inconsistency: callers surface it as
    a provider failure (503), never as a client error.
    """
    if not isinstance(public_pem, str) or not public_pem:
        raise SigningError("stored RSA2048 version has no public key")
    try:
        public_key = serialization.load_pem_public_key(
            public_pem.encode("utf-8")
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SigningError(
            "stored RSA2048 public key is not a PEM public key"
        ) from exc
    if not isinstance(public_key, rsa.RSAPublicKey) or (
        public_key.key_size != _RSA_KEY_SIZE
    ):
        raise SigningError(
            "stored RSA2048 public key is not a 2048-bit RSA public key"
        )
    return public_key


def load_rsa_private_key(private_pem) -> rsa.RSAPrivateKey:
    """Parse and validate exported 2048-bit RSA private material (PEM PKCS8).

    The material was produced by the owning KMS/HSM provider and only lives
    in process memory for the duration of one sign; a corrupt value is a
    backend inconsistency (SigningError), never a client error.
    """
    if not isinstance(private_pem, str) or not private_pem:
        raise SigningError("stored RSA2048 material is empty")
    try:
        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"), password=None
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SigningError(
            "stored RSA2048 material is not a PEM private key"
        ) from exc
    if not isinstance(private_key, rsa.RSAPrivateKey) or (
        private_key.key_size != _RSA_KEY_SIZE
    ):
        raise SigningError(
            "stored RSA2048 material is not a 2048-bit RSA private key"
        )
    return private_key
