"""Envelope encryption for tenant keys (format keymgr-envelope-v1).

A fresh 256-bit data key (DEK) seals the plaintext with AES-256-GCM; the DEK is
then wrapped by the named key version (the key-encryption key, KEK):

* ``AES256`` KEK: the DEK is wrapped with AES-256-GCM (wrap scheme
  ``AES-GCM``);
* ``RSA2048`` KEK: the DEK is wrapped with RSA-OAEP-SHA256
  (``RSA-OAEP-SHA256``).

The envelope is one base64 token whose JSON payload carries only metadata and
wrapped material: ``key_id``, ``version``, the algorithm/schemes, the GCM
nonce/tag/ciphertext, the wrapped DEK and the authenticated AAD. Raw private
keys, data keys and passphrases never enter the envelope; the data key exists
only in process memory for the duration of one call.
"""

import base64
import binascii
import json
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "keymgr-envelope-v1"

# Content encryption is always AES-256-GCM under the ephemeral data key.
ENC_AES_GCM = "AES-GCM"
# KEK wrap schemes.
WRAP_AES_GCM = "AES-GCM"
WRAP_RSA_OAEP_SHA256 = "RSA-OAEP-SHA256"

_AES256 = "AES256"
_RSA2048 = "RSA2048"
_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_RSA_WRAP_LEN = 256  # RSA-2048 OAEP ciphertext length.

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class EnvelopeError(ValueError):
    """An envelope request failure (always surfaced as 400)."""


@dataclass(frozen=True)
class OpenedEnvelope:
    """Structurally validated, still-encrypted envelope contents."""

    key_id: str
    version: int
    algorithm: str
    enc: str
    wrap: str
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    wrapped_key: bytes
    wrap_nonce: Optional[bytes]
    aad: bytes


def b64_decode_field(value, field: str) -> bytes:
    """Strictly decode standard base64 (padding required).

    Raises EnvelopeError naming the request field on any non-string or
    non-canonical input.
    """
    if not isinstance(value, str):
        raise EnvelopeError("field %s must be a base64 string" % field)
    if value == "":
        return b""
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise EnvelopeError(
            "field %s is not valid base64" % field
        ) from exc
    return raw


def b64_encode(raw: bytes) -> str:
    """Canonical standard base64 encoding used for every envelope token."""
    return base64.b64encode(raw).decode("ascii")


def _wrap_dek_with(algorithm: str, kek, dek: bytes) -> tuple:
    """Wrap an existing DEK under the KEK. Returns (wrapped_key, wrap_nonce)."""
    if algorithm == _AES256:
        if not isinstance(kek, (bytes, bytearray)) or len(kek) != _KEY_LEN:
            raise EnvelopeError("server key material is invalid for AES256")
        wrap_nonce = os.urandom(_NONCE_LEN)
        sealed = AESGCM(bytes(kek)).encrypt(wrap_nonce, dek, None)
        return sealed, wrap_nonce
    if algorithm == _RSA2048:
        if not isinstance(kek, rsa.RSAPrivateKey) or kek.key_size != 2048:
            raise EnvelopeError(
                "server key material is invalid for RSA2048"
            )
        sealed = kek.public_key().encrypt(dek, _OAEP)
        return sealed, None
    raise EnvelopeError("unsupported algorithm for envelope: %r" % algorithm)


def _wrap_dek(algorithm: str, kek) -> tuple:
    """Wrap a fresh 32-byte DEK under the KEK. Returns (dek, wk, wrap_nonce)."""
    dek = os.urandom(_KEY_LEN)
    sealed, wrap_nonce = _wrap_dek_with(algorithm, kek, dek)
    return dek, sealed, wrap_nonce


def _unwrap_dek(opened: "OpenedEnvelope", kek) -> bytes:
    """Recover the DEK from the envelope using the KEK."""
    try:
        if opened.algorithm == _AES256:
            if not isinstance(kek, (bytes, bytearray)) or len(kek) != _KEY_LEN:
                raise EnvelopeError(
                    "server key material is invalid for AES256"
                )
            if opened.wrap_nonce is None:
                raise InvalidTag("missing wrap nonce")
            return AESGCM(bytes(kek)).decrypt(
                opened.wrap_nonce, opened.wrapped_key, None
            )
        if opened.algorithm == _RSA2048:
            if not isinstance(kek, rsa.RSAPrivateKey) or kek.key_size != 2048:
                raise EnvelopeError(
                    "server key material is invalid for RSA2048"
                )
            return kek.decrypt(opened.wrapped_key, _OAEP)
    except InvalidTag as exc:
        raise EnvelopeError(
            "field envelope is tampered or cannot be authenticated"
        ) from exc
    except ValueError as exc:
        # RSA decryption failures (wrong key/size/padding) land here.
        raise EnvelopeError(
            "field envelope is tampered or cannot be authenticated"
        ) from exc
    raise EnvelopeError(
        "field envelope is tampered or cannot be authenticated"
    )


def encode_envelope(
    *,
    key_id: str,
    version: int,
    algorithm: str,
    kek,
    plaintext: bytes,
    aad: Optional[bytes] = None,
) -> str:
    """Seal plaintext under a fresh data key wrapped by the KEK.

    Returns the opaque base64 envelope token. The KEK is the raw 32-byte key
    for AES256 or a loaded 2048-bit RSA private key for RSA2048 (its public
    component wraps the DEK).
    """
    if aad is None:
        aad = b""
    dek, wrapped_key, wrap_nonce = _wrap_dek(algorithm, kek)
    nonce = os.urandom(_NONCE_LEN)
    sealed = AESGCM(dek).encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
    wrap = WRAP_AES_GCM if algorithm == _AES256 else WRAP_RSA_OAEP_SHA256
    payload = {
        "format": FORMAT,
        "key_id": key_id,
        "version": version,
        "algorithm": algorithm,
        "enc": ENC_AES_GCM,
        "wrap": wrap,
        "nonce": b64_encode(nonce),
        "tag": b64_encode(tag),
        "ciphertext": b64_encode(ciphertext),
        "wrapped_key": b64_encode(wrapped_key),
        "aad": b64_encode(aad),
    }
    if wrap_nonce is not None:
        payload["wrap_nonce"] = b64_encode(wrap_nonce)
    raw = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return b64_encode(raw)


def _require_str(obj: dict, name: str) -> str:
    value = obj.get(name)
    if not isinstance(value, str) or not value:
        raise EnvelopeError("field envelope has missing or invalid %s" % name)
    return value


def _require_b64(obj: dict, name: str, *, allow_empty: bool = False) -> bytes:
    value = obj.get(name)
    if not isinstance(value, str):
        raise EnvelopeError("field envelope has missing or invalid %s" % name)
    if not value and not allow_empty:
        raise EnvelopeError("field envelope has missing or invalid %s" % name)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise EnvelopeError(
            "field envelope has invalid base64 in %s" % name
        ) from exc


def decode_envelope(token: str) -> OpenedEnvelope:
    """Parse and structurally validate an envelope token (no crypto).

    Raises EnvelopeError (surfaced as 400) naming ``field envelope`` for any
    malformed, truncated, tampered-shape or unsupported-format token.
    """
    if not isinstance(token, str) or not token:
        raise EnvelopeError("field envelope must be a non-empty string")
    try:
        raw = base64.b64decode(token.encode("ascii"), validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise EnvelopeError("field envelope is not valid base64") from exc
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise EnvelopeError(
            "field envelope does not contain a valid JSON object"
        ) from exc
    if not isinstance(obj, dict):
        raise EnvelopeError(
            "field envelope does not contain a valid JSON object"
        )
    if obj.get("format") != FORMAT:
        raise EnvelopeError("field envelope format must be %r" % FORMAT)
    key_id = _require_str(obj, "key_id")
    version = obj.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
    ):
        raise EnvelopeError(
            "field envelope version must be a positive integer"
        )
    algorithm = obj.get("algorithm")
    if algorithm not in (_AES256, _RSA2048):
        raise EnvelopeError(
            "field envelope algorithm must be one of: AES256, RSA2048"
        )
    expected_wrap = (
        WRAP_AES_GCM if algorithm == _AES256 else WRAP_RSA_OAEP_SHA256
    )
    if obj.get("enc") != ENC_AES_GCM:
        raise EnvelopeError("field envelope enc must be %r" % ENC_AES_GCM)
    if obj.get("wrap") != expected_wrap:
        raise EnvelopeError(
            "field envelope wrap must be %r for algorithm %s"
            % (expected_wrap, algorithm)
        )
    nonce = _require_b64(obj, "nonce")
    tag = _require_b64(obj, "tag")
    if len(nonce) != _NONCE_LEN:
        raise EnvelopeError("field envelope nonce must be 12 bytes")
    if len(tag) != _TAG_LEN:
        raise EnvelopeError("field envelope tag must be 16 bytes")
    ciphertext = _require_b64(obj, "ciphertext", allow_empty=True)
    wrapped_key = _require_b64(obj, "wrapped_key")
    wrap_nonce = None
    if algorithm == _AES256:
        wrap_nonce = _require_b64(obj, "wrap_nonce")
        if len(wrap_nonce) != _NONCE_LEN:
            raise EnvelopeError(
                "field envelope wrap_nonce must be 12 bytes"
            )
        # AES-GCM of a 32-byte DEK is exactly 48 bytes (32 + 16 tag).
        if len(wrapped_key) != _KEY_LEN + _TAG_LEN:
            raise EnvelopeError(
                "field envelope wrapped_key has an invalid length"
            )
    else:
        if len(wrapped_key) != _RSA_WRAP_LEN:
            raise EnvelopeError(
                "field envelope wrapped_key has an invalid length"
            )
        if "wrap_nonce" in obj and obj["wrap_nonce"] is not None:
            raise EnvelopeError(
                "field envelope wrap_nonce must be absent for RSA2048"
            )
    aad = b""
    if "aad" in obj and obj["aad"] is not None:
        aad = _require_b64(obj, "aad", allow_empty=True)
    return OpenedEnvelope(
        key_id=key_id,
        version=version,
        algorithm=algorithm,
        enc=ENC_AES_GCM,
        wrap=expected_wrap,
        nonce=nonce,
        tag=tag,
        ciphertext=ciphertext,
        wrapped_key=wrapped_key,
        wrap_nonce=wrap_nonce,
        aad=aad,
    )


def open_envelope(opened: OpenedEnvelope, kek) -> bytes:
    """Unwrap the data key and decrypt the payload (AES/RSA KEK).

    A wrong key version, a modified nonce/tag/ciphertext/wrapped_key or a
    failed RSA unpadding all fail as one field-naming authentication error;
    the caller separately checks that the request AAD equals the envelope AAD.
    """
    dek = _unwrap_dek(opened, kek)
    try:
        sealed = opened.ciphertext + opened.tag
        return AESGCM(dek).decrypt(opened.nonce, sealed, opened.aad)
    except InvalidTag as exc:
        raise EnvelopeError(
            "field envelope is tampered or cannot be authenticated"
        ) from exc


def _decrypt_content(opened: OpenedEnvelope, dek: bytes) -> bytes:
    """Decrypt the payload with an already-recovered 32-byte data key."""
    sealed = opened.ciphertext + opened.tag
    return AESGCM(dek).decrypt(opened.nonce, sealed, opened.aad)


def open_envelope_native(opened: OpenedEnvelope, provider, handle: str) -> bytes:
    """Decrypt via a KMS/HSM-native ``unwrap_key`` provider operation.

    The data key is unwrapped INSIDE the provider by its bound KEK: the
    service never calls ``export_material`` and never loads the KEK private
    material into this process. The provider returns the 32-byte DEK and the
    payload is then authenticated/decrypted here.

    Provider error mapping follows the provider contract unchanged: an
    authentication failure raises ``ProviderInvalidMaterial`` (surfaced as a
    400 naming the envelope); an unknown/algorithm-mismatched handle or any
    backend failure raises ``ProviderUnavailable`` (the fixed 503, no audit
    event); an unexpected ``ValueError``/``TypeError`` from the provider is a
    contract violation and is normalized to ``ProviderUnavailable``. A failed
    content authentication raises :class:`EnvelopeError`.
    """
    from .provider import (
        ProviderInvalidMaterial,
        ProviderUnavailable,
    )

    try:
        dek = provider.unwrap_key(
            handle, opened.wrapped_key, opened.wrap_nonce
        )
    except (ProviderInvalidMaterial, ProviderUnavailable):
        raise
    except (ValueError, TypeError) as exc:
        # A conforming provider cannot raise these for a structurally valid
        # envelope: treat it as a backend/contract fault, never a 400 path
        # with provider text.
        raise ProviderUnavailable(
            "provider unwrap_key raised a contract violation"
        ) from exc
    try:
        return _decrypt_content(opened, dek)
    except InvalidTag as exc:
        raise EnvelopeError(
            "field envelope is tampered or cannot be authenticated"
        ) from exc


def rewrap_envelope(
    opened: OpenedEnvelope,
    source_kek,
    *,
    target_version: int,
    target_algorithm: str,
    target_kek,
) -> str:
    """Re-wrap an authenticated envelope's data key under a new KEK version.

    The source envelope is fully authenticated first: the DEK is unwrapped
    with the source KEK and the content GCM tag is verified (the recovered
    plaintext is used only for that check, never stored or returned). Only
    then is the SAME data key wrapped under the target version's KEK. The
    key_id, nonce, tag, ciphertext and aad bytes are carried over unchanged;
    the version, algorithm and wrap fields are rebuilt for the target. The
    data key itself exists only in process memory for the duration of the
    call and never enters the returned token in the clear.
    """
    dek = _unwrap_dek(opened, source_kek)
    try:
        AESGCM(dek).decrypt(
            opened.nonce, opened.ciphertext + opened.tag, opened.aad
        )
    except InvalidTag as exc:
        raise EnvelopeError(
            "field envelope is tampered or cannot be authenticated"
        ) from exc
    wrapped_key, wrap_nonce = _wrap_dek_with(
        target_algorithm, target_kek, dek
    )
    wrap = (
        WRAP_AES_GCM
        if target_algorithm == _AES256
        else WRAP_RSA_OAEP_SHA256
    )
    payload = {
        "format": FORMAT,
        "key_id": opened.key_id,
        "version": target_version,
        "algorithm": target_algorithm,
        "enc": ENC_AES_GCM,
        "wrap": wrap,
        "nonce": b64_encode(opened.nonce),
        "tag": b64_encode(opened.tag),
        "ciphertext": b64_encode(opened.ciphertext),
        "wrapped_key": b64_encode(wrapped_key),
        "aad": b64_encode(opened.aad),
    }
    if wrap_nonce is not None:
        payload["wrap_nonce"] = b64_encode(wrap_nonce)
    raw = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return b64_encode(raw)
