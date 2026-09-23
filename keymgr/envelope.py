"""Envelope encryption format ``keymgr-envelope-v1``.

An envelope seals an arbitrary plaintext under a fresh random data-encryption
key (DEK); the DEK itself is wrapped by one version of a tenant key and the
whole envelope travels as a single opaque base64 token:

* the plaintext is encrypted with AES-256-GCM under the DEK, with the
  caller-supplied AAD authenticated but never stored;
* for an ``AES256`` key version the DEK is wrapped with AES-GCM under the
  version's 256-bit key (a fresh wrap nonce per envelope);
* for an ``RSA2048`` key version the DEK is wrapped with RSA-OAEP-SHA256
  under the version's public key (no wrap nonce).

The decoded envelope is a JSON object carrying only metadata and ciphertext:
``key_id``, ``version``, ``algorithm``, ``nonce``, ``tag``, ``ciphertext``,
``wrapped_key`` and ``wrap_nonce`` (null for RSA2048). Raw key material, the
DEK and the plaintext never appear in it.
"""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import SUPPORTED_ALGORITHMS

FORMAT = "keymgr-envelope-v1"

_DEK_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16


class EnvelopeError(Exception):
    """An envelope or its inputs failed validation (surfaced as 400).

    The message names the offending field and never embeds key material,
    the data key, the plaintext or the AAD.
    """


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text, field: str) -> bytes:
    if not isinstance(text, str):
        raise EnvelopeError("field %s must be a base64 string" % field)
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("field %s must be valid base64" % field) from exc


def decode_request_b64(value, field: str) -> bytes:
    """Strictly decode a request field (plaintext/aad) named ``field``.

    Request bodies carry standard base64; anything else is a 400 naming the
    field. Shared by the HTTP handler and the CLI.
    """
    if not isinstance(value, str):
        raise EnvelopeError("field %s must be a base64 string" % field)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("field %s must be valid base64" % field) from exc


def encode_request_b64(raw: bytes) -> str:
    """Standard base64 for response/request fields (plaintext)."""
    return base64.b64encode(raw).decode("ascii")


def _aes_kek(material: str) -> bytes:
    """Decode a raw AES256 key from its stored (unwrapped) material form."""
    try:
        raw = base64.b64decode(material, validate=True)
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("stored key material is not usable") from exc
    if len(raw) != 32:
        raise EnvelopeError("stored key material is not usable")
    return raw


def _rsa_public_key(public_key: str):
    try:
        return serialization.load_pem_public_key(public_key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("stored public key is not usable") from exc


def _rsa_private_key(material: str):
    try:
        return serialization.load_pem_private_key(
            material.encode("utf-8"), password=None
        )
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("stored key material is not usable") from exc


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def seal_envelope(
    key_id: str,
    version: int,
    algorithm: str,
    material: str,
    public_key,
    plaintext: bytes,
    aad,
) -> str:
    """Encrypt ``plaintext`` into an opaque envelope token.

    ``material``/``public_key`` are the version's raw material as returned by
    the owning provider; they are used only to wrap the fresh DEK and never
    leave this process. ``aad`` is authenticated but not stored.
    """
    dek = os.urandom(_DEK_LEN)
    nonce = os.urandom(_NONCE_LEN)
    sealed = AESGCM(dek).encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
    if algorithm == "AES256":
        wrap_nonce = os.urandom(_NONCE_LEN)
        wrapped_key = AESGCM(_aes_kek(material)).encrypt(wrap_nonce, dek, None)
        wrap_nonce_field = _b64e(wrap_nonce)
    else:
        wrapped_key = _rsa_public_key(public_key).encrypt(dek, _oaep())
        wrap_nonce_field = None
    envelope = {
        "format": FORMAT,
        "key_id": key_id,
        "version": version,
        "algorithm": algorithm,
        "nonce": _b64e(nonce),
        "tag": _b64e(tag),
        "ciphertext": _b64e(ciphertext),
        "wrapped_key": _b64e(wrapped_key),
        "wrap_nonce": wrap_nonce_field,
    }
    raw = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return _b64e(raw)


def parse_envelope(envelope) -> dict:
    """Decode and structurally validate an envelope token.

    Returns the cleaned field dict (binary fields decoded). Raises
    EnvelopeError naming the offending field on any structural problem;
    authentication itself happens in :func:`open_envelope`.
    """
    raw = _b64d(envelope, "envelope")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise EnvelopeError("field envelope does not contain valid JSON") from exc
    if not isinstance(data, dict):
        raise EnvelopeError("field envelope must be a JSON object")
    if data.get("format") != FORMAT:
        raise EnvelopeError("field envelope.format must be %r" % FORMAT)
    key_id = data.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise EnvelopeError("field envelope.key_id must be a non-empty string")
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise EnvelopeError("field envelope.version must be a positive integer")
    algorithm = data.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise EnvelopeError(
            "field envelope.algorithm must be one of: %s"
            % ", ".join(SUPPORTED_ALGORITHMS)
        )
    nonce = _b64d(data.get("nonce"), "envelope.nonce")
    if len(nonce) != _NONCE_LEN:
        raise EnvelopeError("field envelope.nonce must decode to 12 bytes")
    tag = _b64d(data.get("tag"), "envelope.tag")
    if len(tag) != _TAG_LEN:
        raise EnvelopeError("field envelope.tag must decode to 16 bytes")
    ciphertext = _b64d(data.get("ciphertext"), "envelope.ciphertext")
    wrapped_key = _b64d(data.get("wrapped_key"), "envelope.wrapped_key")
    if not wrapped_key:
        raise EnvelopeError("field envelope.wrapped_key must be non-empty")
    wrap_nonce_raw = data.get("wrap_nonce")
    if algorithm == "AES256":
        wrap_nonce = _b64d(wrap_nonce_raw, "envelope.wrap_nonce")
        if len(wrap_nonce) != _NONCE_LEN:
            raise EnvelopeError(
                "field envelope.wrap_nonce must decode to 12 bytes"
            )
    else:
        if wrap_nonce_raw is not None:
            raise EnvelopeError(
                "field envelope.wrap_nonce must be null for RSA2048"
            )
        wrap_nonce = None
    return {
        "key_id": key_id,
        "version": version,
        "algorithm": algorithm,
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext,
        "wrapped_key": wrapped_key,
        "wrap_nonce": wrap_nonce,
    }


def _tampered() -> EnvelopeError:
    # A GCM/OAEP authentication failure cannot distinguish a tampered
    # envelope from a mismatched AAD; name both candidate fields without
    # leaking which check failed.
    return EnvelopeError(
        "field envelope is tampered or does not match the supplied aad"
    )


def open_envelope(parsed: dict, material: str, aad) -> bytes:
    """Unwrap the DEK and decrypt the envelope payload.

    ``parsed`` comes from :func:`parse_envelope`; ``material`` is the raw
    material of the envelope's exact key version, resolved through its owning
    provider. Any authentication failure (tampering, wrong key, AAD mismatch)
    raises EnvelopeError; the plaintext never appears in any message.
    """
    if parsed["algorithm"] == "AES256":
        kek = _aes_kek(material)
        try:
            dek = AESGCM(kek).decrypt(
                parsed["wrap_nonce"], parsed["wrapped_key"], None
            )
        except InvalidTag as exc:
            raise _tampered() from exc
    else:
        private_key = _rsa_private_key(material)
        try:
            dek = private_key.decrypt(parsed["wrapped_key"], _oaep())
        except ValueError as exc:
            raise _tampered() from exc
    if len(dek) != _DEK_LEN:
        raise _tampered()
    try:
        return AESGCM(dek).decrypt(
            parsed["nonce"], parsed["ciphertext"] + parsed["tag"], aad
        )
    except InvalidTag as exc:
        raise _tampered() from exc
