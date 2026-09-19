"""Passphrase-authenticated encryption of key export bundles.

An export bundle is an opaque base64 string. Inside, a JSON envelope carries
the KDF parameters, salt, nonce and AES-GCM ciphertext of the canonical JSON
payload. The payload itself is versioned (``v: 1``) and holds everything
needed to recreate the key: key_id, label, every version's algorithm,
timestamps, public and private material, the current pointer and the
revocation fields. The passphrase never appears in the bundle; a wrong
passphrase and any tampering are indistinguishable (both fail AEAD).
"""

import base64
import binascii
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .crypto import SUPPORTED_ALGORITHMS

# Value of the "format" field in the export response / payload version.
EXPORT_FORMAT = "keymgr-export-v1"
_PAYLOAD_VERSION = 1

_KDF_NAME = "pbkdf2-sha256"
_KDF_ITERATIONS = 200_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32


class BundleError(Exception):
    """Raised when a bundle cannot be decoded, decrypted or validated.

    The message always names the offending field so the API can return a
    400 that points at it.
    """


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text, field: str) -> bytes:
    if not isinstance(text, str):
        raise BundleError("field %s must be a base64 string" % field)
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleError("field %s must be valid base64" % field) from exc


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bundle(passphrase: str, payload: dict) -> str:
    """Encrypt a payload dict with the passphrase; return opaque base64."""
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt, _KDF_ITERATIONS)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    envelope = {
        "v": _PAYLOAD_VERSION,
        "kdf": _KDF_NAME,
        "iter": _KDF_ITERATIONS,
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ct": _b64e(ciphertext),
    }
    return _b64e(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))


def decrypt_bundle(passphrase: str, bundle: str) -> dict:
    """Decrypt and authenticate a bundle; return the payload dict.

    Any base64/JSON/format/version problem, a wrong passphrase or tampering
    raises BundleError naming the field at fault. Nothing is returned
    partially: either the whole authenticated payload comes back or nothing.
    """
    raw = _b64d(bundle, "bundle")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError("field bundle is not a valid export bundle") from exc
    if not isinstance(envelope, dict):
        raise BundleError("field bundle is not a valid export bundle")
    if envelope.get("v") != _PAYLOAD_VERSION or envelope.get("kdf") != _KDF_NAME:
        raise BundleError("field bundle has an unsupported format or version")
    iterations = envelope.get("iter")
    if not isinstance(iterations, int) or iterations < 1:
        raise BundleError("field bundle has an unsupported format or version")
    salt = _b64d(envelope.get("salt"), "bundle")
    nonce = _b64d(envelope.get("nonce"), "bundle")
    ciphertext = _b64d(envelope.get("ct"), "bundle")
    key = _derive_key(passphrase, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        # Wrong passphrase and tampering are intentionally identical.
        raise BundleError(
            "field bundle cannot be decrypted (wrong passphrase or tampered bundle)"
        ) from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError("field bundle is not a valid export bundle") from exc
    if not isinstance(payload, dict) or payload.get("v") != _PAYLOAD_VERSION:
        raise BundleError("field bundle has an unsupported format or version")
    return payload


def build_export_payload(record) -> dict:
    """Assemble the plaintext payload for one key record.

    Includes private material for every version; it only ever exists inside
    the passphrase-encrypted bundle, never in a response or the ledger.
    """
    return {
        "v": _PAYLOAD_VERSION,
        "format": EXPORT_FORMAT,
        "key_id": record.key_id,
        "label": record.label,
        "current_version": record.current_version,
        "status": record.status,
        "reason": record.reason,
        "operator": record.operator,
        "revoked_at": record.revoked_at,
        "versions": [
            {
                "version": ver.version,
                "created_at": ver.created_at,
                "algorithm": ver.algorithm,
                "public_key": ver.public_key,
                "private_material": ver.private_material,
            }
            for ver in record.versions
        ],
    }


def validate_import_payload(payload: dict) -> dict:
    """Validate a decrypted payload and return a clean record dict.

    Every required field is checked for presence and type; the first problem
    raises BundleError naming the field, so the caller can 400 before any
    state is written (no half-imported keys).
    """
    required_strings = ("key_id", "label", "status")
    for field in required_strings:
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise BundleError("bundle is missing required field: %s" % field)
    # Imported lazily: store does not depend on this module, so no cycle.
    from .store import is_valid_key_id

    if not is_valid_key_id(payload["key_id"]):
        raise BundleError("bundle has an invalid value for field: key_id")
    if payload["status"] not in ("active", "revoked"):
        raise BundleError("bundle has an invalid value for field: status")
    for field in ("reason", "operator", "revoked_at"):
        value = payload.get(field)
        if value is not None and not isinstance(value, str):
            raise BundleError("bundle has an invalid value for field: %s" % field)
    current_version = payload.get("current_version")
    if not isinstance(current_version, int) or current_version < 1:
        raise BundleError("bundle is missing required field: current_version")
    versions = payload.get("versions")
    if not isinstance(versions, list) or not versions:
        raise BundleError("bundle is missing required field: versions")
    cleaned_versions = []
    for ver in versions:
        if not isinstance(ver, dict):
            raise BundleError("bundle has an invalid entry in field: versions")
        number = ver.get("version")
        if not isinstance(number, int) or number < 1:
            raise BundleError(
                "bundle has an invalid value for field: versions.version"
            )
        created_at = ver.get("created_at")
        if not isinstance(created_at, str) or not created_at:
            raise BundleError(
                "bundle is missing required field: versions.created_at"
            )
        algorithm = ver.get("algorithm")
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise BundleError(
                "bundle has an invalid value for field: versions.algorithm"
            )
        public_key = ver.get("public_key")
        if public_key is not None and not isinstance(public_key, str):
            raise BundleError(
                "bundle has an invalid value for field: versions.public_key"
            )
        private_material = ver.get("private_material")
        if not isinstance(private_material, str) or not private_material:
            raise BundleError(
                "bundle is missing required field: versions.private_material"
            )
        cleaned_versions.append(
            {
                "version": number,
                "created_at": created_at,
                "algorithm": algorithm,
                "public_key": public_key,
                "private_material": private_material,
            }
        )
    numbers = [v["version"] for v in cleaned_versions]
    if len(set(numbers)) != len(numbers) or current_version not in numbers:
        raise BundleError(
            "bundle has an invalid value for field: current_version"
        )
    return {
        "key_id": payload["key_id"],
        "label": payload["label"],
        "current_version": current_version,
        "status": payload["status"],
        "reason": payload.get("reason"),
        "operator": payload.get("operator"),
        "revoked_at": payload.get("revoked_at"),
        "versions": cleaned_versions,
    }
