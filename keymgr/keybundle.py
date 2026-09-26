"""Authenticated passphrase encryption for key export/import bundles.

A bundle is an opaque, single base64 token. Its plaintext carries one full key
record (label, every version with its algorithm, timestamps, public and private
material, the current-version pointer and the revocation fields). The key is
derived from the passphrase with a memory-hard KDF and the payload is sealed
with AES-256-GCM, so a wrong passphrase and any tampering both fail
authentication rather than yielding partial plaintext.
"""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import SUPPORTED_ALGORITHMS

FORMAT = "keymgr-export-v1"
_ENVELOPE_VERSION = 1

_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32
_NONCE_LEN = 12


class BundleError(Exception):
    """Base class for bundle failures (all surfaced as 400)."""


class InvalidBundle(BundleError):
    """Malformed envelope, unsupported format/version, or missing fields."""


class WrongPassphrase(BundleError):
    """Authentication failed: wrong passphrase or tampered ciphertext."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text) -> bytes:
    if not isinstance(text, str):
        raise InvalidBundle("field bundle must be a base64 string")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise InvalidBundle("field bundle is not valid base64") from exc


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise InvalidBundle("field passphrase must be a non-empty string")
    kdf = Scrypt(
        salt=salt,
        length=_KEY_LEN,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def seal_envelope(payload: dict, passphrase: str, format_tag: str) -> str:
    """Authenticated-encrypt a payload into an opaque base64 token.

    Shared by the single-key export and the tenant backup; the ``format_tag``
    both names the envelope and authenticates the ciphertext as AAD, so a
    bundle of one format can never be replayed as the other.
    """
    salt = os.urandom(16)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    plaintext = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    envelope = {
        "format": format_tag,
        "version": _ENVELOPE_VERSION,
        "kdf": "scrypt",
        "salt": _b64e(salt),
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "nonce": _b64e(nonce),
        "data": _b64e(
            AESGCM(key).encrypt(nonce, plaintext, format_tag.encode("ascii"))
        ),
    }
    raw = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64e(raw)


def open_envelope(bundle: str, passphrase: str, format_tag: str) -> bytes:
    """Authenticate and decrypt an envelope, returning raw plaintext bytes.

    Raises WrongPassphrase for authentication failures and InvalidBundle for
    structural problems; shared by the single-key and the tenant formats.
    """
    params = _load_envelope(bundle, format_tag)
    if not isinstance(passphrase, str) or not passphrase:
        raise InvalidBundle("field passphrase must be a non-empty string")
    try:
        kdf = Scrypt(
            salt=params["salt"],
            length=_KEY_LEN,
            n=params["n"],
            r=params["r"],
            p=params["p"],
        )
        key = kdf.derive(passphrase.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise InvalidBundle("invalid kdf parameters in field bundle") from exc
    try:
        return AESGCM(key).decrypt(
            params["nonce"], params["data"], format_tag.encode("ascii")
        )
    except InvalidTag as exc:
        raise WrongPassphrase(
            "field passphrase is incorrect or bundle is tampered"
        ) from exc


def encode_bundle(payload: dict, passphrase: str) -> str:
    """Authenticated-encrypt an export payload into an opaque base64 token."""
    return seal_envelope(payload, passphrase, FORMAT)


def _load_envelope(bundle: str, expected_format: str = FORMAT) -> dict:
    raw = _b64d(bundle)
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidBundle("field bundle does not contain valid JSON") from exc
    if not isinstance(envelope, dict):
        raise InvalidBundle("field bundle must be a JSON object")
    if envelope.get("format") != expected_format:
        raise InvalidBundle(
            "field format must be %r" % expected_format
        )
    if envelope.get("version") != _ENVELOPE_VERSION:
        raise InvalidBundle(
            "unsupported bundle version for field bundle: %r"
            % (envelope.get("version"),)
        )
    if envelope.get("kdf") != "scrypt":
        raise InvalidBundle("unsupported kdf for field bundle")
    for name in ("salt", "nonce", "data"):
        if not isinstance(envelope.get(name), str):
            raise InvalidBundle("missing or invalid field: %s" % name)
    try:
        params = {
            "salt": _b64d(envelope["salt"]),
            "nonce": _b64d(envelope["nonce"]),
            "data": _b64d(envelope["data"]),
            "n": int(envelope["n"]),
            "r": int(envelope["r"]),
            "p": int(envelope["p"]),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidBundle("missing or invalid field in bundle header") from exc
    # Only the one parameter set we emit is accepted; this also stops a
    # crafted envelope from requesting an unbounded amount of KDF memory.
    if (
        params["n"] != _SCRYPT_N
        or params["r"] != _SCRYPT_R
        or params["p"] != _SCRYPT_P
        or len(params["salt"]) != 16
        or len(params["nonce"]) != _NONCE_LEN
    ):
        raise InvalidBundle("unsupported kdf parameters for field bundle")
    return params


def _require(data: dict, field: str, types) -> object:
    if field not in data or not isinstance(data[field], types):
        kind = "string" if types is str else "value"
        raise InvalidBundle("field %s must be a %s" % (field, kind))
    return data[field]


def validate_provider_block(block, where: str):
    """Validate an optional KMS/HSM provenance block on one version.

    The block is ``{"provider_id", "handle", "encrypted_material"}``; every
    field must be a non-empty string. ``None``/absent is valid and means the
    version originated on the built-in local provider (``keymgr-export-v1``
    bundles emitted before the provider layer carry no such field). Returns
    the cleaned block or None for a legacy version.
    """
    if block is None:
        return None
    prefix = where + ".provider"
    if not isinstance(block, dict):
        raise InvalidBundle("field %s must be an object" % prefix)
    unknown = set(block) - {"provider_id", "handle", "encrypted_material"}
    if unknown:
        raise InvalidBundle(
            "unknown field %s.%s" % (prefix, sorted(unknown)[0])
        )
    clean = {}
    for name in ("provider_id", "handle", "encrypted_material"):
        value = block.get(name)
        if not isinstance(value, str) or not value:
            raise InvalidBundle(
                "field %s.%s must be a non-empty string" % (prefix, name)
            )
        clean[name] = value
    return clean


def validate_version(ver, where: str) -> dict:
    """Validate one versions[i] block; ``where`` names it in error messages."""
    if not isinstance(ver, dict):
        raise InvalidBundle("field %s must be an object" % where)
    number = ver.get("version")
    created_at = ver.get("created_at")
    algorithm = ver.get("algorithm")
    public_key = ver.get("public_key")
    private_material = ver.get("private_material")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise InvalidBundle(
            "field %s.version must be a positive integer" % where
        )
    if not isinstance(created_at, str) or not created_at:
        raise InvalidBundle("field %s.created_at must be a string" % where)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise InvalidBundle(
            "field %s.algorithm must be one of: %s"
            % (where, ", ".join(SUPPORTED_ALGORITHMS))
        )
    if public_key is not None and not isinstance(public_key, str):
        raise InvalidBundle(
            "field %s.public_key must be a string or null" % where
        )
    if not isinstance(private_material, str) or not private_material:
        raise InvalidBundle(
            "field %s.private_material must be a non-empty string" % where
        )
    provider = validate_provider_block(ver.get("provider"), where)
    revocation = validate_version_revocation(ver, where)
    # Fixed key order for one projected/validated version: identity, material,
    # provenance, then revocation facts.
    return {
        "version": number,
        "created_at": created_at,
        "algorithm": algorithm,
        "public_key": public_key,
        "private_material": private_material,
        "provider": provider,
        "status": revocation["status"],
        "reason": revocation["reason"],
        "operator": revocation["operator"],
        "revoked_at": revocation["revoked_at"],
    }


def validate_version_revocation(data: dict, where: str) -> dict:
    """Validate one version's status/reason/operator/revoked_at.

    The four fields follow the version's original keys in an export or
    backup. A bundle emitted before per-version revocation existed carries
    none of them and the version is treated as active (so older bundles keep
    importing). When present, ``status`` must be ``active`` or ``revoked``:
    a revoked version requires all three facts to be non-empty strings, while
    an active version's facts must all be null (or absent). Returns the
    cleaned quartet.
    """
    if "status" not in data:
        # Legacy version block: every revocation field is absent.
        return {
            "status": "active",
            "reason": None,
            "operator": None,
            "revoked_at": None,
        }
    status = data.get("status")
    if status not in ("active", "revoked"):
        raise InvalidBundle(
            "field %s.status must be 'active' or 'revoked'" % where
        )
    reason = data.get("reason")
    operator = data.get("operator")
    revoked_at = data.get("revoked_at")
    if status == "revoked":
        for name, value in (
            ("reason", reason),
            ("operator", operator),
            ("revoked_at", revoked_at),
        ):
            if not isinstance(value, str) or not value:
                raise InvalidBundle(
                    "field %s.%s must be a non-empty string for a revoked "
                    "version" % (where, name)
                )
    else:
        for name, value in (
            ("reason", reason),
            ("operator", operator),
            ("revoked_at", revoked_at),
        ):
            if value is not None:
                raise InvalidBundle(
                    "field %s.%s must be null for an active version"
                    % (where, name)
                )
        reason = operator = revoked_at = None
    return {
        "status": status,
        "reason": reason,
        "operator": operator,
        "revoked_at": revoked_at,
    }


def validate_revocation_fields(data: dict, where: str = "") -> dict:
    """Validate status/reason/operator/revoked_at and return them cleaned."""
    prefix = where + "." if where else ""
    status = _require(data, "status", str)
    if status not in ("active", "revoked"):
        raise InvalidBundle(
            "field %sstatus must be 'active' or 'revoked'" % prefix
        )
    reason = data.get("reason")
    operator = data.get("operator")
    revoked_at = data.get("revoked_at")
    if status == "revoked":
        for name, value in (
            ("reason", reason),
            ("operator", operator),
            ("revoked_at", revoked_at),
        ):
            if not isinstance(value, str) or not value:
                raise InvalidBundle(
                    "field %s%s must be a non-empty string for a revoked key"
                    % (prefix, name)
                )
    elif any(v is not None for v in (reason, operator, revoked_at)):
        raise InvalidBundle(
            "revocation fields must be null for an active key"
        )
    return {
        "status": status,
        "reason": reason,
        "operator": operator,
        "revoked_at": revoked_at,
    }


def validate_payload(data: dict) -> dict:
    """Validate the decrypted export payload and return a cleaned copy.

    Raises InvalidBundle naming the offending field on any structural
    problem or missing field.
    """
    if not isinstance(data, dict):
        raise InvalidBundle("bundle payload must be a JSON object")
    if data.get("format") != FORMAT:
        raise InvalidBundle("field format must be %r" % FORMAT)

    key_id = _require(data, "key_id", str)
    from .store import is_valid_key_id

    if not is_valid_key_id(key_id):
        raise InvalidBundle("field key_id must be a UUID4")
    label = _require(data, "label", str)

    versions = data.get("versions")
    if not isinstance(versions, list) or not versions:
        raise InvalidBundle("field versions must be a non-empty array")

    seen_versions = set()
    clean_versions = []
    for index, ver in enumerate(versions):
        where = "versions[%d]" % index
        clean = validate_version(ver, where)
        if clean["version"] in seen_versions:
            raise InvalidBundle(
                "field %s.version duplicates another version" % where
            )
        seen_versions.add(clean["version"])
        clean_versions.append(clean)

    current_version = data.get("current_version")
    expected_numbers = set(range(1, len(seen_versions) + 1))
    if seen_versions != expected_numbers:
        raise InvalidBundle(
            "field versions must be the contiguous sequence 1..N with no gaps"
        )
    if (
        not isinstance(current_version, int)
        or isinstance(current_version, bool)
        or current_version != len(clean_versions)
    ):
        raise InvalidBundle(
            "field current_version must point at the latest exported version"
        )
    clean_versions.sort(key=lambda v: v["version"])

    revocation = validate_revocation_fields(data)

    return {
        "format": FORMAT,
        "key_id": key_id,
        "label": label,
        "current_version": current_version,
        "reason": revocation["reason"],
        "operator": revocation["operator"],
        "revoked_at": revocation["revoked_at"],
        "status": revocation["status"],
        "versions": clean_versions,
    }


def decode_bundle(bundle: str, passphrase: str) -> dict:
    """Decrypt and validate a bundle.

    Raises WrongPassphrase for authentication failures (wrong passphrase or
    tampered ciphertext) and InvalidBundle for structural, format/version and
    missing-field problems.
    """
    plaintext = open_envelope(bundle, passphrase, FORMAT)
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidBundle("bundle payload is not valid JSON") from exc
    return validate_payload(data)
