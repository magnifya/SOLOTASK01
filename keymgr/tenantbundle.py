"""Authenticated passphrase encryption for tenant backup/restore bundles.

A tenant bundle is an opaque, single base64 token using the same scrypt +
AES-256-GCM envelope (and the same fixed cost parameters) as a single-key
export; only the authenticated format tag differs, so a backup and an export
bundle can never be replayed for one another. Its plaintext carries the whole
tenant::

    {format, tenant_id, keys, policy}

``keys`` is a list of per-key projections (``key_id``, ``label``,
``current_version``, ``status``, ``reason``, ``operator``, ``revoked_at`` and
every ``versions`` entry with public and private material); ``policy`` is
either null or ``{"rules": [...]}``. Private key material only ever exists
sealed inside the authenticated bundle.
"""

import json

from . import keybundle
from .keybundle import seal_envelope, open_envelope, validate_version
from .policy import PolicyError, validate_rules
from .store import is_valid_key_id

FORMAT = "tenant-backup-v1"


class TenantBundleError(Exception):
    """Base class for tenant bundle failures (all surfaced as 400)."""


class InvalidTenantBundle(TenantBundleError):
    """Malformed envelope, unsupported format/version, or missing fields."""


class WrongTenantPassphrase(TenantBundleError):
    """Authentication failed: wrong passphrase or tampered ciphertext."""


def _require(data: dict, field: str, types) -> object:
    if field not in data or not isinstance(data[field], types):
        kind = "string" if types is str else "value"
        raise InvalidTenantBundle("field %s must be a %s" % (field, kind))
    return data[field]


def encode_bundle(payload: dict, passphrase: str) -> str:
    """Authenticated-encrypt a tenant backup payload into an opaque token."""
    return seal_envelope(payload, passphrase, FORMAT)


def _validate_key(item, index: int) -> dict:
    """Validate one keys[i] entry of a tenant backup payload."""
    where = "keys[%d]" % index
    if not isinstance(item, dict):
        raise InvalidTenantBundle("field %s must be an object" % where)
    key_id = item.get("key_id")
    if not is_valid_key_id(key_id):
        raise InvalidTenantBundle("field %s.key_id must be a UUID4" % where)
    label = item.get("label")
    if not isinstance(label, str):
        raise InvalidTenantBundle("field %s.label must be a string" % where)

    versions = item.get("versions")
    if not isinstance(versions, list) or not versions:
        raise InvalidTenantBundle(
            "field %s.versions must be a non-empty array" % where
        )
    seen_versions = set()
    clean_versions = []
    for v_index, ver in enumerate(versions):
        v_where = "%s.versions[%d]" % (where, v_index)
        # The per-version checks are shared with the single-key format; their
        # InvalidBundle wording already names the offending field.
        try:
            clean = validate_version(ver, v_where)
        except keybundle.InvalidBundle as exc:
            raise InvalidTenantBundle(str(exc)) from exc
        if clean["version"] in seen_versions:
            raise InvalidTenantBundle(
                "field %s.version duplicates another version" % v_where
            )
        seen_versions.add(clean["version"])
        clean_versions.append(clean)
    expected = set(range(1, len(seen_versions) + 1))
    if seen_versions != expected:
        raise InvalidTenantBundle(
            "field %s.versions must be the contiguous sequence 1..N "
            "with no gaps" % where
        )
    clean_versions.sort(key=lambda v: v["version"])
    current_version = item.get("current_version")
    if (
        not isinstance(current_version, int)
        or isinstance(current_version, bool)
        or current_version != len(clean_versions)
    ):
        raise InvalidTenantBundle(
            "field %s.current_version must point at the latest version"
            % where
        )

    try:
        revocation = keybundle.validate_revocation_fields(item, where)
    except keybundle.InvalidBundle as exc:
        raise InvalidTenantBundle(str(exc)) from exc

    return {
        "key_id": key_id,
        "label": label,
        "current_version": current_version,
        "status": revocation["status"],
        "reason": revocation["reason"],
        "operator": revocation["operator"],
        "revoked_at": revocation["revoked_at"],
        "versions": clean_versions,
    }


def _validate_policy(raw) -> object:
    """Validate the policy slot: None, or an object {"rules": [...]}."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise InvalidTenantBundle("field policy must be an object or null")
    unknown = set(raw) - {"rules"}
    if unknown:
        raise InvalidTenantBundle(
            "unknown field %s in policy" % sorted(unknown)[0]
        )
    if "rules" not in raw:
        raise InvalidTenantBundle("missing required field: policy.rules")
    try:
        rules = validate_rules(raw["rules"])
    except PolicyError as exc:
        raise InvalidTenantBundle(str(exc)) from exc
    return {"rules": [r.to_json() for r in rules]}


def validate_payload(data: dict) -> dict:
    """Validate the decrypted tenant payload and return a cleaned copy.

    Raises InvalidTenantBundle naming the offending field on any structural
    problem or missing field.
    """
    if not isinstance(data, dict):
        raise InvalidTenantBundle("bundle payload must be a JSON object")
    if data.get("format") != FORMAT:
        raise InvalidTenantBundle("field format must be %r" % FORMAT)
    tenant_id = _require(data, "tenant_id", str)
    if not tenant_id:
        raise InvalidTenantBundle("field tenant_id must be a non-empty string")

    keys = data.get("keys")
    if not isinstance(keys, list):
        raise InvalidTenantBundle("field keys must be an array")
    seen_key_ids = set()
    clean_keys = []
    for index, item in enumerate(keys):
        clean = _validate_key(item, index)
        if clean["key_id"] in seen_key_ids:
            raise InvalidTenantBundle(
                "field keys[%d].key_id duplicates another key" % index
            )
        seen_key_ids.add(clean["key_id"])
        clean_keys.append(clean)

    if "policy" not in data:
        raise InvalidTenantBundle("missing required field: policy")
    policy = _validate_policy(data["policy"])

    return {
        "format": FORMAT,
        "tenant_id": tenant_id,
        "keys": clean_keys,
        "policy": policy,
    }


def decode_bundle(bundle: str, passphrase: str) -> dict:
    """Decrypt and validate a tenant backup bundle.

    Raises WrongTenantPassphrase for authentication failures (wrong
    passphrase or tampered ciphertext) and InvalidTenantBundle for
    structural, format/version and missing-field problems.
    """
    try:
        plaintext = open_envelope(bundle, passphrase, FORMAT)
    except keybundle.WrongPassphrase as exc:
        raise WrongTenantPassphrase(str(exc)) from exc
    except keybundle.InvalidBundle as exc:
        raise InvalidTenantBundle(str(exc)) from exc
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidTenantBundle("bundle payload is not valid JSON") from exc
    return validate_payload(data)
