"""Tenant-level encrypted backup bundles (format ``tenant-backup-v1``).

A backup bundle seals every key of one tenant (full records, including
private material) plus the tenant's policy document into a single opaque
base64 token. The cryptography is the same envelope as single-key exports
(scrypt -> AES-256-GCM, format string as authenticated data); only the
payload shape differs:

    {"format": "tenant-backup-v1", "tenant_id": ...,
     "keys": [{key_id, label, current_version, status, reason, operator,
               revoked_at, versions: [...]}, ...],
     "policy": null | {"rules": [{subject, actions, effect}, ...]}}

Private material only ever exists inside the sealed bundle; it never
appears in an HTTP response or audit projection.
"""

from . import keybundle
from .keybundle import InvalidBundle, WrongPassphrase  # re-exported
from .policy import PolicyError, validate_rules

FORMAT = "tenant-backup-v1"


def encode_backup(payload: dict, passphrase: str) -> str:
    """Seal a tenant backup payload into an opaque base64 token."""
    return keybundle.seal(payload, passphrase, FORMAT)


def validate_backup(data: dict) -> dict:
    """Validate a decrypted backup payload and return a cleaned copy.

    Raises InvalidBundle naming the offending field on any structural
    problem or missing field.
    """
    if not isinstance(data, dict):
        raise InvalidBundle("bundle payload must be a JSON object")
    if data.get("format") != FORMAT:
        raise InvalidBundle("field format must be %r" % FORMAT)
    tenant_id = data.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise InvalidBundle("field tenant_id must be a non-empty string")

    keys = data.get("keys")
    if not isinstance(keys, list):
        raise InvalidBundle("field keys must be an array")
    seen_key_ids = set()
    clean_keys = []
    for index, entry in enumerate(keys):
        try:
            clean = keybundle.validate_key_entry(entry)
        except InvalidBundle as exc:
            raise InvalidBundle("field keys[%d]: %s" % (index, exc)) from exc
        if clean["key_id"] in seen_key_ids:
            raise InvalidBundle(
                "field keys[%d].key_id duplicates another entry" % index
            )
        seen_key_ids.add(clean["key_id"])
        clean_keys.append(clean)

    policy = data.get("policy")
    if policy is not None:
        if not isinstance(policy, dict):
            raise InvalidBundle("field policy must be an object or null")
        if set(policy) - {"rules"}:
            raise InvalidBundle(
                "unknown field policy.%s" % sorted(set(policy) - {"rules"})[0]
            )
        try:
            rules = validate_rules(policy.get("rules"))
        except PolicyError as exc:
            raise InvalidBundle("field policy.%s" % exc) from exc
        policy = {"rules": [r.to_json() for r in rules]}

    return {
        "format": FORMAT,
        "tenant_id": tenant_id,
        "keys": clean_keys,
        "policy": policy,
    }


def decode_backup(bundle: str, passphrase: str) -> dict:
    """Decrypt and validate a tenant backup bundle.

    Raises WrongPassphrase for authentication failures (wrong passphrase or
    tampered ciphertext) and InvalidBundle for structural, format/version
    and missing-field problems.
    """
    return validate_backup(keybundle.unseal(bundle, passphrase, FORMAT))
