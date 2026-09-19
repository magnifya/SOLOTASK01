"""Tenant-level backup assembly and atomic restore.

A backup gathers every key record of one tenant plus its policy document
into a single sealed ``tenant-backup-v1`` bundle. A restore is the inverse:
it recreates all of the bundle's keys and (when present) the policy in one
logical transaction whose single audit event (``import``, ``key_id`` null)
commits through the same outbox pattern as single-key mutations — every
restored file first lands carrying the pending event, the ledger append
follows, then the markers are cleared. A ledger failure rolls back every
file written by the restore; a crash mid-transaction is repaired on the
next open by the stores' pending-event recovery (the append is idempotent
on event_id, so the same event carried by several files commits once).
"""

import os

from . import audit as audit_mod
from . import tenantbundle
from .policy import validate_rules
from .store import KeyRecord, VersionRecord

# Outcomes of a restore attempt.
RESTORED = "restored"
CONFLICT_KEY = "conflict_key"        # a key_id already belongs to this tenant
CONFLICT_POLICY = "conflict_policy"  # the tenant already has a policy document
CONFLICT_FOREIGN = "conflict_foreign"  # a key_id is owned by another tenant


def build_backup(store, policies, tenant_id: str, passphrase: str) -> str:
    """Seal the tenant's full state (keys + policy) into a backup bundle."""
    records = store.list_tenant_records(tenant_id)
    rules = policies.get(tenant_id)
    payload = {
        "format": tenantbundle.FORMAT,
        "tenant_id": tenant_id,
        "keys": [rec.to_backup_entry() for rec in records],
        "policy": (
            None if rules is None
            else {"rules": [r.to_json() for r in rules]}
        ),
    }
    return tenantbundle.encode_backup(payload, passphrase)


def restore_backup(store, policies, tenant_id: str, payload: dict) -> tuple:
    """Atomically restore a validated backup payload for the tenant.

    Returns (status, key_ids, policy_restored). On any conflict nothing is
    written: a key_id the tenant already owns or an existing policy document
    (even when the bundle carries no policy) is a conflict; a key_id owned
    by another tenant is reported separately so the caller can answer 404
    without leaking ownership. On success the key files, the policy document
    and the single import event commit as one transaction; a ledger failure
    removes every file the restore wrote and raises LedgerError.
    """
    keys = payload["keys"]
    policy = payload["policy"]
    key_ids = [entry["key_id"] for entry in keys]
    rules = None
    if policy is not None:
        # The payload was validated on decode; re-validate to obtain Rules.
        rules = validate_rules(policy["rules"])

    with store.restore_lock(key_ids), policies._write_lock:
        for entry in keys:
            existing = store.peek(entry["key_id"])
            if existing is None:
                continue
            if existing.tenant_id == tenant_id:
                return CONFLICT_KEY, key_ids, False
            return CONFLICT_FOREIGN, key_ids, False
        if policies.get(tenant_id) is not None:
            return CONFLICT_POLICY, key_ids, False

        event = store.audit.new_event(
            tenant_id, audit_mod.ACTION_IMPORT, None,
            audit_mod.OUTCOME_SUCCESS,
        )
        records = [
            KeyRecord(
                key_id=entry["key_id"],
                tenant_id=tenant_id,
                label=entry["label"],
                versions=[
                    VersionRecord(
                        version=ver["version"],
                        created_at=ver["created_at"],
                        algorithm=ver["algorithm"],
                        public_key=ver["public_key"],
                        private_material=ver["private_material"],
                    )
                    for ver in entry["versions"]
                ],
                current_version=entry["current_version"],
                status=entry["status"],
                reason=entry["reason"],
                operator=entry["operator"],
                revoked_at=entry["revoked_at"],
            )
            for entry in keys
        ]

        written = []
        try:
            for record in records:
                written.append(store.write_pending_record(record, event))
            if rules is not None:
                written.append(
                    policies.write_pending_doc(tenant_id, rules, event)
                )
            store.audit.append(event)
        except BaseException:
            # Roll back every file this restore wrote; all of them are new.
            for path in written:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            raise

        for record in records:
            store.clear_pending_record(record)
        if rules is not None:
            policies.clear_pending_doc(tenant_id, rules)

    return RESTORED, key_ids, rules is not None
