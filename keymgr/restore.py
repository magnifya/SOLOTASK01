"""Atomic tenant restore: multi-file outbox transaction over keys and policy.

A restore writes several key files and optionally one policy document as a
single logical transaction. Every file first lands carrying the same pending
marker (the shared audit event plus a manifest of the whole write set); the
single audit event is appended to the ledger once; only then are the markers
cleared. A failure or crash at any point is repaired idempotently on the next
open, mirroring the per-key outbox in :mod:`keymgr.store` and the policy
outbox in :mod:`keymgr.policy`.

Conflict rules, applied before anything touches disk:

* a ``key_id`` that already exists for the requesting tenant is a ``409``
  (nothing is changed);
* a ``key_id`` owned by another tenant answers ``404`` so existence never
  leaks across tenants;
* a policy document already present for the tenant conflicts regardless of
  whether the bundle carries rules or an explicit null (an existing policy is
  never overwritten or deleted); a document on the tenant's hashed path that
  names another owner is treated as a foreign ``404``.

An empty bundle (``keys == []`` and ``policy is null``) creates no files but
still commits the single ``import`` event and reports success.
"""

import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from typing import Dict, Iterator, List, NamedTuple, Optional

from . import audit as audit_mod
from . import tenantbundle
from .audit import AuditEvent, LedgerError
from .policy import Rule

try:  # fcntl is POSIX-only.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Restore outcomes.
RESTORE_CREATED = "created"
RESTORE_SAME_TENANT_CONFLICT = "same_tenant_conflict"
RESTORE_FOREIGN_CONFLICT = "foreign_conflict"


class Conflict(NamedTuple):
    """Why a restore was refused before writing anything."""

    kind: str  # "key" or "policy"
    owner: Optional[str]  # tenant that currently owns the object
    key_id: Optional[str] = None  # set for kind == "key"


class RestoreResult(NamedTuple):
    """Outcome of a restore attempt."""

    status: str
    tenant_id: Optional[str] = None
    key_ids: Optional[List[str]] = None
    policy_restored: Optional[bool] = None
    conflict: Optional[Conflict] = None


class _PendingGroup:
    """Files sharing one restore marker discovered during recovery."""

    def __init__(self, marker: dict) -> None:
        self.marker = marker
        self.key_files: Dict[str, str] = {}  # key_id -> path
        self.policy_file: Optional[str] = None
        self.policy_tenant: Optional[str] = None
        self.policy_rules: List[Rule] = []


class RestoreCoordinator:
    """Coordinates reads for backup and the atomic write set for restore."""

    def __init__(self, store, policy_store) -> None:
        self.store = store
        self.policy_store = policy_store
        # Serialize restores within this process; the cross-process lock file
        # plus per-key fcntl locks and the policy tenant lock still guard
        # individual files.
        self._restore_lock = threading.Lock()
        self._restore_dir = os.path.join(store.data_dir, "restores")
        os.makedirs(self._restore_dir, exist_ok=True)
        self._restore_lock_path = os.path.join(self._restore_dir, "restore.lock")
        # Recover any multi-file transaction interrupted by a crash.
        self.recover()

    @contextmanager
    def _cross_process_restore_lock(self) -> Iterator[None]:
        """Exclusive fcntl lock serializing restores across processes."""
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            yield
            return
        fd = os.open(self._restore_lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # -- backup ------------------------------------------------------------
    def backup_payload(self, tenant_id: str) -> dict:
        """Build the decrypted tenant payload {format, tenant_id, keys, policy}.

        Every key lock and the tenant's policy lock are held while reading,
        so the payload is one committed view: concurrent rotations, revokes,
        imports and policy updates either complete before the snapshot or
        wait for it, never mixing versions, current pointers, revocation
        fields and policy from different commits.
        """
        key_ids = self.store.list_key_ids()
        with self.policy_store.tenant_lock(tenant_id), \
                self.store.all_key_locks(key_ids):
            records = [
                self.store.read_raw(key_id) for key_id in key_ids
            ]
            records = [
                r for r in records
                if r is not None and r.tenant_id == tenant_id
            ]
            rules = self.policy_store.get(tenant_id)
            return {
                "format": tenantbundle.FORMAT,
                "tenant_id": tenant_id,
                "keys": [self.store.backup_entry(r) for r in records],
                "policy": None
                if rules is None
                else {"rules": [r.to_json() for r in rules]},
            }

    def backup_bundle(self, tenant_id: str, passphrase: str) -> str:
        """Seal the tenant's full state into an opaque backup bundle."""
        return tenantbundle.encode_bundle(
            self.backup_payload(tenant_id), passphrase
        )

    # -- restore -----------------------------------------------------------
    @staticmethod
    def _batch_id(payload: dict) -> str:
        """Deterministic id for one restore batch (its validated payload)."""
        canonical = json.dumps(
            payload, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _batch_marker_path(self, batch_id: str) -> str:
        return os.path.join(self._restore_dir, batch_id + ".json")

    def _write_batch_marker(self, batch_id: str, marker: dict) -> None:
        """Atomically persist a restore batch idempotency marker."""
        fd, tmp_path = tempfile.mkstemp(dir=self._restore_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(marker, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self._batch_marker_path(batch_id))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def restore(self, tenant_id: str, payload: dict) -> RestoreResult:
        """Atomically restore a validated tenant payload.

        Returns a created result, or a conflict result after leaving every
        existing file byte-for-byte untouched. Raises LedgerError when the
        transaction cannot be committed; all written files are rolled back.
        The whole operation runs under a cross-process lock so two processes
        restoring the same batch serialize: the loser of the race observes
        the winner's committed files (or its batch marker) and conflicts.
        """
        with self._restore_lock, self._cross_process_restore_lock():
            key_ids = sorted(k["key_id"] for k in payload["keys"])
            policy_rules = None
            if payload["policy"] is not None:
                policy_rules = [
                    Rule.from_json(r) for r in payload["policy"]["rules"]
                ]

            # Conflict scan. Any foreign owner anywhere wins (404); otherwise
            # a same-tenant owner is a 409. Repeated under every lock below.
            conflict = self._scan_conflicts(tenant_id, key_ids)
            if conflict is not None:
                status = (
                    RESTORE_FOREIGN_CONFLICT
                    if conflict.owner != tenant_id
                    else RESTORE_SAME_TENANT_CONFLICT
                )
                return RestoreResult(status=status, conflict=conflict)

            event = self.store.audit.new_event(
                tenant_id, audit_mod.ACTION_IMPORT, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            writes_policy = policy_rules is not None

            if not key_ids and not writes_policy:
                # Empty bundle: no key or policy files, so a persisted batch
                # marker is the idempotency record. Its presence means this
                # batch already committed; a repeated restore of the same
                # batch conflicts instead of committing (and logging) twice.
                batch_id = self._batch_id(payload)
                if os.path.exists(self._batch_marker_path(batch_id)):
                    return RestoreResult(
                        status=RESTORE_SAME_TENANT_CONFLICT,
                        conflict=Conflict(
                            kind="batch", owner=tenant_id, key_id=None
                        ),
                    )
                marker = {
                    "_restore": True,
                    "batch": True,
                    "tenant_id": tenant_id,
                    "event": event.to_json(),
                }
                self._write_batch_marker(batch_id, marker)
                try:
                    self.store.audit.append(event)
                except BaseException:
                    try:
                        os.unlink(self._batch_marker_path(batch_id))
                    except OSError:
                        pass
                    raise
                return RestoreResult(
                    status=RESTORE_CREATED,
                    tenant_id=tenant_id,
                    key_ids=[],
                    policy_restored=False,
                )

            marker = {
                "_restore": True,
                "event": event.to_json(),
                "tenant_id": tenant_id,
                "key_ids": key_ids,
                "policy": writes_policy,
            }

            records = [
                self.store.record_from_backup(
                    tenant_id,
                    next(k for k in payload["keys"] if k["key_id"] == key_id),
                )
                for key_id in key_ids
            ]

            return self._commit(
                tenant_id, key_ids, records, policy_rules, event, marker
            )

    def _scan_conflicts(
        self, tenant_id: str, key_ids: List[str]
    ) -> Optional[Conflict]:
        """Return the first conflict (foreign owners take priority).

        A policy document already present for the tenant conflicts even when
        the bundle's policy slot is null: a restore never overwrites or
        deletes an existing policy.
        """
        same_tenant: Optional[Conflict] = None
        for key_id in key_ids:
            existing = self.store.read_raw(key_id)
            if existing is None:
                continue
            if existing.tenant_id != tenant_id:
                # A foreign key answers 404 immediately and suppresses any
                # same-tenant 409, so cross-tenant existence never leaks.
                return Conflict(
                    kind="key", owner=existing.tenant_id, key_id=key_id
                )
            if same_tenant is None:
                same_tenant = Conflict(
                    kind="key", owner=tenant_id, key_id=key_id
                )
        path = self.policy_store.path_for(tenant_id)
        if os.path.exists(path):
            owner = self.policy_store.owner_of_path(path)
            if owner is not None and owner != tenant_id:
                # The tenant's hashed path holds a document naming another
                # tenant; treat it like a foreign occupation.
                return Conflict(kind="policy", owner=owner)
            if same_tenant is None:
                same_tenant = Conflict(kind="policy", owner=tenant_id)
        return same_tenant

    def _commit(
        self,
        tenant_id: str,
        key_ids: List[str],
        records: list,
        policy_rules: Optional[List[Rule]],
        event: AuditEvent,
        marker: dict,
    ) -> RestoreResult:
        """Run the multi-file outbox transaction under all required locks."""
        locked = []
        try:
            policy_cm = self.policy_store.tenant_lock(tenant_id)
            policy_cm.__enter__()
            locked.append(policy_cm)
            for key_id in key_ids:
                lock_cm = self.store.key_locks(key_id)
                lock_cm.__enter__()
                locked.append(lock_cm)

            # Re-scan now that every file lock is held.
            conflict = self._scan_conflicts(tenant_id, key_ids)
            if conflict is not None:
                status = (
                    RESTORE_FOREIGN_CONFLICT
                    if conflict.owner != tenant_id
                    else RESTORE_SAME_TENANT_CONFLICT
                )
                return RestoreResult(status=status, conflict=conflict)

            written_keys: List[str] = []
            wrote_policy = False
            try:
                # Phase 1: every file lands carrying the shared marker.
                for record in records:
                    self.store.write_restore_pending(record, marker)
                    written_keys.append(record.key_id)
                if policy_rules is not None:
                    self.policy_store.write_restore_pending(
                        tenant_id, policy_rules, marker
                    )
                    wrote_policy = True
                # Phase 2: the single ledger append. The files are the outbox.
                self.store.audit.append(event)
            except BaseException as exc:
                self._rollback(written_keys, wrote_policy, tenant_id)
                if isinstance(exc, LedgerError):
                    raise
                raise LedgerError(
                    "tenant restore failed before commit: %s" % exc
                ) from exc

            # Phase 3: clear the markers. A crash here is repaired on the next
            # open (the event is already durably in the ledger).
            for record in records:
                self.store.clear_restore_pending(record)
            if policy_rules is not None:
                self.policy_store.clear_restore_pending(
                    tenant_id, policy_rules
                )
            return RestoreResult(
                status=RESTORE_CREATED,
                tenant_id=tenant_id,
                key_ids=key_ids,
                policy_restored=policy_rules is not None,
            )
        finally:
            for lock_cm in reversed(locked):
                lock_cm.__exit__(None, None, None)

    def _rollback(
        self, written_keys: List[str], wrote_policy: bool, tenant_id: str
    ) -> None:
        """Remove every file created by a restore that did not commit."""
        for key_id in written_keys:
            self.store.remove_file(key_id)
        if wrote_policy:
            self.policy_store.remove_restore_file(tenant_id)

    # -- crash recovery ----------------------------------------------------
    def recover(self) -> None:
        """Finish or roll back restores interrupted by a crash.

        Files still carrying the shared marker are grouped by the embedded
        event id. When the event reached the ledger the transaction commits
        (markers are cleared); otherwise it never committed and every file of
        the group is removed. Both paths are idempotent. Empty-batch markers
        in the restores directory are permanent idempotency records; recovery
        only makes sure their event reached the ledger. The scan runs under
        the cross-process restore lock so it cannot interleave with a live
        restore in another process.
        """
        with self._restore_lock, self._cross_process_restore_lock():
            self._recover_batch_markers()
            self._recover_file_groups()

    def _recover_batch_markers(self) -> None:
        """Ensure every persisted empty-batch marker's event is in the ledger."""
        try:
            names = os.listdir(self._restore_dir)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(self._restore_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    marker = json.load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(marker, dict) or not marker.get("_restore"):
                continue
            event_data = marker.get("event")
            if not isinstance(event_data, dict):
                continue
            try:
                # Idempotent on event_id: safe whether the crash happened
                # before or after the original ledger append.
                self.store.audit.append(AuditEvent.from_json(event_data))
            except LedgerError:
                # Leave the marker; a later open retries the append.
                continue

    def _recover_file_groups(self) -> None:
        """Finish or roll back multi-file restore groups."""
        groups: Dict[str, _PendingGroup] = {}

        def group_for(marker: dict) -> _PendingGroup:
            eid = marker["event"]["event_id"]
            group = groups.get(eid)
            if group is None:
                group = _PendingGroup(marker)
                groups[eid] = group
            return group

        data_dir = self.store.data_dir
        try:
            names = os.listdir(data_dir)
        except OSError:
            names = []
        for name in names:
            if not (name.endswith(".json") and _is_uuid(name[:-5])):
                continue
            path = os.path.join(data_dir, name)
            record = self.store._read_record(path)
            marker = getattr(record, "pending_event", None)
            if not isinstance(marker, dict) or not marker.get("_restore"):
                continue
            group_for(marker).key_files[record.key_id] = path

        policy_dir = self.policy_store.dir_path
        try:
            policy_names = os.listdir(policy_dir)
        except OSError:
            policy_names = []
        for name in policy_names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(policy_dir, name)
            doc = self.policy_store._read_doc(path)
            if doc is None:
                continue
            owner, rules, pending = doc
            if not isinstance(pending, dict) or not pending.get("_restore"):
                continue
            group = group_for(pending)
            group.policy_file = path
            group.policy_tenant = owner
            group.policy_rules = rules

        for eid, group in groups.items():
            self._recover_group(eid, group)

    def _recover_group(self, eid: str, group: _PendingGroup) -> None:
        marker = group.marker
        tenant_id = marker["tenant_id"]
        try:
            committed = self.store.audit.get_event(eid) is not None
        except LedgerError:
            # Leave the group untouched; a later open retries recovery.
            return
        if not committed:
            # The ledger append never happened: remove every partial file.
            for key_id in list(group.key_files):
                self.store.remove_file(key_id)
            if group.policy_file is not None:
                self.policy_store.remove_restore_file(tenant_id)
            return
        # Committed: finish the transaction by clearing the markers.
        for key_id, path in group.key_files.items():
            record = self.store._read_record(path)
            if record is None or not record.pending_event:
                continue
            self.store.clear_restore_pending(record)
        if group.policy_file is not None:
            self.policy_store.clear_restore_pending(
                group.policy_tenant or tenant_id, group.policy_rules
            )


def _is_uuid(value: str) -> bool:
    from .store import is_valid_key_id

    return is_valid_key_id(value)
