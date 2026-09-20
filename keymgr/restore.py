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
import threading
from contextlib import contextmanager
from typing import Dict, Iterator, List, NamedTuple, Optional

from . import audit as audit_mod
from . import tenantbundle
from .audit import AuditEvent, LedgerError
from .policy import Rule

try:  # fcntl is POSIX-only; restores still work without cross-process locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Restore outcomes.
RESTORE_CREATED = "created"
RESTORE_SAME_TENANT_CONFLICT = "same_tenant_conflict"
RESTORE_FOREIGN_CONFLICT = "foreign_conflict"

# An empty restore writes no key/policy file, so it persists its idempotency
# marker as ``restore-empty-<sha256(tenant_id)>.json`` in the data directory:
# the batch commits at most once and a repeated empty restore of the same
# tenant conflicts instead of logging a second import event.
_EMPTY_MARKER_PREFIX = "restore-empty-"


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
        self.journal: Optional[str] = marker.get("journal")


class RestoreCoordinator:
    """Coordinates reads for backup and the atomic write set for restore."""

    def __init__(self, store, policy_store) -> None:
        self.store = store
        self.policy_store = policy_store
        # Serialize restores within this process; per-key fcntl locks plus the
        # policy write lock still guard individual files.
        self._restore_lock = threading.Lock()
        # Recover any multi-file transaction interrupted by a crash.
        self.recover()

    # -- backup ------------------------------------------------------------
    def backup_payload(self, tenant_id: str) -> dict:
        """Build the decrypted tenant payload {format, tenant_id, keys, policy}.

        The read runs under the tenant's policy lock and every key lock of
        the tenant (all acquired in the same sorted order the restore
        transaction uses), so the bundle is one committed view: a concurrent
        rotate/revoke/policy update in any process is either fully before or
        fully after the snapshot, never mixed into it.
        """
        key_ids = [r.key_id for r in self.store.list_for_tenant(tenant_id)]
        with self.policy_store.tenant_lock(tenant_id), self.store.multi_key_locks(
            key_ids
        ):
            # Re-read under the locks: a record listed above may have been
            # rotated or revoked since the unlocked directory scan.
            records = []
            for key_id in key_ids:
                record = self.store.read_raw(key_id)
                if record is not None and record.tenant_id == tenant_id:
                    records.append(record)
            # Lazily take over any raw pre-provider versions here, under the
            # same key locks, so the backup is one committed view. This only
            # imports/wraps while the local provider is active; with an
            # external provider active a legacy version fails 503 and the
            # backup is refused without a fallback.
            for record in records:
                self.store.prepare_backup_record(record)
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
    @contextmanager
    def _cross_process_restore_lock(self) -> Iterator[None]:
        """Serialize whole restore transactions across processes.

        The in-process ``_restore_lock`` cannot stop a second server or CLI
        process from interleaving its conflict scan with this one's writes;
        an exclusive ``fcntl`` lock on ``restore.lock`` can.
        """
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            yield
            return
        fd = os.open(
            os.path.join(self.store.data_dir, "restore.lock"),
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _empty_marker_path(self, tenant_id: str) -> str:
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return os.path.join(
            self.store.data_dir, _EMPTY_MARKER_PREFIX + digest + ".json"
        )

    def restore(self, tenant_id: str, payload: dict) -> RestoreResult:
        """Atomically restore a validated tenant payload.

        Returns a created result, or a conflict result after leaving every
        existing file byte-for-byte untouched. Raises LedgerError when the
        transaction cannot be committed; all written files and all handles
        minted by the attempt are rolled back.

        Ordering: every version is validated and adopted through its provider
        first (the durable provision journal records each handle as it is
        minted); only then are conflicts rechecked, files written and the
        single audit event appended. A failure, refused conflict or crash at
        any point before that commit point deletes every handle the attempt
        created; the durable event is the point of no return.
        """
        with self._restore_lock, self._cross_process_restore_lock():
            key_ids = sorted(k["key_id"] for k in payload["keys"])
            policy_rules = None
            if payload["policy"] is not None:
                policy_rules = [
                    Rule.from_json(r) for r in payload["policy"]["rules"]
                ]

            # Mint the committing event up front so the provision journal is
            # named after its event_id, letting startup recovery decide
            # committed-vs-not purely from the ledger.
            event = self.store.audit.new_event(
                tenant_id, audit_mod.ACTION_IMPORT, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            journal_id, journal_path = self.store._new_provision_journal(
                event.event_id
            )
            try:
                # Phase 0: complete ALL version validation and provider
                # calls before the conflict recheck or any file write.
                records = []
                try:
                    for key_id in key_ids:
                        entry = next(
                            k for k in payload["keys"] if k["key_id"] == key_id
                        )
                        records.append(
                            self.store.record_from_backup(
                                tenant_id, entry, journal_path
                            )
                        )
                except BaseException:
                    # A later key/version failed: release the handles the
                    # earlier records already minted (record_from_backup
                    # released its own record's handles; do the rest here).
                    for record in records:
                        self.store.release_record_handles(record)
                    raise

                # Conflict scan only after every provider call succeeded.
                # Any foreign owner anywhere wins (404); otherwise a
                # same-tenant owner is a 409. Repeated under every lock.
                conflict = self._scan_conflicts(tenant_id, key_ids)
                if conflict is not None:
                    # Nothing was written; release every minted handle.
                    for record in records:
                        self.store.release_record_handles(record)
                    status = (
                        RESTORE_FOREIGN_CONFLICT
                        if conflict.owner != tenant_id
                        else RESTORE_SAME_TENANT_CONFLICT
                    )
                    return RestoreResult(status=status, conflict=conflict)

                writes_policy = policy_rules is not None

                if not key_ids and not writes_policy:
                    # Empty bundle: no key/policy files or handles, but the
                    # batch still commits a persistent idempotency marker plus
                    # its single import event.
                    with self.policy_store.tenant_lock(tenant_id):
                        policy_path = self.policy_store.path_for(tenant_id)
                        if os.path.exists(policy_path):
                            owner = self.policy_store.owner_of_path(policy_path)
                            if owner is not None and owner != tenant_id:
                                return RestoreResult(
                                    status=RESTORE_FOREIGN_CONFLICT,
                                    conflict=Conflict(kind="policy", owner=owner),
                                )
                            return RestoreResult(
                                status=RESTORE_SAME_TENANT_CONFLICT,
                                conflict=Conflict(kind="policy", owner=tenant_id),
                            )
                        return self._commit_empty(tenant_id, event)

                marker = {
                    "_restore": True,
                    "event": event.to_json(),
                    "tenant_id": tenant_id,
                    "key_ids": key_ids,
                    "policy": writes_policy,
                    # Ties the marker group to the attempt's handle journal.
                    "journal": journal_id,
                }

                return self._commit(
                    tenant_id, key_ids, records, policy_rules, event, marker
                )
            finally:
                # On a normal return (success, refused conflict or a handled
                # rollback) the handles were either committed to the records
                # or released; the journal is spent. A hard crash leaves it on
                # disk for startup recovery, which is the actual safety net.
                self.store.drop_provision_journal(journal_id)

    def _commit_empty(self, tenant_id: str, event: AuditEvent) -> RestoreResult:
        """Commit an empty restore: idempotency marker + one import event.

        The marker file first lands carrying the pending event, the event is
        appended, then the marker is finalized with the event cleared. A
        ledger failure removes the marker (nothing commits); a crash is
        repaired by recovery exactly like a multi-file restore group.
        """
        path = self._empty_marker_path(tenant_id)
        if os.path.exists(path):
            # This tenant already committed an empty restore batch.
            return RestoreResult(
                status=RESTORE_SAME_TENANT_CONFLICT,
                conflict=Conflict(kind="batch", owner=tenant_id),
            )
        marker = {
            "_restore": True,
            "_empty": True,
            "event": event.to_json(),
            "tenant_id": tenant_id,
            "key_ids": [],
            "policy": False,
        }
        self.store._write_atomic(path, marker)
        try:
            self.store.audit.append(event)
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        finalized = dict(marker)
        finalized["event"] = None
        self.store._write_atomic(path, finalized)
        return RestoreResult(
            status=RESTORE_CREATED,
            tenant_id=tenant_id,
            key_ids=[],
            policy_restored=False,
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
        policy_cm = self.policy_store.tenant_lock(tenant_id)
        policy_taken = False
        try:
            policy_cm.__enter__()
            policy_taken = True
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
                # The provider objects were minted before the locks, but no
                # file now commits: release the handles so the backend leaks
                # nothing on the lost conflict race.
                for record in records:
                    self.store.release_record_handles(record)
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
                # The durable append is the commit point.
                self.store.audit.append(event)
            except BaseException as exc:
                # Roll back every file the transaction created AND every
                # handle the attempt minted — including records whose file
                # never landed after a phase-1 failure partway through the
                # write set.
                self._rollback(
                    written_keys, wrote_policy, tenant_id, records
                )
                if isinstance(exc, LedgerError):
                    raise
                raise LedgerError(
                    "tenant restore failed before commit: %s" % exc
                ) from exc

            # Phase 3: clear the markers. The commit point already passed, so
            # this is best-effort housekeeping: a failure here or a crash is
            # repaired idempotently on the next open (event is durably in the
            # ledger, the restored data and its handles stay authoritative).
            for record in records:
                try:
                    self.store.clear_restore_pending(record)
                except OSError:
                    pass
            if policy_rules is not None:
                try:
                    self.policy_store.clear_restore_pending(
                        tenant_id, policy_rules
                    )
                except OSError:
                    pass
            return RestoreResult(
                status=RESTORE_CREATED,
                tenant_id=tenant_id,
                key_ids=key_ids,
                policy_restored=policy_rules is not None,
            )
        finally:
            for lock_cm in reversed(locked):
                lock_cm.__exit__(None, None, None)
            if policy_taken:
                policy_cm.__exit__(None, None, None)

    def _rollback(
        self,
        written_keys: List[str],
        wrote_policy: bool,
        tenant_id: str,
        records: Optional[list] = None,
    ) -> None:
        """Remove every file created by a restore that did not commit.

        The provider handles the would-be records minted are deleted too —
        for *every* record the attempt adopted, including ones whose file
        never landed when phase 1 failed partway through the write set — so a
        failure that aborts the batch leaves no orphaned KMS/HSM objects
        behind.
        """
        by_id = {r.key_id: r for r in (records or [])}
        landed = set(written_keys)
        for key_id in written_keys:
            self.store.remove_file(key_id)
        for key_id, record in by_id.items():
            # Covers both landed (file now removed) and never-landed records.
            self.store.release_record_handles(record)
        if wrote_policy:
            self.policy_store.remove_restore_file(tenant_id)

    # -- crash recovery ----------------------------------------------------
    def recover(self) -> None:
        """Finish or roll back restores interrupted by a crash.

        Files still carrying the shared marker are grouped by the embedded
        event id. When the event reached the ledger the transaction commits
        (markers are cleared); otherwise it never committed and every file of
        the group is removed. Both paths are idempotent.
        """
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
            if name.startswith(_EMPTY_MARKER_PREFIX) and name.endswith(".json"):
                self._recover_empty_marker(os.path.join(data_dir, name))
                continue
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
            if not self._recover_group(eid, group):
                # The ledger could not be read; leave files and journal for a
                # later open to retry rather than risking committed material.
                continue
            # The group is resolved (committed or rolled back); its handle
            # journal, deferred from the store's own startup sweep, is now
            # spent. On the uncommitted path _recover_group already deleted
            # every handle the journal recorded.
            self.store.drop_provision_journal(group.journal)

        # Journals with no marker group (crash before the first file landed)
        # are swept last; their event never committed.
        self._resolve_orphan_journals()

    def _resolve_orphan_journals(self) -> None:
        """Reap provision journals left by restore attempts with no marker.

        A crash after provider adoption but before the first file landed
        leaves a journal but no marker group; the event never committed, so
        every recorded handle is deleted. Marker-referenced journals are
        handled with their group in :meth:`recover`.
        """
        directory = os.path.join(self.store.data_dir, "provisions")
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            journal_id = name[:-5]
            try:
                committed = self.store.audit.get_event(journal_id) is not None
            except LedgerError:
                continue
            if not committed:
                self.store.release_journal_handles(journal_id)
            self.store.drop_provision_journal(journal_id)

    def _recover_empty_marker(self, path: str) -> None:
        """Resolve an empty-restore idempotency marker after a crash.

        A finalized marker (``event`` is null) is the persistent record that
        the batch committed; it stays. A marker still carrying its pending
        event is finished when the event reached the ledger, and removed
        otherwise — both idempotently, mirroring multi-file recovery.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                marker = json.load(fh)
        except (OSError, ValueError):
            return
        if not isinstance(marker, dict) or not marker.get("_restore"):
            return
        event = marker.get("event")
        if not event:
            return  # finalized marker: the committed batch's idempotency record
        try:
            committed = self.store.audit.get_event(event["event_id"]) is not None
        except (LedgerError, KeyError, TypeError):
            return  # leave it for a later open to retry
        if committed:
            finalized = dict(marker)
            finalized["event"] = None
            self.store._write_atomic(path, finalized)
        else:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _recover_group(self, eid: str, group: _PendingGroup) -> bool:
        """Resolve one marker group. True if resolved, False to retry later."""
        marker = group.marker
        tenant_id = marker["tenant_id"]
        try:
            committed = self.store.audit.get_event(eid) is not None
        except LedgerError:
            # Leave the group untouched; a later open retries recovery.
            return False
        if not committed:
            # The ledger append never happened: remove every partial file and
            # release every provider handle the batch minted (the journal
            # also covers records whose file never landed), so a crash before
            # commit leaves no orphaned KMS/HSM objects.
            if group.journal:
                self.store.release_journal_handles(group.journal)
            for key_id, path in list(group.key_files.items()):
                record = self.store._read_record(path)
                if record is not None and not group.journal:
                    # No journal available: fall back to the handles carried
                    # by the landed files themselves.
                    self.store.release_record_handles(record)
                self.store.remove_file(key_id)
            if group.policy_file is not None:
                self.policy_store.remove_restore_file(tenant_id)
            return True
        # Committed: finish the transaction by clearing the markers. This is
        # post-commit housekeeping and best-effort; a rewrite failure leaves
        # the marker for the next open and never rolls the data back.
        for key_id, path in group.key_files.items():
            record = self.store._read_record(path)
            if record is None or not record.pending_event:
                continue
            try:
                self.store.clear_restore_pending(record)
            except OSError:
                pass
        if group.policy_file is not None:
            try:
                self.policy_store.clear_restore_pending(
                    group.policy_tenant or tenant_id, group.policy_rules
                )
            except OSError:
                pass
        return True


def _is_uuid(value: str) -> bool:
    from .store import is_valid_key_id

    return is_valid_key_id(value)
