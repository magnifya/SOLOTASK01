"""Atomic batch rotation of several keys as one idempotent operation.

A batch-rotate request lists 1-100 ``{key_id, algorithm}`` items with distinct
key_ids; each key is rotated exactly as a single-key rotate, but the whole
batch is one logical transaction:

* the in-process and cross-process locks of every distinct key are acquired
  in key_id order first (the same locks single rotate/import and restore use),
  so a 5-second lock-wait timeout surfaces before any provider call, journal
  or file exists and the batch answers timed_out with zero side effects;
* every new version's handle is durably recorded in one provision journal
  named after the committing event as it is minted;
* every participating key file first lands carrying the same pending marker
  (the shared ``batch_rotate`` event plus the per-key new-version manifest);
* exactly one ``batch_rotate`` audit event (key_id null), named after the
  idempotent operation_id, is appended -- that append is the commit point;
* only then are the markers cleared (best-effort housekeeping).

An unknown key or a key owned by another tenant is a refusal after every lock
is held: nothing is written and every handle the batch minted is deleted. A
failure or crash before the commit point rolls every participating file back
to its prior version bytes and deletes every minted handle; the write set is
retained (and retried on the next open) whenever a provider is unreachable or
a handle delete cannot be verified.
"""

import os
from typing import Dict, List, Optional

from . import audit as audit_mod
from .audit import AuditEvent, LedgerError
from .provider import ProviderUnavailable
from .store import KeyRecord, KeyStore, VersionRecord

# Batch size limits.
BATCH_ITEMS_MIN = 1
BATCH_ITEMS_MAX = 100

# Marker flag stored on each participating key file's pending_event while the
# multi-file outbox transaction is in flight.
BATCH_MARKER_FLAG = "_batch_rotate"

# Refusal statuses reported back to the endpoint layer.
BATCH_CREATED = "created"
BATCH_NOT_FOUND = "not_found"


class BatchItemError(ValueError):
    """An item (or the items array) failed request validation (400)."""


class BatchRotateItem:
    """One validated request item, in request order."""

    __slots__ = ("key_id", "algorithm")

    def __init__(self, key_id: str, algorithm: str) -> None:
        self.key_id = key_id
        self.algorithm = algorithm


class BatchRotateResult:
    """Outcome of a batch rotate attempt.

    On success ``items`` holds one projection per request item (request
    order). A refusal carries a machine status and the offending key_id.
    """

    __slots__ = ("status", "items", "key_id")

    def __init__(
        self,
        status: str,
        items: Optional[List[dict]] = None,
        key_id: Optional[str] = None,
    ) -> None:
        self.status = status
        self.items = items
        self.key_id = key_id


class _PendingGroup:
    """Key files sharing one batch marker discovered during recovery."""

    def __init__(self, marker: dict) -> None:
        self.marker = marker
        # key_id -> on-disk path carrying the marker.
        self.key_files: Dict[str, str] = {}
        self.journal: Optional[str] = marker.get("journal")


class BatchRotateCoordinator:
    """Runs and recovers atomic multi-key rotation transactions."""

    def __init__(self, store: KeyStore) -> None:
        self.store = store
        # Recover transactions interrupted by a crash.
        self.recover()

    # -- request path ------------------------------------------------------
    def rotate(
        self,
        tenant_id: str,
        items: List[BatchRotateItem],
        event_id: Optional[str] = None,
        lock_timeout: Optional[float] = None,
        pre_commit=None,
    ) -> BatchRotateResult:
        """Rotate every item's key as one atomic transaction.

        Returns a created result (items in request order), or a not-found
        refusal after leaving every existing file byte-for-byte untouched.
        Raises ProviderUnavailable on a KMS/HSM fault, LockTimeout when the
        lock-wait budget elapses and LedgerError/OSError when the transaction
        cannot commit (files rolled back, minted handles deleted).
        """
        ordered = sorted({item.key_id for item in items})
        # One timestamp for the shared event and every new version, so the
        # committing event and the version set describe one instant.
        from datetime import datetime, timezone

        created_at = datetime.now(timezone.utc).isoformat()

        # Every lock is acquired (in key_id order) BEFORE the event, journal
        # or any provider handle exists: a timed-out wait is zero side effect.
        with self.store.multi_key_locks(ordered, timeout=lock_timeout):
            event = self.store.audit.new_event(
                tenant_id, audit_mod.ACTION_BATCH_ROTATE, None,
                audit_mod.OUTCOME_SUCCESS, timestamp=created_at,
                event_id=event_id,
            )
            journal_id, journal_path = self.store._new_provision_journal(
                event.event_id
            )
            committed = False
            # The record and new version of each key, keyed by key_id.
            records: Dict[str, KeyRecord] = {}
            manifest: List[dict] = []
            try:
                # Provider calls happen one item at a time (request order);
                # each minted handle is journaled durably before the next
                # call. Nothing is written to a key file in this phase.
                for item in items:
                    path = self.store._path_for(item.key_id)
                    record = self.store._read_record(path)
                    if record is None or record.tenant_id != tenant_id:
                        # Unknown or foreign key: identical refusal, no
                        # existence leak, no file touched. The outer finally
                        # deletes every handle minted by earlier items.
                        return BatchRotateResult(
                            BATCH_NOT_FOUND, key_id=item.key_id
                        )
                    provider = self.store._provider_for(
                        record.current.provider_id
                    )
                    next_number = record.current_version + 1
                    triple = provider.rotate(item.algorithm)
                    self.store._append_provision(
                        journal_path,
                        provider.provider_id,
                        triple.handle,
                    )
                    record.append_version(
                        VersionRecord(
                            version=next_number,
                            created_at=created_at,
                            algorithm=item.algorithm,
                            public_key=triple.public_key,
                            provider_id=provider.provider_id,
                            handle=triple.handle,
                            encrypted_material=triple.encrypted_material,
                        )
                    )
                    records[item.key_id] = record
                    manifest.append(
                        {"key_id": item.key_id, "version": next_number}
                    )

                marker = {
                    BATCH_MARKER_FLAG: True,
                    "event": event.to_json(),
                    "tenant_id": tenant_id,
                    "items": manifest,
                    "journal": journal_id,
                }
                result_items = self._commit_locked(
                    ordered, records, marker, event, pre_commit=pre_commit
                )
                committed = True
                return BatchRotateResult(BATCH_CREATED, items=result_items)
            finally:
                if committed:
                    # Handles are owned by the durable versions; drop the
                    # attempt's journal.
                    self.store.drop_provision_journal(journal_id)
                else:
                    # Refusal, provider fault or failed commit: the success
                    # event never landed. Strictly delete every handle the
                    # durable journal records (it also covers handles minted
                    # by items after this frame lost scope). A provider that
                    # cannot be reached or a delete that cannot be verified
                    # retains the journal for the next startup retry and
                    # surfaces as a provider fault instead of orphaning a
                    # backend object.
                    entries = self.store.read_provision_journal(journal_id)
                    if not self.store.strict_delete_handles(entries):
                        raise ProviderUnavailable(
                            "could not delete handles provisioned by an "
                            "aborted batch rotation; cleanup will be retried "
                            "at startup"
                        )
                    self.store.drop_provision_journal(journal_id)

    def _commit_locked(
        self,
        ordered: List[str],
        records: Dict[str, KeyRecord],
        marker: dict,
        event: AuditEvent,
        pre_commit=None,
    ) -> List[dict]:
        """Run the multi-file outbox transaction; caller holds every lock.

        Every file lands carrying the shared marker, the exact idempotent
        result is staged (``pre_commit``), then the single event is appended.
        Any failure rolls every landed file back to its prior bytes (and the
        caller's finally deletes the minted handles); returns the response
        items in the request order carried by ``records``' caller.
        """
        previous: Dict[str, dict] = {}
        written: List[str] = []
        try:
            for key_id in ordered:
                record = records[key_id]
                path = self.store._path_for(key_id)
                previous[key_id] = self.store._read_record(path).to_json()
                record.pending_event = marker
                self.store._write_atomic(path, record.to_json())
                written.append(key_id)
            # records was populated by iterating the request items, so its key
            # order is the request order even though files landed in lock order.
            result_items = [
                self._projection(key_id, records[key_id])
                for key_id in records
            ]
            if pre_commit is not None:
                pre_commit(result_items)
            # The single durable append is the batch's commit point.
            self.store.audit.append(event)
        except BaseException:
            for key_id in written:
                prior = previous.get(key_id)
                if prior is not None:
                    try:
                        self.store._write_atomic(
                            self.store._path_for(key_id), prior
                        )
                    except OSError:
                        pass
            raise
        # Commit point passed: clearing markers is best-effort housekeeping;
        # a crash is repaired idempotently on the next open and never rolls
        # the now-authoritative versions back.
        for key_id in written:
            record = records[key_id]
            record.pending_event = None
            try:
                self.store._write_atomic(
                    self.store._path_for(key_id), record.to_json()
                )
            except OSError:
                pass
        return result_items

    @staticmethod
    def _projection(key_id: str, record) -> dict:
        return {
            "key_id": key_id,
            "version": record.current.version,
            "algorithm": record.current.algorithm,
            "public_key": record.current.public_key,
        }

    # -- crash recovery ----------------------------------------------------
    def recover(self) -> None:
        """Finish or roll back batch rotations interrupted by a crash.

        Key files still carrying a shared ``_batch_rotate`` marker are grouped
        by the embedded event id. When the event reached the ledger the batch
        committed (markers are cleared, versions kept); otherwise it never
        committed: every handle minted by the batch is deleted *strictly*
        first (journal entries when a journal exists, else the handles on the
        landed new versions) -- an unreachable provider or a failed delete
        retains the whole group for a later open -- and only then are the
        uncommitted versions truncated off the files and the markers cleared.
        """
        groups: Dict[str, _PendingGroup] = {}

        def group_for(marker: dict) -> _PendingGroup:
            eid = marker["event"]["event_id"]
            group = groups.get(eid)
            if group is None:
                group = _PendingGroup(marker)
                groups[eid] = group
            return group

        try:
            names = os.listdir(self.store.data_dir)
        except OSError:
            names = []
        for name in names:
            if not (
                name.endswith(".json")
                and self._is_uuid4(name[:-5])
            ):
                continue
            path = os.path.join(self.store.data_dir, name)
            record = self.store._read_record(path)
            marker = getattr(record, "pending_event", None)
            if not isinstance(marker, dict):
                continue
            if not marker.get(BATCH_MARKER_FLAG):
                continue
            group_for(marker).key_files[record.key_id] = path

        for eid, group in groups.items():
            self._recover_group(eid, group)

    def _recover_group(self, eid: str, group: _PendingGroup) -> None:
        """Resolve one marker group; defer (retry later) on uncertainty."""
        marker = group.marker
        tenant_id = marker["tenant_id"]
        try:
            event = self.store.audit.get_event(eid)
        except LedgerError:
            return  # ledger unreadable: leave the group for a later open
        committed = (
            event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS
        )
        if committed:
            self._finish_committed(group)
            if group.journal:
                self.store.drop_provision_journal(group.journal)
            return
        self._rollback_uncommitted(group, tenant_id)

    def _finish_committed(self, group: _PendingGroup) -> None:
        """Clear markers of a committed batch (post-commit housekeeping)."""
        for key_id, path in list(group.key_files.items()):
            record = self.store._read_record(path)
            if record is None or not record.pending_event:
                continue
            record.pending_event = None
            try:
                self.store._write_atomic(path, record.to_json())
            except OSError:
                pass

    def _rollback_uncommitted(self, group: _PendingGroup, tenant_id: str) -> None:
        """Delete all minted handles, then truncate the uncommitted versions.

        Handles come from the durable provision journal when present; an
        older-style group without a journal collects the new versions'
        handles from the landed files themselves (manifest entry version per
        key). Every handle must be deleted and verified while its provider is
        reachable; otherwise the whole group -- files and markers -- stays
        untouched for the next open's retry.
        """
        if group.journal:
            entries = self.store.read_provision_journal(group.journal)
            if entries and not self.store.strict_delete_handles(entries):
                return
        else:
            handles = self._marker_handles(group)
            if handles is None:
                return  # a landed record could not be read; retry later
            if handles and not self.store.strict_delete_handles(handles):
                return
        # Backend confirmed empty: truncate each file back to its prior
        # version and clear the marker.
        manifest = group.marker.get("items", [])
        for entry in manifest:
            key_id = entry["key_id"]
            path = group.key_files.get(key_id)
            if path is None:
                continue  # crashed before this file landed: nothing to roll back
            record = self.store._read_record(path)
            if record is None:
                return  # state changed unexpectedly; defer to a later open
            new_version = int(entry["version"])
            kept = [
                ver for ver in record.versions if ver.version < new_version
            ]
            record.versions = kept
            record.current_version = max(new_version - 1, 0)
            record.pending_event = None
            try:
                self.store._write_atomic(path, record.to_json())
            except OSError:
                return  # leave the group for a later retry
        if group.journal:
            self.store.drop_provision_journal(group.journal)

    def _marker_handles(self, group: _PendingGroup) -> Optional[List[tuple]]:
        """(provider_id, handle) pairs of the batch's new versions on disk."""
        handles: List[tuple] = []
        for entry in group.marker.get("items", []):
            key_id = entry["key_id"]
            path = group.key_files.get(key_id)
            if path is None:
                continue
            record = self.store._read_record(path)
            if record is None:
                return None
            ver = record.get_version(int(entry["version"]))
            if ver is not None:
                handles.append((ver.provider_id, ver.handle))
        return handles

    @staticmethod
    def _is_uuid4(value: str) -> bool:
        from .store import is_valid_key_id

        return is_valid_key_id(value)
