"""Operation artifact mirrors for rotate / import / restore / batch-rotate.

For every idempotent mutation (rotate, import, restore, batch-rotate) an
*artifact mirror* is created at exactly one point: after the Idempotency-Key
is bound (the ``operations/<id>.json`` record exists) and **before** the KMS/
HSM provider is called. It is one more 0600, fsynced JSON file --
``operation-artifacts/<operation_id>.json`` -- that ties together every
durable fact of the attempt:

  * the tenant and the operator (the audited subject);
  * the request path and the canonical (key-sorted, compact) request body;
  * the action and the mutation kind;
  * the write set (every key_id the attempt may create or append to);
  * the current phase of the attempt;
  * every newly minted handle as ``(provider_id, handle)``, recorded the
    instant the backend returns it;
  * the references to the attempt's other durable artifacts: its provision
    journal ``provisions/<id>.json``, the batch snapshot
    ``batch-rotations/<id>.json`` and/or a restore marker (the empty-restore
    marker file).

The mirror contains no private material, wrapping material or passphrase;
handles are recorded only because crash cleanup must be able to name every
backend object the attempt minted. The mirror is never served over HTTP or
the CLI and lives in an owner-only file.

Crash recovery is layered. The key-store, batch and restore outbox recovery
run first and already settle files and provider handles strictly by
``operation_id`` (which is also the audit ``event_id``): a durable matching
event commits the new version(s), otherwise every new handle is deleted and
the trusted old write set is restored. :meth:`ArtifactStore.recover` runs
after that and only retains or removes the *mirror* itself, using it as a
cross-check that the whole evidence group agrees:

* readable ledger, durable event whose action, tenant and operation all match
  and no surviving pending marker names the operation -> the attempt is
  settled and the mirror is discarded (the new versions stay);
* no durable event (or a durable rejection) and no surviving provision
  journal, batch snapshot or pending marker -> the rollback fully verified
  and the mirror is discarded;
* the ledger cannot be read, the commit cannot be confirmed, a durable event
  with the same id disagrees on action/tenant, or a referenced artifact or
  pending marker survives -> the ENTIRE evidence group is retained, nothing
  is guessed or rolled back, and no uncommitted current is projected. The
  request path surfaces 500/503 and the client retries; a later startup
  settles the scene.

Pre-provider-era journal/restore records (no operation artifact exists) keep
using the existing recovery rules unchanged.
"""

import json
import os
import re
import tempfile
import threading
import uuid
from typing import List, Optional

from . import audit as audit_mod
from .audit import AuditLog, LedgerError

# A canonical lowercase RFC 4122 UUID4 (key_id / event_id / operation_id).
# Inlined (rather than imported from .store) to keep this module free of an
# import cycle: the store and the restore coordinator import ArtifactStore.
_UUID4_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def _is_uuid4(value) -> bool:
    return isinstance(value, str) and bool(_UUID4_RE.fullmatch(value))

# Artifact phases, recorded as the attempt crosses each step.
PHASE_STAGED = "staged"
PHASE_PROVISIONED = "provisioned"
PHASE_FILES_WRITTEN = "files_written"

_DIR_NAME = "operation-artifacts"

# Marker kinds the attempt's write set may carry.
_MARKER_RESTORE = "_restore"
_MARKER_BATCH = "_batch_rotate"
_EMPTY_MARKER_PREFIX = "restore-empty-"


class OperationArtifact:
    """One durable artifact mirror, serialized 0600/fsync."""

    def __init__(
        self,
        operation_id: str,
        tenant_id: str,
        operator_id: str,
        path: str,
        request_body: str,
        action: str,
        kind: str,
        phase: str = PHASE_STAGED,
        write_set: Optional[List[str]] = None,
        handles: Optional[List[dict]] = None,
        provision_journal: Optional[str] = None,
        snapshot: Optional[str] = None,
        restore_marker: Optional[str] = None,
    ) -> None:
        self.operation_id = operation_id
        self.tenant_id = tenant_id
        self.operator_id = operator_id
        self.path = path
        self.request_body = request_body
        self.action = action
        self.kind = kind
        self.phase = phase
        # Complete key_id write set, known at stage time (post binding).
        self.write_set: List[str] = list(write_set or [])
        # [{provider_id, handle}] in minting order, de-duplicated.
        self.handles: List[dict] = list(handles or [])
        self.provision_journal = provision_journal
        self.snapshot = snapshot
        # Relative path of the empty-restore marker, when the restore writes
        # no key/policy files.
        self.restore_marker = restore_marker
        # Back-reference to the owning store; set by ArtifactStore.stage and
        # never serialized. The store/coordinator update a mirror only
        # through the artifact object they were handed.
        self._store = None

    # -- writer delegation (serialized/fsynced by the owning store) -------
    def register_handle(self, provider_id: str, handle: str) -> None:
        if self._store is not None:
            self._store.register_handle(self, provider_id, handle)

    def link_provision_journal(self, journal_id: Optional[str]) -> None:
        if self._store is not None:
            self._store.link_provision_journal(self, journal_id)

    def link_snapshot(self, snapshot_id: Optional[str]) -> None:
        if self._store is not None:
            self._store.link_snapshot(self, snapshot_id)

    def set_restore_marker(self, marker_relpath: Optional[str]) -> None:
        if self._store is not None:
            self._store.set_restore_marker(self, marker_relpath)

    def set_phase(self, phase: str) -> None:
        if self._store is not None:
            self._store.set_phase(self, phase)

    def update_write_set(self, key_ids) -> None:
        if self._store is not None:
            self._store.update_write_set(self, key_ids)

    def discard(self) -> bool:
        if self._store is not None:
            return self._store.discard(self)
        return False

    def to_json(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "tenant_id": self.tenant_id,
            "operator_id": self.operator_id,
            "path": self.path,
            "request_body": self.request_body,
            "action": self.action,
            "kind": self.kind,
            "phase": self.phase,
            "write_set": self.write_set,
            "handles": self.handles,
            "provision_journal": self.provision_journal,
            "snapshot": self.snapshot,
            "restore_marker": self.restore_marker,
        }

    @classmethod
    def from_json(cls, data: dict) -> "OperationArtifact":
        return cls(
            operation_id=data["operation_id"],
            tenant_id=data["tenant_id"],
            operator_id=data["operator_id"],
            path=data.get("path", ""),
            request_body=data.get("request_body", ""),
            action=data.get("action", ""),
            kind=data.get("kind", ""),
            phase=data.get("phase", PHASE_STAGED),
            write_set=list(data.get("write_set") or []),
            handles=list(data.get("handles") or []),
            provision_journal=data.get("provision_journal"),
            snapshot=data.get("snapshot"),
            restore_marker=data.get("restore_marker"),
        )


class ArtifactStore:
    """Persists, updates and recovers operation artifact mirrors."""

    def __init__(self, data_dir: str, audit_log: Optional[AuditLog] = None) -> None:
        self.data_dir = data_dir
        self.dir_path = os.path.join(data_dir, _DIR_NAME)
        os.makedirs(self.dir_path, exist_ok=True)
        # Serialize read-modify-write of one mirror within the process; the
        # owning request is the only writer, startup recovery the other.
        self._locks_lock = threading.Lock()
        self._locks: dict = {}
        self.audit = audit_log if audit_log is not None else AuditLog(data_dir)

    # -- paths / locking ---------------------------------------------------
    def _path_for(self, operation_id: str) -> str:
        return os.path.join(self.dir_path, operation_id + ".json")

    def _lock_for(self, operation_id: str) -> threading.Lock:
        with self._locks_lock:
            lock = self._locks.get(operation_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[operation_id] = lock
            return lock

    def _journal_path(self, journal_id: str) -> str:
        return os.path.join(self.data_dir, "provisions", journal_id + ".json")

    def _snapshot_path(self, snapshot_id: str) -> str:
        return os.path.join(
            self.data_dir, "batch-rotations", snapshot_id + ".json"
        )

    def _fsync_dir(self) -> None:
        """Best-effort fsync of the artifact directory after a create/rename."""
        try:
            fd = os.open(self.dir_path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _write_atomic(self, artifact: OperationArtifact) -> None:
        """Rewrite the mirror atomically: temp file, fsync, 0600, rename."""
        payload = artifact.to_json()
        fd, tmp_path = tempfile.mkstemp(dir=self.dir_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self._path_for(artifact.operation_id))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _read(self, operation_id: str) -> Optional[OperationArtifact]:
        try:
            with open(self._path_for(operation_id), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            artifact = OperationArtifact.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None
        if artifact.operation_id != operation_id:
            return None
        return artifact

    # -- request-path API --------------------------------------------------
    def stage(
        self,
        operation_id: str,
        tenant_id: str,
        operator_id: str,
        path: str,
        request_body: str,
        action: str,
        kind: str,
        write_set: Optional[List[str]] = None,
    ) -> OperationArtifact:
        """Atomically create the 0600/fsynced mirror before any provider call.

        Runs strictly after the Idempotency-Key binding (the operation record
        exists) and before the first KMS/HSM call, so a crash at that point
        already leaves a recoverable, owner-only evidence file. Idempotent:
        a retry of the same operation (or a re-entrant stage) loads the
        existing mirror rather than failing, and a surviving mirror whose
        tenant/action disagree is left untouched and reported as None so the
        caller parks rather than adopting foreign evidence.
        """
        artifact = OperationArtifact(
            operation_id=operation_id,
            tenant_id=tenant_id,
            operator_id=operator_id,
            path=path,
            request_body=request_body,
            action=action,
            kind=kind,
            write_set=write_set,
        )
        target = self._path_for(operation_id)
        with self._lock_for(operation_id):
            existing = self._read(operation_id)
            if existing is not None:
                if (
                    existing.tenant_id != tenant_id
                    or existing.action != action
                    or existing.path != path
                ):
                    raise ArtifactConflict(
                        "operation artifact survives with a mismatched binding"
                    )
                existing._store = self
                return existing
            # O_EXCL: the create itself is atomic and can never truncate a
            # mirror another frame just wrote.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fd = -1
                    json.dump(artifact.to_json(), fh)
                    fh.flush()
                    os.fsync(fh.fileno())
            except BaseException:
                try:
                    os.unlink(target)
                except OSError:
                    pass
                raise
            finally:
                if fd >= 0:
                    os.close(fd)
            self._fsync_dir()
        artifact._store = self
        return artifact

    def register_handle(
        self, artifact: OperationArtifact, provider_id: str, handle: str
    ) -> None:
        """Durably record one newly minted handle, in minting order."""
        if not isinstance(provider_id, str) or not provider_id:
            return
        if not isinstance(handle, str) or not handle:
            return
        with self._lock_for(artifact.operation_id):
            fresh = self._read(artifact.operation_id)
            if fresh is not None:
                artifact = fresh
            entry = {"provider_id": provider_id, "handle": handle}
            changed = entry not in artifact.handles
            if changed:
                artifact.handles.append(entry)
            # The first minted handle advances staged -> provisioned.
            if artifact.phase == PHASE_STAGED:
                artifact.phase = PHASE_PROVISIONED
                changed = True
            if changed:
                self._write_atomic(artifact)

    def link_provision_journal(
        self, artifact: OperationArtifact, journal_id: Optional[str]
    ) -> None:
        """Associate the attempt's provision journal once it is created."""
        with self._lock_for(artifact.operation_id):
            fresh = self._read(artifact.operation_id)
            if fresh is not None:
                artifact = fresh
            if artifact.provision_journal != journal_id:
                artifact.provision_journal = journal_id
                self._write_atomic(artifact)

    def link_snapshot(
        self, artifact: OperationArtifact, snapshot_id: Optional[str]
    ) -> None:
        """Associate the batch snapshot once it is durable."""
        with self._lock_for(artifact.operation_id):
            fresh = self._read(artifact.operation_id)
            if fresh is not None:
                artifact = fresh
            if artifact.snapshot != snapshot_id:
                artifact.snapshot = snapshot_id
                self._write_atomic(artifact)

    def set_restore_marker(
        self, artifact: OperationArtifact, marker_relpath: Optional[str]
    ) -> None:
        """Associate the empty-restore marker file for a key-less restore."""
        with self._lock_for(artifact.operation_id):
            fresh = self._read(artifact.operation_id)
            if fresh is not None:
                artifact = fresh
            if artifact.restore_marker != marker_relpath:
                artifact.restore_marker = marker_relpath
                self._write_atomic(artifact)

    def set_phase(self, artifact: OperationArtifact, phase: str) -> None:
        """Advance the durable phase marker of the attempt."""
        with self._lock_for(artifact.operation_id):
            fresh = self._read(artifact.operation_id)
            if fresh is not None:
                artifact = fresh
            if artifact.phase != phase:
                artifact.phase = phase
                self._write_atomic(artifact)

    def update_write_set(
        self, artifact: OperationArtifact, key_ids
    ) -> None:
        """Merge key ids into the durable write set (kept sorted)."""
        with self._lock_for(artifact.operation_id):
            fresh = self._read(artifact.operation_id)
            if fresh is not None:
                artifact = fresh
            merged = sorted(set(artifact.write_set) | set(key_ids))
            if merged != artifact.write_set:
                artifact.write_set = merged
                self._write_atomic(artifact)

    def discard(self, artifact: OperationArtifact) -> bool:
        """Remove the mirror after the attempt is durably settled.

        Returns True when no mirror remains. A removal failure leaves it for
        the next startup's recovery sweep rather than being swallowed.
        """
        try:
            os.unlink(self._path_for(artifact.operation_id))
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def settle(self, operation_id: str) -> None:
        """Discard a request's mirror once its evidence group is fully gone.

        Request-path counterpart of :meth:`recover`: the terminal state has
        just been persisted. The mirror is removed only when the attempt no
        longer references a surviving provision journal, batch snapshot or
        restore marker and no pending outbox marker names the operation. A
        provider-failure terminal whose handle cleanup could not be verified
        keeps a referenced journal, so the mirror -- the evidence of the
        retained group -- stays too; a 500/uncertain-commit caller never
        invokes this. A missing mirror is a no-op.
        """
        artifact = self._read(operation_id)
        if artifact is None:
            return
        if self._referenced_artifacts_survive(artifact):
            return
        if self._pending_marker_naming(operation_id):
            return
        self.discard(artifact)

    # -- crash recovery ----------------------------------------------------
    def _pending_marker_naming(self, operation_id: str) -> bool:
        """Whether a surviving outbox marker still names this operation.

        Scans key files (single-key rotate/import, ``_restore`` and
        ``_batch_rotate`` groups) and the empty-restore markers. A pending
        marker that survives after the outbox recovery ran means that recovery
        parked the scene (unreadable ledger, foreign event, failed delete), so
        the mirror must stay as part of the evidence group.
        """
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            # A data directory that cannot be listed is conservatively treated
            # as "a marker may survive": retain the evidence.
            return True
        for name in names:
            if name.endswith(".json") and _is_uuid4(name[:-5]):
                path = os.path.join(self.data_dir, name)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        doc = json.load(fh)
                except (OSError, ValueError):
                    continue
                marker = doc.get("pending_event") if isinstance(doc, dict) else None
                if self._marker_names(marker, operation_id):
                    return True
            elif (
                name.startswith(_EMPTY_MARKER_PREFIX)
                and name.endswith(".json")
            ):
                path = os.path.join(self.data_dir, name)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        marker = json.load(fh)
                except (OSError, ValueError):
                    continue
                if self._marker_names(marker, operation_id):
                    return True
        return False

    @staticmethod
    def _marker_names(marker, operation_id: str) -> bool:
        if not isinstance(marker, dict) or not marker:
            return False
        if marker.get(_MARKER_RESTORE) or marker.get(_MARKER_BATCH):
            event = marker.get("event")
            return (
                isinstance(event, dict)
                and event.get("event_id") == operation_id
            )
        # Single-key outbox marker: the event fields sit flat.
        return marker.get("event_id") == operation_id

    def _referenced_artifacts_survive(self, artifact: OperationArtifact) -> bool:
        """Whether the journal/snapshot the mirror references still exists.

        A provision journal and a batch snapshot are rollback-only artifacts
        removed on commit, so a surviving one is always unresolved evidence.
        The empty-restore marker differs: once committed it is *finalized*
        (its ``event`` becomes null) and stays permanently as the empty
        batch's idempotency record; only a still-pending marker carrying this
        operation's event counts as unresolved evidence.
        """
        if artifact.provision_journal:
            if os.path.exists(self._journal_path(artifact.provision_journal)):
                return True
        if artifact.snapshot:
            if os.path.exists(self._snapshot_path(artifact.snapshot)):
                return True
        if artifact.restore_marker:
            rel = artifact.restore_marker
            # Only a data-dir-relative name is ever stored; never follow an
            # absolute or traversing path.
            if os.path.sep not in rel and ".." not in rel:
                marker_path = os.path.join(self.data_dir, rel)
                if self._pending_restore_marker_names(marker_path,
                                                      artifact.operation_id):
                    return True
        return False

    def _pending_restore_marker_names(
        self, marker_path: str, operation_id: str
    ) -> bool:
        """Whether an empty-restore marker still carries THIS pending event.

        A finalized marker (``event`` null) is the committed batch's permanent
        idempotency record and is not unresolved evidence.
        """
        try:
            with open(marker_path, "r", encoding="utf-8") as fh:
                marker = json.load(fh)
        except (OSError, ValueError):
            # Missing -> no evidence; unreadable -> retain conservatively.
            return os.path.exists(marker_path)
        return self._marker_names(marker, operation_id)

    @staticmethod
    def _event_is_foreign(artifact: OperationArtifact, event) -> bool:
        """Whether a durable same-id event is not THIS operation's event.

        The durable fact must carry the mirror's tenant and the mirror's
        action; a same-id event disagreeing on either is an id collision and
        parks the evidence group.
        """
        if event is None:
            return False
        if event.tenant_id != artifact.tenant_id:
            return True
        if event.action != artifact.action:
            return True
        return False

    def recover(self) -> None:
        """Retain or discard mirrors left by crashed attempts.

        Runs after the key-store and restore outbox recovery, which have
        already committed or rolled files/handles back by operation_id. See
        the module docstring for the exact retain/discard rules. A mirror that
        cannot be settled now is left byte-for-byte for the next open; this
        method never deletes handles or rewrites key files itself.
        """
        try:
            names = os.listdir(self.dir_path)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            operation_id = name[:-5]
            try:
                if uuid.UUID(operation_id).version != 4:
                    # An unidentifiable mirror is never auto-settled.
                    continue
            except (ValueError, AttributeError, TypeError):
                continue
            artifact = self._read(operation_id)
            if artifact is None:
                # Corrupt/unreadable mirror: retain the evidence group rather
                # than guessing; an operator inspects it.
                continue
            self._recover_one(artifact)

    def _recover_one(self, artifact: OperationArtifact) -> None:
        try:
            event = self.audit.get_event(artifact.operation_id)
        except LedgerError:
            # Ledger unreadable: nothing is provable; keep every artifact.
            return
        except Exception:
            # Any other read failure is treated as an outage too.
            return

        if event is not None and self._event_is_foreign(artifact, event):
            # A durable event carries the id but action/tenant disagree:
            # neither commit nor rollback is provable. Retain the group.
            return

        if (
            event is not None
            and event.outcome == audit_mod.OUTCOME_SUCCESS
            and event.action == artifact.action
            and event.tenant_id == artifact.tenant_id
        ):
            # Committed. The store/coordinator recovery already cleared the
            # committed markers/journal/snapshot; a surviving pending marker
            # means that recovery parked the scene, so the mirror stays.
            if self._pending_marker_naming(artifact.operation_id):
                return
            self.discard(artifact)
            return

        # No durable success event (event absent, or a durable rejection):
        # the attempt never committed. The outbox recovery has deleted the
        # minted handles and restored the trusted old write set; retain the
        # mirror while any journal, snapshot or pending marker still survives
        # (a provider outage or an unreadable ledger parked that work) and
        # discard it only once the whole rollback evidence is gone.
        if self._referenced_artifacts_survive(artifact):
            return
        if self._pending_marker_naming(artifact.operation_id):
            return
        self.discard(artifact)


class ArtifactConflict(Exception):
    """A surviving artifact mirror belongs to a different binding."""
