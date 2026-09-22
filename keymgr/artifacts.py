"""Durable artifact mirrors for idempotent mutations.

After an Idempotency-Key is bound (the ``operations/<id>.json`` record is
durable) and before any KMS/HSM provider is called, the rotate / import /
restore / batch-rotate executors create one mirror file
``operation-artifacts/<operation_id>.json`` (0600, fsynced, atomic rename).

The mirror is the single crash-recovery cross-reference tying together every
durable artifact of one attempt:

* the idempotent operation record ``operations/<operation_id>.json``;
* the provider provision journal ``provisions/<operation_id>.json`` and every
  freshly minted handle (``provider_id``/``handle``);
* a restore's write set and shared marker (``_restore`` / ``_empty``);
* a batch rotation's write set and its snapshot
  ``batch-rotations/<operation_id>.json``.

It records the tenant, the operator, the request path and the canonical
(normalized, key-sorted compact JSON) request, the action, the exact write
set, the current phase and the set of new handles. Crash recovery (run after
the key/restore outbox recovery has settled the files) verifies that the
durable event and every referenced artifact agree with the mirror: when the
event is confirmed and action/tenant/operation all match, the mirror is
cleaned and the new versions kept; when the event never reached the ledger,
the outbox recovery has already deleted every new handle and restored the
trusted old write set, and the mirror is cleaned only once that is verified.

An unreadable ledger, an uncertain commit, a missing or inconsistent mirror
reference, or a corrupt batch snapshot can prove neither side: the ENTIRE
evidence set is preserved (nothing is guessed, no uncommitted current is
exposed) and the request/recovery answers 500/503 and waits for a retry.
Records predating mirrors (legacy journal/restore markers) keep using the
existing recovery rules unchanged.
"""

import json
import os
import tempfile
import threading
import uuid
from typing import Dict, List, Optional

from . import audit as audit_mod
from .audit import LedgerError

# Phases of one mirrored attempt, in order. The mirror is always rewritten
# atomically (temp file, fsync, 0600 rename), so a crash lands on either the
# previous complete phase or the next one -- never on a torn descriptor.
PHASE_BOUND = "bound"  # mirror durable, no provider call yet
PHASE_PROVISIONING = "provisioning"  # journal live, handles being minted
PHASE_STAGED = "staged"  # write set durable (files/markers landed)
PHASE_COMMITTED = "committed"  # the ledger event is the commit point
PHASE_ROLLED_BACK = "rolled_back"  # new handles deleted / old set restored

_DIR_NAME = "operation-artifacts"

# Kinds and the audit action each commits with.
_KIND_ACTIONS = {
    "rotate": audit_mod.ACTION_ROTATE,
    "batch_rotate": audit_mod.ACTION_BATCH_ROTATE,
    "import": audit_mod.ACTION_IMPORT,
    "restore": audit_mod.ACTION_IMPORT,
}


class ArtifactInconsistent(Exception):
    """A surviving mirror disagrees with the durable facts it references.

    Recovery can neither commit nor roll such an attempt back safely: the
    whole evidence set is preserved for a later open/operator.
    """


class ArtifactUnavailable(Exception):
    """The mirror cannot be read/written or the commit cannot be decided.

    Mirrors a transient backend condition (503): retry later, preserve
    everything, expose nothing.
    """


class TakeoverResult:
    """Outcome of :meth:`ArtifactStore.takeover` for a same-binding retry.

    ``kind`` is one of:

    * ``"execute"`` -- the dead owner left no committed event and no residual
      evidence; a fresh ``bound`` mirror was (re)built and the caller must run
      the executor once under the SAME operation_id;
    * ``"terminal"`` -- a durable own event (or the stored staged result)
      settles the operation; the caller replays the now-terminal record
      without executing anything;
    * ``"parked"`` -- the evidence is missing/corrupt/inconsistent or the
      outbox cannot yet be settled; the operation STAYS pending (the caller
      answers 500/503 and retries later). Nothing may be executed.
    """

    EXECUTE = "execute"
    TERMINAL = "terminal"
    PARKED = "parked"

    def __init__(self, kind: str, mirror: Optional["ArtifactMirror"] = None,
                 record=None) -> None:
        self.kind = kind
        self.mirror = mirror
        self.record = record


def _new_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class ArtifactMirror:
    """One in-flight mirror, rewritten durably as the attempt progresses."""

    def __init__(self, artifact_store: "ArtifactStore", operation,
                 descriptor: Optional[dict] = None) -> None:
        self.artifact_store = artifact_store
        self.operation = operation
        self.descriptor: Dict = descriptor or {}
        self._lock = threading.Lock()

    @property
    def operation_id(self) -> str:
        return self.descriptor["operation_id"]

    def path(self) -> str:
        return self.artifact_store.path_for(self.operation_id)

    # -- mutators (durable rewrites) ---------------------------------------
    def _persist(self) -> None:
        self.descriptor["updated_at"] = _new_timestamp()
        self.artifact_store.write_descriptor(self.descriptor)

    def describe(self, facts: dict) -> "ArtifactMirror":
        """Merge request/action/write-set facts into the mirror (durable).

        Called once, still before any provider call: the kind, the audit
        action and the exact write set become part of the crash evidence.
        """
        with self._lock:
            kind = facts.get("kind")
            if kind not in _KIND_ACTIONS:
                raise ArtifactInconsistent("unknown mirror kind: %r" % kind)
            self.descriptor["kind"] = kind
            self.descriptor["action"] = facts.get(
                "action", _KIND_ACTIONS[kind]
            )
            write_set = facts.get("write_set")
            if isinstance(write_set, list):
                normalized = sorted(
                    key_id for key_id in write_set
                    if _is_key_id(key_id)
                )
                self.descriptor["write_set"] = normalized
            if facts.get("policy") is not None:
                self.descriptor["policy"] = bool(facts["policy"])
            self._persist()
        return self

    def provision(self, journal_id: str, snapshot: Optional[str] = None) -> None:
        """Tie the provision journal (and batch snapshot) to the mirror."""
        with self._lock:
            self.descriptor["journal"] = journal_id
            if snapshot is not None:
                self.descriptor["snapshot"] = snapshot
            if self.descriptor.get("phase") == PHASE_BOUND:
                self.descriptor["phase"] = PHASE_PROVISIONING
            self._persist()

    def phase(self, phase: str) -> None:
        """Advance the mirror phase, rewriting it durably."""
        with self._lock:
            self.descriptor["phase"] = phase
            self._persist()

    def add_handle(self, provider_id: str, handle: str) -> None:
        """Record one freshly minted handle in the mirror (durable).

        Mirrors the provision journal entry: the handle is appended to the
        mirror's ordered unique handle list immediately after it is recorded
        in the journal, so a crash always leaves the two in agreement.
        """
        with self._lock:
            handles = self.descriptor.setdefault("handles", [])
            pair = {"provider_id": provider_id, "handle": handle}
            if pair not in handles:
                handles.append(pair)
            if self.descriptor.get("phase") == PHASE_BOUND:
                self.descriptor["phase"] = PHASE_PROVISIONING
            self._persist()

    def note_restore_empty(self, marker_path: str) -> None:
        """Tie an empty-restore marker file to the mirror."""
        with self._lock:
            self.descriptor["empty_marker"] = marker_path
            self._persist()

    def discard(self) -> bool:
        """Remove the mirror file. Returns True when it no longer exists."""
        return self.artifact_store.discard(self.operation_id)


class ArtifactStore:
    """Owns the ``operation-artifacts`` directory and crash settlement."""

    def __init__(self, data_dir: str, key_store, audit_log=None) -> None:
        self.data_dir = data_dir
        self.dir_path = os.path.join(data_dir, _DIR_NAME)
        self.key_store = key_store
        # key_store may be None only when an explicit audit log is supplied:
        # create()/describe()/phase() never touch the key store, while the
        # startup settlement and request-path verification do (so those call
        # sites always pass a recovered store).
        self.audit = audit_log if audit_log is not None else key_store.audit
        self._lock = threading.Lock()
        self._parked: set = set()
        # Ids adjudicated from a present mirror during the latest startup
        # settlement; the missing-mirror sweep must not re-park them.
        self._adjudicated: set = set()

    # -- paths / io --------------------------------------------------------
    def path_for(self, operation_id: str) -> str:
        return os.path.join(self.dir_path, operation_id + ".json")

    def write_descriptor(self, descriptor: dict) -> None:
        """Atomically write one mirror (0600, fsynced before rename)."""
        path = self.path_for(descriptor["operation_id"])
        fd, tmp_path = tempfile.mkstemp(dir=self.dir_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(descriptor, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _read_descriptor(self, operation_id: str) -> Optional[dict]:
        try:
            with open(self.path_for(operation_id), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    def discard(self, operation_id: str) -> bool:
        try:
            os.unlink(self.path_for(operation_id))
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def is_parked(self, operation_id: str) -> bool:
        """Whether a pending operation's mirror must keep it pending."""
        return operation_id in self._parked

    # -- request-path lifecycle -------------------------------------------
    def create(self, operation) -> ArtifactMirror:
        """Create the bound-phase mirror for a freshly bound operation.

        The mirror only carries the binding facts (tenant, operator, path,
        canonical request) and the ``bound`` phase; the executor adds kind,
        action and write set (still before the first provider call).
        """
        descriptor = {
            "version": 1,
            "operation_id": operation.operation_id,
            "tenant_id": operation.tenant_id,
            "operator_id": operation.operator_id,
            "path": operation.path,
            "request_body": operation.request_body,
            "kind": None,
            "action": None,
            "phase": PHASE_BOUND,
            "write_set": [],
            "handles": [],
            "journal": None,
            "snapshot": None,
            "empty_marker": None,
            "policy": False,
            "created_at": _new_timestamp(),
            "updated_at": None,
        }
        os.makedirs(self.dir_path, exist_ok=True)
        self.write_descriptor(descriptor)
        return ArtifactMirror(self, operation, descriptor)

    def after_terminal(self, mirror: Optional[ArtifactMirror]) -> None:
        """Request-path mirror cleanup once the operation reached a terminal.

        Committed terminals verify ownership of every minted handle; refusal/
        failure terminals require the attempt's rollback artifacts to be gone.
        A mirror whose evidence cannot be verified (a delete the provider
        could not confirm, an unreadable ledger) is intentionally LEFT on
        disk: the next startup settles it, and until then the evidence stays
        complete.
        """
        if mirror is None:
            return
        descriptor = self._read_descriptor(mirror.operation_id)
        if descriptor is None:
            return
        phase = descriptor.get("phase")
        if phase == PHASE_COMMITTED:
            if self._committed_state_verified(descriptor):
                self.discard(mirror.operation_id)
            return
        if phase in (PHASE_ROLLED_BACK, PHASE_BOUND):
            if not self._residual_evidence(descriptor):
                self.discard(mirror.operation_id)
            return
        # provisioning/staged after a terminal response: the store's abort
        # path either verified the rollback (journal/snapshot gone) or parked
        # the scene. Decide from the durable facts, never from the phase.
        if not self._residual_evidence(descriptor):
            self.discard(mirror.operation_id)

    # -- request-path takeover of a dead owner's attempt ------------------
    def takeover(self, operation_store, record, settle_outbox,
                 resolve_committed=None):
        """Take over a still-pending operation after acquiring its lease.

        The caller (a same-binding HTTP/CLI retry) already holds the dead
        owner's execution lease. This decides, purely from durable facts and
        WITHOUT calling any provider itself:

        * settle the attempt's outbox evidence (markers/journal/snapshot) via
          ``settle_outbox(kind, operation_id)``;
        * a durable own event -> finalize the operation from the staged result
          and return ``terminal`` for verbatim replay;
        * the event never landed and every rollback artifact is gone -> drop a
          spent mirror, rebuild a fresh ``bound`` mirror and return ``execute``
          so the caller runs the attempt ONCE under the SAME operation_id;
        * a missing/corrupt/inconsistent mirror with residual evidence, an
          unreadable ledger, a foreign same-id event, or an outbox that cannot
          yet settle -> return ``parked`` (operation stays pending; the caller
          answers 500/503 and retries). Nothing is guessed and no uncommitted
          current is exposed.
        """
        operation_id = record.operation_id
        mirror_path = self.path_for(operation_id)
        mirror_present = os.path.exists(mirror_path)
        descriptor = self._read_descriptor(operation_id) if mirror_present else None

        if (
            descriptor is not None
            and not self._binding_matches(descriptor, record)
        ):
            # The mirror is a DIFFERENT attempt than the bound operation:
            # never settle over it or execute against it.
            self._parked.add(operation_id)
            return TakeoverResult(TakeoverResult.PARKED)

        # The kind is needed to drive outbox settlement; it is derivable from
        # the durable operation details/path even when the mirror is missing
        # or corrupt. If it cannot be derived at all, nothing is provable.
        kind = self._infer_kind(record, descriptor)
        if kind is None:
            self._parked.add(operation_id)
            return TakeoverResult(TakeoverResult.PARKED)

        # Settle the durable outbox evidence first. This is ledger-driven and
        # idempotent: a durable own event commits the files forward, otherwise
        # minted handles are deleted and the old write set restored. A backend
        # that cannot confirm a delete leaves the evidence in place. Any
        # failure to settle (an unreadable ledger/dir, a torn parse) parks the
        # attempt rather than risking a guess; parking is always retryable.
        try:
            settle_outbox(kind, operation_id)
        except Exception:
            self._parked.add(operation_id)
            return TakeoverResult(TakeoverResult.PARKED)

        event = None
        try:
            event = self.audit.get_event(operation_id)
        except LedgerError:
            self._parked.add(operation_id)
            return TakeoverResult(TakeoverResult.PARKED)

        if event is not None:
            # The operation store decides own-vs-foreign and replays the
            # staged 201/403/404/409 verbatim from durable context (it does
            # not need the mirror). A foreign same-id event leaves the
            # operation pending (finalize_pending returns False).
            finalized = operation_store.finalize_pending(
                record,
                resolve_committed=resolve_committed,
                is_parked=lambda _id: False,
            )
            if not finalized:
                self._parked.add(operation_id)
                return TakeoverResult(TakeoverResult.PARKED)
            record = operation_store._read_record(operation_id)
            if descriptor is not None:
                # A healthy mirror can be cleaned once post-commit ownership
                # verifies; a corrupt one is retained as evidence rather than
                # discarded unverified.
                self.after_terminal(
                    ArtifactMirror(self, record, descriptor)
                )
            return TakeoverResult(TakeoverResult.TERMINAL, record=record)

        # No durable event: the attempt never committed. Residual evidence
        # (a journal, snapshot, key/policy marker or empty-restore marker)
        # means the outbox could not fully roll back -- park and retry later.
        if self._event_residual_evidence(operation_id):
            self._parked.add(operation_id)
            return TakeoverResult(TakeoverResult.PARKED)

        if descriptor is not None:
            # A PRESENT, healthy mirror whose outbox fully rolled back is the
            # same scene startup settles as failed(500): finalize it that way
            # (deterministic whether recovered by a restart or a retry) and
            # drop the now-spent mirror. This is NOT re-executed -- the first
            # attempt got far enough to keep its mirror, so its interruption
            # is a recorded failure rather than a pre-provider mirror fault.
            finalized = operation_store.finalize_pending(
                operation_store._read_record(operation_id) or record,
                resolve_committed=resolve_committed,
                is_parked=lambda _id: False,
            )
            if not finalized:
                self._parked.add(operation_id)
                return TakeoverResult(TakeoverResult.PARKED)
            record = operation_store._read_record(operation_id)
            self.after_terminal(ArtifactMirror(self, record, descriptor))
            return TakeoverResult(TakeoverResult.TERMINAL, record=record)

        # MISSING or CORRUPT mirror -- the failure happened while creating the
        # 0600 mirror before the first provider call. The event never landed
        # and there is no residual evidence, so the mirror can be rebuilt:
        # discard a torn file, create a fresh bound mirror and run the attempt
        # ONCE under the SAME operation_id. A failure here propagates as
        # OSError; the caller keeps the operation pending and answers 500/503.
        if mirror_present:
            if not self.discard(operation_id) and os.path.exists(mirror_path):
                self._parked.add(operation_id)
                return TakeoverResult(TakeoverResult.PARKED)
        record = operation_store._read_record(operation_id) or record
        mirror = self.create(record)
        return TakeoverResult(TakeoverResult.EXECUTE, mirror=mirror, record=record)

    @staticmethod
    def _infer_kind(record, descriptor: Optional[dict]) -> Optional[str]:
        """The attempt kind from the mirror, the stored details or the path."""
        if descriptor is not None:
            kind = descriptor.get("kind")
            if isinstance(kind, str) and kind in _KIND_ACTIONS:
                return kind
        kind = (record.details or {}).get("kind") if record.details else None
        if isinstance(kind, str) and kind in _KIND_ACTIONS:
            return kind
        path = record.path or ""
        if path == "/v1/keys/batch-rotate":
            return "batch_rotate"
        if path == "/v1/keys/import":
            return "import"
        if path == "/v1/restore":
            return "restore"
        if path.startswith("/v1/keys/") and path.endswith("/rotate"):
            return "rotate"
        return None

    # -- startup settlement ------------------------------------------------
    def settle_pending(self, operation_store) -> None:
        """Settle surviving mirrors of crashed processes at startup.

        Must run AFTER the key-store and restore outbox recovery (which settle
        files, markers, snapshots, journals and handles) and BEFORE the
        operation store finalizes pending operations. A mirror whose commit
        event is durable and consistent is discarded; a mirror of a fully
        rolled-back attempt is discarded (the operation then finalizes as the
        stored 500 interruption); anything unprovable keeps the ENTIRE
        evidence set and parks the operation pending for a later open.
        """
        self._parked = set()
        # Ids this pass explicitly adjudicated from a PRESENT mirror (commit
        # verified-and-discarded, rollback verified-and-discarded, terminal
        # housekeeping, or a mirror intentionally retained): the
        # missing-mirror pass must not re-park these just because the mirror
        # file was discarded here before the operation was finalized.
        self._adjudicated = set()
        try:
            names = os.listdir(self.dir_path)
        except FileNotFoundError:
            names = []
        except OSError:
            # The mirror directory exists but cannot be read: every
            # mirror-required pending operation must be parked because its
            # mirror can neither be confirmed nor ruled out.
            self._park_all_mirror_required(operation_store)
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            operation_id = name[:-5]
            if not _is_uuid4(operation_id):
                # An unidentifiable mirror can never be cross-checked against
                # an operation/event: keep it for operator resolution.
                continue
            self._settle_one(operation_id, operation_store)
        # A mirror-required pending operation whose mirror file is MISSING
        # (the process died at/around the 0600 mirror create) is parked too:
        # without the cross-index nothing can be cross-checked, so the legacy
        # no-mirror finalization must not run for it. Legacy operations bound
        # before the mirror contract keep the old rules and are unaffected.
        self._park_missing_mirrors(operation_store)

    def _park_all_mirror_required(self, operation_store) -> None:
        """Park every still-pending mirror-required operation."""
        import os as _os

        try:
            names = _os.listdir(operation_store.dir_path)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json") or name == "index.json":
                continue
            record = operation_store._read_record(name[:-5])
            if (
                record is not None
                and not record.is_terminal()
                and getattr(record, "mirror_required", False)
            ):
                self._parked.add(record.operation_id)

    def _park_missing_mirrors(self, operation_store) -> None:
        """Park mirror-required pending operations with no surviving mirror."""
        try:
            names = os.listdir(operation_store.dir_path)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json") or name == "index.json":
                continue
            operation_id = name[:-5]
            if operation_id in self._parked or operation_id in self._adjudicated:
                continue
            record = operation_store._read_record(operation_id)
            if record is None or record.is_terminal():
                continue
            if not getattr(record, "mirror_required", False):
                # Records predating the mirror contract are never forced to
                # have one: legacy journal/marker recovery still applies.
                continue
            if os.path.exists(self.path_for(operation_id)):
                continue
            self._parked.add(operation_id)

    def _settle_one(self, operation_id: str, operation_store) -> None:
        # The mirror file is present, so this id is adjudicated here and must
        # not be revisited by the missing-mirror sweep (even when this method
        # discards the mirror before the operation is finalized).
        self._adjudicated.add(operation_id)
        descriptor = self._read_descriptor(operation_id)
        record = operation_store._read_record(operation_id)
        if descriptor is None:
            self._settle_corrupt_mirror(operation_id, record)
            return
        if record is None or not self._binding_matches(descriptor, record):
            # Mirror references a missing operation or a different binding:
            # the two durable records disagree, nothing can be guessed.
            self._parked.add(operation_id)
            return
        try:
            event = self.audit.get_event(operation_id)
        except LedgerError:
            # The commit authority cannot be read: retain everything.
            self._parked.add(operation_id)
            return

        if record.is_terminal():
            # The original process reached a terminal before dying; only the
            # mirror unlink may have been missed. Never re-finalize it.
            self._settle_terminal(descriptor, record, event)
            return

        # Pending operation.
        if event is not None and self._event_confirms(descriptor, event):
            # Durable success with matching action/tenant: keep the new
            # versions, clean the mirror once post-commit ownership verifies.
            # The event is the commit fact regardless of residual markers, so
            # the operation is never parked on this branch.
            if self._committed_state_verified(descriptor):
                self.discard(operation_id)
            return
        if event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS:
            # A durable success carries this id but action/tenant disagree:
            # an id collision. Neither commit nor rollback is provable.
            self._parked.add(operation_id)
            return
        # Event absent, or a durable rejected terminal: the attempt never
        # committed. The outbox recovery has either finished the rollback or
        # deliberately parked the scene (provider down, corrupt basis).
        if self._residual_evidence(descriptor):
            self._parked.add(operation_id)
        else:
            self.discard(operation_id)

    def _settle_corrupt_mirror(self, operation_id: str, record) -> None:
        """Settle a present-but-unreadable mirror at startup.

        A torn/corrupt mirror can still be outweighed by the ledger: the
        event is the commit authority. When the bound record is pending and a
        durable SUCCESS event carrying the right action and tenant is present
        ("event in the ledger == committed"), the outbox recovery has already
        committed the files forward and the operation finalizes normally --
        the corrupt mirror is merely retained as evidence, not blocking.
        Without that fact nothing is provable and the operation stays parked.
        """
        if record is None:
            # No operation to cross-check the mirror against: preserve it.
            self._parked.add(operation_id)
            return
        if record.is_terminal():
            # Terminal records are never re-finalized; just retain the file.
            return
        expected_action = self._infer_kind(record, None)
        expected_action = _KIND_ACTIONS.get(expected_action)
        try:
            event = self.audit.get_event(operation_id)
        except LedgerError:
            self._parked.add(operation_id)
            return
        if (
            event is not None
            and event.outcome == audit_mod.OUTCOME_SUCCESS
            and event.tenant_id == record.tenant_id
            and (
                expected_action is None or event.action == expected_action
            )
        ):
            # Committed despite the corrupt mirror: leave the file for the
            # operator but do NOT park, so the operation finalizes from the
            # ledger/staged result.
            return
        self._parked.add(operation_id)

    def _settle_terminal(self, descriptor: dict, record, event) -> None:
        """Discard a terminal operation's mirror only when its state verifies."""
        if record.status == "succeeded":
            if event is not None and self._event_confirms(descriptor, event):
                if self._committed_state_verified(descriptor):
                    self.discard(record.operation_id)
            return
        # failed/conflict/timed_out: uncommitted terminal. The store/restore
        # recovery removes its artifacts; a surviving journal/snapshot/marker
        # means cleanup is still retrying and the mirror stays as its index.
        if not self._residual_evidence(descriptor):
            self.discard(record.operation_id)

    # -- verification primitives -------------------------------------------
    @staticmethod
    def _binding_matches(descriptor: dict, record) -> bool:
        """Whether the mirror is the SAME attempt as the operation record."""
        if descriptor.get("operation_id") != record.operation_id:
            return False
        for field in ("tenant_id", "operator_id", "path", "request_body"):
            if descriptor.get(field) != getattr(record, field):
                return False
        kind = descriptor.get("kind")
        if kind is not None and kind not in _KIND_ACTIONS:
            return False
        action = descriptor.get("action")
        if action is not None and action not in (
            audit_mod.ACTION_ROTATE,
            audit_mod.ACTION_BATCH_ROTATE,
            audit_mod.ACTION_IMPORT,
        ):
            return False
        return True

    @staticmethod
    def _event_confirms(descriptor: dict, event) -> bool:
        """Whether a durable event is exactly this mirror's commit event.

        The event id is the operation id by construction; action and tenant
        must additionally agree with the mirror. A rejected event or an
        action/tenant mismatch never confirms a commit.
        """
        if event is None or event.outcome != audit_mod.OUTCOME_SUCCESS:
            return False
        tenant = descriptor.get("tenant_id")
        if tenant is not None and event.tenant_id != tenant:
            return False
        kind = descriptor.get("kind")
        expected = descriptor.get("action") or _KIND_ACTIONS.get(kind)
        if expected is None:
            # The mirror never recorded which action the attempt commits
            # (crash between create and describe): a durable event cannot be
            # confirmed as THIS attempt's commit -- action agreement is
            # unprovable, so never clean on it.
            return False
        return event.action == expected

    def _committed_state_verified(self, descriptor: dict) -> bool:
        """Verify the committed write set owns every mirror handle.

        Every write-set key file must exist, belong to the mirror's tenant
        and carry no unresolved pending marker of another outcome; and every
        (provider_id, handle) the mirror recorded must be owned by one of the
        surviving committed versions. The provision journal and a batch
        snapshot are post-commit housekeeping and must already be gone (a
        surviving one keeps the mirror for the next open). Marker-clear
        residue (event already durable) never hides the committed state.
        """
        operation_id = descriptor["operation_id"]
        journal_id = descriptor.get("journal") or operation_id
        if os.path.exists(self.key_store._provision_path(journal_id)):
            return False
        if descriptor.get("snapshot") and os.path.exists(
            self.key_store._batch_snapshot_path(descriptor["snapshot"])
        ):
            return False
        tenant_id = descriptor.get("tenant_id")
        owned = set()
        for key_id in descriptor.get("write_set", []):
            record = self.key_store._read_record(self.key_store._path_for(key_id))
            if record is None or record.tenant_id != tenant_id:
                return False
            for ver in record.versions:
                owned.add((ver.provider_id, ver.handle))
        expected = {
            (entry.get("provider_id"), entry.get("handle"))
            for entry in descriptor.get("handles", [])
            if isinstance(entry, dict)
        }
        return expected.issubset(owned)

    def _residual_evidence(self, descriptor: dict) -> bool:
        """Whether uncommitted-attempt artifacts still survive on disk.

        Scans the provision journal, the batch snapshot, the restore empty
        marker and every key file carrying a pending marker named after this
        operation. The outbox recovery leaves these in place exactly while it
        is parking the scene (unreadable ledger, unreachable provider,
        corrupt/missing basis, id collision); while any survives the mirror
        cannot be dropped.
        """
        operation_id = descriptor["operation_id"]
        journal_id = descriptor.get("journal") or operation_id
        if os.path.exists(self.key_store._provision_path(journal_id)):
            return True
        if descriptor.get("snapshot") and os.path.exists(
            self.key_store._batch_snapshot_path(descriptor["snapshot"])
        ):
            return True
        empty_marker = descriptor.get("empty_marker")
        if isinstance(empty_marker, str) and self._pending_empty_marker(
            empty_marker, operation_id
        ):
            return True
        return self._marker_names_event(operation_id)

    def _pending_empty_marker(self, path: str, operation_id: str) -> bool:
        """An empty-restore marker still carrying THIS pending event."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                marker = json.load(fh)
        except (OSError, ValueError):
            # Corrupt marker reference: treat as residual evidence so the
            # mirror (and the marker) stay for a later, safer open.
            return os.path.exists(path)
        if not isinstance(marker, dict):
            return os.path.exists(path)
        event = marker.get("event")
        if isinstance(event, dict):
            return event.get("event_id") == operation_id
        return False

    def _marker_names_event(self, operation_id: str) -> bool:
        """Whether any key/policy file still carries a pending marker for id."""
        directory = self.data_dir
        try:
            names = os.listdir(directory)
        except OSError:
            # Cannot scan: assume evidence may survive and retain the mirror.
            return True
        for name in names:
            if not (name.endswith(".json") and _is_key_id(name[:-5])):
                continue
            record = self.key_store._read_record(os.path.join(directory, name))
            marker = getattr(record, "pending_event", None)
            if not isinstance(marker, dict):
                continue
            nested = marker.get("event")
            desc = nested if isinstance(nested, dict) else marker
            if isinstance(desc, dict) and desc.get("event_id") == operation_id:
                return True
        return self._policy_marker_names_event(operation_id)

    def _policy_marker_names_event(self, operation_id: str) -> bool:
        """Whether a policy file carries a pending marker for this id."""
        policy_dir = os.path.join(self.data_dir, "policies")
        try:
            policy_names = os.listdir(policy_dir)
        except OSError:
            return False
        for name in policy_names:
            if not name.endswith(".json"):
                continue
            try:
                with open(
                    os.path.join(policy_dir, name), "r", encoding="utf-8"
                ) as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            pending = doc.get("pending_event")
            if not isinstance(pending, dict):
                continue
            nested = pending.get("event")
            desc = nested if isinstance(nested, dict) else pending
            if isinstance(desc, dict) and desc.get("event_id") == operation_id:
                return True
        return False

    def _empty_marker_names_event(self, operation_id: str) -> bool:
        """Whether any surviving empty-restore marker still names this id."""
        directory = self.data_dir
        try:
            names = os.listdir(directory)
        except OSError:
            return True
        for name in names:
            if not (
                name.startswith("restore-empty-") and name.endswith(".json")
            ):
                continue
            path = os.path.join(directory, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    marker = json.load(fh)
            except (OSError, ValueError):
                if os.path.exists(path):
                    # Corrupt marker reference: treat as residual evidence.
                    return True
                continue
            if not isinstance(marker, dict):
                continue
            event = marker.get("event")
            if isinstance(event, dict) and event.get("event_id") == operation_id:
                return True
        return False

    def _event_residual_evidence(self, operation_id: str) -> bool:
        """Whether ANY uncommitted-attempt artifact survives for one id.

        Mirror-independent counterpart of :meth:`_residual_evidence`, used when
        a same-binding retry takes over an attempt whose mirror is missing or
        was rebuilt: the provision journal, the batch snapshot, pending key/
        policy markers and empty-restore markers are all scanned by event id.
        A mirror that requires rollback evidence to be gone parks the attempt
        while any of these survives.
        """
        if os.path.exists(self.key_store._provision_path(operation_id)):
            return True
        if os.path.exists(
            self.key_store._batch_snapshot_path(operation_id)
        ):
            return True
        if self._marker_names_event(operation_id):
            return True
        if self._empty_marker_names_event(operation_id):
            return True
        return False


def _is_uuid4(value: str) -> bool:
    try:
        return uuid.UUID(value).version == 4
    except (ValueError, AttributeError, TypeError):
        return False


def _is_key_id(value) -> bool:
    """Canonical lowercase UUID4 check (lazy import avoids a store cycle)."""
    from .store import is_valid_key_id

    return is_valid_key_id(value)
