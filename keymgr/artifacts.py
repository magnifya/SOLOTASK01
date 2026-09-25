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

import hashlib
import json
import os
import tempfile
import threading
import uuid
from contextlib import contextmanager
from typing import Dict, List, Optional

try:  # cross-process attempt claims are POSIX fcntl locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

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
    # Envelope encryption is a read-only idempotent operation: it mints no
    # provider handle and writes no key file, but its one audit event is still
    # named after the operation_id, so its mirror commits by the ledger event.
    "encrypt": audit_mod.ACTION_ENCRYPT,
}

# Kinds that only ever READ the key set and can never record a freshly minted
# provider handle, a provision journal, a batch snapshot or a restore marker.
_READ_ONLY_KINDS = frozenset(("encrypt",))


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


class ArtifactStrandUnavailable(Exception):
    """A bound, still-pending attempt cannot be started or taken over now.

    Raised on the request path when the 0600 mirror cannot be created
    (``OSError`` making the directory/temp file/rename), or when a retry of a
    bound pending operation finds surviving evidence it cannot reconcile and
    cannot prove safe to restart. The operation STAYS pending: no provider is
    called, no key/handle/audit is written, and the caller answers a
    material-safe 500/503 so the next open or retry can rebuild the mirror and
    replay the attempt under the SAME operation_id.

    ``http_status`` is the response the caller sends (500 for a persistence
    fault, 503 for a parked scene that a retry/restart may clear); the
    operation record itself stays pending regardless.
    """

    def __init__(self, message: str = "", http_status: int = 503) -> None:
        super().__init__(message)
        self.http_status = http_status


class ArtifactAlreadyTerminal(Exception):
    """A takeover re-read found the operation already at a terminal state.

    The binding was observed pending before the claim, but the original owner
    finished while the claim was being acquired. The caller replays the
    freshly read terminal record verbatim instead of re-executing anything.
    """

    def __init__(self, record) -> None:
        super().__init__("operation already terminal")
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
        action and the exact write set become part of the crash evidence. A
        durable-rewrite failure here happens with NO journal, handle, key or
        event in existence, so it is a restartable strand fault (the operation
        stays pending for a same-id retry) rather than a failed(500) terminal.

        The facts are validated strictly rather than filtered: the kind must
        be one of the four mirrored mutations, the action must be the audit
        action that kind commits with, and the write set must list unique
        canonical key ids with the kind's exact shape (rotate/import a single
        key_id; batch_rotate the full non-empty item set; restore the possibly
        empty set of newly created keys). Anything else is an
        :class:`ArtifactInconsistent` programming/corruption error instead of
        being silently normalized away, so the mirror's cross-reference can
        never disagree with the operation it mirrors.
        """
        with self._lock:
            kind = facts.get("kind")
            if kind not in _KIND_ACTIONS:
                raise ArtifactInconsistent("unknown mirror kind: %r" % kind)
            canonical_action = _KIND_ACTIONS[kind]
            action = facts.get("action", canonical_action)
            if action != canonical_action:
                raise ArtifactInconsistent(
                    "mirror action %r does not match kind %r (%r)"
                    % (action, kind, canonical_action)
                )
            write_set = facts.get("write_set")
            normalized = self._validated_write_set(kind, write_set)
            self.descriptor["kind"] = kind
            self.descriptor["action"] = action
            self.descriptor["write_set"] = normalized
            if facts.get("policy") is not None:
                self.descriptor["policy"] = bool(facts["policy"])
            try:
                self._persist()
            except OSError as exc:
                raise ArtifactStrandUnavailable(str(exc), 500)
        return self

    @staticmethod
    def _validated_write_set(kind: str, write_set) -> List[str]:
        """The exact, sorted write set a kind may carry, else inconsistent."""
        if not isinstance(write_set, list):
            raise ArtifactInconsistent(
                "mirror write_set must be a list, got %r" % type(write_set)
            )
        normalized: List[str] = []
        seen = set()
        for key_id in write_set:
            if not _is_key_id(key_id) or key_id in seen:
                raise ArtifactInconsistent(
                    "mirror write_set entry is not a unique UUID4: %r" % (key_id,)
                )
            seen.add(key_id)
            normalized.append(key_id)
        normalized.sort()
        if kind in ("rotate", "import", "encrypt") and len(normalized) != 1:
            raise ArtifactInconsistent(
                "mirror kind %r requires exactly one write-set key, got %d"
                % (kind, len(normalized))
            )
        if kind == "batch_rotate" and not normalized:
            raise ArtifactInconsistent(
                "a batch_rotate mirror requires a non-empty write set"
            )
        return normalized

    def provision(self, journal_id: str, snapshot: Optional[str] = None) -> None:
        """Tie the provision journal (and batch snapshot) to the mirror.

        Both durable artifacts are named after the attempt's operation id, so
        a reference naming any other id is an inconsistency rather than a
        quietly stored cross-reference.
        """
        with self._lock:
            operation_id = self.operation_id
            if journal_id != operation_id:
                raise ArtifactInconsistent(
                    "provision journal %r does not name operation %r"
                    % (journal_id, operation_id)
                )
            if snapshot is not None and snapshot != operation_id:
                raise ArtifactInconsistent(
                    "batch snapshot %r does not name operation %r"
                    % (snapshot, operation_id)
                )
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

    def reset_for_pending_retry(self) -> None:
        """Return a still-pending attempt's mirror to a clean ``bound`` strand.

        Used when a bound idempotent operation made NO durable provider
        progress -- it waited out the reconnect gate, or its owning
        provider_id was displaced by a reconnect -- after the caller has
        already removed the (empty) provision journal and minted no handle.
        The mirror is durably reset to the same image a fresh bind has, so the
        operation stays PENDING and an identical retry takes it over under the
        same operation_id exactly once.
        """
        with self._lock:
            self.descriptor["phase"] = PHASE_BOUND
            self.descriptor["handles"] = []
            self.descriptor["journal"] = None
            self.descriptor["snapshot"] = None
            self._persist()

    def add_handle(self, provider_id: str, handle: str) -> None:
        """Record one freshly minted handle in the mirror (durable).

        Mirrors the provision journal entry: the handle is appended to the
        mirror's ordered unique handle list immediately after it is recorded
        in the journal, so a crash always leaves the two in agreement.
        """
        with self._lock:
            handles = self.descriptor.setdefault("handles", [])
            if not isinstance(provider_id, str) or not provider_id:
                raise ArtifactInconsistent(
                    "a mirrored handle requires a non-empty provider_id"
                )
            if not isinstance(handle, str) or not handle:
                raise ArtifactInconsistent(
                    "a mirrored handle requires a non-empty handle"
                )
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
        # Per-operation in-process attempt guards. fcntl serializes across
        # processes, but flock is per-process, so threads inside one server
        # process need this guard too.
        self._thread_guards: Dict[str, threading.Lock] = {}
        # Operation ids whose mirror could not be settled at this startup:
        # the operation store must leave them pending for a later open rather
        # than guessing a terminal.
        self._parked: set = set()

    def _thread_guard(self, operation_id: str) -> threading.Lock:
        with self._lock:
            guard = self._thread_guards.get(operation_id)
            if guard is None:
                guard = threading.Lock()
                self._thread_guards[operation_id] = guard
            return guard

    # -- paths / io --------------------------------------------------------
    def path_for(self, operation_id: str) -> str:
        return os.path.join(self.dir_path, operation_id + ".json")

    def _claim_path(self, operation_id: str) -> str:
        return os.path.join(self.dir_path, operation_id + ".lock")

    @contextmanager
    def _claim(self, operation_id: str, blocking: bool):
        """Hold the in-process and cross-process attempt claims for one op.

        Both an in-process per-id lock (the HTTP server is threaded while
        flock is per-process) and an fcntl exclusive lock on
        ``operation-artifacts/<id>.lock`` are held for the WHOLE
        first-provider-call..terminal window: a concurrent HTTP/CLI retry in
        any thread or process can only take the attempt over once the original
        owner is truly gone, never while it is minting handles.

        ``blocking=False`` raises :class:`BlockingIOError` when another owner
        currently holds the claim; ``blocking=True`` waits. A storage fault
        taking the claim raises :class:`ArtifactStrandUnavailable`.
        """
        guard = self._thread_guard(operation_id)
        acquired = guard.acquire(blocking=blocking)
        if not acquired:
            raise BlockingIOError(operation_id)
        fd = -1
        locked = False
        try:
            os.makedirs(self.dir_path, exist_ok=True)
            fd = os.open(
                self._claim_path(operation_id),
                os.O_RDWR | os.O_CREAT,
                0o600,
            )
            if fcntl is not None:
                flags = fcntl.LOCK_EX
                if not blocking:
                    flags |= fcntl.LOCK_NB
                # LOCK_NB contention raises BlockingIOError, reported distinctly
                # from a storage fault by the calling guard.
                fcntl.flock(fd, flags)
                locked = True
            yield fd
        except OSError as exc:
            if isinstance(exc, BlockingIOError):
                raise
            raise ArtifactStrandUnavailable(str(exc), 500)
        finally:
            if fcntl is not None and locked and fd >= 0:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            guard.release()

    def attempt(self, operation, blocking: bool, takeover: bool = False,
                operation_store=None):
        """Context manager owning one attempt's mirror + cross-process claim.

        For a freshly bound operation (``takeover=False``) it creates the
        ``bound`` mirror directly and never reads the ledger -- a fresh bind
        has no prior evidence. For a retried identical binding whose operation
        is still pending (``takeover=True``) it RE-READS the operation record
        while holding the claim: if the original owner meanwhile reached a
        terminal, ArtifactAlreadyTerminal carries the fresh record for exact
        replay. Otherwise it takes the strand over under the SAME
        operation_id, but only when the mirror is missing with zero surviving
        evidence (a failed/stranded mirror creation) or is an intact ``bound``
        mirror with no journal, snapshot, marker, handle or durable event --
        i.e. the provider was never effectively called. Anything less provable
        raises ArtifactStrandUnavailable: the operation stays pending, the
        scene stays parked for the next process restart, and no provider is
        called twice.
        """
        operation_id = operation.operation_id
        return self._Attempt(
            self, operation, operation_id, blocking, takeover,
            operation_store,
        )

    class _Attempt:
        def __init__(self, store, operation, operation_id, blocking,
                     takeover, operation_store):
            self.store = store
            self.operation = operation
            self.operation_id = operation_id
            self.blocking = blocking
            self.takeover = takeover
            self.operation_store = operation_store
            self._cm = None
            self.mirror = None

        def __enter__(self):
            self._cm = self.store._claim(
                self.operation_id, self.blocking
            )
            self._cm.__enter__()
            try:
                self.mirror = self.store._claim_strand(
                    self.operation, self.takeover, self.operation_store
                )
                return self.mirror
            except BaseException:
                self._cm.__exit__(None, None, None)
                self._cm = None
                raise

        def __exit__(self, exc_type, exc, tb):
            try:
                return None
            finally:
                if self._cm is not None:
                    self._cm.__exit__(exc_type, exc, tb)

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
        """Whether a pending operation must be kept pending at settlement.

        Both genuinely parked evidence sets (corrupt/inconsistent, provider
        down) and clean pre-provider strands waiting for a takeover retry keep
        the operation pending: neither may be finalized failed(500), so the
        request path is the only thing allowed to conclude them.
        """
        return operation_id in self._parked

    # -- request-path strand claim / takeover ------------------------------
    def _event_durable(self, operation_id: str):
        """Return the durable event for the id, or None; False if unreadable."""
        try:
            return self.audit.get_event(operation_id)
        except LedgerError:
            return False

    def _clean_strand_descriptor(self, operation, descriptor: dict) -> bool:
        """Whether the attempt provably never reached a provider.

        Evidence required to (re)start a bound attempt under the same
        operation_id: no durable event of any outcome, no provision journal,
        no batch snapshot, no restore marker and no key/policy pending marker
        naming this operation. Anything less returns False and the caller
        parks instead of guessing.
        """
        if self.key_store is None:
            return False
        event = self._event_durable(operation.operation_id)
        if event is False or event is not None:
            # Unreadable ledger, or a durable commit/rejection: the startup
            # settlement owns those; a request never re-runs them.
            return False
        return not self._residual_evidence(descriptor)

    def _claim_strand(self, operation, takeover: bool,
                      operation_store=None) -> ArtifactMirror:
        """Create (fresh bind) or safely take over the attempt mirror.

        Claim lock is held. A fresh bind never had an attempt, so its mirror
        is created directly WITHOUT reading the ledger (a get_event there
        would block behind a held audit lock before the first provider call).
        Only an explicit takeover re-reads the operation record (the claim is
        the serialization boundary with the original owner) and re-validates
        the surviving evidence.
        """
        if not takeover:
            try:
                return self.create(operation)
            except OSError as exc:
                raise ArtifactStrandUnavailable(str(exc), 500)
        operation_id = operation.operation_id
        # Re-read the record UNDER the claim: the original owner may have
        # reached a terminal after this request observed "pending" but before
        # the claim was granted. Hand the fresh terminal to the caller for an
        # exact replay rather than re-executing or wrongly parking it.
        if operation_store is not None:
            fresh = operation_store._read_record(operation_id)
            if fresh is not None and fresh.is_terminal():
                raise ArtifactAlreadyTerminal(fresh)
        descriptor = self._read_descriptor(operation_id)
        if descriptor is not None:
            if not self._binding_matches(descriptor, operation):
                raise ArtifactStrandUnavailable(
                    "mirror does not match the operation binding"
                )
            return self._take_over(operation, descriptor)
        if os.path.exists(self.path_for(operation_id)):
            # Named on disk but unparseable: a corrupt mirror is evidence to
            # preserve, never rebuilt over by a live request.
            raise ArtifactStrandUnavailable("corrupt mirror")
        # Missing mirror: the classic failed strand (mirror creation raised
        # before the first provider call) -- only restartable when not a trace
        # of the attempt survives and nothing committed under this id.
        probe = {
            "operation_id": operation_id,
            "journal": None,
            "snapshot": None,
            "empty_marker": None,
        }
        if not self._clean_strand_descriptor(operation, probe):
            raise ArtifactStrandUnavailable(
                "missing mirror with surviving or uncertain evidence"
            )
        try:
            return self.create(operation)
        except OSError as exc:
            raise ArtifactStrandUnavailable(str(exc), 500)

    def _take_over(
        self, operation, descriptor: dict
    ) -> ArtifactMirror:
        """Re-open an intact, never-committed mirror for a retried attempt.

        Only a mirror that provably never reached a provider can be restarted
        on the request path: it is still at the ``bound`` phase with no handle
        recorded, has no provision journal/batch snapshot/marker and has no
        durable event of any outcome. A mirror that reached provisioning (a
        journal or a handle existed) is finalized by the startup crash rule
        instead -- a request never re-executes it. The descriptor is reset to
        a fresh ``bound`` image as the executor re-describes the write set.
        """
        phase = descriptor.get("phase")
        if phase != PHASE_BOUND or descriptor.get("handles"):
            raise ArtifactStrandUnavailable(
                "mirror phase %r cannot be taken over" % phase
            )
        if descriptor.get("journal") or descriptor.get("snapshot"):
            raise ArtifactStrandUnavailable(
                "mirror already references a journal or snapshot"
            )
        if not self._clean_strand_descriptor(operation, descriptor):
            raise ArtifactStrandUnavailable(
                "surviving evidence blocks the mirror takeover"
            )
        # Reset the durable image to a fresh bound strand. Discard first so a
        # stale reference can never ride along.
        if not self.discard(operation.operation_id):
            raise ArtifactStrandUnavailable("stale mirror could not be removed")
        try:
            return self.create(operation)
        except OSError as exc:
            raise ArtifactStrandUnavailable(str(exc), 500)

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
        """Request-path mirror cleanup once an attempt ran.

        Committed terminals verify ownership of every minted handle; refusal/
        failure terminals require the attempt's rollback artifacts to be gone.
        A mirror whose evidence cannot be verified (a delete the provider
        could not confirm, an unreadable ledger) is intentionally LEFT on
        disk: the next startup settles it, and until then the evidence stays
        complete.

        A still-``bound`` mirror whose operation is PENDING (the describe/
        provision step itself failed before a provider was called) is retained
        too: the mirror stays the parked attempt's cross-reference until a
        same-id HTTP/CLI retry takes it over. Only a mirror whose operation
        actually reached a terminal is eligible for the bound-phase discard.
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
        if phase == PHASE_BOUND:
            # A rejection/provider terminal finalizes the operation and clears
            # an untouched bound mirror; a strand failure leaves it pending and
            # keeps the mirror as the parked attempt's index.
            if getattr(mirror.operation, "status", None) == "pending":
                return
            if not self._residual_evidence(descriptor):
                self.discard(mirror.operation_id)
            return
        if phase == PHASE_ROLLED_BACK:
            if not self._residual_evidence(descriptor):
                self.discard(mirror.operation_id)
            return
        # provisioning/staged after a terminal response: the store's abort
        # path either verified the rollback (journal/snapshot gone) or parked
        # the scene. Decide from the durable facts, never from the phase.
        if not self._residual_evidence(descriptor):
            self.discard(mirror.operation_id)

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
        try:
            names = os.listdir(self.dir_path)
        except OSError:
            # The mirror directory itself is unreadable: settle nothing and
            # let the missing-mirror pass below park every bound operation
            # rather than finalizing one without its evidence.
            names = []
        for name in names:
            if not name.endswith(".json"):
                continue
            operation_id = name[:-5]
            if not _is_uuid4(operation_id):
                # An unidentifiable mirror can never be cross-checked against
                # an operation/event: keep it for operator resolution.
                continue
            self._settle_one(operation_id, operation_store)
        self._settle_missing_mirrors(names, operation_store)

    def _settle_missing_mirrors(self, mirror_names, operation_store) -> None:
        """Park pending operations of the mirrored generation with no mirror.

        A ``mirror_required`` pending operation whose mirror never landed (the
        0600 creation failed, or the process died on that exact syscall) is not
        guessed into failed(500): with no evidence it stays pending as a clean
        strand the next identical HTTP/CLI request takes over under the same
        operation_id; with surviving evidence it is parked the same way until
        a later open. Records predating mirrors (``mirror_required`` false)
        keep the legacy recovery rules and are intentionally untouched.
        """
        present = {name[:-5] for name in mirror_names if name.endswith(".json")}
        try:
            op_names = os.listdir(operation_store.dir_path)
        except OSError:
            return
        for name in op_names:
            if not name.endswith(".json") or name == "index.json":
                continue
            operation_id = name[:-5]
            if operation_id in present:
                continue
            record = operation_store._read_record(operation_id)
            if record is None or record.is_terminal():
                continue
            if not getattr(record, "mirror_required", False):
                # Legacy binding: no mirror was ever mandatory.
                continue
            self._parked.add(operation_id)

    def _settle_one(self, operation_id: str, operation_store) -> None:
        descriptor = self._read_descriptor(operation_id)
        if descriptor is None:
            # Corrupt/unreadable mirror: preserve the evidence and park the
            # operation rather than guessing.
            self._parked.add(operation_id)
            return
        record = operation_store._read_record(operation_id)
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
            # Durable success with matching action/tenant. Keep the new
            # versions and clean the mirror ONLY once the committed write set,
            # every surviving reference and the staged 201 response all verify.
            # The event is the commit fact regardless of residual markers, so a
            # verification miss parks the evidence but never rolls it back.
            if self._committed_state_verified(descriptor) and (
                self._staged_success_response_backed(descriptor, record)
            ):
                self.discard(operation_id)
            return
        if event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS:
            # A durable success carries this id but action/tenant disagree:
            # an id collision. Neither commit nor rollback is provable.
            self._parked.add(operation_id)
            return
        if event is not None and not self._rejected_event_matches(
            descriptor, record, event
        ):
            # A durable event with this id is not the mirror's own rejection
            # (action/tenant/key/outcome or staged response mismatch): the id
            # collides with a different terminal. Park rather than replaying.
            self._parked.add(operation_id)
            return
        # Event absent, or a durable rejected terminal that matches: the
        # attempt never committed its write set. The outbox recovery has
        # either finished the rollback or deliberately parked the scene
        # (provider down, corrupt/missing basis).
        if self._residual_evidence(descriptor):
            self._parked.add(operation_id)
            return
        if event is not None:
            # A durable, matching rejected terminal (403/404/409/503) with no
            # residual file/journal: the rejection already committed and the
            # operation store replays its staged result verbatim; the mirror
            # is spent housekeeping. Never park a decided terminal for a retry.
            self.discard(operation_id)
            return
        # No event and no residual evidence. Decide from whether the provider
        # was ever reached: a mirror that stayed at ``bound`` (no journal/
        # handle) represents an attempt interrupted exactly around mirror
        # creation -- keep it pending (and retain the mirror as its index) so
        # the next identical HTTP/CLI request takes it over under the same
        # operation_id. A mirror that reached provisioning and was then fully
        # rolled back (provider failure / conflict / ledger failure) is the
        # legacy interruption: drop the mirror so the operation finalizes
        # failed(500) exactly as before.
        if self._never_provisioned(descriptor):
            self._parked.add(operation_id)
        else:
            self.discard(operation_id)

    @staticmethod
    def _never_provisioned(descriptor: dict) -> bool:
        """Whether the mirror proves the provider was never reached."""
        return (
            descriptor.get("phase") == PHASE_BOUND
            and not descriptor.get("handles")
            and not descriptor.get("journal")
            and not descriptor.get("snapshot")
        )

    def _settle_terminal(self, descriptor: dict, record, event) -> None:
        """Discard a terminal operation's mirror only when its state verifies."""
        if record.status == "succeeded":
            if event is not None and self._event_confirms(descriptor, event):
                if self._committed_state_verified(
                    descriptor
                ) and self._staged_success_response_backed(descriptor, record):
                    self.discard(record.operation_id)
            return
        # failed/conflict/timed_out: an uncommitted terminal. A durable
        # rejection must still BE this mirror's rejection (action/tenant/
        # outcome/response agree); the store/restore recovery removes the
        # artifacts, so a surviving journal/snapshot/marker means cleanup is
        # still retrying and the mirror stays as its index.
        if event is not None and not self._rejected_event_matches(
            descriptor, record, event
        ):
            return
        if not self._residual_evidence(descriptor):
            self.discard(record.operation_id)

    # -- verification primitives -------------------------------------------
    @staticmethod
    def _descriptor_consistent(descriptor: dict, allow_undescribed: bool):
        """Whether one on-disk mirror descriptor is internally well-formed.

        A descriptor is the cross-index of an attempt, so every reference it
        carries must already be self-consistent before it is compared against
        anything else:

        * ``kind`` (once described) is one of the four mirrored mutations and
          ``action`` is exactly the audit action that kind commits with;
        * ``write_set`` is a list of unique canonical key ids with the kind's
          exact shape (rotate/import one key; batch a non-empty set; restore a
          possibly empty set);
        * ``handles`` is a duplicate-free list of non-empty
          ``{provider_id, handle}`` pairs;
        * the journal/snapshot references name the operation itself and a
          snapshot only accompanies a batch rotation.

        ``allow_undescribed`` admits a still-``bound`` mirror that crashed
        before ``describe`` (kind/action unset, empty write set).
        """
        if not isinstance(descriptor, dict):
            return False
        operation_id = descriptor.get("operation_id")
        if not _is_uuid4(operation_id):
            return False
        for field in ("tenant_id", "operator_id", "path", "request_body"):
            value = descriptor.get(field)
            if not isinstance(value, str):
                return False
        if not descriptor.get("tenant_id"):
            return False
        kind = descriptor.get("kind")
        action = descriptor.get("action")
        write_set = descriptor.get("write_set")
        if kind is None:
            if not allow_undescribed:
                return False
            if action is not None or write_set:
                return False
        else:
            if kind not in _KIND_ACTIONS or action != _KIND_ACTIONS[kind]:
                return False
            if not ArtifactStore._valid_write_set_shape(kind, write_set):
                return False
        # A read-only kind (encrypt) mints nothing: any handle, provision
        # journal, batch snapshot, restore marker or policy fact on its mirror
        # is by construction an inconsistency.
        if kind in _READ_ONLY_KINDS:
            if descriptor.get("handles"):
                return False
            if descriptor.get("journal") is not None:
                return False
            if descriptor.get("snapshot") is not None:
                return False
            if descriptor.get("empty_marker") is not None:
                return False
            if descriptor.get("policy"):
                return False
        journal = descriptor.get("journal")
        if journal is not None and journal != operation_id:
            return False
        snapshot = descriptor.get("snapshot")
        if snapshot is not None:
            if snapshot != operation_id or kind != "batch_rotate":
                return False
        empty_marker = descriptor.get("empty_marker")
        if empty_marker is not None and not isinstance(empty_marker, str):
            return False
        if not isinstance(descriptor.get("policy"), bool):
            return False
        handles = descriptor.get("handles")
        if not isinstance(handles, list):
            return False
        seen = set()
        for entry in handles:
            if not isinstance(entry, dict):
                return False
            provider_id = entry.get("provider_id")
            handle = entry.get("handle")
            if (
                not isinstance(provider_id, str)
                or not provider_id
                or not isinstance(handle, str)
                or not handle
            ):
                return False
            pair = (provider_id, handle)
            if pair in seen:
                return False
            seen.add(pair)
        return True

    @staticmethod
    def _valid_write_set_shape(kind: str, write_set) -> bool:
        """The kind's exact write-set shape (unique canonical UUID4s)."""
        if not isinstance(write_set, list):
            return False
        seen = set()
        for key_id in write_set:
            if not _is_key_id(key_id) or key_id in seen:
                return False
            seen.add(key_id)
        if kind in ("rotate", "import", "encrypt") and len(seen) != 1:
            return False
        if kind == "batch_rotate" and not seen:
            return False
        return True

    @staticmethod
    def _details_correspond(descriptor: dict, record) -> bool:
        """Whether the operation record's durable details match the mirror.

        The kind/action must correspond to the exact ``key_id`` (rotate/
        import), ``items`` set (batch rotation) or ``key_ids`` plus policy
        flag (restore) the executor persisted in ``operations/<id>.json``.
        A mirror that was never described has nothing yet to correspond.
        """
        kind = descriptor.get("kind")
        if kind is None:
            return True
        details = getattr(record, "details", None)
        if not isinstance(details, dict) or details.get("kind") != kind:
            return False
        write_set = descriptor.get("write_set") or []
        if kind in ("rotate", "import", "encrypt"):
            return details.get("key_id") == (write_set[0] if write_set else None)
        if kind == "batch_rotate":
            items = details.get("items")
            if not isinstance(items, list):
                return False
            item_keys = set()
            for item in items:
                if not isinstance(item, dict) or not _is_key_id(
                    item.get("key_id")
                ):
                    return False
                item_keys.add(item["key_id"])
            return item_keys == set(write_set)
        key_ids = details.get("key_ids")
        if not isinstance(key_ids, list) or sorted(key_ids) != sorted(write_set):
            return False
        return bool(details.get("policy_restored")) == bool(
            descriptor.get("policy")
        )

    def _binding_matches(self, descriptor: dict, record) -> bool:
        """Whether the mirror is the SAME attempt as the operation record.

        Compares the full binding (tenant/operator/path/canonical request),
        requires an internally consistent descriptor, and -- once the mirror
        is described -- requires the record's durable details to name the
        exact same kind, key_id/items, write set and policy fact.
        """
        if descriptor.get("operation_id") != record.operation_id:
            return False
        for field in ("tenant_id", "operator_id", "path", "request_body"):
            if descriptor.get(field) != getattr(record, field):
                return False
        if not self._descriptor_consistent(descriptor, allow_undescribed=True):
            return False
        if not self._details_correspond(descriptor, record):
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

    def _rejected_event_matches(self, descriptor: dict, record, event) -> bool:
        """Whether a durable REJECTED terminal event belongs to this mirror.

        A rejection commits no write set, but its event must still name the
        operation and carry the mirror's action and tenant; rotate/import
        rejections project the one write-set key while batch/restore events
        project no key. When the record staged its audit descriptor / result
        before the append, those durable facts must agree with the event and
        the staged response must be a refusal (never a 201). Anything less
        leaves the evidence parked.
        """
        if event is None or event.outcome != audit_mod.OUTCOME_REJECTED:
            return False
        if descriptor.get("kind") is None:
            return False
        if event.action != descriptor.get("action"):
            return False
        if event.tenant_id != descriptor.get("tenant_id"):
            return False
        kind = descriptor.get("kind")
        write_set = descriptor.get("write_set") or []
        if kind in ("rotate", "import", "encrypt"):
            if event.key_id != (write_set[0] if write_set else None):
                return False
        elif event.key_id is not None:
            return False
        details = getattr(record, "details", None)
        if isinstance(details, dict):
            audit_desc = details.get("audit")
            if isinstance(audit_desc, dict):
                if audit_desc.get("action") not in (None, event.action):
                    return False
                if audit_desc.get("outcome") not in (
                    None, audit_mod.OUTCOME_REJECTED
                ):
                    return False
                if audit_desc.get("tenant_id") not in (None, event.tenant_id):
                    return False
            result = details.get("result")
            if isinstance(result, dict) and result.get("http_status") == 201:
                # A staged 201 response cannot share an id with a rejection.
                return False
        return True

    def _staged_success_response_backed(
        self, descriptor: dict, record
    ) -> bool:
        """Whether a staged 201 response is backed by the committed write set.

        Startup settlement uses this when the operation record persisted its
        exact success response before the commit-point append: the on-disk
        committed state must actually support that response (the named
        versions exist; a restore's key set and policy flag match). Records
        without a staged response (older bindings, crafted recovery scenes)
        skip this and rely on the artifact checks alone.
        """
        details = getattr(record, "details", None)
        if not isinstance(details, dict):
            return True
        result = details.get("result")
        if not isinstance(result, dict):
            return True
        http_status = result.get("http_status")
        response = result.get("response")
        if http_status is None and response is None:
            return True
        if not isinstance(response, dict):
            return False
        kind = descriptor.get("kind")
        tenant_id = descriptor.get("tenant_id")
        write_set = descriptor.get("write_set") or []
        # Mutating operations stage a 201; the read-only encrypt stages a 200.
        allowed_status = 200 if kind in _READ_ONLY_KINDS else 201
        if http_status != allowed_status:
            return False
        if kind in ("rotate", "import"):
            key_id = write_set[0] if write_set else None
            if response.get("key_id") != key_id:
                return False
            key = self.key_store._read_record(self.key_store._path_for(key_id))
            if key is None or key.tenant_id != tenant_id:
                return False
            if kind == "rotate":
                version = response.get("version")
                if not isinstance(version, int) or key.get_version(version) is None:
                    return False
        elif kind == "batch_rotate":
            items = response.get("items")
            if not isinstance(items, list):
                return False
            response_keys = set()
            for item in items:
                if not isinstance(item, dict):
                    return False
                key_id = item.get("key_id")
                if not _is_key_id(key_id):
                    return False
                response_keys.add(key_id)
                key = self.key_store._read_record(
                    self.key_store._path_for(key_id)
                )
                if key is None or key.tenant_id != tenant_id:
                    return False
                version = item.get("version")
                if not isinstance(version, int) or key.get_version(version) is None:
                    return False
            if response_keys != set(write_set):
                return False
        elif kind == "encrypt":
            # The read-only encrypt creates nothing: the key must still exist
            # for the mirror's tenant and the staged envelope must name that
            # same key and one of its existing versions. The envelope bytes
            # themselves are opaque -- only structural metadata is checked.
            from . import envelope as envelope_mod

            key_id = write_set[0] if write_set else None
            if response.get("format") != envelope_mod.FORMAT:
                return False
            if response.get("operation_id") != descriptor.get("operation_id"):
                return False
            token = response.get("envelope")
            if not isinstance(token, str) or not token:
                return False
            try:
                opened = envelope_mod.decode_envelope(token)
            except Exception:
                return False
            if opened.key_id != key_id:
                return False
            key = self.key_store._read_record(self.key_store._path_for(key_id))
            if key is None or key.tenant_id != tenant_id:
                return False
            if key.get_version(opened.version) is None:
                return False
        elif kind == "restore":
            key_ids = response.get("key_ids")
            if not isinstance(key_ids, list) or sorted(key_ids) != sorted(
                write_set
            ):
                return False
            if response.get("policy_restored") != bool(descriptor.get("policy")):
                return False
            for key_id in write_set:
                key = self.key_store._read_record(
                    self.key_store._path_for(key_id)
                )
                if key is None or key.tenant_id != tenant_id:
                    return False
        return True

    def _committed_state_verified(self, descriptor: dict) -> bool:
        """Verify the committed write set and every surviving reference.

        Every write-set key file must exist, belong to the mirror's tenant,
        carry no unresolved pending marker of this operation and own every
        (provider_id, handle) the mirror recorded; a restore that carried a
        policy leaves the tenant's committed policy document, and an empty
        restore leaves its finalized (event-cleared) marker. The provision
        journal and a batch snapshot are post-commit housekeeping and must
        already be gone. Finally every surviving on-disk reference must be
        cross-consistent with the mirror (a missing/corrupt/duplicate/extra
        reference keeps the mirror for the next open).
        """
        if not self._descriptor_consistent(descriptor, allow_undescribed=False):
            return False
        operation_id = descriptor["operation_id"]
        journal_id = descriptor.get("journal") or operation_id
        if os.path.exists(self.key_store._provision_path(journal_id)):
            return False
        if descriptor.get("snapshot") and os.path.exists(
            self.key_store._batch_snapshot_path(descriptor["snapshot"])
        ):
            return False
        kind = descriptor.get("kind")
        tenant_id = descriptor.get("tenant_id")
        owned = set()
        for key_id in descriptor.get("write_set", []):
            record = self.key_store._read_record(self.key_store._path_for(key_id))
            if record is None or record.tenant_id != tenant_id:
                return False
            marker = getattr(record, "pending_event", None)
            if isinstance(marker, dict) and self._marker_event_id(
                marker
            ) == operation_id:
                return False
            for ver in record.versions:
                owned.add((ver.provider_id, ver.handle))
        expected = {
            (entry.get("provider_id"), entry.get("handle"))
            for entry in descriptor.get("handles", [])
            if isinstance(entry, dict)
        }
        if not expected.issubset(owned):
            return False
        if kind == "restore" and not self._committed_restore_extras_verified(
            descriptor
        ):
            return False
        if not self._surviving_artifacts_consistent(descriptor):
            return False
        return True

    def _committed_restore_extras_verified(self, descriptor: dict) -> bool:
        """Committed restore policy document and empty-restore marker checks."""
        tenant_id = descriptor.get("tenant_id")
        if descriptor.get("policy"):
            doc = self._read_policy_doc(self._policy_doc_path(tenant_id))
            if doc is None:
                return False
            owner, pending = doc
            if owner != tenant_id:
                return False
            if isinstance(pending, dict) and self._marker_event_id(
                pending
            ) == descriptor.get("operation_id"):
                return False
        if not descriptor.get("write_set") and not descriptor.get("policy"):
            # An empty restore commits only its persistent marker: it must
            # survive, be finalized (event cleared) and name this tenant.
            path = descriptor.get("empty_marker")
            if not isinstance(path, str) or not os.path.exists(path):
                return False
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    marker = json.load(fh)
            except (OSError, ValueError):
                return False
            if not isinstance(marker, dict) or not marker.get("_empty"):
                return False
            if marker.get("tenant_id") != tenant_id or marker.get("event") is not None:
                return False
        return True

    def _policy_doc_path(self, tenant_id: str) -> str:
        # Mirror PolicyStore._path_for WITHOUT constructing a PolicyStore: its
        # constructor runs outbox recovery, which a read-only verification must
        # never trigger as a side effect.
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return os.path.join(self.data_dir, "policies", digest + ".json")

    def _read_policy_doc(self, path: str):
        """Read (tenant_id, pending_event) from a policy file, side-effect free.

        Rules are not validated here -- only the owning tenant and the pending
        marker are cross-checked -- so this never instantiates PolicyStore (and
        never runs its startup outbox recovery). Returns None when the file is
        absent or unreadable.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(doc, dict):
            return None
        return doc.get("tenant_id"), doc.get("pending_event")

    # -- surviving-artifact cross-validation -------------------------------
    def _surviving_artifacts_consistent(self, descriptor: dict) -> bool:
        """Whether every surviving on-disk reference cross-agrees.

        Returns False when a surviving reference is missing, corrupt,
        duplicated or carries more/fewer facts than the mirror; the caller
        then keeps the whole evidence set. Absence of an artifact the attempt
        legitimately removed is fine.
        """
        try:
            self._journal_verdict(descriptor)
            kind = descriptor.get("kind")
            if kind == "batch_rotate":
                self._snapshot_verdict(descriptor)
            elif descriptor.get("snapshot"):
                return False
            if kind == "restore":
                self._restore_artifacts_verdict(descriptor)
            elif isinstance(descriptor.get("empty_marker"), str):
                return False
        except ArtifactInconsistent:
            return False
        return True

    def _journal_verdict(self, descriptor: dict) -> None:
        """Cross-check a surviving provision journal against the mirror.

        Compares the journal's operation header (operation_id/tenant/action)
        and its exact provider_id/handle SET with the mirror: a corrupt,
        duplicated or extra entry is an inconsistency. Legacy headerless
        journals keep id-only resolution, but their handle set must still
        equal the mirror's. Absence is fine. Raises ArtifactInconsistent.
        """
        operation_id = descriptor["operation_id"]
        journal_id = descriptor.get("journal") or operation_id
        path = self.key_store._provision_path(journal_id)
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw_lines = [
                    line for line in fh.read().splitlines() if line.strip()
                ]
        except OSError as exc:
            raise ArtifactInconsistent(str(exc))
        entries = []
        header = None
        for index, raw in enumerate(raw_lines):
            try:
                line = json.loads(raw)
            except ValueError:
                raise ArtifactInconsistent("corrupt provision journal line")
            if not isinstance(line, dict):
                raise ArtifactInconsistent(
                    "provision journal line is not an object"
                )
            if index == 0 and "operation_id" in line:
                header = line
                continue
            provider_id = line.get("provider_id")
            handle = line.get("handle")
            if not (
                isinstance(provider_id, str)
                and provider_id
                and isinstance(handle, str)
                and handle
            ):
                raise ArtifactInconsistent("provision journal entry is malformed")
            entries.append((provider_id, handle))
        kind = descriptor.get("kind")
        if header is not None:
            if header.get("operation_id") != journal_id:
                raise ArtifactInconsistent(
                    "provision journal header names another operation"
                )
            if kind is not None:
                if header.get("tenant_id") != descriptor.get("tenant_id"):
                    raise ArtifactInconsistent(
                        "provision journal tenant disagrees with the mirror"
                    )
                if header.get("action") != descriptor.get("action"):
                    raise ArtifactInconsistent(
                        "provision journal action disagrees with the mirror"
                    )
        pairs = set()
        for pair in entries:
            if pair in pairs:
                raise ArtifactInconsistent(
                    "duplicate handle entry in provision journal"
                )
            pairs.add(pair)
        mirrored = {
            (entry.get("provider_id"), entry.get("handle"))
            for entry in descriptor.get("handles", [])
            if isinstance(entry, dict)
        }
        if pairs != mirrored:
            raise ArtifactInconsistent(
                "provision journal handle set disagrees with the mirror"
            )

    @staticmethod
    def _marker_event_id(marker) -> Optional[str]:
        """The event id a (possibly nested) pending marker names."""
        if not isinstance(marker, dict):
            return None
        nested = marker.get("event")
        desc = nested if isinstance(nested, dict) else marker
        event_id = desc.get("event_id") if isinstance(desc, dict) else None
        return event_id if isinstance(event_id, str) else None

    def _scan_pending_markers(self, operation_id: str) -> list:
        """All surviving pending markers (key files, policy doc) naming an id."""
        found = []
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            return found
        for name in names:
            if not (name.endswith(".json") and _is_key_id(name[:-5])):
                continue
            record = self.key_store._read_record(os.path.join(self.data_dir, name))
            marker = getattr(record, "pending_event", None)
            if isinstance(marker, dict) and self._marker_event_id(
                marker
            ) == operation_id:
                found.append(("key", record.key_id, marker))
        policy_dir = os.path.join(self.data_dir, "policies")
        try:
            policy_names = os.listdir(policy_dir)
        except OSError:
            return found
        for name in policy_names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(policy_dir, name)
            doc = self._read_policy_doc(path)
            owner = None
            pending = None
            if doc is None:
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        raw = json.load(fh)
                except (OSError, ValueError):
                    continue
                if isinstance(raw, dict):
                    owner = raw.get("tenant_id")
                    pending = raw.get("pending_event")
            else:
                owner, pending = doc
            if isinstance(pending, dict) and self._marker_event_id(
                pending
            ) == operation_id:
                found.append(("policy", owner, pending))
        return found

    def _snapshot_verdict(self, descriptor: dict) -> None:
        """Cross-check a surviving batch snapshot against the mirror.

        Filename/event id, tenant, the exact key_id set, and every
        ``previous_b64`` image (strictly decoded into a tenant-matching,
        version-contiguous KeyRecord with no pending marker) must agree with
        the mirror and with every residual batch marker. A surviving snapshot
        the mirror never named, or a referenced but corrupt/mismatched one,
        is an inconsistency.
        """
        operation_id = descriptor["operation_id"]
        tenant_id = descriptor.get("tenant_id")
        referenced = descriptor.get("snapshot")
        expected_id = referenced or operation_id
        path = self.key_store._batch_snapshot_path(expected_id)
        present = os.path.exists(path)
        if referenced is None:
            if present:
                raise ArtifactInconsistent(
                    "unnamed batch snapshot survives for the operation"
                )
            return
        if not present:
            # Referenced but gone: legitimate only after a verified rollback;
            # the residual-marker scan decides whether files still need it.
            return
        raw = self.key_store._read_batch_snapshot(expected_id)
        if not isinstance(raw, dict):
            raise ArtifactInconsistent("batch snapshot is missing or corrupt")
        if raw.get("event_id") != expected_id:
            raise ArtifactInconsistent(
                "batch snapshot event_id disagrees with its filename"
            )
        if raw.get("tenant_id") != tenant_id:
            raise ArtifactInconsistent(
                "batch snapshot tenant disagrees with the mirror"
            )
        snapshot_keys = set()
        for entry in raw.get("keys", []):
            if not isinstance(entry, dict) or not _is_key_id(entry.get("key_id")):
                raise ArtifactInconsistent("batch snapshot key entry is malformed")
            snapshot_keys.add(entry["key_id"])
        if snapshot_keys != set(descriptor.get("write_set", [])):
            raise ArtifactInconsistent(
                "batch snapshot key set disagrees with the mirror write set"
            )
        markers = [
            marker
            for _where, _owner, marker in self._scan_pending_markers(
                operation_id
            )
            if isinstance(marker, dict) and marker.get("_batch_rotate")
        ]
        if self.key_store._validated_batch_snapshot(
            expected_id, raw, markers
        ) is None:
            raise ArtifactInconsistent(
                "batch snapshot contents or residual markers are invalid"
            )

    def _restore_artifacts_verdict(self, descriptor: dict) -> None:
        """Cross-check surviving restore markers (multi-file and empty)."""
        operation_id = descriptor["operation_id"]
        tenant_id = descriptor.get("tenant_id")
        write_set = set(descriptor.get("write_set", []))
        for where, owner, marker in self._scan_pending_markers(operation_id):
            if not isinstance(marker, dict) or not marker.get("_restore"):
                raise ArtifactInconsistent(
                    "a pending marker naming the restore is not a restore marker"
                )
            if marker.get("_empty"):
                continue
            desc = marker.get("event")
            if not isinstance(desc, dict):
                raise ArtifactInconsistent("restore marker carries no event")
            if desc.get("event_id") != operation_id:
                raise ArtifactInconsistent("restore marker names another event")
            if desc.get("action") != audit_mod.ACTION_IMPORT:
                raise ArtifactInconsistent(
                    "restore marker event action is not import"
                )
            if desc.get("tenant_id") != tenant_id or marker.get(
                "tenant_id"
            ) != tenant_id:
                raise ArtifactInconsistent(
                    "restore marker tenant disagrees with the mirror"
                )
            key_ids = marker.get("key_ids")
            if not isinstance(key_ids, list) or set(key_ids) != write_set:
                raise ArtifactInconsistent(
                    "restore marker write set disagrees with the mirror"
                )
            if bool(marker.get("policy")) != bool(descriptor.get("policy")):
                raise ArtifactInconsistent(
                    "restore marker policy flag disagrees with the mirror"
                )
            journal = marker.get("journal")
            if journal is not None and journal != operation_id:
                raise ArtifactInconsistent(
                    "restore marker journal does not name the operation"
                )
            if where == "policy" and owner != tenant_id:
                raise ArtifactInconsistent(
                    "restored policy document names another tenant"
                )
        empty_path = descriptor.get("empty_marker")
        if isinstance(empty_path, str) and os.path.exists(empty_path):
            try:
                with open(empty_path, "r", encoding="utf-8") as fh:
                    marker = json.load(fh)
            except (OSError, ValueError):
                raise ArtifactInconsistent("empty restore marker is corrupt")
            if not isinstance(marker, dict) or not marker.get("_empty"):
                raise ArtifactInconsistent("empty restore marker is malformed")
            if marker.get("tenant_id") != tenant_id:
                raise ArtifactInconsistent(
                    "empty restore marker tenant disagrees with the mirror"
                )
            event = marker.get("event")
            if event is None:
                return
            if not isinstance(event, dict):
                raise ArtifactInconsistent(
                    "empty restore marker event is malformed"
                )
            if event.get("event_id") != operation_id:
                raise ArtifactInconsistent(
                    "empty restore marker names another event"
                )
            if (
                event.get("action") != audit_mod.ACTION_IMPORT
                or event.get("tenant_id") != tenant_id
            ):
                raise ArtifactInconsistent(
                    "empty restore marker event disagrees with the mirror"
                )

    def _residual_evidence(self, descriptor: dict) -> bool:
        """Whether uncommitted-attempt artifacts still survive on disk.

        Scans the provision journal, the batch snapshot, the restore empty
        marker and every key/policy file carrying a pending marker named after
        this operation. The outbox recovery leaves these in place exactly while
        it is parking the scene (unreadable ledger, unreachable provider,
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
        return bool(self._scan_pending_markers(operation_id))

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


def _is_uuid4(value: str) -> bool:
    try:
        return uuid.UUID(value).version == 4
    except (ValueError, AttributeError, TypeError):
        return False


def _is_key_id(value) -> bool:
    """Canonical lowercase UUID4 check (lazy import avoids a store cycle)."""
    from .store import is_valid_key_id

    return is_valid_key_id(value)
