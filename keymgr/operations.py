"""Idempotent operations for key rotate / import / tenant restore.

The three mutating endpoints

* ``POST /v1/keys/{key_id}/rotate``
* ``POST /v1/keys/import``
* ``POST /v1/restore``

accept an ``Idempotency-Key`` header (CLI: ``--idempotency-key``). A key is
1-128 ASCII characters from ``[A-Za-z0-9._~-]``; a missing, empty, duplicated
or illegal header is a ``400`` (CLI exit ``2``) with no side effects.

A binding is the triple ``(tenant_id, operator, idempotency_key)``. The first
request mints a UUID4 ``operation_id`` (also used as the committing audit
``event_id``), records a ``pending`` operation, and is the only request that
submits. A retry with the same binding and the same canonicalized body reuses
the stored status code, response and audit event; the same binding with a
different body (or path) answers ``409`` naming the existing operation_id.
Concurrent requests for one binding serialize; a request that waits more than
five seconds on the binding lock answers ``503`` ``timed_out`` without
writing keys, audit events or provider handles.

Operation state: ``pending`` / ``succeeded`` / ``failed`` / ``conflict`` /
``timed_out``. Every response produced for a bound operation carries its
``operation_id``; error bodies contain only ``error`` and ``operation_id``.

``GET /v1/operations/{operation_id}`` is scoped to one tenant and operator:
``200`` gives ``operation_id``, ``tenant_id``, ``status``, ``http_status`` and
``response`` (the last two null while pending); an unknown id or another
tenant's (or operator's) operation answers ``404``.

Crash recovery keys on operation_id == event_id: at startup each leftover
pending operation is finalized from the ledger/outbox state, and half-written
files and provider handles are reaped by the existing outbox/provision
recovery. The semantics are identical over HTTP and the CLI.
"""

import hashlib
import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import audit as audit_mod
from . import keybundle
from . import tenantbundle
from .audit import LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .provider import ProviderInvalidMaterial, ProviderUnavailable
from .restore import (
    RESTORE_CREATED,
    RESTORE_SAME_TENANT_CONFLICT,
)
from .store import IMPORT_CONFLICT, is_valid_key_id

try:  # fcntl is POSIX-only; binding locks degrade to in-process elsewhere.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Endpoints covered by idempotency, and their logical (canonical) paths. The
# CLI synthesizes the same path strings so HTTP and CLI share one fingerprint
# space.
OP_ROTATE = "rotate"
OP_IMPORT = "import"
OP_RESTORE = "restore"

ROTATE_PATH = "/v1/keys/%s/rotate"
IMPORT_PATH = "/v1/keys/import"
RESTORE_PATH = "/v1/restore"

#: Operation states.
STATUS_PENDING = "pending"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_CONFLICT = "conflict"
STATUS_TIMED_OUT = "timed_out"

#: Wait bound for a binding lock, after which the waiter answers timed_out.
LOCK_WAIT_SECONDS = 5.0

_DIR_NAME = "operations"


class IdempotencyKeyError(ValueError):
    """The Idempotency-Key header/argument is missing, empty or illegal.

    Surfaced as HTTP ``400`` / CLI exit ``2`` before any operation state is
    created (no side effects).
    """


class BindingConflict(Exception):
    """Same (tenant, operator, key) binding is reused with another request.

    The conflicting request answers ``409`` naming the *existing*
    operation_id; no new operation is created and the existing one is not
    modified.
    """

    def __init__(self, existing_operation_id: str) -> None:
        super().__init__("idempotency key is bound to a different request")
        self.existing_operation_id = existing_operation_id


class BindingTimeout(Exception):
    """Waiting on a binding lock took longer than ``LOCK_WAIT_SECONDS``.

    Nothing is written by the waiter. ``operation_id`` is the in-flight
    binding's operation when its record was already observable.
    """

    def __init__(self, operation_id: Optional[str] = None) -> None:
        super().__init__("timed out waiting for idempotent operation lock")
        self.operation_id = operation_id


def is_valid_idempotency_key(value) -> bool:
    """True for 1-128 chars of [A-Za-z0-9._~-] (ASCII only)."""
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    for ch in value:
        if not (
            "a" <= ch <= "z"
            or "A" <= ch <= "Z"
            or "0" <= ch <= "9"
            or ch in "._~-"
        ):
            return False
    return True


def canonical_fingerprint(path: str, payload: dict) -> str:
    """SHA-256 over the canonical path plus canonicalized JSON body.

    The body is re-serialized with sorted keys and compact separators, so two
    requests differing only in JSON whitespace or key order are the same
    request; any field difference is a different request.
    """
    body = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256()
    digest.update(path.encode("utf-8"))
    digest.update(b"\n")
    digest.update(body.encode("utf-8"))
    return digest.hexdigest()


@dataclass
class OperationRecord:
    """One idempotent operation, persisted as a single 0600 JSON file."""

    operation_id: str
    idempotency_key: str
    tenant_id: str
    operator: str
    path: str
    request_fingerprint: str
    status: str = STATUS_PENDING
    http_status: Optional[int] = None
    response: Optional[dict] = None
    intent: Optional[dict] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    # Outbox marker for a terminal rejection whose audit event has not yet
    # been durably appended. Mirrors the key/policy outbox: the terminal
    # status and response land together with the marker, the ledger append
    # follows (idempotent on operation_id == event_id), and the marker is
    # then cleared. A crash in between is repaired on the next open.
    pending_event: Optional[dict] = None

    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "version": 1,
            "operation_id": self.operation_id,
            "idempotency_key": self.idempotency_key,
            "tenant_id": self.tenant_id,
            "operator": self.operator,
            "path": self.path,
            "request_fingerprint": self.request_fingerprint,
            "status": self.status,
            "http_status": self.http_status,
            "response": self.response,
            "intent": self.intent,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "pending_event": self.pending_event,
        }

    @classmethod
    def from_json(cls, data: dict) -> "OperationRecord":
        return cls(
            operation_id=data["operation_id"],
            idempotency_key=data["idempotency_key"],
            tenant_id=data["tenant_id"],
            operator=data["operator"],
            path=data["path"],
            request_fingerprint=data["request_fingerprint"],
            status=data.get("status", STATUS_PENDING),
            http_status=data.get("http_status"),
            response=data.get("response"),
            intent=data.get("intent"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            pending_event=data.get("pending_event"),
        )

    def to_status_response(self) -> dict:
        """Body of GET /v1/operations/{operation_id}.

        http_status and response are both null while the operation is
        pending; a terminal operation carries the exact status code and the
        exact response body a retry would receive.
        """
        if self.status == STATUS_PENDING:
            http_status = None
            response = None
        else:
            http_status = self.http_status
            response = self.response
        return {
            "operation_id": self.operation_id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "http_status": http_status,
            "response": response,
        }

    @property
    def terminal(self) -> bool:
        return self.status in (
            STATUS_SUCCEEDED,
            STATUS_FAILED,
            STATUS_CONFLICT,
            STATUS_TIMED_OUT,
        )


class _ExecError(Exception):
    """An executor-raised terminal failure of a bound operation.

    The pinned audit event (when one is due) has already been written by the
    executor before raising. ``op_status`` is the operation state to persist
    (``failed`` for every terminal error except a same-tenant 409, which is
    ``conflict``).
    """

    def __init__(self, http_status: int, message: str,
                 op_status: str = STATUS_FAILED) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.op_status = op_status


class _RebuildUnavailable(Exception):
    """A committed operation's success response cannot be rebuilt yet."""


class OperationStore:
    """Persistent idempotent-operation records and their execution facade."""

    def __init__(self, data_dir: str, store, policy_store, coordinator) -> None:
        self.data_dir = data_dir
        self.dir_path = os.path.join(data_dir, _DIR_NAME)
        self.bindings_dir = os.path.join(self.dir_path, "bindings")
        os.makedirs(self.bindings_dir, exist_ok=True)
        self.store = store
        self.policy_store = policy_store
        self.coordinator = coordinator
        self.audit = store.audit
        # One in-process lock per binding, serializing threads in this
        # process; an fcntl lock on a per-binding sidecar file serializes
        # separate processes (HTTP servers and CLI invocations alike).
        self._locks_guard = threading.Lock()
        self._binding_locks: dict = {}
        # Finalize operations interrupted by a crash (the key/outbox stores'
        # own recovery, constructed before this one, has already reaped
        # half-written files and provider handles).
        self.recover_pending()

    # -- paths / locks -----------------------------------------------------
    @staticmethod
    def _binding_hash(tenant_id: str, operator: str, idempotency_key: str) -> str:
        digest = hashlib.sha256()
        digest.update(tenant_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(operator.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(idempotency_key.encode("utf-8"))
        return digest.hexdigest()

    def _op_path(self, operation_id: str) -> str:
        return os.path.join(self.dir_path, operation_id + ".json")

    def _pointer_path(self, binding_hash: str) -> str:
        return os.path.join(self.bindings_dir, binding_hash + ".json")

    def _lock_path(self, binding_hash: str) -> str:
        return os.path.join(self.bindings_dir, binding_hash + ".lock")

    def _binding_lock(self, binding_hash: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._binding_locks.get(binding_hash)
            if lock is None:
                lock = threading.Lock()
                self._binding_locks[binding_hash] = lock
            return lock

    def _write_atomic(self, path: str, payload: dict) -> None:
        """Atomically write a 0600 JSON file (fsync + rename)."""
        directory = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
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

    def _persist(self, record: OperationRecord) -> None:
        record.updated_at = datetime.now(timezone.utc).isoformat()
        self._write_atomic(self._op_path(record.operation_id), record.to_json())

    def _read_op(self, operation_id: str) -> Optional[OperationRecord]:
        if not _is_uuid4(operation_id):
            return None
        try:
            with open(self._op_path(operation_id), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            return OperationRecord.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None

    def _read_pointer(self, binding_hash: str) -> Optional[str]:
        try:
            with open(
                self._pointer_path(binding_hash), "r", encoding="utf-8"
            ) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        operation_id = data.get("operation_id") if isinstance(data, dict) else None
        return operation_id if isinstance(operation_id, str) else None

    def _create_pointer(self, binding_hash: str, operation_id: str) -> Optional[str]:
        """Claim a binding for one operation. None on success, else the
        operation id another request won the race with."""
        path = self._pointer_path(binding_hash)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self._read_pointer(binding_hash)
        try:
            os.write(fd, json.dumps({"operation_id": operation_id}).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return None

    class _BindingHeld:
        """Handle to an acquired cross-process binding lock."""

        def __init__(self, fd: Optional[int], thread_lock) -> None:
            self.fd = fd
            self.thread_lock = thread_lock

        def release(self) -> None:
            if self.fd is not None:
                try:
                    if fcntl is not None:
                        fcntl.flock(self.fd, fcntl.LOCK_UN)
                finally:
                    os.close(self.fd)
                self.fd = None
            self.thread_lock.release()

    def _acquire_binding(
        self, binding_hash: str
    ) -> "_BindingHeld":
        """Acquire the binding lock, waiting at most LOCK_WAIT_SECONDS.

        The in-process lock is taken with a timeout; the cross-process
        ``fcntl`` lock is polled non-blocking. On timeout BindingTimeout is
        raised (best-effort carrying the in-flight operation id); the waiter
        has written nothing.
        """
        thread_lock = self._binding_lock(binding_hash)
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        if not thread_lock.acquire(timeout=LOCK_WAIT_SECONDS):
            raise BindingTimeout(self._read_pointer(binding_hash))
        try:
            fd = os.open(
                self._lock_path(binding_hash), os.O_RDWR | os.O_CREAT, 0o600
            )
        except OSError:
            thread_lock.release()
            raise
        try:
            while True:
                if fcntl is None:
                    break
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        os.close(fd)
                        thread_lock.release()
                        raise BindingTimeout(
                            self._read_pointer(binding_hash)
                        )
                    time.sleep(0.05)
        except BaseException:
            os.close(fd)
            thread_lock.release()
            raise
        return self._BindingHeld(fd, thread_lock)

    # -- public read -------------------------------------------------------
    def get_operation(
        self,
        operation_id: str,
        tenant_id: str,
        operator: str,
    ) -> Optional[OperationRecord]:
        """Return an operation owned by this tenant AND operator, else None.

        An unknown id, another tenant's operation, or another operator's
        operation all answer None so existence never leaks.
        """
        record = self._read_op(operation_id)
        if record is None:
            return None
        if record.tenant_id != tenant_id or record.operator != operator:
            return None
        return record

    # -- crash recovery ----------------------------------------------------
    def recover_pending(self) -> None:
        """Finalize operations interrupted by a crash.

        Pass 1 finishes any terminal record still carrying an outbox marker
        (append is idempotent on operation_id). Pass 2 resolves pending
        records from the ledger: a pinned success event commits the
        operation (response rebuilt from durable state); with no event, a
        pointer-bound operation stays pending for a same-binding retry, while
        an orphan (file landed but its pointer never did) is finalized
        failed. The key/outbox stores have already reaped any half-written
        files and provider handles keyed by the same ids.
        """
        try:
            names = os.listdir(self.dir_path)
        except OSError:
            return
        records = []
        for name in names:
            if not name.endswith(".json"):
                continue
            record = self._read_op(name[:-5])
            if record is not None:
                records.append(record)
        # Pass 1: finish terminal records whose rejected event may not yet
        # have been appended (the record and marker landed, then a crash).
        for record in records:
            if record.pending_event:
                self._resolve_marker(record)
        # Pass 2: resolve the pending records.
        for record in records:
            if record.status != STATUS_PENDING:
                continue
            try:
                event = self.audit.get_event(record.operation_id)
            except LedgerError:
                # The ledger cannot be read right now; leave it pending for a
                # later open or a live same-binding request to resolve.
                continue
            if event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS:
                try:
                    self._rebuild_success(record, event)
                except _RebuildUnavailable:
                    continue
            elif event is not None:
                # A rejected event belongs to a terminal record; a pending
                # record naming one is an interrupted stray — mark failed.
                self._terminalize(
                    record, 500,
                    "operation interrupted before completion",
                    STATUS_FAILED,
                )
            else:
                # No committing event. When the binding pointer still names
                # this operation, a same-binding retry (which carries the
                # body again) re-executes under the same operation_id, so
                # leave it pending. If the pointer is missing or points at
                # another operation, this record died in the window after
                # its file landed but before the pointer was created: it has
                # no key, event or handle, and can never be replayed by a
                # client, so finalize it as a failed (interrupted) op.
                binding_hash = self._binding_hash(
                    record.tenant_id, record.operator,
                    record.idempotency_key,
                )
                pointed = self._read_pointer(binding_hash)
                if pointed != record.operation_id:
                    self._terminalize(
                        record, 500,
                        "operation interrupted before completion",
                        STATUS_FAILED,
                    )

    def _resume_pending(self, record: OperationRecord) -> bool:
        """Resolve a pending record from the ledger before a live retry.

        True when the record was finalized (committed success); False when
        its event is absent, i.e. nothing committed and the caller should
        re-execute under the same operation_id.
        """
        event = self.audit.get_event(record.operation_id)
        if event is None:
            return False
        if event.outcome == audit_mod.OUTCOME_SUCCESS:
            try:
                self._rebuild_success(record, event)
            except _RebuildUnavailable as exc:
                # The success event is durable but its response could not be
                # rebuilt. Never re-execute (that would duplicate the
                # mutation); surface a 500 and leave the record pending for
                # a later retry.
                raise LedgerError(
                    "committed operation %s cannot be rebuilt yet"
                    % record.operation_id
                ) from exc
            return True
        self._terminalize(
            record, 500, "operation interrupted before completion",
            STATUS_FAILED,
        )
        return True

    # -- terminal states ---------------------------------------------------
    def _terminalize(
        self,
        record: OperationRecord,
        http_status: int,
        message: Optional[str],
        op_status: str,
        response: Optional[dict] = None,
    ) -> None:
        if response is None:
            response = {
                "error": message,
                "operation_id": record.operation_id,
            }
        record.status = op_status
        record.http_status = http_status
        record.response = response
        self._persist(record)

    def _succeed(
        self, record: OperationRecord, http_status: int, body: dict
    ) -> None:
        response = dict(body)
        response["operation_id"] = record.operation_id
        # The committing success event is owned by the key/restore outbox; a
        # success record carries no operation-level pending marker.
        record.pending_event = None
        self._terminalize(
            record, http_status, None, STATUS_SUCCEEDED, response=response
        )

    def _rejection_event(
        self, record: OperationRecord, tenant_id, key_id, action, invisible
    ):
        """Mint the pinned rejected event (the tenant_conflict collapse
        mirrors KeyStore.audit_attempt)."""
        if (
            not invisible
            and isinstance(tenant_id, str)
            and tenant_id
            and (key_id is None or is_valid_key_id(key_id))
        ):
            return self.audit.new_event(
                tenant_id, action, key_id, audit_mod.OUTCOME_REJECTED,
                event_id=record.operation_id,
            )
        return self.audit.new_event(
            None, audit_mod.ACTION_TENANT_CONFLICT, None,
            audit_mod.OUTCOME_REJECTED, event_id=record.operation_id,
        )

    def _resolve_marker(self, record: OperationRecord) -> bool:
        """Finish a terminal record's carried outbox marker.

        Appends the pinned event (idempotent on operation_id) and clears the
        marker. False means the ledger append failed and the marker stays.
        """
        marker = record.pending_event
        if not marker:
            return True
        try:
            from .audit import AuditEvent
            self.audit.append(AuditEvent.from_json(marker))
        except LedgerError:
            return False
        record.pending_event = None
        try:
            self._persist(record)
        except OSError:
            # The event is durable; a later open clears the marker.
            pass
        return True

    def _reject(
        self,
        record: OperationRecord,
        http_status: int,
        message: str,
        op_status: str = STATUS_FAILED,
        *,
        tenant_id=None,
        key_id=None,
        action=None,
        invisible: bool = False,
    ) -> None:
        """Commit a terminal error and its rejected event as one outbox.

        The terminal status/response land together with the pending marker,
        the pinned event is appended durably (idempotent on
        operation_id), then the marker is cleared. A crash anywhere in
        between is repaired on the next open; a replay reuses the exact
        event. If the ledger append itself fails the request is a 500 (the
        staged 4xx is overwritten).
        """
        event = self._rejection_event(
            record, tenant_id, key_id, action, invisible
        )
        record.status = op_status
        record.http_status = http_status
        record.response = {
            "error": message,
            "operation_id": record.operation_id,
        }
        record.pending_event = event.to_json()
        self._persist(record)
        if not self._resolve_marker(record):
            message500 = "audit ledger failure while finalizing operation"
            record.pending_event = None
            self._terminalize(record, 500, message500, STATUS_FAILED)
            raise _ExecError(500, message500, STATUS_FAILED)
        raise _ExecError(http_status, message, op_status)

    def _provider_failure(self, record: OperationRecord) -> None:
        """Terminalize a provider backend fault as 503 (no audit event)."""
        self._terminalize(
            record, 503, "key management provider is unavailable",
            STATUS_FAILED,
        )
        raise _ExecError(
            503, "key management provider is unavailable", STATUS_FAILED
        )

    def _ledger_failure(self, record: OperationRecord, exc) -> None:
        """Terminalize a ledger/persistence failure as 500."""
        message = "audit ledger failure: %s" % exc
        self._terminalize(record, 500, message, STATUS_FAILED)
        raise _ExecError(500, message, STATUS_FAILED)

    # -- entry points used by the HTTP handlers and the CLI ---------------
    def run_rotate(
        self,
        *,
        tenant_id: str,
        operator: str,
        idempotency_key: str,
        key_id: str,
        payload: dict,
    ) -> OperationRecord:
        """Run (or replay) an idempotent rotate."""
        return self._run(
            OP_ROTATE, tenant_id, operator, idempotency_key,
            ROTATE_PATH % key_id, payload,
            {"kind": OP_ROTATE, "key_id": key_id},
        )

    def run_import(
        self,
        *,
        tenant_id: str,
        operator: str,
        idempotency_key: str,
        payload: dict,
    ) -> OperationRecord:
        """Run (or replay) an idempotent single-key import."""
        return self._run(
            OP_IMPORT, tenant_id, operator, idempotency_key,
            IMPORT_PATH, payload, {"kind": OP_IMPORT},
        )

    def run_restore(
        self,
        *,
        tenant_id: str,
        operator: str,
        idempotency_key: str,
        payload: dict,
    ) -> OperationRecord:
        """Run (or replay) an idempotent tenant restore."""
        return self._run(
            OP_RESTORE, tenant_id, operator, idempotency_key,
            RESTORE_PATH, payload, {"kind": OP_RESTORE},
        )

    def _run(
        self,
        kind: str,
        tenant_id: str,
        operator: str,
        idempotency_key: str,
        path: str,
        payload: dict,
        intent: dict,
    ) -> OperationRecord:
        """Claim the binding, then execute exactly once under its lock.

        A terminal record for the same binding+fingerprint is replayed
        as-is. The same binding with another path/body raises
        BindingConflict.
        A pending record left by a crashed process is resolved from the
        ledger when possible, otherwise re-executed under the same
        operation_id. The binding lock is held for the whole execution, so
        concurrent same-binding requests wait (and time out after five
        seconds without side effects).
        """
        if not is_valid_idempotency_key(idempotency_key):
            raise IdempotencyKeyError(
                "Idempotency-Key must be 1-128 characters from "
                "[A-Za-z0-9._~-]"
            )
        fingerprint = canonical_fingerprint(path, payload)
        binding_hash = self._binding_hash(tenant_id, operator, idempotency_key)
        try:
            held = self._acquire_binding(binding_hash)
        except BindingTimeout:
            # The waiter submits nothing: no key file, audit event or
            # provider handle is produced. It still gets its own terminal
            # timed_out record (it never claims the binding pointer, which
            # stays owned by the in-flight operation) so its 503 response
            # carries an operation_id and GET can observe it.
            waiter = OperationRecord(
                operation_id=str(uuid.uuid4()),
                idempotency_key=idempotency_key,
                tenant_id=tenant_id,
                operator=operator,
                path=path,
                request_fingerprint=fingerprint,
                intent=dict(intent),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._terminalize(
                waiter, 503,
                "timed out waiting for idempotent operation lock",
                STATUS_TIMED_OUT,
            )
            raise BindingTimeout(waiter.operation_id)
        try:
            existing_id = self._read_pointer(binding_hash)
            if existing_id is not None:
                record = self._read_op(existing_id)
                if record is None:
                    # A pointer without its record is corrupt internal state.
                    raise LedgerError(
                        "idempotency binding %r has no operation record"
                        % idempotency_key
                    )
                if (
                    record.path != path
                    or record.request_fingerprint != fingerprint
                ):
                    raise BindingConflict(existing_id)
                if record.terminal:
                    # Finish a marker the startup sweep could not (e.g. the
                    # ledger was briefly unreadable); idempotent on event id.
                    if record.pending_event:
                        self._resolve_marker(record)
                    return record
                # The holder crashed mid-flight; commit from the ledger when
                # its event landed, otherwise re-run under the same id.
                if self._resume_pending(record):
                    return record
            else:
                operation_id = str(uuid.uuid4())
                record = OperationRecord(
                    operation_id=operation_id,
                    idempotency_key=idempotency_key,
                    tenant_id=tenant_id,
                    operator=operator,
                    path=path,
                    request_fingerprint=fingerprint,
                    intent=dict(intent),
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                # The pending record lands before the binding pointer, so a
                # pointer always names a readable operation.
                self._persist(record)
                winner = self._create_pointer(
                    binding_hash, operation_id
                )
                if winner is not None:
                    # Lost an O_EXCL race despite holding the lock (another
                    # process): re-read and follow the winner's record.
                    raced = self._read_op(winner)
                    if raced is None:
                        raise LedgerError("idempotency binding race")
                    if (
                        raced.path != path
                        or raced.request_fingerprint != fingerprint
                    ):
                        raise BindingConflict(winner)
                    if raced.terminal:
                        return raced
                    if self._resume_pending(raced):
                        return raced
                    record = raced
            try:
                self._execute(kind, record, payload)
            except _ExecError:
                pass
            return record
        finally:
            held.release()

    # -- execution ---------------------------------------------------------
    def _execute(self, kind: str, record: OperationRecord, payload: dict) -> None:
        if kind == OP_ROTATE:
            self._exec_rotate(record, payload)
        elif kind == OP_IMPORT:
            self._exec_import(record, payload)
        else:
            self._exec_restore(record, payload)

    def _exec_rotate(self, record: OperationRecord, payload: dict) -> None:
        tenant_id = record.tenant_id
        operator = record.operator
        key_id = record.intent["key_id"]
        algorithm = payload.get("algorithm")
        if not isinstance(algorithm, str):
            self._reject(
                record, 400, "missing required field: algorithm",
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_ROTATE,
            )
        if algorithm not in SUPPORTED_ALGORITHMS:
            self._reject(
                record, 400,
                "unsupported value for field algorithm: %r (supported: %s)"
                % (algorithm, ", ".join(SUPPORTED_ALGORITHMS)),
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_ROTATE,
            )
        if not self.policy_store.is_allowed(
            tenant_id, audit_mod.ACTION_ROTATE, operator
        ):
            self._reject(
                record, 403, "action not permitted by policy",
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_ROTATE,
            )
        try:
            key_record = self.store.rotate(
                key_id, tenant_id, algorithm,
                event_id=record.operation_id,
            )
        except ProviderUnavailable:
            self._provider_failure(record)
        except LedgerError as exc:
            self._ledger_failure(record, exc)
        if key_record is None:
            self._reject(
                record, 404, "key not found",
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_ROTATE,
            )
        # The pinned success event committed in the same outbox transaction
        # as the new version.
        self._succeed(record, 201, key_record.to_rotate_response())

    def _exec_import(self, record: OperationRecord, payload: dict) -> None:
        tenant_id = record.tenant_id
        operator = record.operator
        passphrase = payload.get("passphrase")
        if not isinstance(passphrase, str) or not passphrase:
            self._reject(
                record, 400, "field passphrase must be a non-empty string",
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        bundle = payload.get("bundle")
        if not isinstance(bundle, str) or not bundle:
            self._reject(
                record, 400, "field bundle must be a non-empty string",
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        try:
            decoded = keybundle.decode_bundle(bundle, passphrase)
        except keybundle.BundleError as exc:
            self._reject(
                record, 400, str(exc),
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        key_id = decoded["key_id"]
        if not self.policy_store.is_allowed(
            tenant_id, audit_mod.ACTION_IMPORT, operator
        ):
            self._reject(
                record, 403, "action not permitted by policy",
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_IMPORT,
            )
        # Remember enough to rebuild the exact 201 after a crash between the
        # commit point and the terminal record write.
        record.intent = {
            "kind": OP_IMPORT,
            "key_id": key_id,
            "current_version": decoded["current_version"],
        }
        self._persist(record)
        try:
            status, key_record = self.store.import_bundle(
                tenant_id, decoded, event_id=record.operation_id
            )
        except ProviderInvalidMaterial as exc:
            self._reject(
                record, 400, str(exc),
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_IMPORT,
            )
        except ProviderUnavailable:
            self._provider_failure(record)
        except LedgerError as exc:
            self._ledger_failure(record, exc)
        if status == IMPORT_CONFLICT:
            if key_record.tenant_id == tenant_id:
                self._reject(
                    record, 409,
                    "key_id already exists for this tenant",
                    STATUS_CONFLICT,
                    tenant_id=tenant_id, key_id=key_id,
                    action=audit_mod.ACTION_IMPORT,
                )
            self._reject(
                record, 404, "key not found",
                tenant_id=tenant_id, key_id=key_id,
                action=audit_mod.ACTION_IMPORT,
            )
        self._succeed(record, 201, key_record.to_create_response())

    def _exec_restore(self, record: OperationRecord, payload: dict) -> None:
        tenant_id = record.tenant_id
        operator = record.operator
        passphrase = payload.get("passphrase")
        if not isinstance(passphrase, str) or not passphrase:
            self._reject(
                record, 400, "field passphrase must be a non-empty string",
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        bundle = payload.get("bundle")
        if not isinstance(bundle, str) or not bundle:
            self._reject(
                record, 400, "field bundle must be a non-empty string",
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        try:
            decoded = tenantbundle.decode_bundle(bundle, passphrase)
        except tenantbundle.TenantBundleError as exc:
            self._reject(
                record, 400, str(exc),
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        if not self.policy_store.is_allowed(
            tenant_id, audit_mod.ACTION_IMPORT, operator
        ):
            self._reject(
                record, 403, "action not permitted by policy",
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        if decoded["tenant_id"] != tenant_id:
            self._reject(
                record, 404, "tenant backup not found",
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        key_ids = sorted(k["key_id"] for k in decoded["keys"])
        policy_restored = decoded["policy"] is not None
        record.intent = {
            "kind": OP_RESTORE,
            "key_ids": key_ids,
            "policy_restored": policy_restored,
        }
        self._persist(record)
        try:
            result = self.coordinator.restore(
                tenant_id, decoded, event_id=record.operation_id
            )
        except ProviderInvalidMaterial as exc:
            self._reject(
                record, 400, str(exc),
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        except ProviderUnavailable:
            self._provider_failure(record)
        except LedgerError as exc:
            self._ledger_failure(record, exc)
        if result.status == RESTORE_CREATED:
            self._succeed(
                record, 201,
                {
                    "tenant_id": result.tenant_id,
                    "key_ids": result.key_ids,
                    "policy_restored": result.policy_restored,
                },
            )
            return
        if result.status == RESTORE_SAME_TENANT_CONFLICT:
            self._reject(
                record, 409, "backup target already contains this data",
                STATUS_CONFLICT,
                tenant_id=tenant_id, key_id=None,
                action=audit_mod.ACTION_IMPORT,
            )
        self._reject(
            record, 404, "tenant backup not found",
            tenant_id=tenant_id, key_id=None,
            action=audit_mod.ACTION_IMPORT,
        )

    # -- post-crash success rebuild ----------------------------------------
    def _rebuild_success(
        self, record: OperationRecord, event
    ) -> None:
        """Rebuild and persist the 201 response for a committed operation.

        Raises _RebuildUnavailable when durable state cannot support the
        rebuild yet (the record stays pending for a later attempt).
        """
        intent = record.intent or {}
        kind = intent.get("kind")
        if kind == OP_ROTATE:
            key_id = intent.get("key_id") or event.key_id
            key_record = self.store.read_raw(key_id)
            if key_record is None or key_record.tenant_id != record.tenant_id:
                raise _RebuildUnavailable()
            version = None
            for ver in key_record.versions:
                if ver.created_at == event.timestamp:
                    version = ver
                    break
            if version is None:
                raise _RebuildUnavailable()
            body = {
                "key_id": key_record.key_id,
                "version": version.version,
                "algorithm": version.algorithm,
                "public_key": version.public_key,
            }
        elif kind == OP_IMPORT:
            key_id = intent.get("key_id") or event.key_id
            key_record = self.store.read_raw(key_id)
            if key_record is None or key_record.tenant_id != record.tenant_id:
                raise _RebuildUnavailable()
            version = key_record.get_version(
                intent.get("current_version") or key_record.current_version
            ) or key_record.current
            body = {
                "key_id": key_record.key_id,
                "algorithm": version.algorithm,
                "public_key": version.public_key,
            }
        elif kind == OP_RESTORE:
            body = {
                "tenant_id": record.tenant_id,
                "key_ids": list(intent.get("key_ids") or []),
                "policy_restored": bool(intent.get("policy_restored")),
            }
        else:
            raise _RebuildUnavailable()
        self._succeed(record, 201, body)


def _is_uuid4(value: str) -> bool:
    return is_valid_key_id(value)
