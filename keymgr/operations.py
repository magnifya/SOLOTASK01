"""Idempotent operation records for mutating key endpoints.

The rotate / import / restore endpoints accept an ``Idempotency-Key`` header
(CLI: ``--idempotency-key``). One key, scoped by tenant and operator, is bound
to exactly one operation: its canonical request (path and normalized body) and
its outcome (HTTP status and response body). A retried request presenting the
same binding replays the stored status/response without any side effect; the
same key with a different binding is a conflict that names the original
``operation_id``.

Each operation has an RFC 4122 UUID4 ``operation_id`` (used verbatim as the
operation's audit ``event_id``) and moves through ``pending`` ->
``succeeded`` / ``failed`` / ``conflict`` / ``timed_out``. Records persist in
``operations/<operation_id>.json`` (0600); the idempotency-key index
``operations/index.json`` maps a scoped key to its operation_id. All
read-modify-write of the index is serialized by one in-process lock plus an
exclusive ``fcntl`` lock on ``operations.lock``, so two concurrent requests
carrying the same key (across threads or processes) can never both execute:
exactly one begins, the other finds the pending binding and waits.

A process that dies while an operation is pending is repaired on the next
open via :meth:`OperationStore.recover_pending`: when the operation's audit
event (named after the operation_id) reached the ledger the operation
committed and the supplied resolver rebuilds its response; otherwise the
operation never committed and is recorded as failed. The half-finished key
files and provider handles themselves are reaped by the store/coordinator
outbox recovery, which must run first.
"""

import hashlib
import json
import os
import tempfile
import threading
import time
import uuid
from typing import Callable, NamedTuple, Optional

try:  # fcntl is POSIX-only; idempotency still works without cross-process locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Operation states.
STATUS_PENDING = "pending"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_CONFLICT = "conflict"
STATUS_TIMED_OUT = "timed_out"

_DIR_NAME = "operations"
_INDEX_NAME = "index.json"
_LOCK_NAME = "operations.lock"

# A concurrent, same-key request waits at most this long for the in-flight
# owner to reach a terminal state; beyond that it answers timed_out (503 / CLI
# 1) without writing any key, audit event or provider handle.
LOCK_WAIT_SECONDS = 5.0
_POLL_SECONDS = 0.02


def is_valid_idempotency_key(value) -> bool:
    """Validate an Idempotency-Key: 1-128 chars from the unreserved ASCII set.

    The permitted alphabet is RFC 3986 unreserved characters:
    ``A-Z a-z 0-9 . _ ~ -``.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    for ch in value:
        if not (
            "A" <= ch <= "Z"
            or "a" <= ch <= "z"
            or "0" <= ch <= "9"
            or ch in "._~-"
        ):
            return False
    return True


def state_for_http_status(http_status: int) -> str:
    """Map a terminal response's HTTP status to its operation state.

    201 is the only success; an explicit request conflict (409) is the
    "conflict" state. Every other terminal refusal (400/403/404) or backend
    failure (500/503) records as "failed". A crash-recovered operation whose
    audit event is durable therefore lands in the same state the original
    request would have, including a reconstructed rejection.
    """
    if http_status == 201:
        return STATUS_SUCCEEDED
    if http_status == 409:
        return STATUS_CONFLICT
    return STATUS_FAILED


def normalize_body(body: Optional[dict]) -> str:
    """Canonical JSON form of a request body for binding comparison.

    Keys are sorted and compact separators are used so bodies that differ only
    in key order or whitespace bind as the same request; a semantically
    different body binds differently and therefore conflicts.
    """
    return json.dumps(
        body if body is not None else {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


# Maps the durable operation kind to the audit action of its single terminal
# event. Recovery uses it to verify that an event found under the
# operation_id really is THIS operation's commit point (and not an id
# collision belonging to a different action/tenant).
_KIND_ACTIONS = {
    "rotate": "rotate",
    "import": "import",
    "restore": "import",
    "batch_rotate": "batch_rotate",
}


def expected_action_for(record: "OperationRecord"):
    """The audit action a committed operation's event must carry (or None)."""
    kind = (record.details or {}).get("kind")
    return _KIND_ACTIONS.get(kind)


def make_artifact_callbacks(operation_store: "OperationStore", key_store):
    """Build ``(register, on_handle, on_group, rollback_uncommitted)``.

    These wire the bound operation record to the durable crash-recovery
    artifacts of rotate/import/restore/batch-rotate without either layer
    importing the other:

    * ``register(record, **fields)`` merges artifact references into the
      0600-locked operation record;
    * ``on_handle(provider_id, handle)`` mirrors one freshly journaled handle
      the instant it is minted;
    * ``on_group(journal=, snapshot=, write_set=, marker=)`` mirrors the
      attempt's durable journal/snapshot/write-set before any handle exists;
    * ``rollback_uncommitted(record)`` is offered to
      :meth:`OperationStore.recover_pending` when no commit event exists. It
      idempotently deletes every handle reachable through the mirror (the
      last-resort source when the journal/snapshot were already independently
      removed) and returns True only when every delete is verified. A single
      failure parks the pending operation for a later open; the store-level
      outbox recovery, which runs first, remains the primary rollback path.
    """
    def register(record, **fields):
        operation_store.register_artifacts(record, **fields)

    def on_handle(record):
        def _cb(provider_id, handle):
            operation_store.register_artifacts(
                record,
                handles=[{"provider_id": provider_id, "handle": handle}],
            )
        return _cb

    def on_group(record):
        def _cb(journal=None, snapshot=None, write_set=None, marker=None):
            operation_store.register_artifacts(
                record,
                journal=journal,
                snapshot=snapshot,
                write_set=list(write_set or []),
                marker=marker,
            )
        return _cb

    def rollback_uncommitted(record) -> bool:
        artifacts = (record.details or {}).get("_artifacts") or {}
        handles = artifacts.get("handles") or []
        cleaned = True
        for pair in handles:
            provider_id = pair.get("provider_id")
            handle = pair.get("handle")
            if not (
                isinstance(provider_id, str)
                and provider_id
                and isinstance(handle, str)
                and handle
            ):
                continue
            # Idempotent: a handle already removed by the outbox sweep simply
            # confirms; an unreachable provider reports False and parks the
            # whole operation for a later open.
            try:
                deleted = key_store._delete_provisioned_handle(
                    provider_id, handle
                )
            except Exception:
                deleted = False
            if not deleted:
                cleaned = False
        return cleaned

    return register, on_handle, on_group, rollback_uncommitted


class BeginResult(NamedTuple):
    """Outcome of :meth:`OperationStore.begin`.

    ``kind`` is one of ``"new"`` (the caller owns and must execute the
    operation), ``"replay"`` (a finished operation to replay) or
    ``"conflict"`` (the key is bound to a different request). A ``"replay"``
    may still be ``pending``; the caller waits via :meth:`await_terminal`.
    """

    kind: str
    record: Optional["OperationRecord"]


class OperationRecord:
    """One persisted idempotent operation."""

    def __init__(
        self,
        operation_id: str,
        tenant_id: str,
        operator_id: str,
        path: str,
        request_body: str,
        idempotency_key: str,
        status: str = STATUS_PENDING,
        http_status: Optional[int] = None,
        response: Optional[dict] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        self.operation_id = operation_id
        self.tenant_id = tenant_id
        self.operator_id = operator_id
        self.path = path
        self.request_body = request_body
        self.idempotency_key = idempotency_key
        self.status = status
        self.http_status = http_status
        self.response = response
        self.created_at = created_at
        self.updated_at = updated_at
        # Mutation-specific facts the executor stashes before it runs, so a
        # crash-recovery resolver can rebuild the committed response without
        # the original request (e.g. a restore's write set).
        self.details = details

    # The operation_id is the audit event_id of the mutation it wraps, so the
    # two subsystems resolve a crash by the same identifier.
    @property
    def event_id(self) -> str:
        return self.operation_id

    def to_json(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "tenant_id": self.tenant_id,
            "operator_id": self.operator_id,
            "path": self.path,
            "request_body": self.request_body,
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "http_status": self.http_status,
            "response": self.response,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "details": self.details,
        }

    @classmethod
    def from_json(cls, data: dict) -> "OperationRecord":
        return cls(
            operation_id=data["operation_id"],
            tenant_id=data["tenant_id"],
            operator_id=data["operator_id"],
            path=data["path"],
            request_body=data.get("request_body", ""),
            idempotency_key=data.get("idempotency_key", ""),
            status=data.get("status", STATUS_PENDING),
            http_status=data.get("http_status"),
            response=data.get("response"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            details=data.get("details"),
        )

    def is_terminal(self) -> bool:
        return self.status in (
            STATUS_SUCCEEDED,
            STATUS_FAILED,
            STATUS_CONFLICT,
            STATUS_TIMED_OUT,
        )

    def same_binding(self, tenant_id: str, operator_id: str,
                     path: str, request_body: str) -> bool:
        """Whether a request is the identical binding this op recorded."""
        return (
            self.tenant_id == tenant_id
            and self.operator_id == operator_id
            and self.path == path
            and self.request_body == request_body
        )

    def to_status_response(self) -> dict:
        """Body of GET /v1/operations/{operation_id}.

        A pending operation exposes neither http_status nor response.
        """
        pending = self.status == STATUS_PENDING
        return {
            "operation_id": self.operation_id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "http_status": None if pending else self.http_status,
            "response": None if pending else self.response,
        }


class OperationStore:
    """Persistent idempotent-operation records and key bindings."""

    def __init__(self, data_dir: str, audit_log=None) -> None:
        self.data_dir = data_dir
        self.dir_path = os.path.join(data_dir, _DIR_NAME)
        os.makedirs(self.dir_path, exist_ok=True)
        self._index_path = os.path.join(self.dir_path, _INDEX_NAME)
        self._lock_path = os.path.join(self.data_dir, _LOCK_NAME)
        self._index_lock = threading.Lock()
        if audit_log is not None:
            self.audit = audit_log
        else:  # Import lazily-to-wire the concrete ledger without a cycle here.
            from .audit import AuditLog

            self.audit = AuditLog(data_dir)

    # -- paths / locking ---------------------------------------------------
    def _path_for(self, operation_id: str) -> str:
        return os.path.join(self.dir_path, operation_id + ".json")

    def _locked(self):
        """Take the in-process lock and the cross-process fcntl lock."""
        self._index_lock.acquire()
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            return -1
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            self._index_lock.release()
            raise
        return fd

    def _unlocked(self, fd: int) -> None:
        try:
            if fcntl is not None and fd >= 0:  # pragma: no branch - POSIX
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        finally:
            self._index_lock.release()

    def _write_atomic(self, path: str, payload: dict) -> None:
        fd, tmp_path = tempfile.mkstemp(dir=self.dir_path, suffix=".tmp")
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

    def _write_record(self, record: OperationRecord) -> None:
        self._write_atomic(self._path_for(record.operation_id), record.to_json())

    def _read_record(self, operation_id: str) -> Optional[OperationRecord]:
        try:
            with open(self._path_for(operation_id), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            return OperationRecord.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None

    def _scope(self, tenant_id: str, operator_id: str, key: str) -> str:
        # The Idempotency-Key is globally scoped: one key value binds exactly
        # one operation. Tenant, operator, path and normalized body are part
        # of the recorded *binding*, so reusing the same key under a different
        # tenant/operator/path/body is detected as a different binding and
        # answered 409 (naming the original operation), rather than silently
        # treated as a fresh operation. (Tenant/operator isolation of the
        # stored record is still enforced independently on GET.)
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _load_index(self) -> dict:
        try:
            with open(self._index_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {"bindings": {}}
        except (OSError, ValueError):
            return {"bindings": {}}
        bindings = data.get("bindings")
        if not isinstance(bindings, dict):
            return {"bindings": {}}
        return {"bindings": bindings}

    # -- begin / finish ----------------------------------------------------
    def peek(
        self,
        tenant_id: str,
        operator_id: str,
        path: str,
        request_body: str,
        idempotency_key: str,
    ) -> BeginResult:
        """Read-only binding lookup; never creates an operation.

        Lets a caller detect a replay/conflict *before* doing side-effect-free
        but expensive validation (such as decrypting a bundle). Returns
        ``replay`` (identical binding; the record may still be pending) or
        ``conflict`` (same key, different binding), or ``new`` when the key is
        unbound. A later :meth:`begin` remains authoritative for concurrency.
        """
        scope = self._scope(tenant_id, operator_id, idempotency_key)
        fd = self._locked()
        try:
            index = self._load_index()
            bound = index["bindings"].get(scope)
            if bound is None:
                return BeginResult("new", None)
            existing = self._read_record(bound)
            if existing is None:
                return BeginResult("new", None)
            kind = (
                "replay"
                if existing.same_binding(
                    tenant_id, operator_id, path, request_body
                )
                else "conflict"
            )
            return BeginResult(kind, existing)
        finally:
            self._unlocked(fd)

    def begin(
        self,
        tenant_id: str,
        operator_id: str,
        path: str,
        request_body: str,
        idempotency_key: str,
    ) -> BeginResult:
        """Bind the key and create/return the operation for one request.

        Under the global index lock: if the scoped key is unbound a fresh
        ``pending`` operation is persisted (record file first, index second)
        and returned as ``new``; if it is already bound the stored operation
        is returned as ``replay`` for an identical binding or ``conflict`` for
        a different one. Exactly one concurrent same-key request can win
        ``new``; the others observe the pending binding.
        """
        scope = self._scope(tenant_id, operator_id, idempotency_key)
        fd = self._locked()
        try:
            index = self._load_index()
            bound = index["bindings"].get(scope)
            if bound is not None:
                existing = self._read_record(bound)
                if existing is None:
                    # Index points at a missing record: treat as a fresh bind
                    # rather than wedging the key forever.
                    bound = None
            if bound is not None:
                kind = (
                    "replay"
                    if existing.same_binding(
                        tenant_id, operator_id, path, request_body
                    )
                    else "conflict"
                )
                return BeginResult(kind, existing)

            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).isoformat()
            operation_id = str(uuid.uuid4())
            record = OperationRecord(
                operation_id=operation_id,
                tenant_id=tenant_id,
                operator_id=operator_id,
                path=path,
                request_body=request_body,
                idempotency_key=idempotency_key,
                status=STATUS_PENDING,
                created_at=now,
                updated_at=now,
            )
            self._write_record(record)
            index["bindings"][scope] = operation_id
            self._write_atomic(self._index_path, index)
            return BeginResult("new", record)
        finally:
            self._unlocked(fd)

    def await_terminal(
        self, record: OperationRecord, timeout: float = LOCK_WAIT_SECONDS
    ) -> OperationRecord:
        """Wait for a concurrently-owned operation to finish.

        Polls the record file until the owner records a terminal state, or
        until ``timeout`` elapses, in which case the still-pending record is
        returned (the caller answers timed_out without mutating it).
        """
        deadline = time.monotonic() + timeout
        current = record
        while not current.is_terminal():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return current
            time.sleep(min(_POLL_SECONDS, remaining))
            refreshed = self._read_record(current.operation_id)
            if refreshed is None:
                continue
            current = refreshed
        return current

    def update_details(self, record: OperationRecord, details: dict) -> None:
        """Persist recovery facts on a still-pending owned operation.

        ``details`` is merged into the already-persisted context rather than
        replacing it, so a terminal rejection never erases the operation kind,
        the exact key_id rule or other facts recorded before the business
        check ran. Written before the mutation runs, so a crash after the
        audit commit but before :meth:`finish` can still rebuild the committed
        response from durable context alone.
        """
        merged = dict(record.details or {})
        merged.update(details)
        record.details = merged
        fd = self._locked()
        try:
            self._write_record(record)
        finally:
            self._unlocked(fd)

    def register_artifacts(self, record: "OperationRecord", **fields) -> None:
        """Durably record the crash-recovery artifacts of a bound operation.

        The moment a provider call has minted a handle (and before any of it
        can become unreachable), the request path registers the durable
        references recovery needs to settle the group without trusting a
        single artifact:

        * ``provider_id``   -- the owning provider of every minted handle;
        * ``journal``       -- the provisions/<event_id>.json handle journal;
        * ``snapshot``      -- the batch-rotations/<event_id>.json snapshot;
        * ``write_set``     -- every key_id the attempt may write;
        * ``handles``       -- ``[{provider_id, handle}, ...]`` minted so far,
          merged by identity so re-registration after each mint keeps the full
          set;
        * ``marker``        -- where the outbox marker lives ("key:<id>",
          "policy:<tenant>", "restore-empty:<tenant>").

        Written to the 0600 operation record atomically under the same
        in-process + fcntl lock as every other record update. A crash right
        after a provider call but before this merge is still covered by the
        durable provision journal itself; this mirror is what lets operation
        recovery delete handles when the journal has already been independently
        removed. No handle, material or passphrase beyond the opaque handle
        token is stored here, and operation projections never expose details.
        """
        merged = dict(record.details or {})
        artifacts = dict(merged.get("_artifacts") or {})
        handles = list(artifacts.get("handles") or [])
        for pair in fields.pop("handles", []) or []:
            if (
                isinstance(pair, dict)
                and isinstance(pair.get("provider_id"), str)
                and pair["provider_id"]
                and isinstance(pair.get("handle"), str)
                and pair["handle"]
            ):
                token = {"provider_id": pair["provider_id"],
                         "handle": pair["handle"]}
                if token not in handles:
                    handles.append(token)
        if handles:
            artifacts["handles"] = handles
        write_set = list(artifacts.get("write_set") or [])
        for key_id in fields.pop("write_set", []) or []:
            if isinstance(key_id, str) and key_id and key_id not in write_set:
                write_set.append(key_id)
        if write_set:
            artifacts["write_set"] = write_set
        for name, value in fields.items():
            if value is not None:
                artifacts[name] = value
        merged["_artifacts"] = artifacts
        record.details = merged
        fd = self._locked()
        try:
            self._write_record(record)
        finally:
            self._unlocked(fd)

    def stage_terminal(
        self,
        record: OperationRecord,
        http_status: int,
        response: dict,
        audit: Optional[dict] = None,
    ) -> None:
        """Durably persist the exact terminal result *before* the event append.

        The staged ``result`` (HTTP status plus the complete error/success
        response body) and optional ``audit`` descriptor are merged into the
        operation context and fsynced to the record file. Once the subsequent
        audit append lands, crash recovery replays this exact status/response
        verbatim -- never re-evaluating the policy, re-reading the object or
        re-decrypting the bundle. A crash before the append leaves both the
        stage and the event uncommitted and the operation is later finalized
        as failed(500).
        """
        details = dict(record.details or {})
        details["result"] = {
            "http_status": http_status,
            "response": response,
        }
        # Explicit terminal status mirror; also read by the legacy fallback
        # resolver for records predating the staged "result".
        details["terminal"] = http_status
        if audit is not None:
            details["audit"] = audit
        self.update_details(record, details)

    def finish(
        self,
        record: OperationRecord,
        status: str,
        http_status: int,
        response: dict,
    ) -> None:
        """Persist the terminal state/response of an owned operation."""
        from datetime import datetime, timezone

        record.status = status
        record.http_status = http_status
        record.response = response
        record.updated_at = datetime.now(timezone.utc).isoformat()
        fd = self._locked()
        try:
            self._write_record(record)
        finally:
            self._unlocked(fd)

    def get(
        self, operation_id: str, tenant_id: str, operator_id: str
    ) -> Optional[OperationRecord]:
        """Return an operation visible to exactly one tenant and operator.

        An unknown id, a malformed id, or an operation owned by another tenant
        or another operator all return None so existence never leaks.
        """
        try:
            if uuid.UUID(operation_id).version != 4:
                return None
        except (ValueError, AttributeError, TypeError):
            return None
        record = self._read_record(operation_id)
        if record is None:
            return None
        if record.tenant_id != tenant_id or record.operator_id != operator_id:
            return None
        return record

    # -- crash recovery ----------------------------------------------------
    def recover_pending(
        self,
        resolve_committed: Optional[
            Callable[["OperationRecord", object], "tuple[int, dict]"]
        ] = None,
        rollback_uncommitted: Optional[
            Callable[["OperationRecord"], bool]
        ] = None,
    ) -> None:
        """Finish operations left pending by a crashed process.

        Must run *after* the key-store and restore outbox recovery, so the
        ledger already reflects every half-committed mutation. For each
        pending operation:

        * when its event reached the ledger it is the commit point only when
          its ``event_id`` (the lookup key), ``action`` and ``tenant_id`` all
          agree with THIS operation -- an id collision with a different
          action/tenant is never treated as a commit, the operation is left
          pending and the scene is preserved for a later open. Once verified,
          the terminal status/response persisted with the rejection/success
          context (``details["result"]``) are replayed verbatim -- the policy,
          the current object state and the (possibly no longer decryptable)
          bundle are never consulted again, so a later policy/state change
          cannot turn a 403 into a 404/409 or rewrite the first response; only
          when no result was staged (older records) does
          ``resolve_committed(record, event)`` rebuild a best-effort
          projection.
        * when the event never reached the ledger the operation never
          committed: ``rollback_uncommitted(record)`` is offered the durable
          artifact mirror (journal/snapshot/handle set) so it can delete any
          minted handle the outbox sweeps could not tie to a surviving
          artifact; only when that reports fully settled is the operation
          recorded failed(500). A failed/False rollback leaves the operation
          pending for a later open -- the scene is never partially resolved.
        """
        try:
            names = os.listdir(self.dir_path)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json") or name == _INDEX_NAME:
                continue
            operation_id = name[:-5]
            record = self._read_record(operation_id)
            if record is None or record.status != STATUS_PENDING:
                continue
            event = None
            try:
                event = self.audit.get_event(record.event_id)
            except Exception:
                # Cannot decide right now; leave it for a later open.
                continue
            if event is not None:
                if not self._event_matches_operation(record, event):
                    # A durable event carries this id but names a different
                    # action or tenant (id collision/corruption): it is not
                    # this operation's commit point. Leave the operation and
                    # its scene untouched for a later open.
                    continue
                details = record.details or {}
                staged = details.get("result")
                if (
                    isinstance(staged, dict)
                    and isinstance(staged.get("http_status"), int)
                    and isinstance(staged.get("response"), dict)
                ):
                    # The durable fact: replay the first status/response
                    # byte-for-byte regardless of the current policy/state.
                    http_status = int(staged["http_status"])
                    response = staged["response"]
                else:
                    # Backwards-compatible recovery for records that
                    # committed before the result was staged.
                    http_status, response = 201, {
                        "operation_id": record.operation_id
                    }
                    if resolve_committed is not None:
                        try:
                            http_status, response = resolve_committed(
                                record, event
                            )
                        except Exception:
                            http_status, response = 201, {
                                "operation_id": record.operation_id
                            }
                self.finish(
                    record,
                    state_for_http_status(http_status),
                    http_status,
                    response,
                )
            else:
                # No event under this id: the mutation never reached its
                # commit point. Let the caller reconcile any minted handle
                # reachable only through the operation's artifact mirror; a
                # report of failure parks the operation so a later open
                # retries rather than finalizing while an orphan may exist.
                if rollback_uncommitted is not None:
                    try:
                        settled = rollback_uncommitted(record)
                    except Exception:
                        settled = False
                    if not settled:
                        continue
                self.finish(
                    record,
                    STATUS_FAILED,
                    500,
                    {"error": "operation interrupted before commit",
                     "operation_id": record.operation_id},
                )

    @staticmethod
    def _event_matches_operation(
        record: "OperationRecord", event
    ) -> bool:
        """Whether a durable event is really this operation's terminal event.

        The lookup already pins ``event_id`` (the operation_id). Recovery
        additionally requires the action and tenant to agree with the bound
        operation, so a same-id event belonging to another action or tenant
        can never be mistaken for the commit point. Records predating the
        kind/context fields are accepted on tenant agreement alone for
        backwards compatibility.
        """
        if event.event_id != record.event_id:
            return False
        if (
            event.tenant_id is not None
            and event.tenant_id != record.tenant_id
        ):
            return False
        expected_action = expected_action_for(record)
        if expected_action is not None and event.action != expected_action:
            return False
        return True
