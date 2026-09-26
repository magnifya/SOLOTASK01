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

    200 and 201 are successes; an explicit request conflict (409) is the
    "conflict" state. Every other terminal refusal (400/403/404) or backend
    failure (500/503) records as "failed". A crash-recovered operation whose
    audit event is durable therefore lands in the same state the original
    request would have, including a reconstructed rejection.
    """
    if http_status in (200, 201):
        return STATUS_SUCCEEDED
    if http_status == 409:
        return STATUS_CONFLICT
    return STATUS_FAILED


# The audit action each operation kind commits with.
_KIND_ACTIONS = {
    "rotate": "rotate",
    "batch_rotate": "batch_rotate",
    "import": "import",
    "restore": "import",
    "encrypt": "encrypt",
    "migrate": "migrate",
}


def _event_matches_operation(record: "OperationRecord", event) -> bool:
    """Whether a durable ledger event is THIS operation's commit event.

    Crash recovery decides committed-vs-not purely from the ledger, but the
    event id alone is not enough: a durable event whose tenant, action or
    outcome disagrees with the operation's recorded context belongs to a
    different mutation that happens to carry the same id, and must not
    finalize this operation either way. The tenant must always match the
    operation record; the action/outcome are checked against the staged
    terminal audit descriptor when one exists, else the event must be a
    success whose action fits the operation kind (when the kind is known).
    """
    if event.tenant_id != record.tenant_id:
        return False
    details = record.details or {}
    audit_desc = details.get("audit")
    if isinstance(audit_desc, dict):
        action = audit_desc.get("action")
        if isinstance(action, str) and action and event.action != action:
            return False
        outcome = audit_desc.get("outcome")
        if isinstance(outcome, str) and outcome and event.outcome != outcome:
            return False
        return True
    if event.outcome != "success":
        return False
    expected = _KIND_ACTIONS.get(details.get("kind"))
    if expected is not None and event.action != expected:
        return False
    return True


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
        mirror_required: bool = False,
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
        # Whether this binding is of the mirrored generation: its 0600
        # artifact mirror is created after the bind and before the first
        # provider call. A pending operation of this generation whose mirror
        # is missing is a RETRYABLE strand (the mirror creation failed or the
        # process crashed right there), never a guessable failed(500). Old
        # records without the flag keep the legacy recovery rules -- a mirror
        # is never mandatory for them.
        self.mirror_required = mirror_required

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
            "mirror_required": self.mirror_required,
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
            mirror_required=bool(data.get("mirror_required", False)),
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
        mirror_required: bool = True,
    ) -> BeginResult:
        """Bind the key and create/return the operation for one request.

        Under the global index lock: if the scoped key is unbound a fresh
        ``pending`` operation is persisted (record file first, index second)
        and returned as ``new``; if it is already bound the stored operation
        is returned as ``replay`` for an identical binding or ``conflict`` for
        a different one. Exactly one concurrent same-key request can win
        ``new``; the others observe the pending binding.

        ``mirror_required`` marks the binding as of the artifact-mirror
        generation. The mirrored mutations (rotate/import/restore/batch and
        the read-only idempotent encrypt) pass True; legacy/test wiring that
        runs without an ArtifactStore passes False and keeps the pre-mirror
        crash rules.
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
                mirror_required=mirror_required,
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

    def finalize_durable(
        self,
        record: OperationRecord,
        http_status: int,
        response: dict,
        audit: Optional[dict] = None,
    ) -> None:
        """Stage a terminal result, then make the audit event the commit point.

        Used by the read-only idempotent encrypt, which has no key-file
        outbox: the exact terminal status/response (and the audit descriptor
        naming the operation's event) are fsynced to the operation record
        first, then the single ledger event named after the operation_id is
        appended durably. The append's event_id dedupe makes a retry
        idempotent. Only once the append returns does the caller finish the
        operation and release the envelope; a crash before the append leaves
        the operation pending with neither event nor envelope answer, so a
        restart/retry re-runs the encryption exactly once and never answers
        from an uncommitted stage. Raises ``LedgerError`` if the commit point
        itself cannot be reached (the response is then withheld).
        """
        self.stage_terminal(record, http_status, response, audit=audit)
        desc = audit or {}
        self.audit.append(
            self.audit.new_event(
                record.tenant_id,
                desc.get("action"),
                desc.get("key_id"),
                desc.get("outcome"),
                event_id=record.operation_id,
            )
        )

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
        is_parked: Optional[Callable[[str], bool]] = None,
    ) -> None:
        """Finish operations left pending by a crashed process.

        Must run *after* the key-store and restore outbox recovery, so the
        ledger already reflects every half-committed mutation. For each
        pending operation: when its event reached the ledger the operation
        is durable and the terminal status/response persisted *with the
        rejection/success context* (``details["result"]``) are replayed
        verbatim -- the policy, the current object state and the (possibly no
        longer decryptable) bundle are never consulted again, so a later
        policy/state change cannot turn a 403 into a 404/409 or rewrite the
        first response; only when no result was staged (older records) does
        ``resolve_committed(record, event)`` rebuild a best-effort
        projection. When the event never reached the ledger the operation
        never committed and is recorded as a 500 failure (the outbox/
        provision recovery has already removed its half-written files and
        minted handles).
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
            # The artifact-mirror settlement runs first: a surviving mirror
            # whose evidence is incomplete/inconsistent (unreadable ledger,
            # uncertain commit, corrupt/missing basis) keeps the operation
            # pending for a later open rather than guessing a terminal.
            if is_parked is not None and is_parked(operation_id):
                continue
            event = None
            try:
                event = self.audit.get_event(record.event_id)
            except Exception:
                # Cannot decide right now; leave it for a later open.
                continue
            if event is not None and not _event_matches_operation(
                record, event
            ):
                # A durable event carries this operation's id but is not the
                # operation's own event (tenant/action/outcome mismatch): the
                # id collides with a different mutation, so the operation can
                # be finalized neither as committed nor as failed. Leave it
                # pending for operator/startup resolution rather than
                # replaying a response the durable fact does not support.
                continue
            if event is not None:
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
                    details_now = record.details or {}
                    if details_now.get("kind") == "encrypt":
                        # The event is durable but the exact 200 envelope was
                        # not staged (a scene the encrypt flow never produces):
                        # the envelope cannot be reconstructed without the
                        # request, so never fabricate one. Keep the op pending
                        # for an identical retry, which dedupes on the durable
                        # event and re-seals under the same operation_id.
                        continue
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
                details = record.details or {}
                if details.get("kind") == "encrypt":
                    # A read-only idempotent encrypt crashed before its event
                    # became durable: no key/handle/outbox exists, and the
                    # sealed envelope cannot be rebuilt at startup (the
                    # request plaintext/aad are deliberately not stored). Keep
                    # the operation PENDING with the envelope hidden; an
                    # identical HTTP/CLI retry runs it once under the same
                    # operation_id, then either commits the event or re-answers
                    # from durable facts. Never guess a failed(500) terminal.
                    continue
                self.finish(
                    record,
                    STATUS_FAILED,
                    500,
                    {"error": "operation interrupted before commit",
                     "operation_id": record.operation_id},
                )
