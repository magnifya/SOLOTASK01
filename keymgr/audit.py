"""Persistent append-only audit ledger with tenant-isolated pagination."""

import base64
import hashlib
import hmac
import json
import os
import threading
import uuid
from dataclasses import dataclass
from typing import List, NamedTuple, Optional

try:  # fcntl is POSIX-only.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Actions written to the ledger. A request with a missing, empty, illegal or
# tenant-inconsistent identifier is recorded as TENANT_CONFLICT instead.
ACTION_CREATE = "create"
ACTION_READ = "read"
ACTION_ROTATE = "rotate"
ACTION_REVOKE = "revoke"
ACTION_IMPORT = "import"
ACTION_EXPORT = "export"
ACTION_AUDIT = "audit"
ACTION_TENANT_CONFLICT = "tenant_conflict"
# Policy management actions. These are audited but are never themselves
# governed by a tenant policy (management is exempt from enforcement).
ACTION_POLICY_READ = "policy_read"
ACTION_POLICY_UPDATE = "policy_update"
ACTION_POLICY_DELETE = "policy_delete"
ACTIONS = (
    ACTION_CREATE,
    ACTION_READ,
    ACTION_ROTATE,
    ACTION_REVOKE,
    ACTION_IMPORT,
    ACTION_EXPORT,
    ACTION_AUDIT,
    ACTION_TENANT_CONFLICT,
    ACTION_POLICY_READ,
    ACTION_POLICY_UPDATE,
    ACTION_POLICY_DELETE,
)

OUTCOME_SUCCESS = "success"
OUTCOME_REJECTED = "rejected"
OUTCOMES = (OUTCOME_SUCCESS, OUTCOME_REJECTED)

_LOG_NAME = "audit.log"
_LOCK_NAME = "audit.log.lock"
_SECRET_NAME = "audit.secret"


class LedgerError(Exception):
    """Raised when the audit ledger cannot be written or read durably."""


class InvalidCursor(Exception):
    """Raised when a pagination cursor is malformed, tampered or stale."""


@dataclass
class AuditEvent:
    """One immutable audit record. Never carries key material."""

    event_id: str
    tenant_id: Optional[str]
    action: str
    key_id: Optional[str]
    outcome: str
    timestamp: str
    seq: int = 0

    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "key_id": self.key_id,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
            "seq": self.seq,
        }

    @classmethod
    def from_json(cls, data: dict) -> "AuditEvent":
        return cls(
            event_id=data["event_id"],
            tenant_id=data.get("tenant_id"),
            action=data["action"],
            key_id=data.get("key_id"),
            outcome=data["outcome"],
            timestamp=data["timestamp"],
            seq=int(data.get("seq", 0)),
        )

    def to_response(self) -> dict:
        """Projection for GET /v1/audit: ledger-internal seq is omitted."""
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "key_id": self.key_id,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
        }


class AuditPage(NamedTuple):
    """Result of one ledger query: a page of events and the next cursor."""

    events: List[AuditEvent]
    next_cursor: Optional[str]


class AuditLog:
    """File-backed append-only audit log (one JSON object per line).

    All appends are serialized by one process-wide lock plus an exclusive
    ``fcntl`` lock on a sidecar file, so multiple server threads and processes
    share a monotonic ``seq`` without interleaving or losing lines. Pagination
    cursors are HMAC-signed and bound to the tenant, the active filters and the
    ledger snapshot they were issued against.
    """

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._log_path = os.path.join(data_dir, _LOG_NAME)
        self._lock_path = os.path.join(data_dir, _LOCK_NAME)
        self._secret_path = os.path.join(data_dir, _SECRET_NAME)
        self._append_lock = threading.Lock()
        self._secret: Optional[bytes] = None

    # -- paths / locking ---------------------------------------------------
    @property
    def path(self) -> str:
        return self._log_path

    def _locked_file(self):
        """Open the sidecar lock file and take an exclusive fcntl lock."""
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            return fd
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            raise
        return fd

    def _unlock_file(self, fd: int) -> None:
        try:
            if fcntl is not None:  # pragma: no branch - POSIX in practice
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _signing_secret(self) -> bytes:
        """Load (creating once, 0600) the HMAC secret used for cursors."""
        if self._secret is not None:
            return self._secret
        try:
            with open(self._secret_path, "rb") as fh:
                secret = fh.read()
            if secret:
                self._secret = secret
                return secret
        except FileNotFoundError:
            pass
        secret = os.urandom(32)
        fd = os.open(self._secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, secret.hex().encode("ascii"))
            os.fsync(fd)
        except FileExistsError:
            os.close(fd)
            with open(self._secret_path, "rb") as fh:
                self._secret = fh.read()
            return self._secret
        else:
            os.close(fd)
        self._secret = secret.hex().encode("ascii")
        return self._secret

    # -- reads -------------------------------------------------------------
    def _read_all_locked(self) -> List[AuditEvent]:
        """Read every ledger line. Caller must hold no lock; takes none."""
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise LedgerError("cannot read audit log: %s" % exc) from exc
        events: List[AuditEvent] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(AuditEvent.from_json(json.loads(line)))
            except (ValueError, KeyError, TypeError):
                # A torn/corrupt tail line must not poison reads; the writer
                # only ever fsyncs complete lines.
                continue
        return events

    def _read_all(self) -> List[AuditEvent]:
        """Read under the append lock for a consistent snapshot."""
        with self._append_lock:
            return self._read_all_locked()

    @staticmethod
    def _fingerprint(events: List[AuditEvent]) -> str:
        """Stable digest identifying one ledger snapshot (its event set)."""
        digest = hashlib.sha256()
        for event in events:
            digest.update(str(event.seq).encode("ascii"))
            digest.update(b":")
            digest.update(event.event_id.encode("utf-8"))
            digest.update(b"\n")
        digest.update(b"count=%d" % len(events))
        return digest.hexdigest()

    # -- writes ------------------------------------------------------------
    def new_event(
        self,
        tenant_id: Optional[str],
        action: str,
        key_id: Optional[str],
        outcome: str,
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """Mint an event with a fresh event_id and UTC timestamp (seq unset)."""
        # Imported lazily to avoid a module import cycle at package import.
        from datetime import datetime, timezone

        return AuditEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            action=action,
            key_id=key_id,
            outcome=outcome,
            timestamp=timestamp
            or datetime.now(timezone.utc).isoformat(),
        )

    def append(self, event: AuditEvent) -> AuditEvent:
        """Append one event durably, assigning the next monotonic seq.

        Raises LedgerError if the line cannot be committed. The fsync before
        release means a returned event is on disk.
        """
        with self._append_lock:
            fd = self._locked_file()
            try:
                existing = self._read_all_locked()
                # Idempotent on event_id: recovery re-append after a crash
                # between the ledger write and the outbox-marker clear must
                # not produce a duplicate line.
                for prior in existing:
                    if prior.event_id == event.event_id:
                        event.seq = prior.seq
                        return event
                event.seq = (existing[-1].seq + 1) if existing else 1
                line = json.dumps(event.to_json(), separators=(",", ":")) + "\n"
                try:
                    with open(self._log_path, "a", encoding="utf-8") as fh:
                        fh.write(line)
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError as exc:
                    raise LedgerError("cannot write audit log: %s" % exc) from exc
            finally:
                self._unlock_file(fd)
        return event

    # -- cursors -----------------------------------------------------------
    def _encode_cursor(self, payload: dict) -> str:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        token = base64.urlsafe_b64encode(raw).rstrip(b"=")
        mac = hmac.new(self._signing_secret(), token, hashlib.sha256).hexdigest()
        return (token + b"." + mac.encode("ascii")).decode("ascii")

    def _decode_cursor(self, raw: str) -> dict:
        try:
            token_b, mac_b = raw.encode("ascii").split(b".", 1)
        except (ValueError, AttributeError) as exc:
            raise InvalidCursor("malformed cursor") from exc
        expected = hmac.new(
            self._signing_secret(), token_b, hashlib.sha256
        ).hexdigest().encode("ascii")
        if not hmac.compare_digest(expected, mac_b):
            raise InvalidCursor("invalid or tampered cursor")
        padded = token_b + b"=" * (-len(token_b) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise InvalidCursor("malformed cursor") from exc
        if not isinstance(payload, dict):
            raise InvalidCursor("malformed cursor")
        return payload

    # -- queries -----------------------------------------------------------
    @staticmethod
    def _sort_key(event: AuditEvent):
        return event.timestamp, event.event_id, event.seq

    def query(
        self,
        tenant_id: str,
        key_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> AuditPage:
        """Return one tenant-isolated, filter-bound, snapshot-bound page.

        Events are ordered by (timestamp, event_id) ascending. Conflict
        records carry a null tenant and are therefore visible to nobody.
        A cursor is valid only with the same tenant, filters and an unchanged
        ledger snapshot; otherwise InvalidCursor is raised.
        """
        anchor = None
        fingerprint = None
        if cursor is not None:
            payload = self._decode_cursor(cursor)
            try:
                if payload.get("t") != tenant_id:
                    raise InvalidCursor("cursor does not match tenant_id")
                if payload.get("k") != key_id or payload.get("a") != action:
                    raise InvalidCursor("cursor does not match filters")
                if int(payload.get("l", -1)) != limit:
                    raise InvalidCursor("cursor does not match limit")
                anchor = (payload["ts"], payload["eid"], int(payload["seq"]))
                fingerprint = payload["f"]
            except (KeyError, TypeError, ValueError) as exc:
                raise InvalidCursor("malformed cursor") from exc

        events = self._read_all()

        selected_all = [
            e
            for e in events
            if e.tenant_id == tenant_id
            and (key_id is None or e.key_id == key_id)
            and (action is None or e.action == action)
        ]
        selected_all.sort(key=self._sort_key)
        # The snapshot is scoped to exactly the events this tenant and these
        # filters can see: another tenant's activity must not invalidate the
        # cursor, while any change to the visible set does.
        current_fingerprint = self._fingerprint(selected_all)
        if fingerprint is not None and fingerprint != current_fingerprint:
            raise InvalidCursor("cursor snapshot is no longer valid")

        selected = selected_all
        if anchor is not None:
            selected = [e for e in selected if self._sort_key(e) > anchor]

        page = selected[:limit]
        if len(selected) > limit and page:
            last = page[-1]
            next_cursor = self._encode_cursor(
                {
                    "v": 1,
                    "t": tenant_id,
                    "k": key_id,
                    "a": action,
                    "l": limit,
                    "ts": last.timestamp,
                    "eid": last.event_id,
                    "seq": last.seq,
                    "f": current_fingerprint,
                }
            )
        else:
            next_cursor = None
        return AuditPage(events=page, next_cursor=next_cursor)
