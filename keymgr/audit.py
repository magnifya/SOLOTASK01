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
ACTION_BATCH_ROTATE = "batch_rotate"
ACTION_REVOKE = "revoke"
ACTION_IMPORT = "import"
ACTION_EXPORT = "export"
ACTION_MIGRATE = "migrate"
ACTION_ENCRYPT = "encrypt"
ACTION_DECRYPT = "decrypt"
ACTION_REWRAP = "rewrap"
ACTION_SIGN = "sign"
ACTION_VERIFY = "verify"
ACTION_AUDIT = "audit"
ACTION_LIST = "list"
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
    ACTION_BATCH_ROTATE,
    ACTION_REVOKE,
    ACTION_IMPORT,
    ACTION_EXPORT,
    ACTION_MIGRATE,
    ACTION_ENCRYPT,
    ACTION_DECRYPT,
    ACTION_REWRAP,
    ACTION_SIGN,
    ACTION_VERIFY,
    ACTION_AUDIT,
    ACTION_LIST,
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
_ANCHOR_NAME = "audit-anchor.json"

# Key order of a legacy (pre-chain) ledger line; chained lines append
# prev_mac and mac after these seven keys.
_EVENT_KEYS = (
    "event_id",
    "tenant_id",
    "action",
    "key_id",
    "outcome",
    "timestamp",
    "seq",
)
_CHAIN_KEYS = _EVENT_KEYS + ("prev_mac", "mac")
_ANCHOR_KEYS = ("schema_version", "legacy_bytes", "legacy_mac")
_LEGACY_DOMAIN = b"legacy\0"
_HEX_LOWER = frozenset("0123456789abcdef")


def _compact_json(obj: dict) -> bytes:
    """Canonical ledger encoding: compact UTF-8 JSON, non-ASCII as-is."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _is_hex64(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in _HEX_LOWER for ch in value)
    )


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

    The ledger is tamper-evident: on first load the pre-existing (legacy)
    lines are strictly validated and committed into ``audit-anchor.json``
    (byte count plus an HMAC over ``"legacy\\0" + raw bytes``); every line
    appended afterwards carries ``prev_mac``/``mac`` chaining back to that
    anchor. Anchor, prefix and chain are re-verified on every locked read
    and write; any mismatch raises ``LedgerError``.
    """

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._log_path = os.path.join(data_dir, _LOG_NAME)
        self._lock_path = os.path.join(data_dir, _LOCK_NAME)
        self._secret_path = os.path.join(data_dir, _SECRET_NAME)
        self._anchor_path = os.path.join(data_dir, _ANCHOR_NAME)
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
        """Load (creating once, 0600) the HMAC secret used for cursors.

        The read-or-create runs under the same cross-process file lock as
        appends, so two processes initializing concurrently cannot raise
        FileExistsError or read a half-written secret.
        """
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
        fd = self._locked_file()
        try:
            # Re-check under the lock: another process may have completed
            # the initialization while this one waited.
            return self._signing_secret_locked()
        finally:
            self._unlock_file(fd)

    def _signing_secret_locked(self) -> bytes:
        """Read-or-create the HMAC secret; caller holds the file lock."""
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
        secret = os.urandom(32).hex().encode("ascii")
        out = os.open(
            self._secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            os.write(out, secret)
            os.fsync(out)
        finally:
            os.close(out)
        self._secret = secret
        return secret

    # -- reads -------------------------------------------------------------
    def _read_log_bytes_locked(self) -> bytes:
        """Raw ledger bytes (empty when no log exists yet)."""
        try:
            with open(self._log_path, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return b""
        except OSError as exc:
            raise LedgerError("cannot read audit log: %s" % exc) from exc

    @staticmethod
    def _split_lines(raw: bytes) -> List[bytes]:
        """Split into records on newlines; any empty line is corruption."""
        if not raw:
            return []
        lines = raw.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        if any(not line for line in lines):
            raise LedgerError("audit ledger is corrupt: empty line")
        return lines

    @staticmethod
    def _parse_line(line: bytes) -> dict:
        try:
            obj = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise LedgerError("audit ledger is corrupt: %s" % exc) from exc
        if not isinstance(obj, dict):
            raise LedgerError("audit ledger is corrupt: not an object")
        return obj

    @staticmethod
    def _check_event_fields(obj: dict, expected_seq: int, seen: set) -> None:
        """Type, seq-continuity and event_id-uniqueness checks (both formats)."""
        seq = obj["seq"]
        if (
            not isinstance(obj["event_id"], str)
            or not isinstance(obj["action"], str)
            or not isinstance(obj["outcome"], str)
            or not isinstance(obj["timestamp"], str)
            or (
                obj["tenant_id"] is not None
                and not isinstance(obj["tenant_id"], str)
            )
            or (
                obj["key_id"] is not None
                and not isinstance(obj["key_id"], str)
            )
        ):
            raise LedgerError("audit ledger is corrupt: bad field types")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise LedgerError("audit ledger is corrupt: bad seq")
        if seq != expected_seq:
            raise LedgerError("audit ledger is corrupt: non-sequential seq")
        if obj["event_id"] in seen:
            raise LedgerError("audit ledger is corrupt: duplicate event_id")
        seen.add(obj["event_id"])

    def _validate_legacy_lines(self, lines: List[bytes]) -> List[AuditEvent]:
        """Strictly validate pre-chain lines: exact key order, field types,
        seq continuous from 1 and unique event_ids."""
        events: List[AuditEvent] = []
        seen: set = set()
        for line in lines:
            obj = self._parse_line(line)
            if tuple(obj.keys()) != _EVENT_KEYS:
                raise LedgerError("audit ledger is corrupt: bad event keys")
            self._check_event_fields(obj, len(events) + 1, seen)
            events.append(AuditEvent.from_json(obj))
        return events

    def _read_anchor_locked(self):
        """Return (legacy_bytes, legacy_mac), or None if no anchor exists."""
        try:
            with open(self._anchor_path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise LedgerError("cannot read audit anchor: %s" % exc) from exc
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise LedgerError("audit anchor is corrupt: %s" % exc) from exc
        if not isinstance(obj, dict) or tuple(obj.keys()) != _ANCHOR_KEYS:
            raise LedgerError("audit anchor is corrupt: bad keys")
        schema_version = obj["schema_version"]
        legacy_bytes = obj["legacy_bytes"]
        legacy_mac = obj["legacy_mac"]
        if isinstance(schema_version, bool) or schema_version != 1:
            raise LedgerError("audit anchor is corrupt: bad schema_version")
        if (
            isinstance(legacy_bytes, bool)
            or not isinstance(legacy_bytes, int)
            or legacy_bytes < 0
        ):
            raise LedgerError("audit anchor is corrupt: bad legacy_bytes")
        if not _is_hex64(legacy_mac):
            raise LedgerError("audit anchor is corrupt: bad legacy_mac")
        return legacy_bytes, legacy_mac

    def _write_anchor_locked(self, legacy_bytes: int, legacy_mac: str) -> None:
        """Commit the anchor atomically (temp file, fsync, rename), 0600."""
        payload = _compact_json(
            {
                "schema_version": 1,
                "legacy_bytes": legacy_bytes,
                "legacy_mac": legacy_mac,
            }
        )
        tmp_path = self._anchor_path + ".tmp"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp_path, self._anchor_path)
        except OSError as exc:
            raise LedgerError("cannot write audit anchor: %s" % exc) from exc

    def _secret_locked(self) -> bytes:
        try:
            return self._signing_secret_locked()
        except OSError as exc:
            raise LedgerError("cannot load audit secret: %s" % exc) from exc

    def _load_locked(self):
        """Verify anchor, legacy prefix and chain under the held locks.

        On first load (no anchor yet) the whole existing log is validated as
        legacy lines and the anchor committing to its bytes is created. Every
        later load re-verifies the anchor, the MAC'd legacy prefix and the
        full prev_mac/mac chain. Any inconsistency raises LedgerError; no
        line is ever skipped and nothing is re-signed. Returns the events
        plus the mac the next appended line must name as its prev_mac.
        """
        raw = self._read_log_bytes_locked()
        anchor = self._read_anchor_locked()
        if anchor is None:
            # First load: validate the whole log as legacy lines before the
            # anchor commits to exactly these bytes.
            events = self._validate_legacy_lines(self._split_lines(raw))
            legacy_mac = hmac.new(
                self._secret_locked(), _LEGACY_DOMAIN + raw, hashlib.sha256
            ).hexdigest()
            self._write_anchor_locked(len(raw), legacy_mac)
            return events, legacy_mac
        legacy_bytes, legacy_mac = anchor
        if legacy_bytes > len(raw):
            raise LedgerError("audit ledger is shorter than its anchor")
        prefix = raw[:legacy_bytes]
        secret = self._secret_locked()
        actual = hmac.new(
            secret, _LEGACY_DOMAIN + prefix, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(actual, legacy_mac):
            raise LedgerError("audit ledger prefix does not match its anchor")
        events = self._validate_legacy_lines(self._split_lines(prefix))
        seen = {event.event_id for event in events}
        prev_mac = legacy_mac
        seq = len(events)
        for line in self._split_lines(raw[legacy_bytes:]):
            obj = self._parse_line(line)
            if tuple(obj.keys()) != _CHAIN_KEYS:
                raise LedgerError("audit ledger is corrupt: bad chained keys")
            if not _is_hex64(obj["prev_mac"]) or not _is_hex64(obj["mac"]):
                raise LedgerError("audit ledger is corrupt: bad mac")
            seq += 1
            self._check_event_fields(obj, seq, seen)
            if obj["prev_mac"] != prev_mac:
                raise LedgerError("audit ledger chain is broken")
            expected = hmac.new(
                secret,
                _compact_json({key: obj[key] for key in _CHAIN_KEYS[:8]}),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, obj["mac"]):
                raise LedgerError("audit ledger chain is broken")
            if _compact_json(obj) != line:
                raise LedgerError("audit ledger is corrupt: non-canonical line")
            events.append(AuditEvent.from_json(obj))
            prev_mac = obj["mac"]
        return events, prev_mac

    def _read_all(self) -> List[AuditEvent]:
        """Read under both locks for a consistent cross-process snapshot.

        Appends commit (write + fsync) while holding the exclusive file
        lock, so a reader holding the same lock never observes a torn or
        partially-committed tail.
        """
        with self._append_lock:
            fd = self._locked_file()
            try:
                events, _ = self._load_locked()
                return events
            finally:
                self._unlock_file(fd)

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
        event_id: Optional[str] = None,
    ) -> AuditEvent:
        """Mint an event with a fresh (or supplied) id and UTC timestamp.

        ``event_id`` may be supplied so an idempotent operation's audit event
        is named after its ``operation_id``; crash recovery then resolves both
        by the same identifier. The ledger dedupes on event_id, so reusing an
        id never appends twice.
        """
        # Imported lazily to avoid a module import cycle at package import.
        from datetime import datetime, timezone

        return AuditEvent(
            event_id=event_id or str(uuid.uuid4()),
            tenant_id=tenant_id,
            action=action,
            key_id=key_id,
            outcome=outcome,
            timestamp=timestamp
            or datetime.now(timezone.utc).isoformat(),
        )

    def append(self, event: AuditEvent) -> AuditEvent:
        """Append one event durably, assigning the next monotonic seq.

        The line is hash-chained: it carries the previous entry's mac (or
        the anchor's legacy_mac for the first chained line) as prev_mac and
        its own mac over the canonical encoding of the eight preceding keys.
        Raises LedgerError if the chain does not verify or the line cannot
        be committed. The fsync before release means a returned event is on
        disk.
        """
        with self._append_lock:
            fd = self._locked_file()
            try:
                existing, tail_mac = self._load_locked()
                # Idempotent on event_id: recovery re-append after a crash
                # between the ledger write and the outbox-marker clear must
                # not produce a duplicate line.
                for prior in existing:
                    if prior.event_id == event.event_id:
                        event.seq = prior.seq
                        return event
                event.seq = (existing[-1].seq + 1) if existing else 1
                payload = event.to_json()
                payload["prev_mac"] = tail_mac
                payload["mac"] = hmac.new(
                    self._secret_locked(),
                    _compact_json(payload),
                    hashlib.sha256,
                ).hexdigest()
                line = _compact_json(payload) + b"\n"
                try:
                    with open(self._log_path, "ab") as fh:
                        fh.write(line)
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError as exc:
                    raise LedgerError("cannot write audit log: %s" % exc) from exc
            finally:
                self._unlock_file(fd)
        return event

    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Look up one event by event_id, or None if it has not been logged.

        Used by multi-file restore recovery to decide whether the shared
        event reached the ledger after a crash.
        """
        for event in self._read_all():
            if event.event_id == event_id:
                return event
        return None

    def commitment(self, message: str) -> str:
        """Keyed, opaque digest of request material that must never be stored.

        The idempotent encrypt binds on the exact (normalized) request, but its
        plaintext and AAD are secret. The operation/mirror records therefore
        carry only this HMAC-SHA256 commitment (keyed by the 0600
        ``audit.secret``) of the secret fields: equal inputs replay, differing
        inputs conflict, and the material itself can neither be recovered from
        disk nor forged without the secret.
        """
        return hmac.new(
            self._signing_secret(),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

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
