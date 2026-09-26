"""Persistent append-only audit ledger with tenant-isolated pagination."""

import base64
import hashlib
import hmac
import json
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass
from typing import List, NamedTuple, Optional, Tuple

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

# Key order of a pre-chain (legacy) ledger line; chained lines append
# ``prev_mac`` and ``mac``. The anchor file fixes its own key order.
_EVENT_FIELDS = (
    "event_id",
    "tenant_id",
    "action",
    "key_id",
    "outcome",
    "timestamp",
    "seq",
)
_CHAIN_FIELDS = _EVENT_FIELDS + ("prev_mac", "mac")
_ANCHOR_FIELDS = ("schema_version", "legacy_bytes", "legacy_mac")
_ANCHOR_SCHEMA_VERSION = 1
_HEX64 = frozenset("0123456789abcdef")


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

    The ledger is tamper-evident: the first load validates any pre-chain
    (legacy) lines and anchors their byte count and HMAC in
    ``audit-anchor.json`` (0600, temp-file fsync + rename); every line
    appended afterwards carries ``prev_mac``/``mac`` chaining back to that
    anchor. Every read and append re-verifies anchor, anchored prefix and
    the full chain under the file lock; corruption raises LedgerError and
    is never skipped or re-signed.
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
        # MAC of the last committed line (or of the anchored legacy prefix
        # when no chained line exists yet). Valid only while the file lock
        # is held; refreshed by every verified read.
        self._chain_head: Optional[str] = None

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
        """Read-or-create the HMAC secret. Caller holds the file lock."""
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

    # -- tamper-evident chain ------------------------------------------------
    @staticmethod
    def _dumps_compact(obj: dict) -> str:
        """Compact UTF-8 JSON, non-ASCII as-is, no trailing newline."""
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _is_hex64(value) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(ch in _HEX64 for ch in value)
        )

    @staticmethod
    def _legacy_mac(secret: bytes, raw: bytes) -> str:
        """HMAC-SHA256 of the anchored pre-chain bytes (``legacy\\0`` tag)."""
        return hmac.new(secret, b"legacy\0" + raw, hashlib.sha256).hexdigest()

    def _event_mac(self, secret: bytes, event: AuditEvent, prev_mac: str) -> str:
        """HMAC-SHA256 of the line's first eight keys, same encoding."""
        payload = event.to_json()
        payload["prev_mac"] = prev_mac
        return hmac.new(
            secret,
            self._dumps_compact(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _check_event_fields(
        obj: dict, expected_seq: int, seen_ids: set
    ) -> AuditEvent:
        """Type-check the seven event fields of one parsed line."""
        event_id = obj["event_id"]
        tenant_id = obj["tenant_id"]
        action = obj["action"]
        key_id = obj["key_id"]
        outcome = obj["outcome"]
        timestamp = obj["timestamp"]
        seq = obj["seq"]
        if not isinstance(event_id, str):
            raise LedgerError("audit log event_id is not a string")
        if tenant_id is not None and not isinstance(tenant_id, str):
            raise LedgerError("audit log tenant_id is not a string or null")
        if not isinstance(action, str):
            raise LedgerError("audit log action is not a string")
        if key_id is not None and not isinstance(key_id, str):
            raise LedgerError("audit log key_id is not a string or null")
        if not isinstance(outcome, str):
            raise LedgerError("audit log outcome is not a string")
        if not isinstance(timestamp, str):
            raise LedgerError("audit log timestamp is not a string")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise LedgerError("audit log seq is not a positive integer")
        if seq != expected_seq:
            raise LedgerError("audit log seq is not consecutive from 1")
        if event_id in seen_ids:
            raise LedgerError("audit log event_id is duplicated")
        seen_ids.add(event_id)
        return AuditEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            action=action,
            key_id=key_id,
            outcome=outcome,
            timestamp=timestamp,
            seq=seq,
        )

    def _parse_legacy_line(
        self, line: str, expected_seq: int, seen_ids: set
    ) -> AuditEvent:
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise LedgerError("audit log line is not valid JSON") from exc
        if not isinstance(obj, dict) or tuple(obj.keys()) != _EVENT_FIELDS:
            raise LedgerError("audit log line has unknown or misordered keys")
        return self._check_event_fields(obj, expected_seq, seen_ids)

    def _parse_legacy(self, raw: bytes) -> List[AuditEvent]:
        """Validate a pre-chain ledger byte-for-byte.

        Empty lines, bad JSON and unknown keys are corruption; seq must run
        consecutively from 1 and event_id must be unique.
        """
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LedgerError("audit log is not valid UTF-8") from exc
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()  # the trailing newline of the last line
        events: List[AuditEvent] = []
        seen_ids: set = set()
        for line in lines:
            if not line:
                raise LedgerError("audit log contains an empty line")
            events.append(
                self._parse_legacy_line(line, len(events) + 1, seen_ids)
            )
        return events

    def _parse_chained_line(
        self,
        line: str,
        secret: bytes,
        expected_seq: int,
        expected_prev: str,
        seen_ids: set,
    ) -> Tuple[AuditEvent, str]:
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise LedgerError("audit log line is not valid JSON") from exc
        if not isinstance(obj, dict) or tuple(obj.keys()) != _CHAIN_FIELDS:
            raise LedgerError("audit log line has unknown or misordered keys")
        prev_mac = obj["prev_mac"]
        mac = obj["mac"]
        if not self._is_hex64(prev_mac) or not self._is_hex64(mac):
            raise LedgerError("audit log line MACs are not 64-hex")
        event = self._check_event_fields(obj, expected_seq, seen_ids)
        if prev_mac != expected_prev:
            raise LedgerError("audit log chain is broken")
        if not hmac.compare_digest(
            self._event_mac(secret, event, prev_mac), mac
        ):
            raise LedgerError("audit log line MAC mismatch")
        return event, mac

    def _read_anchor_locked(self) -> Optional[dict]:
        """Read and validate the anchor; None if it does not exist yet."""
        try:
            with open(self._anchor_path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise LedgerError("cannot read audit anchor: %s" % exc) from exc
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise LedgerError("audit anchor is corrupt") from exc
        if not isinstance(obj, dict) or tuple(obj.keys()) != _ANCHOR_FIELDS:
            raise LedgerError("audit anchor is corrupt")
        schema_version = obj["schema_version"]
        legacy_bytes = obj["legacy_bytes"]
        legacy_mac = obj["legacy_mac"]
        if (
            isinstance(schema_version, bool)
            or schema_version != _ANCHOR_SCHEMA_VERSION
            or isinstance(legacy_bytes, bool)
            or not isinstance(legacy_bytes, int)
            or legacy_bytes < 0
            or not self._is_hex64(legacy_mac)
        ):
            raise LedgerError("audit anchor is corrupt")
        return obj

    def _create_anchor_locked(self, raw: bytes) -> str:
        """Anchor the validated legacy bytes; return their MAC.

        The anchor is compact UTF-8 JSON (non-ASCII as-is, no trailing
        newline) committed by temp-file fsync + rename with 0600. A creation
        or I/O failure raises LedgerError and leaves no anchor behind.
        """
        legacy_mac = self._legacy_mac(self._signing_secret_locked(), raw)
        payload = self._dumps_compact(
            {
                "schema_version": _ANCHOR_SCHEMA_VERSION,
                "legacy_bytes": len(raw),
                "legacy_mac": legacy_mac,
            }
        ).encode("utf-8")
        try:
            fd, tmp_path = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
        except OSError as exc:
            raise LedgerError("cannot write audit anchor: %s" % exc) from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self._anchor_path)
        except OSError as exc:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise LedgerError("cannot write audit anchor: %s" % exc) from exc
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return legacy_mac

    def _verify_locked(self, raw: bytes, anchor: dict) -> List[AuditEvent]:
        """Verify anchor, anchored prefix and the full MAC chain."""
        secret = self._signing_secret_locked()
        legacy_bytes = anchor["legacy_bytes"]
        if len(raw) < legacy_bytes:
            raise LedgerError("audit log is shorter than its anchored prefix")
        prefix, rest = raw[:legacy_bytes], raw[legacy_bytes:]
        if not hmac.compare_digest(
            self._legacy_mac(secret, prefix), anchor["legacy_mac"]
        ):
            raise LedgerError("audit log legacy prefix does not match anchor")
        events = self._parse_legacy(prefix)
        head = anchor["legacy_mac"]
        if rest:
            if not rest.endswith(b"\n"):
                raise LedgerError("audit log has a torn final line")
            try:
                text = rest.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LedgerError("audit log is not valid UTF-8") from exc
            seen_ids = {event.event_id for event in events}
            seq = len(events) + 1
            for line in text.split("\n")[:-1]:
                if not line:
                    raise LedgerError("audit log contains an empty line")
                event, head = self._parse_chained_line(
                    line, secret, seq, head, seen_ids
                )
                events.append(event)
                seq += 1
        self._chain_head = head
        return events

    # -- reads -------------------------------------------------------------
    def _read_all_locked(self) -> List[AuditEvent]:
        """Read and verify every ledger line. Caller holds the file lock.

        The first load validates the pre-chain (legacy) bytes and anchors
        them in ``audit-anchor.json``; every later load verifies the anchor,
        the anchored prefix and the whole MAC chain. Corruption raises
        LedgerError; lines are never skipped and nothing is re-signed.
        """
        try:
            with open(self._log_path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            raw = b""
        except OSError as exc:
            raise LedgerError("cannot read audit log: %s" % exc) from exc
        anchor = self._read_anchor_locked()
        if anchor is None:
            events = self._parse_legacy(raw)
            self._chain_head = self._create_anchor_locked(raw)
            return events
        return self._verify_locked(raw, anchor)

    def _read_all(self) -> List[AuditEvent]:
        """Read under both locks for a consistent cross-process snapshot.

        Appends commit (write + fsync) while holding the exclusive file
        lock, so a reader holding the same lock never observes a torn or
        partially-committed tail.
        """
        with self._append_lock:
            fd = self._locked_file()
            try:
                return self._read_all_locked()
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

        The line carries the seven event fields plus ``prev_mac``/``mac``:
        the first chained line links to the anchor's ``legacy_mac``, every
        later one to the previous line's ``mac``. Raises LedgerError if the
        chain cannot be verified or the line cannot be committed. The fsync
        before release means a returned event is on disk.
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
                prev_mac = self._chain_head
                record = event.to_json()
                record["prev_mac"] = prev_mac
                record["mac"] = self._event_mac(
                    self._signing_secret_locked(), event, prev_mac
                )
                line = self._dumps_compact(record) + "\n"
                try:
                    with open(self._log_path, "a", encoding="utf-8") as fh:
                        fh.write(line)
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError as exc:
                    raise LedgerError("cannot write audit log: %s" % exc) from exc
                self._chain_head = record["mac"]
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
