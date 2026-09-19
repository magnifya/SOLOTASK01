"""Persistent, tenant-scoped audit log for key operations.

Events are appended to an append-only JSONL file next to the key files.
Each event carries: event_id, tenant_id, action, key_id, outcome and a
UTC timestamp. Events whose tenant could not be determined
(action="tenant_conflict") are stored with both identifiers null and are
never visible to any tenant query.
"""

import base64
import hashlib
import hmac
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import List, Optional

try:  # fcntl is POSIX-only; appending still works without cross-process locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Actions that appear in audit events.
ACTIONS = ("create", "read", "rotate", "revoke", "tenant_conflict")

# Outcomes recorded on every event.
OUTCOMES = ("success", "rejected")

# Fields exposed to API/CLI consumers, in response order.
_PUBLIC_FIELDS = ("event_id", "tenant_id", "action", "key_id", "outcome", "timestamp")


class AuditError(Exception):
    """Raised when an audit event cannot be persisted."""


class CursorError(Exception):
    """Raised when a pagination cursor is invalid, tampered or stale."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class AuditLog:
    """Append-only audit event log backed by one JSONL file."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._path = os.path.join(self.data_dir, "audit.jsonl")
        self._secret_path = os.path.join(self.data_dir, "audit.secret")
        self._lock = threading.Lock()
        self._secret = self._load_secret()

    # -- internal helpers -------------------------------------------------
    def _load_secret(self) -> bytes:
        """Load or create the HMAC secret used to sign cursors."""
        try:
            with open(self._secret_path, "r", encoding="ascii") as fh:
                return bytes.fromhex(fh.read().strip())
        except (OSError, ValueError):
            secret = os.urandom(32)
            fd = os.open(self._secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="ascii") as fh:
                    fh.write(secret.hex())
                    fh.flush()
                    os.fsync(fh.fileno())
            except BaseException:
                try:
                    os.unlink(self._secret_path)
                except OSError:
                    pass
                raise
            return secret

    def _sign(self, payload: bytes) -> str:
        return _b64encode(hmac.new(self._secret, payload, hashlib.sha256).digest())

    def _read_events(self) -> List[dict]:
        """Read every stored event; malformed lines are skipped."""
        events = []
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(event, dict) and "seq" in event:
                        events.append(event)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise AuditError("cannot read audit log: %s" % exc) from exc
        return events

    @staticmethod
    def _public(event: dict) -> dict:
        """Projection exposed to clients: no internal sequence number."""
        return {name: event.get(name) for name in _PUBLIC_FIELDS}

    # -- writing -----------------------------------------------------------
    def append(
        self,
        action: str,
        tenant_id: Optional[str],
        key_id: Optional[str],
        outcome: str,
    ) -> dict:
        """Persist one event and return it. Raises AuditError on failure."""
        event = {
            "event_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "action": action,
            "key_id": key_id,
            "outcome": outcome,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            # The next sequence number is one past the current maximum, so
            # restarts and concurrent processes never reuse a number.
            seq = 1 + max((e["seq"] for e in self._read_events()), default=0)
            event["seq"] = seq
            line = json.dumps(event, separators=(",", ":")) + "\n"
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    if fcntl is not None:
                        fcntl.flock(fd, fcntl.LOCK_EX)
                    os.write(fd, line.encode("utf-8"))
                    os.fsync(fd)
                finally:
                    if fcntl is not None:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    os.close(fd)
            except OSError as exc:
                raise AuditError("cannot write audit event: %s" % exc) from exc
        return self._public(event)

    # -- querying ----------------------------------------------------------
    def _encode_cursor(
        self,
        tenant_id: str,
        key_id: Optional[str],
        action: Optional[str],
        snapshot: int,
        last: list,
    ) -> str:
        payload = json.dumps(
            {
                "v": 1,
                "tenant_id": tenant_id,
                "key_id": key_id,
                "action": action,
                "snapshot": snapshot,
                "last": last,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return _b64encode(payload) + "." + self._sign(payload)

    def _decode_cursor(
        self,
        cursor: str,
        tenant_id: str,
        key_id: Optional[str],
        action: Optional[str],
    ) -> dict:
        try:
            raw_payload, signature = cursor.split(".", 1)
            payload = _b64decode(raw_payload)
        except (ValueError, TypeError):
            raise CursorError("invalid cursor: malformed encoding")
        if not hmac.compare_digest(self._sign(payload), signature):
            raise CursorError("invalid cursor: signature mismatch")
        try:
            data = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise CursorError("invalid cursor: malformed payload")
        if not isinstance(data, dict) or data.get("v") != 1:
            raise CursorError("invalid cursor: unsupported shape")
        # The cursor is bound to the tenant and the filters: a paginated
        # scan may not change them mid-stream.
        if (
            data.get("tenant_id") != tenant_id
            or data.get("key_id") != key_id
            or data.get("action") != action
        ):
            raise CursorError("invalid cursor: tenant or filters changed")
        last = data.get("last")
        snapshot = data.get("snapshot")
        if (
            not isinstance(last, list)
            or len(last) != 2
            or not all(isinstance(item, str) for item in last)
            or not isinstance(snapshot, int)
        ):
            raise CursorError("invalid cursor: malformed position")
        return data

    def query(
        self,
        tenant_id: str,
        key_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> dict:
        """Return {"events": [...], "next_cursor": ...} for one tenant.

        Events are ordered by (timestamp, event_id) ascending. The cursor
        binds the tenant, the filters and a snapshot of the log, so
        paginating never repeats or skips events within that snapshot.
        Raises CursorError for an invalid, tampered or mismatched cursor.
        """
        with self._lock:
            events = self._read_events()
        if cursor is not None:
            state = self._decode_cursor(cursor, tenant_id, key_id, action)
            snapshot = state["snapshot"]
            last = (state["last"][0], state["last"][1])
        else:
            # First page: the snapshot is everything visible right now;
            # later pages ignore events appended after this point.
            snapshot = max((e["seq"] for e in events), default=0)
            last = None
        visible = [
            e
            for e in events
            if e["seq"] <= snapshot
            and e.get("tenant_id") == tenant_id
            and (key_id is None or e.get("key_id") == key_id)
            and (action is None or e.get("action") == action)
        ]
        visible.sort(key=lambda e: (e["timestamp"], e["event_id"]))
        if last is not None:
            visible = [
                e for e in visible if (e["timestamp"], e["event_id"]) > last
            ]
        page = visible[:limit]
        next_cursor = None
        if len(visible) > limit and page:
            next_cursor = self._encode_cursor(
                tenant_id,
                key_id,
                action,
                snapshot,
                [page[-1]["timestamp"], page[-1]["event_id"]],
            )
        return {
            "events": [self._public(e) for e in page],
            "next_cursor": next_cursor,
        }
