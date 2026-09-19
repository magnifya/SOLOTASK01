"""Persistent, tenant-isolated, versioned key storage."""

import json
import os
import re
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional

from .audit import AuditLog
from .crypto import generate_key

try:  # fcntl is POSIX-only; rotation still works without cross-process locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# A key_id is a canonical UUID4 hex string; validating it prevents path
# traversal via key_id in lookups.
_KEY_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


@dataclass
class VersionRecord:
    """One immutable key version. Old versions are never overwritten."""

    version: int
    created_at: str
    algorithm: str
    public_key: Optional[str]
    private_material: str

    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "private_material": self.private_material,
        }

    @classmethod
    def from_json(cls, data: dict) -> "VersionRecord":
        return cls(
            version=int(data["version"]),
            created_at=data["created_at"],
            algorithm=data["algorithm"],
            public_key=data.get("public_key"),
            private_material=data["private_material"],
        )

    def to_version_response(self, key_id: str) -> dict:
        """Body of GET .../versions/{v} and .../current. No private material."""
        return {
            "key_id": key_id,
            "version": self.version,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
        }


@dataclass
class KeyRecord:
    """A named key owned by one tenant, with append-only versions."""

    key_id: str
    tenant_id: str
    label: str
    versions: list = field(default_factory=list)  # list[VersionRecord]
    current_version: int = 0
    # Revocation state. Records written before revocation existed have no
    # status on disk and are treated as "active".
    status: str = "active"
    reason: Optional[str] = None
    operator: Optional[str] = None
    revoked_at: Optional[str] = None

    @property
    def created_at(self) -> str:
        """Creation time of the key: the timestamp of its first version."""
        return self.versions[0].created_at

    @property
    def current(self) -> VersionRecord:
        return self.versions[self.current_version - 1]

    def get_version(self, version: int) -> Optional[VersionRecord]:
        for ver in self.versions:
            if ver.version == version:
                return ver
        return None

    def append_version(self, ver: VersionRecord) -> None:
        """Append an immutable version and advance the current pointer."""
        self.versions.append(ver)
        self.current_version = ver.version

    def to_json(self) -> dict:
        return {
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "label": self.label,
            "current_version": self.current_version,
            "status": self.status,
            "reason": self.reason,
            "operator": self.operator,
            "revoked_at": self.revoked_at,
            "versions": [ver.to_json() for ver in self.versions],
        }

    @classmethod
    def from_json(cls, data: dict) -> "KeyRecord":
        if "versions" in data:
            versions = [VersionRecord.from_json(v) for v in data["versions"]]
            current_version = int(data["current_version"])
        else:
            # Backwards compatibility with the pre-versioning flat format.
            versions = [
                VersionRecord(
                    version=1,
                    created_at=data["created_at"],
                    algorithm=data["algorithm"],
                    public_key=data.get("public_key"),
                    private_material=data["private_material"],
                )
            ]
            current_version = 1
        return cls(
            key_id=data["key_id"],
            tenant_id=data["tenant_id"],
            label=data["label"],
            versions=versions,
            current_version=current_version,
            status=data.get("status", "active"),
            reason=data.get("reason"),
            operator=data.get("operator"),
            revoked_at=data.get("revoked_at"),
        )

    def to_create_response(self) -> dict:
        """Body of POST /v1/keys (201). Never contains private material."""
        return {
            "key_id": self.key_id,
            "algorithm": self.current.algorithm,
            "public_key": self.current.public_key,
        }

    def to_rotate_response(self) -> dict:
        """Body of POST .../rotate (201). Never contains private material."""
        return {
            "key_id": self.key_id,
            "version": self.current.version,
            "algorithm": self.current.algorithm,
            "public_key": self.current.public_key,
        }

    def to_status_response(self) -> dict:
        """Body of GET .../status (200) and POST .../revoke (200).

        For an active key the revocation fields are null.
        """
        return {
            "key_id": self.key_id,
            "status": self.status,
            "reason": self.reason,
            "operator": self.operator,
            "revoked_at": self.revoked_at,
        }

    def to_get_response(self) -> dict:
        """Body of GET /v1/keys/{key_id} (200). Never contains private material."""
        return {
            "algorithm": self.current.algorithm,
            "label": self.label,
            "created_at": self.created_at,
            "public_key": self.current.public_key,
        }


class KeyStore:
    """File-backed key store with one JSON file per key."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        # One lock per key_id serializes read-modify-write within a process.
        self._locks_lock = threading.Lock()
        self._locks: dict = {}
        self.audit = AuditLog(data_dir)

    def record_tenant_conflict(self) -> None:
        """Audit a request whose tenant was missing, empty or conflicting.

        Both identifiers are null, so the event is never visible to any
        tenant's audit query. Raises AuditError if the event cannot be
        persisted.
        """
        self.audit.append("tenant_conflict", None, None, "rejected")

    def _key_lock(self, key_id: str) -> threading.Lock:
        with self._locks_lock:
            lock = self._locks.get(key_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[key_id] = lock
            return lock

    def _path_for(self, key_id: str) -> str:
        return os.path.join(self.data_dir, key_id + ".json")

    def _lock_path_for(self, key_id: str) -> str:
        return os.path.join(self.data_dir, key_id + ".lock")

    @contextmanager
    def _file_lock(self, key_id: str) -> Iterator[None]:
        """Cross-process advisory lock guarding rotation of a single key."""
        lock_path = self._lock_path_for(key_id)
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            yield
            return
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _write_atomic(self, path: str, payload: dict) -> None:
        """Write JSON to path atomically, with owner-only permissions.

        The temp file is fsynced before the rename, so a crash at any point
        leaves either the previous file or the complete new file.
        """
        fd, tmp_path = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
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

    def _read_record(self, path: str) -> Optional[KeyRecord]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            return KeyRecord.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None

    def create(self, tenant_id: str, algorithm: str, label: str) -> KeyRecord:
        """Generate, persist and return a new key record (version 1)."""
        generated = generate_key(algorithm)
        key_id = str(uuid.uuid4())
        record = KeyRecord(
            key_id=key_id,
            tenant_id=tenant_id,
            label=label,
            versions=[
                VersionRecord(
                    version=1,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    algorithm=algorithm,
                    public_key=generated.public_material,
                    private_material=generated.private_material,
                )
            ],
            current_version=1,
        )
        # The key_id is fresh, but take the same locks as rotation so a
        # concurrent rotate cannot observe a half-written create.
        with self._key_lock(key_id), self._file_lock(key_id):
            self._write_atomic(self._path_for(key_id), record.to_json())
            try:
                self.audit.append("create", tenant_id, key_id, "success")
            except BaseException:
                # The mutation and its audit event commit together: if the
                # event cannot be persisted, the key must not persist either.
                try:
                    os.unlink(self._path_for(key_id))
                except OSError:
                    pass
                raise
        return record

    def get(
        self, key_id: str, tenant_id: str, audit: bool = False
    ) -> Optional[KeyRecord]:
        """Return the record only when it belongs to the tenant, else None.

        With audit=True a "read" event is written: success records both
        identifiers, while an unknown or foreign key records only the
        requesting tenant (key_id stays null).
        """
        record = self._get_unchecked(key_id, tenant_id)
        if audit:
            if record is None:
                self.audit.append("read", tenant_id, None, "rejected")
            else:
                self.audit.append("read", tenant_id, key_id, "success")
        return record

    def _get_unchecked(self, key_id: str, tenant_id: str) -> Optional[KeyRecord]:
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        record = self._read_record(self._path_for(key_id))
        if record is None or record.tenant_id != tenant_id:
            # Same result whether the key is missing or owned by another
            # tenant: never confirm the existence of another tenant's key.
            return None
        return record

    def rotate(self, key_id: str, tenant_id: str, algorithm: str) -> Optional[KeyRecord]:
        """Append a new version with fresh material.

        Returns None for an unknown or foreign key. Versions are strictly
        incrementing; the on-disk state is read, extended and written back
        atomically under per-key locks so concurrent rotations never lose a
        version or leave a dangling current pointer. The rotation and its
        audit event commit together: if the event cannot be persisted, the
        previous on-disk state is restored.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            self.audit.append("rotate", tenant_id, None, "rejected")
            return None
        path = self._path_for(key_id)
        with self._key_lock(key_id), self._file_lock(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                self.audit.append("rotate", tenant_id, None, "rejected")
                return None
            previous = record.to_json()
            next_number = record.current_version + 1
            generated = generate_key(algorithm)
            record.append_version(
                VersionRecord(
                    version=next_number,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    algorithm=algorithm,
                    public_key=generated.public_material,
                    private_material=generated.private_material,
                )
            )
            self._write_atomic(path, record.to_json())
            try:
                self.audit.append("rotate", tenant_id, key_id, "success")
            except BaseException:
                # Roll back the rotation so no mutation persists without
                # its audit event.
                self._write_atomic(path, previous)
                raise
        return record

    def revoke(
        self, key_id: str, tenant_id: str, reason: str, operator: str
    ) -> Optional[KeyRecord]:
        """Mark a key as revoked, keeping the first revocation's values.

        Returns None for an unknown or foreign key. The read-modify-write
        runs under the same per-key locks as rotation and is committed
        atomically, so repeated or concurrent revokes are idempotent: the
        first reason/operator/revoked_at win and are never overwritten.
        The revocation and its audit event commit together.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            self.audit.append("revoke", tenant_id, None, "rejected")
            return None
        path = self._path_for(key_id)
        with self._key_lock(key_id), self._file_lock(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                self.audit.append("revoke", tenant_id, None, "rejected")
                return None
            if record.status != "revoked":
                previous = record.to_json()
                record.status = "revoked"
                record.reason = reason
                record.operator = operator
                record.revoked_at = datetime.now(timezone.utc).isoformat()
                self._write_atomic(path, record.to_json())
                try:
                    self.audit.append("revoke", tenant_id, key_id, "success")
                except BaseException:
                    # Roll back so no mutation persists without its event.
                    self._write_atomic(path, previous)
                    raise
            else:
                # Idempotent re-revoke still counts as a successful revoke.
                self.audit.append("revoke", tenant_id, key_id, "success")
        return record

    def get_version(
        self, key_id: str, tenant_id: str, version: int, audit: bool = False
    ) -> Optional[tuple]:
        """Return (record, version_record); None if key/version not accessible.

        With audit=True a "read" event is written. An unknown version of
        the tenant's own key records both identifiers; an unknown or
        foreign key records only the requesting tenant.
        """
        record = self._get_unchecked(key_id, tenant_id)
        if record is None:
            if audit:
                self.audit.append("read", tenant_id, None, "rejected")
            return None
        ver = record.get_version(version)
        if ver is None:
            if audit:
                self.audit.append("read", tenant_id, key_id, "rejected")
            return None
        if audit:
            self.audit.append("read", tenant_id, key_id, "success")
        return record, ver

