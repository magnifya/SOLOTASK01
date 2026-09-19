"""Persistent, tenant-isolated, versioned key storage.

On-disk format (one ``<key_id>.json`` file per key)::

    {
      "key_id": "...", "tenant_id": "...", "label": "...",
      "current_version": 2,
      "versions": {
        "1": {"version": 1, "created_at": "...", "algorithm": "...",
              "public_key": "...", "private_material": "..."},
        ...
      }
    }

Files written by the pre-versioning layout (flat fields, no ``versions``)
are transparently interpreted as a single version 1.

Writes are atomic (temp file + ``os.replace``) and rotations are serialized
per key with an exclusive ``flock`` plus a process-internal lock, so
concurrent rotations never lose versions or leave a dangling pointer.
"""

import fcntl
import json
import os
import re
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .crypto import generate_key

# A key_id is a canonical UUID4 hex string; validating it prevents path
# traversal via key_id in lookups.
_KEY_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


@dataclass
class KeyVersion:
    """One immutable version of a key."""

    version: int
    created_at: str
    algorithm: str
    public_key: Optional[str]
    private_material: str

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "private_material": self.private_material,
        }

    @classmethod
    def from_json(cls, data: dict) -> "KeyVersion":
        return cls(
            version=int(data["version"]),
            created_at=data["created_at"],
            algorithm=data["algorithm"],
            public_key=data.get("public_key"),
            private_material=data["private_material"],
        )


@dataclass
class KeyRecord:
    """A key and all of its immutable versions plus the current pointer."""

    key_id: str
    tenant_id: str
    label: str
    current_version: int
    versions: dict = field(default_factory=dict)  # type: ignore[type-arg]

    # -- (de)serialization -------------------------------------------------
    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "label": self.label,
            "current_version": self.current_version,
            "versions": {
                str(number): version.to_json()
                for number, version in sorted(self.versions.items())
            },
        }

    @classmethod
    def from_json(cls, data: dict) -> "KeyRecord":
        if "versions" in data:
            versions = {
                int(number): KeyVersion.from_json(version_data)
                for number, version_data in data["versions"].items()
            }
            return cls(
                key_id=data["key_id"],
                tenant_id=data["tenant_id"],
                label=data["label"],
                current_version=int(data["current_version"]),
                versions=versions,
            )
        # Legacy pre-versioning file: its single payload becomes version 1.
        version = KeyVersion(
            version=1,
            created_at=data["created_at"],
            algorithm=data["algorithm"],
            public_key=data.get("public_key"),
            private_material=data["private_material"],
        )
        return cls(
            key_id=data["key_id"],
            tenant_id=data["tenant_id"],
            label=data["label"],
            current_version=1,
            versions={1: version},
        )

    @property
    def current(self) -> KeyVersion:
        return self.versions[self.current_version]

    # -- response projections (never contain private material) -------------
    def to_create_response(self) -> dict:
        """Body of POST /v1/keys (201)."""
        return {
            "key_id": self.key_id,
            "version": self.current.version,
            "algorithm": self.current.algorithm,
            "public_key": self.current.public_key,
        }

    def to_get_response(self) -> dict:
        """Body of GET /v1/keys/{key_id} (200)."""
        return {
            "key_id": self.key_id,
            "version": self.current.version,
            "label": self.label,
            "created_at": self.current.created_at,
            "algorithm": self.current.algorithm,
            "public_key": self.current.public_key,
        }

    def to_rotate_response(self) -> dict:
        """Body of POST /v1/keys/{key_id}/rotate (201)."""
        return {
            "key_id": self.key_id,
            "version": self.current.version,
            "algorithm": self.current.algorithm,
            "public_key": self.current.public_key,
        }

    def to_version_response(self, version_number: int) -> Optional[dict]:
        """Body of GET /v1/keys/{key_id}/versions/{version}."""
        version = self.versions.get(version_number)
        if version is None:
            return None
        return {
            "key_id": self.key_id,
            "version": version.version,
            "created_at": version.created_at,
            "algorithm": version.algorithm,
            "public_key": version.public_key,
        }

    def to_current_response(self) -> dict:
        """Body of GET /v1/keys/{key_id}/current."""
        return self.to_version_response(self.current.version)  # type: ignore[return-value]


class KeyStore:
    """File-backed key store with one JSON file per key."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        # Serializes threads inside this process; flock serializes separate
        # processes against the same data directory.
        self._locks_guard = threading.Lock()
        self._key_locks: dict = {}

    # -- low-level helpers -------------------------------------------------
    def _path_for(self, key_id: str) -> str:
        return os.path.join(self.data_dir, key_id + ".json")

    def _lock_for(self, key_id: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._key_locks.get(key_id)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key_id] = lock
            return lock

    def _write_atomic(self, path: str, payload: dict) -> None:
        """Write JSON to path atomically, with owner-only permissions.

        A failed write leaves any previously persisted file untouched: the
        temp file is discarded and the destination is only reached via
        os.replace on success.
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

    def _read(self, key_id: str) -> Optional[KeyRecord]:
        """Read and parse a key file, or None if it is missing/corrupt."""
        path = self._path_for(key_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            return KeyRecord.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None

    def _mutate_locked(
        self, key_id: str, mutate
    ):
        """Run ``mutate(record_or_none)`` under the per-key lock.

        The mutate callback returns ``(result, should_write)``; when
        should_write is true the returned (possibly new) record is persisted
        atomically while still holding the lock. flock makes the
        read-modify-write transactional across processes as well.
        """
        path = self._path_for(key_id)
        with self._lock_for(key_id):
            with open(path + ".lock", "a") as lock_fh:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                try:
                    record = self._read(key_id)
                    result, should_write = mutate(record)
                    if should_write:
                        assert result is not None
                        self._write_atomic(path, result.to_json())
                    return result
                finally:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    # -- public API --------------------------------------------------------
    def create(self, tenant_id: str, algorithm: str, label: str) -> KeyRecord:
        """Generate, persist and return a new key record (version 1)."""
        generated = generate_key(algorithm)
        record = KeyRecord(
            key_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            label=label,
            current_version=1,
            versions={
                1: KeyVersion(
                    version=1,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    algorithm=algorithm,
                    public_key=generated.public_material,
                    private_material=generated.private_material,
                )
            },
        )
        self._write_atomic(self._path_for(record.key_id), record.to_json())
        return record

    def get(self, key_id: str, tenant_id: str) -> Optional[KeyRecord]:
        """Return the record only when it belongs to the tenant, else None."""
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        record = self._read(key_id)
        if record is None or record.tenant_id != tenant_id:
            return None
        return record

    def rotate(
        self, key_id: str, tenant_id: str, algorithm: str
    ) -> Optional[KeyRecord]:
        """Append a freshly generated version and point current at it.

        Returns the updated record, or None if the key is unknown to this
        tenant. The key's label is carried over unchanged.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            return None

        def mutate(record):
            if record is None or record.tenant_id != tenant_id:
                # Do not reveal another tenant's key: behave like a miss.
                return None, False
            generated = generate_key(algorithm)
            next_number = max(record.versions) + 1
            record.versions[next_number] = KeyVersion(
                version=next_number,
                created_at=datetime.now(timezone.utc).isoformat(),
                algorithm=algorithm,
                public_key=generated.public_material,
                private_material=generated.private_material,
            )
            record.current_version = next_number
            return record, True

        return self._mutate_locked(key_id, mutate)

    def get_version(
        self, key_id: str, tenant_id: str, version_number: int
    ) -> Optional[KeyRecord]:
        """Return the record (tenant-checked) if it has that version."""
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        if not isinstance(version_number, int) or version_number < 1:
            return None
        record = self.get(key_id, tenant_id)
        if record is None or version_number not in record.versions:
            return None
        return record

    def get_current(
        self, key_id: str, tenant_id: str
    ) -> Optional[KeyRecord]:
        """Tenant-checked current version; semantically identical to get."""
        return self.get(key_id, tenant_id)
