"""Persistent, tenant-isolated key storage."""

import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .crypto import generate_key

# A key_id is a canonical UUID4 hex string; validating it prevents path
# traversal via key_id in lookups.
_KEY_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass
class KeyRecord:
    key_id: str
    tenant_id: str
    algorithm: str
    label: str
    created_at: str
    public_key: Optional[str]
    private_material: str

    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "algorithm": self.algorithm,
            "label": self.label,
            "created_at": self.created_at,
            "public_key": self.public_key,
            "private_material": self.private_material,
        }

    @classmethod
    def from_json(cls, data: dict) -> "KeyRecord":
        return cls(
            key_id=data["key_id"],
            tenant_id=data["tenant_id"],
            algorithm=data["algorithm"],
            label=data["label"],
            created_at=data["created_at"],
            public_key=data.get("public_key"),
            private_material=data["private_material"],
        )

    def to_create_response(self) -> dict:
        """Body of POST /v1/keys (201). Never contains private material."""
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
        }

    def to_get_response(self) -> dict:
        """Body of GET /v1/keys/{key_id} (200). Never contains private material."""
        return {
            "algorithm": self.algorithm,
            "label": self.label,
            "created_at": self.created_at,
            "public_key": self.public_key,
        }


class KeyStore:
    """File-backed key store with one JSON file per key."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)

    def _path_for(self, key_id: str) -> str:
        return os.path.join(self.data_dir, key_id + ".json")

    def _write_atomic(self, path: str, payload: dict) -> None:
        """Write JSON to path atomically, with owner-only permissions."""
        fd, tmp_path = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def create(self, tenant_id: str, algorithm: str, label: str) -> KeyRecord:
        """Generate, persist and return a new key record."""
        generated = generate_key(algorithm)
        record = KeyRecord(
            key_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            algorithm=algorithm,
            label=label,
            created_at=datetime.now(timezone.utc).isoformat(),
            public_key=generated.public_material,
            private_material=generated.private_material,
        )
        self._write_atomic(self._path_for(record.key_id), record.to_json())
        return record

    def get(self, key_id: str, tenant_id: str) -> Optional[KeyRecord]:
        """Return the record only when it belongs to the tenant, else None."""
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        path = self._path_for(key_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if data.get("tenant_id") != tenant_id:
            return None
        return KeyRecord.from_json(data)
