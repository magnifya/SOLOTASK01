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

from . import audit as audit_mod
from . import keybundle
from . import provider as provider_mod
from .audit import AuditEvent, AuditLog, LedgerError
from .provider import (
    LOCAL_PROVIDER_ID,
    ProviderUnavailable,
)

try:  # fcntl is POSIX-only; rotation still works without cross-process locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# A key_id is a canonical RFC 4122 UUID4 hex string: the version nibble must
# be 4 and the variant nibble must be one of 8/9/a/b. Validating it prevents
# path traversal via key_id in lookups and rejects malformed identifiers as
# parameter errors rather than missing keys.
_KEY_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def is_valid_key_id(key_id) -> bool:
    """True only for a canonical lowercase RFC 4122 UUID4 string."""
    return isinstance(key_id, str) and bool(_KEY_ID_RE.fullmatch(key_id))


# Outcomes of an import: a brand-new record, or a key_id that already exists
# (whose on-disk record must remain byte-for-byte untouched).
IMPORT_CREATED = "created"
IMPORT_CONFLICT = "conflict"


@dataclass
class VersionRecord:
    """One immutable key version. Old versions are never overwritten.

    Private material is owned by a KMS/HSM provider: the record persists only
    the provider's id, an opaque handle and opaque encrypted material. Raw
    key material is never stored. Records written before the provider layer
    carried raw ``private_material`` owned by the built-in local provider;
    KeyStore adopts those into the local provider on open.
    """

    version: int
    created_at: str
    algorithm: str
    public_key: Optional[str]
    provider_id: str = LOCAL_PROVIDER_ID
    handle: str = ""
    encrypted_material: str = ""

    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "provider_id": self.provider_id,
            "handle": self.handle,
            "encrypted_material": self.encrypted_material,
        }

    @classmethod
    def from_json(cls, data: dict) -> "VersionRecord":
        provider_id = data.get("provider_id")
        if provider_id is None:
            # Pre-provider record: raw material was owned by the built-in
            # local software provider and is adopted on open.
            provider_id = LOCAL_PROVIDER_ID
        return cls(
            version=int(data["version"]),
            created_at=data["created_at"],
            algorithm=data["algorithm"],
            public_key=data.get("public_key"),
            provider_id=provider_id,
            handle=data.get("handle") or "",
            encrypted_material=(
                data["encrypted_material"]
                if "encrypted_material" in data
                else data["private_material"]
            ),
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
    # Outbox: when set, this event is committed to the audit ledger as part of
    # the same logical transaction as the record on disk. A value surviving a
    # restart means the process crashed between the key-file commit and the
    # ledger append; KeyStore recovers it on open.
    pending_event: Optional[dict] = None

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
            "pending_event": self.pending_event,
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
                    provider_id=LOCAL_PROVIDER_ID,
                    handle="",
                    encrypted_material=data["private_material"],
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
            pending_event=data.get("pending_event"),
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

    def __init__(self, data_dir: str, audit_log: Optional[AuditLog] = None) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        # One lock per key_id serializes read-modify-write within a process.
        self._locks_lock = threading.Lock()
        self._locks: dict = {}
        self.audit = audit_log if audit_log is not None else AuditLog(data_dir)
        # Remember the data directory without importing a module:factory
        # provider or creating local provider state. A module:factory
        # provider loads lazily on its first operation, and a pre-provider
        # record is taken over by the local provider lazily on the first
        # export/backup that needs its material (and never while a non-local
        # provider is active).
        provider_mod.bind_data_dir(self.data_dir)
        # First finish/roll back interrupted single-key outbox transactions
        # (their resolution keeps the key's handles and drops the journal) ...
        self._recover_pending_events()
        # ... then delete handles provisioned by attempts that died before
        # their commit point (their audit event never reached the ledger and
        # no pending marker references it). Multi-file restore groups are
        # resolved later by the RestoreCoordinator, which reaps their
        # journals itself.
        self._recover_provisions()

    # -- provider helpers --------------------------------------------------
    @staticmethod
    def _provider():
        """The active KMS/HSM provider (imported lazily on first use)."""
        return provider_mod.get_provider()

    # -- provision journal -------------------------------------------------
    # An import/restore attempt mints provider objects (handles) *before* its
    # conflict recheck, file writes and the durable audit append. The journal
    # records every minted handle as it appears and is removed only after the
    # attempt finishes (commit or clean rollback). A process killed in between
    # is cleaned up at the next open: handles whose committing audit event is
    # in the ledger stay; every other handle is deleted, idempotently.
    _PROVISION_DIR = "provisions"

    def _provision_path(self, journal_id: str) -> str:
        return os.path.join(
            self.data_dir, self._PROVISION_DIR, journal_id + ".json"
        )

    def _new_provision_journal(self, journal_id: str):
        """Create one journal file for an import/restore attempt.

        The journal is named after the attempt's audit ``event_id``: a
        leftover journal can then be resolved at any startup by asking the
        ledger whether that event committed — committed means keep every
        handle, otherwise delete them. Returns (journal_id, path). A crash
        before the journal exists simply means no handles were recorded yet.
        """
        directory = os.path.join(self.data_dir, self._PROVISION_DIR)
        os.makedirs(directory, exist_ok=True)
        path = self._provision_path(journal_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        return journal_id, path

    def _append_provision(self, path: str, provider_id: str, handle: str) -> None:
        """Durably record one minted handle in an attempt's journal."""
        entry = {"provider_id": provider_id, "handle": handle}
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def _discard_provision_journal(self, path: str) -> None:
        """Drop an attempt's journal after it committed or rolled back."""
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            # Best effort: a stale journal is harmless (recovery re-deletes
            # handles of a committed event by id and re-deletes others), so a
            # cleanup failure must not mask the request's outcome.
            pass

    def _delete_provisioned_handle(self, provider_id: str, handle: str) -> None:
        if provider_id == LOCAL_PROVIDER_ID:
            # Crash cleanup may need the local backend before any request
            # configured it; bind it here (this never imports an external
            # module:factory provider).
            try:
                provider_mod.configure_local(self.data_dir)
            except ProviderUnavailable:
                return
        try:
            provider = self._provider_for(provider_id)
        except ProviderUnavailable:
            return
        try:
            provider.delete(handle)
        except Exception:
            pass

    def _restore_marker_journals(self) -> set:
        """Journal ids referenced by still-present restore markers.

        A multi-file restore transaction is resolved by the
        RestoreCoordinator; its journals must not be reaped here even if its
        single shared event is not in the ledger yet (the coordinator either
        commits and keeps the handles, or rolls the whole group back and
        deletes them). Markers can live on a key file or, for a policy-only
        restore, in the policies directory.
        """
        referenced = set()

        def consider(marker) -> None:
            if isinstance(marker, dict) and marker.get("_restore"):
                journal_id = marker.get("journal")
                if isinstance(journal_id, str) and journal_id:
                    referenced.add(journal_id)

        try:
            names = os.listdir(self.data_dir)
        except OSError:
            names = []
        for name in names:
            if name.endswith(".json") and is_valid_key_id(name[:-5]):
                record = self._read_record(os.path.join(self.data_dir, name))
                if record is not None:
                    consider(record.pending_event)
        policy_dir = os.path.join(self.data_dir, "policies")
        try:
            policy_names = os.listdir(policy_dir)
        except OSError:
            policy_names = []
        for name in policy_names:
            if not name.endswith(".json"):
                continue
            try:
                with open(
                    os.path.join(policy_dir, name), "r", encoding="utf-8"
                ) as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(doc, dict):
                consider(doc.get("pending_event"))
        return referenced

    def _recover_provisions(self) -> None:
        """Delete handles from attempts that died before committing.

        A journal line is kept (handle retained) only when its transaction's
        audit event reached the ledger. Journals of uncommitted attempts are
        applied (every recorded handle deleted, idempotently) and removed;
        committed journals are removed as well. Journals still referenced by a
        restore marker are deferred to the RestoreCoordinator. Nothing here
        imports a provider when there are no handles to reap, so opening a
        store for plain reads stays provider-free.
        """
        deferred = self._restore_marker_journals()
        directory = os.path.join(self.data_dir, self._PROVISION_DIR)
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            journal_id = name[:-5]
            if journal_id in deferred:
                continue
            path = os.path.join(directory, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            entries = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, dict):
                    continue
                provider_id = entry.get("provider_id")
                handle = entry.get("handle")
                if isinstance(provider_id, str) and provider_id and isinstance(
                    handle, str
                ) and handle:
                    entries.append((provider_id, handle))
            committed = False
            try:
                if uuid.UUID(journal_id).version == 4:
                    committed = self.audit.get_event(journal_id) is not None
            except (ValueError, AttributeError):
                committed = False
            except LedgerError:
                # Cannot decide right now; leave the whole journal for a
                # later open rather than deleting committed material.
                continue
            if not committed:
                for provider_id, handle in entries:
                    self._delete_provisioned_handle(provider_id, handle)
            try:
                os.unlink(path)
            except OSError:
                pass

    def drop_provision_journal(self, journal_id: str) -> None:
        """Remove an attempt journal after it committed or rolled back."""
        if not journal_id:
            return
        self._discard_provision_journal(self._provision_path(journal_id))

    def read_provision_journal(self, journal_id: str) -> list:
        """Return the (provider_id, handle) pairs an attempt journal holds."""
        if not journal_id:
            return []
        path = self._provision_path(journal_id)
        entries = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            provider_id = entry.get("provider_id")
            handle = entry.get("handle")
            if isinstance(provider_id, str) and provider_id and isinstance(
                handle, str
            ) and handle:
                entries.append((provider_id, handle))
        return entries

    def release_journal_handles(self, journal_id: str) -> None:
        """Idempotently delete every handle recorded in an attempt journal."""
        for provider_id, handle in self.read_provision_journal(journal_id):
            self._delete_provisioned_handle(provider_id, handle)

    def _take_over_legacy(self, record: KeyRecord) -> None:
        """Lazily adopt raw pre-provider versions into the local provider.

        Only runs while the local provider is the active provider; a legacy
        version touched while a module:factory provider is active is refused
        by :meth:`_provider_for` instead (503) and nothing is rewritten. Every
        version is validated and wrapped *before* the file is rewritten once,
        atomically: if validation or the write fails the original file stays
        byte-for-byte intact and the handles just minted are released.
        """
        if not provider_mod.active_is_local():
            return
        local = provider_mod.configure_local(self.data_dir)
        adopted = []
        new_versions = []
        changed = False
        try:
            for ver in record.versions:
                if (
                    ver.provider_id == LOCAL_PROVIDER_ID
                    and not ver.handle
                ):
                    triple = local.import_material(
                        ver.algorithm,
                        ver.public_key,
                        ver.encrypted_material,
                    )
                    adopted.append(triple.handle)
                    new_versions.append(
                        (
                            ver,
                            triple.handle,
                            triple.encrypted_material,
                            triple.public_key,
                        )
                    )
                    changed = True
            if not changed:
                return
            for ver, handle, material, public_key in new_versions:
                ver.handle = handle
                ver.encrypted_material = material
                if ver.public_key is None:
                    ver.public_key = public_key
            self._write_atomic(
                self._path_for(record.key_id), record.to_json()
            )
        except BaseException:
            # Validation failed or the atomic rewrite did not land: the
            # original file is untouched. Release the registry entries this
            # takeover just minted so the local backend leaks nothing.
            for handle in adopted:
                try:
                    local.delete(handle)
                except Exception:
                    pass
            raise

    # -- audit bookkeeping -------------------------------------------------
    def audit_conflict(self, event_id: Optional[str] = None) -> None:
        """Record an invisible tenant_conflict event (both ids null)."""
        self.audit.append(
            self.audit.new_event(
                None,
                audit_mod.ACTION_TENANT_CONFLICT,
                None,
                audit_mod.OUTCOME_REJECTED,
                event_id=event_id,
            )
        )

    def audit_attempt(
        self,
        tenant_id,
        key_id,
        action: str,
        outcome: str,
        event_id: Optional[str] = None,
    ) -> None:
        """Record one attempt against a key.

        When the tenant is known and non-empty and the key_id is either
        absent (create) or a legal UUID4, both identifiers are recorded and
        the event is visible to that tenant only. A missing/empty/illegal
        identifier collapses to an invisible tenant_conflict with null ids.
        ``event_id`` pins the event id (idempotent operations pin it to their
        operation_id so a replayed request reuses the exact same event).
        """
        if (
            isinstance(tenant_id, str)
            and tenant_id
            and (key_id is None or is_valid_key_id(key_id))
            and action in (
                audit_mod.ACTION_CREATE,
                audit_mod.ACTION_READ,
                audit_mod.ACTION_ROTATE,
                audit_mod.ACTION_REVOKE,
                audit_mod.ACTION_IMPORT,
                audit_mod.ACTION_EXPORT,
                audit_mod.ACTION_AUDIT,
            )
        ):
            event = self.audit.new_event(
                tenant_id, action, key_id, outcome, event_id=event_id
            )
        else:
            event = self.audit.new_event(
                None,
                audit_mod.ACTION_TENANT_CONFLICT,
                None,
                audit_mod.OUTCOME_REJECTED,
                event_id=event_id,
            )
        self.audit.append(event)

    def _recover_pending_events(self) -> None:
        """Commit outbox events left pending by a crashed process."""
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            return
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            path = os.path.join(self.data_dir, name)
            key_id = name[:-5]
            with self._key_lock(key_id), self._file_lock(key_id):
                record = self._read_record(path)
                if record is None or not record.pending_event:
                    continue
                # A multi-file tenant restore transaction is resolved by the
                # RestoreCoordinator (its manifest drives the shared event),
                # not by this per-key recovery.
                if record.pending_event.get("_restore"):
                    continue
                # append() is idempotent on event_id, so this is safe whether
                # the crash happened before or after the ledger write.
                event = AuditEvent.from_json(record.pending_event)
                journal_id = record.pending_event.get("journal")
                try:
                    self.audit.append(event)
                    record.pending_event = None
                    self._write_atomic(path, record.to_json())
                except (LedgerError, OSError):
                    # The ledger or directory is temporarily unwritable.
                    # Leave the marker in place; it is retried on the next
                    # open (the append is idempotent on event_id).
                    continue
                if isinstance(journal_id, str) and journal_id:
                    # The import committed (event is in the ledger); its
                    # minted handles are now owned by the key, so the
                    # attempt's provision journal is finished.
                    self.drop_provision_journal(journal_id)

    def _commit_mutation(
        self,
        path: str,
        record: KeyRecord,
        event: AuditEvent,
        previous: Optional[dict],
        provider=None,
        new_handles=(),
        journal_id: Optional[str] = None,
    ) -> None:
        """Commit a key-file change and its event as one logical transaction.

        The record is first written carrying the pending event (an outbox
        marker), the event is then appended durably to the ledger, and the
        marker is cleared in a second atomic write. If the ledger append
        fails the key file is rolled back (deleted for a brand-new key whose
        ``previous`` is None, restored to its prior bytes otherwise), and any
        provider handles the change minted are deleted, so a failed ledger
        write leaves neither a single-sided file nor an orphaned HSM object.
        ``journal_id`` (import only) is folded into the marker so crash
        recovery can drop the attempt's provision journal after resolving it.
        A crash at any point is repaired idempotently by
        _recover_pending_events on the next open.
        """
        marker = event.to_json()
        if journal_id:
            marker = dict(marker)
            marker["journal"] = journal_id
        record.pending_event = marker

        def release_handles() -> None:
            # Best effort; never mask the original failure.
            if provider is None:
                return
            for handle in new_handles:
                try:
                    provider.delete(handle)
                except Exception:
                    pass

        try:
            self._write_atomic(path, record.to_json())
            self.audit.append(event)
        except BaseException:
            # Only roll the file back when it may have landed: a failure of
            # the ledger append, or of the initial write after a partial file.
            if os.path.exists(path):
                if previous is None:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                else:
                    try:
                        self._write_atomic(path, previous)
                    except Exception:
                        pass
            release_handles()
            raise
        # The durable ledger append is the commit point: the change and its
        # event are now authoritative and must never be rolled back. Clearing
        # the marker is best-effort housekeeping; a failure here (or a crash)
        # is repaired on the next open and must not surface as a failed
        # request or trigger handle deletion.
        record.pending_event = None
        try:
            self._write_atomic(path, record.to_json())
        except OSError:
            pass

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

    @staticmethod
    def _provider_for(provider_id: str):
        """Return the provider instance that owns ``provider_id``.

        The built-in local provider is usable only while ``KEYMGR_PROVIDER``
        is unset or explicitly ``local``: a record (or bundle provenance
        block) owned by ``local`` while a module:factory provider is active is
        refused as unavailable (503), never silently handled locally. Any
        other id must match the currently active external provider, which is
        imported lazily here. A record naming an inactive provider cannot be
        rotated/exported/imported and fails 503 rather than switching
        providers.
        """
        if provider_id == LOCAL_PROVIDER_ID:
            if provider_mod.active_is_local():
                return provider_mod.get_local_provider()
            raise ProviderUnavailable(
                "record is owned by the local provider, which is not active"
            )
        active = provider_mod.get_provider()
        if active.provider_id != provider_id:
            raise ProviderUnavailable(
                "record provider %r is not the active provider" % provider_id
            )
        return active

    def create(self, tenant_id: str, algorithm: str, label: str) -> KeyRecord:
        """Generate, persist and return a new key record (version 1).

        Material is minted by the active KMS/HSM provider; only the provider
        triple (provider_id, handle, encrypted_material) is persisted. The
        create event is committed in the same transaction as the key file; a
        ledger failure deletes both the just-written file and the minted
        handle and raises LedgerError, so the change and its event never land
        separately.
        """
        provider = self._provider()
        triple = provider.generate(algorithm)
        key_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        record = KeyRecord(
            key_id=key_id,
            tenant_id=tenant_id,
            label=label,
            versions=[
                VersionRecord(
                    version=1,
                    created_at=created_at,
                    algorithm=algorithm,
                    public_key=triple.public_key,
                    provider_id=provider.provider_id,
                    handle=triple.handle,
                    encrypted_material=triple.encrypted_material,
                )
            ],
            current_version=1,
        )
        event = self.audit.new_event(
            tenant_id, audit_mod.ACTION_CREATE, key_id,
            audit_mod.OUTCOME_SUCCESS, timestamp=created_at,
        )
        # The key_id is fresh, but take the same locks as rotation so a
        # concurrent rotate cannot observe a half-written create.
        with self._key_lock(key_id), self._file_lock(key_id):
            self._commit_mutation(
                self._path_for(key_id), record, event, None,
                provider=provider, new_handles=(triple.handle,),
            )
        return record

    def get(self, key_id: str, tenant_id: str) -> Optional[KeyRecord]:
        """Return the record only when it belongs to the tenant, else None."""
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        record = self._read_record(self._path_for(key_id))
        if record is None or record.tenant_id != tenant_id:
            # Same result whether the key is missing or owned by another
            # tenant: never confirm the existence of another tenant's key.
            return None
        return record

    def rotate(
        self,
        key_id: str,
        tenant_id: str,
        algorithm: str,
        event_id: Optional[str] = None,
    ) -> Optional[KeyRecord]:
        """Append a new version with fresh material.

        Returns None for an unknown or foreign key. Versions are strictly
        incrementing; the on-disk state is read, extended and written back
        atomically under per-key locks so concurrent rotations never lose a
        version or leave a dangling current pointer. ``event_id`` pins the
        committing audit event (an idempotent operation reuses its
        operation_id); a fresh id is minted otherwise.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        path = self._path_for(key_id)
        with self._key_lock(key_id), self._file_lock(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                return None
            if event_id is not None:
                # Crash-after-commit replay guard: the pinned event already
                # reached the ledger, so its version is authoritative. Do not
                # mint another version; the caller replays the stored result.
                try:
                    if self.audit.get_event(event_id) is not None:
                        return record
                except LedgerError:
                    pass
            # A version is rotated on the provider that owns the record;
            # switching providers mid-key is refused (503), never silently
            # migrated.
            provider = self._provider_for(record.current.provider_id)
            previous = record.to_json()
            next_number = record.current_version + 1
            created_at = datetime.now(timezone.utc).isoformat()
            triple = provider.rotate(algorithm)
            record.append_version(
                VersionRecord(
                    version=next_number,
                    created_at=created_at,
                    algorithm=algorithm,
                    public_key=triple.public_key,
                    provider_id=provider.provider_id,
                    handle=triple.handle,
                    encrypted_material=triple.encrypted_material,
                )
            )
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_ROTATE, key_id,
                audit_mod.OUTCOME_SUCCESS, timestamp=created_at,
                event_id=event_id,
            )
            self._commit_mutation(
                path, record, event, previous,
                provider=provider, new_handles=(triple.handle,),
            )
        return record

    def revoke(
        self, key_id: str, tenant_id: str, reason: str, operator: str
    ) -> Optional[KeyRecord]:
        """Mark a key as revoked, keeping the first revocation's values.

        Returns None for an unknown or foreign key. The read-modify-write
        runs under the same per-key locks as rotation and is committed
        atomically, so repeated or concurrent revokes are idempotent: the
        first reason/operator/revoked_at win and are never overwritten.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        path = self._path_for(key_id)
        with self._key_lock(key_id), self._file_lock(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                return None
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_REVOKE, key_id,
                audit_mod.OUTCOME_SUCCESS,
            )
            if record.status != "revoked":
                previous = record.to_json()
                record.status = "revoked"
                record.reason = reason
                record.operator = operator
                record.revoked_at = event.timestamp
                self._commit_mutation(path, record, event, previous)
            else:
                # Idempotent repeat: nothing changes, but the successful
                # revoke call is still written to the ledger.
                self.audit.append(event)
        return record

    def get_version(
        self, key_id: str, tenant_id: str, version: int
    ) -> Optional[tuple]:
        """Return (record, version_record); None if key/version not accessible."""
        record = self.get(key_id, tenant_id)
        if record is None:
            return None
        ver = record.get_version(version)
        if ver is None:
            return None
        return record, ver

    # -- export / import ---------------------------------------------------
    def _export_version(self, ver: VersionRecord) -> dict:
        """Project one version for a sealed bundle.

        The owning provider turns the stored handle back into exportable
        material; a version whose provider is not active cannot be exported
        and raises ProviderUnavailable (503) rather than leaking an opaque
        blob. The bundle carries the raw material (legacy ``private_material``
        field) plus a ``provider`` provenance block mirroring the persisted
        triple. Both exist only inside the authenticated bundle.
        """
        provider = self._provider_for(ver.provider_id)
        exported = provider.export_material(ver.handle)
        return {
            "version": ver.version,
            "created_at": ver.created_at,
            "algorithm": ver.algorithm,
            "public_key": ver.public_key,
            "private_material": exported.encrypted_material,
            "provider": {
                "provider_id": ver.provider_id,
                "handle": ver.handle,
                "encrypted_material": ver.encrypted_material,
            },
        }

    def export_payload(self, record: KeyRecord) -> dict:
        """Build the single-key export payload via the owning provider(s)."""
        return {
            "format": keybundle.FORMAT,
            "key_id": record.key_id,
            "label": record.label,
            "current_version": record.current_version,
            "status": record.status,
            "reason": record.reason,
            "operator": record.operator,
            "revoked_at": record.revoked_at,
            "versions": [self._export_version(v) for v in record.versions],
        }

    def export_bundle(
        self, key_id: str, tenant_id: str, passphrase: str
    ) -> Optional[str]:
        """Seal a tenant's full key record into an opaque bundle.

        Returns None for an unknown or foreign key, so the caller cannot tell
        the two cases apart. Export does not mutate committed state beyond the
        lazy one-time adoption of a pre-provider record, and never imports a
        non-local provider; its audit event is appended by the caller
        alongside the response, like a read.
        """
        if not is_valid_key_id(key_id):
            return None
        path = self._path_for(key_id)
        with self._key_lock(key_id), self._file_lock(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                return None
            # Adopt a raw legacy record now, under the key locks and only
            # while the local provider is active. When a module:factory
            # provider is active this is a no-op and _export_version fails
            # the local-owned version as 503, without rewriting anything.
            self._take_over_legacy(record)
            return keybundle.encode_bundle(
                self.export_payload(record), passphrase
            )

    def prepare_backup_record(self, record: KeyRecord) -> KeyRecord:
        """Lazily adopt a record's legacy versions for a tenant backup.

        Called by the RestoreCoordinator while it already holds the key
        locks, so the takeover rewrite is part of the backup's consistent
        snapshot.
        """
        self._take_over_legacy(record)
        return record

    def _adopt_imported_version(self, ver: dict, journal: Optional[str] = None) -> tuple:
        """Adopt one validated bundle version through its target provider.

        Returns (VersionRecord, provider). A ``provider`` provenance block
        naming the active provider imports through it; a block naming another
        provider is a 503 mismatch. A legacy bundle without a block
        (``keymgr-export-v1`` emitted before the provider layer) is interpreted
        as local material, and is accepted only while the local provider is
        the active one — with an external provider configured it is refused
        503 and never falls back. Only the provider's freshly-minted triple is
        ever persisted; raw private material is never written to a key file.
        Every minted handle is durably recorded in ``journal`` (when given)
        before the call returns, so a crash before the commit point reaps it.
        """
        block = ver.get("provider")
        if block is None:
            if not provider_mod.active_is_local():
                raise ProviderUnavailable(
                    "legacy bundle without a provider block is local-only; "
                    "the local provider is not active"
                )
            target = provider_mod.configure_local(self.data_dir)
        else:
            target = self._provider_for(block["provider_id"])
        triple = target.import_material(
            ver["algorithm"], ver["public_key"], ver["private_material"]
        )
        if journal is not None:
            self._append_provision(journal, target.provider_id, triple.handle)
        public_key = (
            triple.public_key
            if triple.public_key is not None
            else ver["public_key"]
        )
        record = VersionRecord(
            version=ver["version"],
            created_at=ver["created_at"],
            algorithm=ver["algorithm"],
            public_key=public_key,
            provider_id=target.provider_id,
            handle=triple.handle,
            encrypted_material=triple.encrypted_material,
        )
        return record, target

    @staticmethod
    def _release_handles(adopted) -> None:
        """Best-effort delete of (provider, handle) pairs on a failed import."""
        for target, handle in adopted:
            try:
                target.delete(handle)
            except Exception:
                pass

    def release_record_handles(self, record: KeyRecord) -> None:
        """Best-effort delete every provider handle a (to-be-discarded) record holds.

        Used when a restore that minted provider objects never commits; each
        version is routed to its owning provider. A missing/inactive provider
        only means that provider's handles cannot be reached from here, so the
        cleanup is skipped for those versions rather than failing the rollback.
        """
        for ver in record.versions:
            try:
                target = self._provider_for(ver.provider_id)
            except ProviderUnavailable:
                continue
            try:
                target.delete(ver.handle)
            except Exception:
                pass

    def import_bundle(
        self,
        tenant_id: str,
        payload: dict,
        event_id: Optional[str] = None,
    ) -> tuple:
        """Persist a validated export payload under the importing tenant.

        Returns (IMPORT_CREATED, record) for a brand-new key_id, or
        (IMPORT_CONFLICT, existing) when the key_id already exists; the
        existing record on disk is never touched, and the caller decides 409
        versus 404 from its owner. Every version is adopted through the
        matching provider (a mismatch raises ProviderUnavailable -> 503 and
        malformed material ProviderInvalidMaterial -> 400) **before** the
        conflict recheck or any file is written; handles minted by a refused
        or failed attempt are all deleted and no file or audit line changes.
        A successful import and its audit event commit through the same
        outbox transaction as create/rotate.
        """
        key_id = payload["key_id"]
        # Mint the committing event up front so the provision journal is
        # named after its event_id: a leftover journal resolves at any startup
        # by asking the ledger whether the event committed.
        event = self.audit.new_event(
            tenant_id, audit_mod.ACTION_IMPORT, key_id,
            audit_mod.OUTCOME_SUCCESS, event_id=event_id,
        )
        journal_id, journal_path = self._new_provision_journal(event.event_id)
        try:
            adopted = []  # (provider, handle)
            versions = []
            try:
                for ver in payload["versions"]:
                    version_record, target = self._adopt_imported_version(
                        ver, journal_path
                    )
                    versions.append(version_record)
                    adopted.append((target, version_record.handle))
            except BaseException:
                self._release_handles(adopted)
                raise
            record = KeyRecord(
                key_id=key_id,
                tenant_id=tenant_id,
                label=payload["label"],
                versions=versions,
                current_version=payload["current_version"],
                status=payload["status"],
                reason=payload["reason"],
                operator=payload["operator"],
                revoked_at=payload["revoked_at"],
            )
            path = self._path_for(key_id)
            with self._key_lock(key_id), self._file_lock(key_id):
                # Conflict recheck only after every version validated and
                # every provider call succeeded; nothing has been written.
                existing = self._read_record(path)
                if existing is not None:
                    if event_id is not None:
                        # A replay pinned to an event already in the ledger is
                        # the same commit finishing, not a new conflict: the
                        # existing record is this operation's result.
                        try:
                            if self.audit.get_event(event_id) is not None:
                                self._release_handles(adopted)
                                return IMPORT_CREATED, existing
                        except LedgerError:
                            pass
                    self._release_handles(adopted)
                    return IMPORT_CONFLICT, existing
                try:
                    # Rollback of the just-created file plus explicit handle
                    # release below; the provision journal also reaps on
                    # crash.
                    self._commit_mutation(
                        path, record, event, None,
                        journal_id=journal_id,
                    )
                except BaseException:
                    self._release_handles(adopted)
                    raise
                # Committed: the handles are owned by the new record and the
                # durable event makes the journal obsolete.
                self.drop_provision_journal(journal_id)
                journal_id = None
            return IMPORT_CREATED, record
        finally:
            if journal_id is not None:
                # Any non-commit exit (provider failure, validation, conflict,
                # aborted transaction): every minted handle was released
                # above; the journal itself is no longer needed.
                self.drop_provision_journal(journal_id)

    # -- tenant backup / restore ------------------------------------------
    def list_for_tenant(self, tenant_id: str) -> list:
        """Return all KeyRecords owned by the tenant (sorted by key_id)."""
        records = []
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            return records
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            record = self._read_record(os.path.join(self.data_dir, name))
            if record is not None and record.tenant_id == tenant_id:
                records.append(record)
        records.sort(key=lambda r: r.key_id)
        return records

    def backup_entry(self, record: KeyRecord) -> dict:
        """Project a record for a tenant backup payload.

        The projection includes private material; it is only ever sealed
        inside the authenticated tenant bundle and never appears in a
        response or an audit projection. Each version is resolved through its
        owning provider exactly like a single-key export.
        """
        return {
            "key_id": record.key_id,
            "label": record.label,
            "current_version": record.current_version,
            "status": record.status,
            "reason": record.reason,
            "operator": record.operator,
            "revoked_at": record.revoked_at,
            "versions": [self._export_version(v) for v in record.versions],
        }

    def read_raw(self, key_id: str) -> Optional[KeyRecord]:
        """Read a record by key_id without a tenant check (restore checks)."""
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        return self._read_record(self._path_for(key_id))

    def record_from_backup(
        self, tenant_id: str, entry: dict, journal: Optional[str] = None
    ) -> KeyRecord:
        """Build an unsaved KeyRecord from a validated backup keys[i] entry.

        Every version is adopted through its matching provider (the bundle's
        ``provider`` provenance block, or the built-in local provider for a
        legacy bundle without one and only while local is active), so the
        restored record carries fresh handles and never raw private material.
        A provider mismatch raises ProviderUnavailable (503); malformed
        material raises ProviderInvalidMaterial (400). Minted handles are
        durably recorded in ``journal`` and released on any later failure.
        """
        versions = []
        adopted = []
        try:
            for ver in entry["versions"]:
                version_record, target = self._adopt_imported_version(
                    ver, journal
                )
                versions.append(version_record)
                adopted.append((target, version_record.handle))
        except BaseException:
            # A later version failed a provider match or validation; release
            # every handle this record minted for its earlier versions.
            self._release_handles(adopted)
            raise
        record = KeyRecord(
            key_id=entry["key_id"],
            tenant_id=tenant_id,
            label=entry["label"],
            versions=versions,
            current_version=entry["current_version"],
            status=entry["status"],
            reason=entry["reason"],
            operator=entry["operator"],
            revoked_at=entry["revoked_at"],
        )
        return record

    def write_restore_pending(
        self, record: KeyRecord, marker: dict
    ) -> None:
        """Atomically write a restored key file carrying the shared marker.

        Used by the RestoreCoordinator's multi-file outbox transaction; the
        caller guarantees the key_id is free and holds the per-key locks.
        """
        record.pending_event = marker
        self._write_atomic(self._path_for(record.key_id), record.to_json())

    def clear_restore_pending(self, record: KeyRecord) -> None:
        """Rewrite a restored key file without its pending marker."""
        record.pending_event = None
        self._write_atomic(self._path_for(record.key_id), record.to_json())

    def remove_file(self, key_id: str) -> None:
        """Delete a key file written by a restore being rolled back."""
        try:
            os.unlink(self._path_for(key_id))
        except FileNotFoundError:
            pass

    @contextmanager
    def key_locks(self, key_id: str) -> Iterator[None]:
        """Acquire the in-process and cross-process locks for one key_id."""
        with self._key_lock(key_id), self._file_lock(key_id):
            yield

    @contextmanager
    def multi_key_locks(self, key_ids) -> Iterator[None]:
        """Acquire the per-key locks for many key_ids, in sorted order.

        A fixed acquisition order keeps this deadlock-free against the
        restore transaction, which also takes its key locks sorted.
        """
        acquired = []
        try:
            for key_id in sorted(set(key_ids)):
                lock_cm = self.key_locks(key_id)
                lock_cm.__enter__()
                acquired.append(lock_cm)
            yield
        finally:
            for lock_cm in reversed(acquired):
                lock_cm.__exit__(None, None, None)

