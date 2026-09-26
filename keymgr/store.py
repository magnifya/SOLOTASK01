"""Persistent, tenant-isolated, versioned key storage."""

import base64
import functools
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, List, NamedTuple, Optional, Tuple

from . import audit as audit_mod
from . import keybundle
from . import provider as provider_mod
from . import signing as signing_mod
from .artifacts import PHASE_COMMITTED, PHASE_ROLLED_BACK, PHASE_STAGED
from .audit import AuditEvent, AuditLog, InvalidCursor, LedgerError
from .provider import (
    LOCAL_PROVIDER_ID,
    ProviderIdentityMismatch,
    ProviderInvalidMaterial,
    ProviderReconnectPending,
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


# A batch rotation carries 1-100 items.
BATCH_MIN_ITEMS = 1
BATCH_MAX_ITEMS = 100


def is_valid_expected_version(value) -> bool:
    """True only for a positive int version precondition (never a bool)."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
    )


def validate_batch_items(raw) -> Tuple[Optional[List[Tuple[str, str, Optional[int]]]], Optional[str]]:
    """Validate a batch-rotate items array (shared by HTTP and CLI).

    Returns ``(items, None)`` with ``items`` a list of ``(key_id, algorithm,
    expected_version)`` triples in request order (``expected_version`` is
    None when the item omits the optional optimistic-concurrency
    precondition), or ``(None, message)`` naming the offending field.
    ``items`` must be a list of 1-100 objects carrying only ``key_id``,
    ``algorithm`` and optionally ``expected_version``; ``key_id`` values are
    unique canonical lowercase UUID4s, ``algorithm`` values are
    AES256/RSA2048 and ``expected_version`` is a positive integer (a bool is
    not a version). The check is side-effect free and runs before the
    Idempotency-Key is bound.
    """
    from .crypto import SUPPORTED_ALGORITHMS

    if not isinstance(raw, list) or not (
        BATCH_MIN_ITEMS <= len(raw) <= BATCH_MAX_ITEMS
    ):
        return None, (
            "field items must be an array of %d to %d items"
            % (BATCH_MIN_ITEMS, BATCH_MAX_ITEMS)
        )
    items: List[Tuple[str, str, Optional[int]]] = []
    seen = set()
    for index, element in enumerate(raw):
        if not isinstance(element, dict):
            return None, "field items[%d] must be an object" % index
        extra = [
            field
            for field in element
            if field not in ("key_id", "algorithm", "expected_version")
        ]
        if extra:
            return None, (
                "field items[%d].%s is not accepted by this endpoint"
                % (index, extra[0])
            )
        key_id = element.get("key_id")
        if not is_valid_key_id(key_id):
            return None, "field items[%d].key_id must be a UUID4" % index
        if key_id in seen:
            return None, (
                "field items contains a duplicate key_id: %s" % key_id
            )
        seen.add(key_id)
        algorithm = element.get("algorithm")
        if not isinstance(algorithm, str) or algorithm not in SUPPORTED_ALGORITHMS:
            return None, (
                "field items[%d].algorithm must be one of: %s"
                % (index, ", ".join(SUPPORTED_ALGORITHMS))
            )
        expected_version = element.get("expected_version")
        if expected_version is not None and not is_valid_expected_version(
            expected_version
        ):
            return None, (
                "field items[%d].expected_version must be a positive integer"
                % index
            )
        items.append((key_id, algorithm, expected_version))
    return items, None


# Outcomes of an import: a brand-new record, or a key_id that already exists
# (whose on-disk record must remain byte-for-byte untouched).
IMPORT_CREATED = "created"
IMPORT_CONFLICT = "conflict"

# Default upper bound (seconds) an idempotent operation waits on a per-key or
# restore lock before giving up as timed_out: no key material, audit event or
# provider handle may be written past this point.
DEFAULT_LOCK_TIMEOUT = 5.0

# Sentinel: surviving batch artifacts disagree about their tenant.
_TENANT_MISMATCH = object()

# Sentinel: a markerless file is named by a surviving, non-committed batch
# snapshot whose pre-image cannot be proven, so the record must be hidden
# entirely rather than projected from disk.
_HIDE_UNCOMMITTED = object()


class KeyListPage(NamedTuple):
    """Result of one key-list query: a page of records and the next cursor."""

    records: List["KeyRecord"]
    next_cursor: Optional[str]


class LockTimeout(Exception):
    """A guarded key could not be locked within the allowed wait.

    Raised only for idempotent operations after the lock-wait budget is
    exhausted; the caller answers timed_out and has mutated nothing.
    """


class KeyAlreadyMigrated(Exception):
    """Bound 409 signal: every version is already on the ready provider.

    Raised by :meth:`KeyStore.migrate` after the idempotency key is bound:
    no provider call is made, no journal/handle/event is written, and the
    caller turns it into the bound conflict terminal.
    """


class ExpectedVersionMismatch(Exception):
    """Bound 409 signal: an expected_version precondition does not hold.

    Raised by :meth:`KeyStore.rotate`/:meth:`KeyStore.batch_rotate` after
    the idempotency key is bound, under the held per-key locks, judged on
    the committed ``current_version`` before any journal, event, provider
    call or file write: nothing has been minted or mutated, and the caller
    turns it into the bound conflict terminal (one rejected event named
    after the operation_id).
    """


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
    # Per-version revocation state. A version written before version-level
    # revocation existed has no such fields on disk and is treated as active.
    status: str = "active"
    reason: Optional[str] = None
    operator: Optional[str] = None
    revoked_at: Optional[str] = None

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
            "status": self.status,
            "reason": self.reason,
            "operator": self.operator,
            "revoked_at": self.revoked_at,
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
            # A version without revocation fields (an older file/export) is
            # active; a revoked version carries all three facts together.
            status=data.get("status", "active"),
            reason=data.get("reason"),
            operator=data.get("operator"),
            revoked_at=data.get("revoked_at"),
        )

    @property
    def is_revoked(self) -> bool:
        return self.status == "revoked"

    def to_version_response(self, key_id: str) -> dict:
        """Body of GET .../versions/{v} and .../current. No private material."""
        return {
            "key_id": key_id,
            "version": self.version,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
        }

    def to_version_status_response(self, key_id: str) -> dict:
        """Body of GET .../versions/{v}/status and its revoke POST.

        For an active version the revocation fields are null.
        """
        return {
            "key_id": key_id,
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "operator": self.operator,
            "revoked_at": self.revoked_at,
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

    def to_list_response(self) -> dict:
        """One item of GET /v1/keys (200). Never contains private material.

        ``created_at`` is the first version's timestamp; every other field
        projects the committed current snapshot.
        """
        return {
            "key_id": self.key_id,
            "label": self.label,
            "current_version": self.current_version,
            "algorithm": self.current.algorithm,
            "status": self.status,
            "created_at": self.created_at,
            "public_key": self.current.public_key,
        }


def _provider_session(func):
    """Pin one logical provider operation to a single provider instance.

    The wrapped KeyStore operation runs inside one reconnect gate lease: the
    whole operation (including its crash-safety rollback deletes) uses the
    provider instance captured at admission, so a reconnect drains it rather
    than swapping underneath it, and a wait past the five-second budget fails
    with zero provider side effects.
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        with provider_mod.provider_call():
            return func(self, *args, **kwargs)

    return wrapper


class NativeUnwrap(NamedTuple):
    """A resolved version whose DEK must be unwrapped natively.

    Returned by :meth:`KeyStore.crypto_material` in ``native_unwrap`` mode
    when the version's owning provider declares the ``unwrap_key`` operation:
    the caller passes this provider/handle pair to
    ``envelope.open_envelope_native`` instead of receiving exportable KEK
    material, so private KEK material never enters the service process.
    """

    provider: object
    handle: str


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
        # ... resolve multi-key batch-rotation groups (commit-point event
        # durable -> keep and clear markers; otherwise roll every file of the
        # group back only after every minted handle was deleted) ...
        self._recover_batch_rotations()
        # ... then take over raw pre-provider records once, at startup, while
        # the local provider is active (a plain file scan; an external
        # module:factory provider is never imported or configured here) ...
        self._migrate_legacy_records()
        # ... then delete handles provisioned by attempts that died before
        # their commit point (their audit event never reached the ledger and
        # no pending marker references it). Multi-file restore groups are
        # resolved later by the RestoreCoordinator, which reaps their
        # journals itself.
        self._recover_provisions()
        # ... and finally settle whole-key migrations: a committed move reaps
        # its OLD handles from its migration snapshot; an uncommitted one
        # (journal already reaped above) restores the key file's pre-move
        # bytes.
        self._recover_migrations()

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

    def _new_provision_journal(
        self,
        journal_id: str,
        tenant_id: Optional[str] = None,
        action: Optional[str] = None,
    ):
        """Create one journal file for an import/restore attempt.

        The journal is named after the attempt's audit ``event_id``: a
        leftover journal can then be resolved at any startup by asking the
        ledger whether that event committed — committed means keep every
        handle, otherwise delete them. Returns (journal_id, path). A crash
        before the journal exists simply means no handles were recorded yet.

        The first line is a header naming the operation (its id, tenant and
        action), so crash recovery can verify that a durable event carrying
        the journal's id really is THIS attempt's commit event before
        keeping the handles: a same-id event whose action or tenant
        disagrees is a collision and must not orphan or adopt anything.
        Journals written before the header existed simply have no first
        line and fall back to the legacy id-only resolution.
        """
        directory = os.path.join(self.data_dir, self._PROVISION_DIR)
        os.makedirs(directory, exist_ok=True)
        path = self._provision_path(journal_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            header = {"operation_id": journal_id}
            if isinstance(tenant_id, str) and tenant_id:
                header["tenant_id"] = tenant_id
            if isinstance(action, str) and action:
                header["action"] = action
            line = json.dumps(header, separators=(",", ":")) + "\n"
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            # The journal never landed and no handle can reference it yet;
            # drop the partial file so a headerless journal cannot outlive
            # the attempt and be misread as a legacy one.
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        finally:
            if fd >= 0:
                os.close(fd)
        return journal_id, path

    def _append_provision(self, path: str, provider_id: str, handle: str) -> None:
        """Durably record one minted handle in an attempt's journal.

        The journal is rewritten atomically (temp file, fsync, 0600 rename)
        rather than appended in place: a crash mid-write can never tear a
        line and silently lose a handle record, which would orphan the
        backend object. Callers always hold the attempt's key locks, so the
        read-modify-write is serialized against every other writer.
        """
        entry = {"provider_id": provider_id, "handle": handle}
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                existing = fh.read()
        except OSError:
            existing = ""
        directory = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(existing + line)
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

    def _discard_provision_journal(self, path: str) -> bool:
        """Drop an attempt's journal after it committed or rolled back.

        Returns True when the journal is gone (including an already-absent
        one); a removal failure leaves the journal in place for the next
        open's recovery sweep instead of being silently swallowed.
        """
        try:
            os.unlink(path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def _delete_provisioned_handle(self, provider_id: str, handle: str) -> bool:
        """Delete one uncommitted handle. Returns True on success.

        A cleanup failure is never silently swallowed: False keeps the
        attempt's provision journal on disk so the next open retries the
        delete. Crash cleanup may need the local backend before any request
        configured it (this never imports an external module:factory
        provider); a missing/inactive provider whose handle cannot be reached
        is likewise reported, not hidden.
        """
        if provider_id == LOCAL_PROVIDER_ID:
            try:
                provider_mod.configure_local(self.data_dir)
            except ProviderUnavailable:
                return False
        try:
            provider = self._provider_for(provider_id)
        except ProviderUnavailable:
            return False
        try:
            provider.delete(handle)
        except Exception:
            return False
        return True

    def _restore_marker_journals(self) -> set:
        """Journal ids referenced by still-present outbox markers.

        A multi-file restore transaction is resolved by the
        RestoreCoordinator and a multi-key batch-rotation group by
        _recover_batch_rotations; their journals must not be reaped here even
        if its shared event is not in the ledger yet (the coordinator/group
        recovery either commits and keeps the handles, or rolls the whole
        group back and deletes them). A single-key rotate/import marker
        carrying a journal is deferred as well whenever its ledger append
        could not be settled earlier in this same open: deleting its handles
        before the event is durable would orphan the record the next open
        commits. Markers can live on a key file or, for a policy-only restore,
        in the policies directory.
        """
        referenced = set()

        def consider(marker) -> None:
            if not isinstance(marker, dict):
                return
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

    def _rollback_provision_entries(self, entries) -> bool:
        """Delete handles recorded by an uncommitted attempt.

        Returns True only when every handle was deleted (or its provider
        cannot be reached but is not local — see _delete_provisioned_handle);
        a single failed delete means False and the journal must be retained
        for a retry on the next open. Deletes stay idempotent.
        """
        cleaned = True
        for provider_id, handle in entries:
            if not self._delete_provisioned_handle(provider_id, handle):
                cleaned = False
        return cleaned

    def _recover_provisions(self) -> None:
        """Settle provision journals left by attempts that did not finish.

        Resolution is driven purely by the ledger event named after the
        journal (the operation/event id):

        * a durable ``success`` event is the commit point -- the minted
          handles are now owned by the records and stay, the journal is
          removed;
        * no event, or a durable ``rejected`` event (a bound provider-failure
          terminal), means the attempt never owned the handles -- every
          recorded handle is deleted idempotently and the journal is removed
          only once every delete succeeds;
        * an unreadable ledger, a non-UUID journal or a failed handle delete
          leaves everything in place for the next open.

        Journals still referenced by a restore marker are deferred to the
        RestoreCoordinator. Nothing here imports a provider when there are no
        handles to reap, so opening a store for plain reads stays
        provider-free.
        """
        deferred = (
            self._restore_marker_journals()
            | self.batch_recovery_journal_ids()
        )
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
            try:
                is_uuid4 = uuid.UUID(journal_id).version == 4
            except (ValueError, AttributeError):
                # An unidentifiable journal can never be resolved against an
                # event: leave it for manual/operator resolution rather than
                # deleting possibly-committed material.
                continue
            if not is_uuid4:
                continue
            event = None
            try:
                event = self.audit.get_event(journal_id)
            except LedgerError:
                # Cannot decide right now; leave the whole journal for a
                # later open rather than deleting committed material.
                continue
            if event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS:
                if self._journal_event_is_foreign_success(journal_id, event):
                    # A durable success carries this id but its action or
                    # tenant disagrees with the journal's operation header:
                    # an id collision, neither commit nor rollback is
                    # provable. Park the whole journal for resolution.
                    continue
                # Committed: handles belong to the durable records; housekeep
                # the journal. A failed unlink simply retries on next open.
                self._discard_provision_journal(path)
                continue
            # Event absent (crash/rollback) or a durable rejected terminal:
            # the attempt never owned the handles. Retain the journal until
            # every handle delete actually succeeds.
            if self._rollback_provision_entries(entries):
                self._discard_provision_journal(path)

    def drop_provision_journal(self, journal_id: str) -> bool:
        """Remove an attempt journal after it committed or fully rolled back.

        Returns True when no journal remains. A failed unlink keeps it for
        startup recovery.
        """
        if not journal_id:
            return True
        return self._discard_provision_journal(self._provision_path(journal_id))

    def rollback_provision_journal(self, journal_id: str) -> bool:
        """Delete every handle an uncommitted attempt journaled, then drop it.

        Used by the request path when an import/rotate/restore aborts before
        its commit point (provider fault, refused conflict, ledger failure).
        The journal is removed only once every recorded handle has been
        deleted; a failed backend delete retains it so the next open retries
        — cleanup failures are reported, never swallowed. Idempotent.
        """
        if not journal_id:
            return True
        entries = self.read_provision_journal(journal_id)
        if not self._rollback_provision_entries(entries):
            return False
        return self.drop_provision_journal(journal_id)

    def _abort_provision(self, journal_id: str, adopted=()) -> None:
        """Scrub handles of an aborted attempt and reconcile its journal.

        Deletes the still-known ``(provider, handle)`` pairs directly and then
        the durable journal (which covers handles whose entries were recorded
        but whose in-memory pair the aborting frame no longer holds); deletes
        are idempotent. Raises ProviderUnavailable when any delete cannot be
        verified -- the journal then stays on disk and startup retries -- so a
        cleanup failure is a 503, never a silent orphan.
        """
        cleaned = self._release_handles(adopted)
        if not self.rollback_provision_journal(journal_id):
            cleaned = False
        if not cleaned:
            raise ProviderUnavailable(
                "could not delete a handle provisioned by an aborted attempt; "
                "cleanup will be retried at startup"
            )

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

    def read_provision_journal_header(self, journal_id: str) -> Optional[dict]:
        """Return the journal's operation header, or None when absent.

        The header is the journal's first line and names the attempt's
        operation (``operation_id``/``tenant_id``/``action``). Journals
        written before headers existed have handle entries only and yield
        None; a corrupt first line also yields None (the journal is then
        resolved conservatively, as if it had no header).
        """
        if not journal_id:
            return None
        path = self._provision_path(journal_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                first = fh.readline()
        except OSError:
            return None
        try:
            header = json.loads(first)
        except ValueError:
            return None
        if not isinstance(header, dict):
            return None
        if header.get("operation_id") != journal_id:
            return None
        return header

    def _journal_event_is_commit(self, journal_id: str, event) -> bool:
        """Whether a durable SUCCESS event is THIS journal's commit event.

        The event must be a success whose action and tenant agree with the
        journal's operation header. A journal without a readable header
        (legacy format) falls back to id-only resolution, the historical
        behavior. A mismatched event is an id collision: it neither commits
        the journal's handles nor proves them uncommitted, and the caller
        must park the journal rather than adopting or deleting anything.
        """
        if event is None or event.outcome != audit_mod.OUTCOME_SUCCESS:
            return False
        header = self.read_provision_journal_header(journal_id)
        if header is None:
            return True
        action = header.get("action")
        if isinstance(action, str) and action and event.action != action:
            return False
        tenant = header.get("tenant_id")
        if isinstance(tenant, str) and tenant and event.tenant_id != tenant:
            return False
        return True

    def _journal_event_is_foreign_success(self, journal_id: str, event) -> bool:
        """Whether a durable SUCCESS event carries the id but is foreign.

        Such a collision parks the journal: the handles can neither be
        adopted (this attempt never committed) nor safely reaped without
        resolution, so the whole journal is left for an operator/later open.
        """
        if event is None or event.outcome != audit_mod.OUTCOME_SUCCESS:
            return False
        return not self._journal_event_is_commit(journal_id, event)

    def release_journal_handles(self, journal_id: str) -> bool:
        """Idempotently delete every handle recorded in an attempt journal.

        Returns True only when every delete succeeded.
        """
        return self._rollback_provision_entries(
            self.read_provision_journal(journal_id)
        )

    def _migrate_legacy_records(self) -> None:
        """Startup sweep adopting raw pre-provider records into local.

        Runs only while the built-in local provider is active. With a
        module:factory provider configured the sweep does nothing: it never
        imports that provider or rewrites a local-owned record (the record is
        refused 503 by the owning-provider gates instead, with no fallback).
        Only files that genuinely hold a raw legacy version are opened with
        the provider, so a data directory of modern records creates no DEK or
        registry and loads no provider on startup -- plain reads stay
        provider-free.

        Every candidate is adopted under its per-key locks: each raw version
        is validated and wrapped by the local provider, then the file is
        rewritten once atomically so the plaintext field disappears. A
        validation or write failure leaves the original file byte-for-byte
        intact (the just-minted handles are released) and never aborts
        startup; the record can be retried by a later export/backup.
        """
        if not provider_mod.active_is_local():
            return
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            return
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            key_id = name[:-5]
            path = os.path.join(self.data_dir, name)
            # One provider-free peek: only a record that actually carries a
            # raw legacy version proceeds to wrapping.
            record = self._read_record(path)
            if record is None or not any(
                ver.provider_id == LOCAL_PROVIDER_ID and not ver.handle
                for ver in record.versions
            ):
                continue
            try:
                with self._key_lock(key_id), self._file_lock(key_id):
                    # Re-read under the locks: another process may have
                    # adopted the record since the unlocked directory scan.
                    locked = self._read_record(path)
                    if locked is None:
                        continue
                    self._take_over_legacy(locked)
            except Exception:
                # The original file is untouched and any minted handles were
                # already released inside _take_over_legacy; skip this
                # record rather than failing startup.
                continue

    def _take_over_legacy(self, record: KeyRecord) -> None:
        """Adopt raw pre-provider versions into the local provider.

        Callers hold the key's in-process and cross-process locks. Only runs
        while the local provider is the active provider; a legacy version
        touched while a module:factory provider is active is refused by
        :meth:`_provider_for` instead (503) and nothing is rewritten. Every
        version is validated and wrapped *before* the file is rewritten once,
        atomically: if validation or the write fails the original file stays
        byte-for-byte intact and the handles just minted are released.
        """
        if not provider_mod.active_is_local():
            return
        if not any(
            ver.provider_id == LOCAL_PROVIDER_ID and not ver.handle
            for ver in record.versions
        ):
            # Nothing raw left to adopt: a projected unsettled view exports
            # through its existing handles without rewriting anything.
            return
        if getattr(record, "_unsettled_projection", False):
            # This object is a projected pre-batch view of a file that is
            # still marked on disk. Minting adoption handles and rewriting
            # would destroy the preserved crash scene; refuse the adoption
            # so the caller's export/backup answers 503 rather than guessing.
            raise ProviderUnavailable(
                "record is projected from an unsettled batch snapshot and "
                "cannot be rewritten until recovery settles"
            )
        if isinstance(record.pending_event, dict) and record.pending_event:
            # A read/backup must never rewrite a file whose transaction is
            # unresolved (event not durable): the trimmed committed view is a
            # projection only, and a rewrite would discard the recovery
            # scene. Committed markers (event durable) are safe.
            if not self._marker_event_durable(record.pending_event):
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
    def audit_conflict(self) -> None:
        """Record an invisible tenant_conflict event (both ids null)."""
        self.audit.append(
            self.audit.new_event(
                None,
                audit_mod.ACTION_TENANT_CONFLICT,
                None,
                audit_mod.OUTCOME_REJECTED,
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

        ``event_id`` names the event explicitly: an idempotent mutation's
        terminal rejection uses its operation_id, so the failure event is
        stable across a crash and replays instead of being written twice.
        """
        if (
            isinstance(tenant_id, str)
            and tenant_id
            and (key_id is None or is_valid_key_id(key_id))
            and action in (
                audit_mod.ACTION_CREATE,
                audit_mod.ACTION_READ,
                audit_mod.ACTION_ROTATE,
                audit_mod.ACTION_BATCH_ROTATE,
                audit_mod.ACTION_REVOKE,
                audit_mod.ACTION_REVOKE_VERSION,
                audit_mod.ACTION_IMPORT,
                audit_mod.ACTION_EXPORT,
                audit_mod.ACTION_MIGRATE,
                audit_mod.ACTION_ENCRYPT,
                audit_mod.ACTION_DECRYPT,
                audit_mod.ACTION_REWRAP,
                audit_mod.ACTION_SIGN,
                audit_mod.ACTION_VERIFY,
                audit_mod.ACTION_AUDIT,
                audit_mod.ACTION_LIST,
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
                # and a multi-key batch-rotation group by
                # _recover_batch_rotations; neither is resolved here.
                if record.pending_event.get("_restore") or record.pending_event.get(
                    "_batch_rotate"
                ):
                    continue
                # append() is idempotent on event_id, so this is safe whether
                # the crash happened before or after the ledger write.
                event = AuditEvent.from_json(record.pending_event)
                journal_id = record.pending_event.get("journal")
                try:
                    existing = self.audit.get_event(event.event_id)
                except LedgerError:
                    # The ledger cannot be read right now; leave the marker
                    # in place for the next open rather than guessing.
                    continue
                if existing is not None and (
                    existing.outcome != audit_mod.OUTCOME_SUCCESS
                    or existing.action != event.action
                    or existing.tenant_id != event.tenant_id
                ):
                    # A durable event already carries this id but is not
                    # exactly this operation's success event (a rejection, or
                    # an action/tenant collision): the scene can be settled
                    # neither by committing nor by rolling back. Park it --
                    # marker, journal and handles stay for operator/startup
                    # resolution, and reads keep hiding the uncommitted
                    # current.
                    continue
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
        pre_commit=None,
        marker_extra: Optional[dict] = None,
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
        ``marker_extra`` folds additional recovery facts (e.g. the version a
        per-version revocation targets) into the marker, so the committed
        projection can undo exactly that change while the event is not
        durable. ``pre_commit`` (when given) runs strictly between the
        durable marker write and the ledger append: it lets the caller
        durably persist the idempotent operation's terminal context so the
        response can be replayed verbatim once the event lands; an exception
        rolls the file and handles back exactly like a failed ledger append.
        A crash at any point is repaired idempotently by
        _recover_pending_events on the next open.
        """
        marker = event.to_json()
        if journal_id or marker_extra:
            marker = dict(marker)
            if journal_id:
                marker["journal"] = journal_id
            if marker_extra:
                marker.update(marker_extra)
        record.pending_event = marker

        def release_handles() -> bool:
            # Returns False when a minted handle could not be deleted: the
            # caller must surface that (503) instead of hiding an orphaned
            # backend object.
            if provider is None:
                return True
            cleaned = True
            for handle in new_handles:
                try:
                    provider.delete(handle)
                except Exception:
                    cleaned = False
            return cleaned

        try:
            self._write_atomic(path, record.to_json())
            if pre_commit is not None:
                # The in-memory record already carries the version being
                # committed, so the caller can stage the exact 201 response
                # before the commit-point append.
                pre_commit(record)
            self.audit.append(event)
        except BaseException as exc:
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
            if not release_handles():
                # The file is rolled back but a backend object survives:
                # report a provider failure (503, generic client message);
                # callers keep/retry the provision journal so startup
                # eventually deletes the handle.
                raise ProviderUnavailable(
                    "rollback could not delete a provisioned provider handle"
                ) from exc
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
    def _timed_inproc(self, key_id: str, deadline) -> Iterator[None]:
        """Acquire the per-key in-process lock against a shared deadline."""
        inproc = self._key_lock(key_id)
        remaining = max(deadline - time.monotonic(), 0.0)
        if not inproc.acquire(timeout=remaining):
            raise LockTimeout(key_id)
        try:
            yield
        finally:
            inproc.release()

    @contextmanager
    def _file_lock(self, key_id: str, deadline=None) -> Iterator[None]:
        """Cross-process advisory lock guarding mutation of a single key.

        The in-process lock is taken separately by callers. With ``deadline``
        (a monotonic deadline) the fcntl lock is acquired non-blocking with
        polling and :class:`LockTimeout` is raised when the deadline passes;
        otherwise this blocks until acquired, the historical behavior.
        """
        lock_path = self._lock_path_for(key_id)
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            yield
            return
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        acquired = False
        try:
            if deadline is None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise LockTimeout(key_id)
                        time.sleep(min(0.02, remaining))
            acquired = True
            yield
        finally:
            if acquired:
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

    def _write_bytes_atomic(self, path: str, raw: bytes) -> None:
        """Write raw bytes to path atomically (0600, fsynced before rename).

        Used to restore a rotated key file to its EXACT pre-batch bytes: a
        JSON re-serialization could differ from the original even while
        decoding to the same object, so an uncommitted batch rollback writes
        the snapshot's captured bytes verbatim instead.
        """
        fd, tmp_path = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
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

    @staticmethod
    def _read_file_bytes(path: str) -> bytes:
        with open(path, "rb") as fh:
            return fh.read()

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
            # The built-in local provider is a provider_id like any other:
            # when a readable committed state names a different active entry
            # and local WAS active earlier in this data directory (a directed
            # switchover/reconnect displaced it), a bound idempotent operation
            # owned by it must stay PENDING until a local entry is active
            # again, exactly like an external id. A local id never active here
            # (or a corrupt/missing committed state) is the classic
            # inactive-provider terminal refusal (503), never a silent
            # fallback.
            if provider_mod.local_provider_displaced():
                raise ProviderIdentityMismatch(
                    "record provider %r was displaced by a provider switch"
                    % LOCAL_PROVIDER_ID
                )
            raise ProviderUnavailable(
                "record is owned by the local provider, which is not active"
            )
        active = provider_mod.get_provider()
        if active.provider_id != provider_id:
            # The active provider carries a different id. If the record's id
            # WAS active earlier in this data directory, the record belongs to
            # an instance displaced by a reconnect: a PENDING idempotent
            # operation must stay pending until a provider with the same id is
            # reconnected, rather than being frozen as a terminal failure. A
            # provider id never active here is the classic inactive-provider
            # refusal (503), never a silent switch.
            if provider_mod.provider_was_active(provider_id):
                raise ProviderIdentityMismatch(
                    "record provider %r was displaced by a reconnect to %r"
                    % (provider_id, active.provider_id)
                )
            raise ProviderUnavailable(
                "record provider %r is not the active provider" % provider_id
            )
        return active

    @_provider_session
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

    def _marker_event_durable(self, marker) -> bool:
        """True when a pending marker's SUCCESS event reached the ledger.

        Markers carry the event nested under ``"event"`` (the multi-file
        shapes) or flat (single-key outbox). Only a durable ``success`` event
        commits the file change: a durable ``rejected`` terminal with the same
        id can coexist with a preserved (parked) scene when an in-request
        rollback itself failed, and that state must still be treated as
        uncommitted -- reads project the prior version and mutators wait for
        crash recovery. The durable event must also BE this operation's
        event: a same-id event whose action or tenant disagrees is an id
        collision, not this mutation's commit point, and is treated as not
        durable (the scene parks rather than exposing an uncommitted
        current). An unreadable ledger is treated as not durable.
        """
        if not isinstance(marker, dict):
            return False
        nested = marker.get("event")
        desc = nested if isinstance(nested, dict) else marker
        event_id = desc.get("event_id") if isinstance(desc, dict) else None
        if not isinstance(event_id, str) or not event_id:
            return False
        try:
            event = self.audit.get_event(event_id)
        except LedgerError:
            return False
        if event is None or event.outcome != audit_mod.OUTCOME_SUCCESS:
            return False
        action = desc.get("action") if isinstance(desc, dict) else None
        if isinstance(action, str) and action and event.action != action:
            return False
        tenant = desc.get("tenant_id") if isinstance(desc, dict) else None
        if isinstance(tenant, str) and tenant and event.tenant_id != tenant:
            return False
        return True

    def _batch_committed_view(self, record: KeyRecord) -> Optional[KeyRecord]:
        """Project one file carrying an unsettled ``_batch_rotate`` marker.

        The old state is reconstructed from the DURABLE snapshot
        ``batch-rotations/<event_id>.json``, re-read from disk and validated
        exactly like crash recovery (filename == event_id, payload event_id/
        tenant, the marker's journal/snapshot references and complete unique
        key set, every ``previous_b64`` strictly decoded into a KeyRecord with
        matching key_id/tenant, contiguous versions and a valid
        current_version) -- never from this frame's in-memory file.

        Returns the snapshot's pre-batch KeyRecord, the on-disk record when the
        batch's success event is durable, or None (hide the record) whenever:

        * the snapshot is missing, corrupt or semantically mismatched;
        * the marker's action/tenant/event references do not agree;
        * the ledger cannot be read (an outage must never expose an
          uncommitted current).
        """
        marker = record.pending_event
        if not isinstance(marker, dict) or not marker.get("_batch_rotate"):
            return None
        desc = marker.get("event")
        if not isinstance(desc, dict):
            return None
        eid = desc.get("event_id")
        if not is_valid_key_id(eid):
            return None
        if desc.get("action") != audit_mod.ACTION_BATCH_ROTATE:
            return None
        marker_tenant = desc.get("tenant_id")
        if (
            not isinstance(marker_tenant, str)
            or marker_tenant != record.tenant_id
            or marker.get("tenant_id") != record.tenant_id
        ):
            return None
        # The ledger is the commit authority. An unreadable ledger is
        # "unsettled and unprovable": hide rather than project either view.
        try:
            event = self.audit.get_event(eid)
        except LedgerError:
            return None
        if event is not None:
            if (
                event.outcome == audit_mod.OUTCOME_SUCCESS
                and event.action == audit_mod.ACTION_BATCH_ROTATE
                and event.tenant_id == record.tenant_id
            ):
                # Committed: the new versions are authoritative; only
                # marker-clear housekeeping remains.
                return record
            # A durable rejected terminal with the same id leaves the
            # preserved scene uncommitted -- fall through to the snapshot.
        snapshot_path = self._batch_snapshot_path(eid)
        if not os.path.exists(snapshot_path):
            return None
        raw_snapshot = self._read_batch_snapshot(eid)
        if raw_snapshot is None or raw_snapshot.get("tenant_id") != record.tenant_id:
            return None
        # This file's own marker carries the complete write set; it is enough
        # to cross-validate every artifact of the attempt.
        entries = self._validated_batch_snapshot(eid, raw_snapshot, [marker])
        if entries is None:
            return None
        for key_id, _raw_bytes, previous_record in entries:
            if key_id == record.key_id:
                # This view is a PROJECTION of durable rollback data, not the
                # file on disk: tag it so export/backup's lazy legacy adoption
                # never rewrites the still-marked file (which would destroy
                # the preserved crash scene). An old legacy version that would
                # have needed adoption is therefore refused 503 while the
                # group is unsettled, instead of being guessed at.
                previous_record._unsettled_projection = True
                return previous_record
        return None

    def _migration_committed_view(
        self, record: KeyRecord, desc: dict
    ) -> Optional[KeyRecord]:
        """Project a key file carrying an unsettled migrate marker.

        A migrate rewrites the same version set's provider triples in place,
        so its pre-image cannot be derived from the in-memory record: it is
        rebuilt exclusively from the durable ``migrations/<event_id>.json``
        snapshot (the key file's literal pre-move bytes). A durable matching
        ``migrate`` success makes the on-disk triples authoritative; an
        absent/unreadable ledger, a corrupt/missing snapshot or any mismatch
        hides the record rather than exposing uncommitted triples.
        """
        eid = desc.get("event_id") if isinstance(desc, dict) else None
        if not is_valid_key_id(eid):
            return None
        try:
            event = self.audit.get_event(eid)
        except LedgerError:
            return None
        if event is not None:
            if (
                event.outcome == audit_mod.OUTCOME_SUCCESS
                and event.action == audit_mod.ACTION_MIGRATE
                and event.tenant_id == record.tenant_id
            ):
                return record
        facts = self._validated_migration_snapshot(
            self._read_migration_snapshot(eid)
        )
        if facts is None:
            return None
        (_eid, tenant_id, key_id, previous_bytes, _old) = facts
        if key_id != record.key_id or tenant_id != record.tenant_id:
            return None
        try:
            previous = KeyRecord.from_json(
                json.loads(previous_bytes.decode("utf-8"))
            )
        except (ValueError, KeyError, TypeError):
            return None
        # A projection must never be rewritten by the lazy legacy takeover.
        previous._unsettled_projection = True
        return previous

    def _committed_record(
        self, record: KeyRecord
    ) -> Optional[KeyRecord]:
        """Project only the durable state of a file read from disk.

        A key file can carry an outbox pending marker while a transaction is
        in flight or because the process crashed before recovery settled it.
        A marker whose event is already in the ledger is effectively
        committed (only marker-clear housekeeping remains) and is shown. A
        marker whose event is NOT durable hides its uncommitted change:

        * a batch-rotate group projects each file's pre-batch state from the
          DURABLE, fully validated batch snapshot -- never from the in-memory
          file -- and hides the record on any missing/corrupt/mismatched
          artifact or an unreadable ledger;
        * a single-key rotate appends one new version: that trailing version
          and the advanced ``current_version`` are stripped, so no uncommitted
          current, handle or material is ever projected; if no committed
          version remains the key is hidden entirely;
        * create/import write a brand-new file and restore writes brand-new
          key files: an uncommitted one is hidden entirely.

        The ledger being unreadable is treated conservatively as
        "not durable", so an outage can never expose an uncommitted current.
        The passed object is freshly parsed from one file read and is local
        to the caller, so mutating its view never touches disk.
        """
        marker = record.pending_event
        if not isinstance(marker, dict) or not marker:
            # A markerless file can still belong to an unfinished batch: the
            # process may have restored/cleared some files before crashing,
            # leaving only the snapshot/journal. Project the durable pre-image
            # (or hide the record when that cannot be proven) rather than
            # exposing an uncommitted current that recovery may overwrite.
            view = self._markerless_batch_view(record)
            if view is _HIDE_UNCOMMITTED:
                return None
            if view is not None:
                return view
            return record
        if marker.get("_batch_rotate"):
            # Batch groups are projected exclusively from the durable
            # snapshot; an in-memory trim of the current file could never
            # prove another key's pre-image and must not be trusted.
            return self._batch_committed_view(record)
        if self._marker_event_durable(marker):
            return record
        nested = marker.get("event")
        desc = nested if isinstance(nested, dict) else marker
        if marker.get("_restore"):
            # A restore only ever creates brand-new key files; an
            # uncommitted one (rolled back, or parked pending recovery) must
            # not become visible.
            return None
        action = desc.get("action") if isinstance(desc, dict) else None
        # A single-key rotate appends one new version. Batch groups never
        # reach this branch: they are projected from the durable snapshot
        # above (an in-memory trim cannot prove another key's pre-image).
        if action == audit_mod.ACTION_MIGRATE:
            # A migrate rewrites the SAME versions' provider triples in place,
            # so the pre-image cannot be derived by trimming the in-memory
            # record: project it exclusively from the durable migration
            # snapshot (the key file's literal pre-move bytes), exactly like
            # a batch group. A missing/corrupt snapshot or an unreadable
            # ledger hides the record rather than exposing uncommitted triples.
            return self._migration_committed_view(record, desc)
        if action == audit_mod.ACTION_ROTATE:
            if len(record.versions) <= 1:
                return None
            record.versions = record.versions[:-1]
            record.current_version = record.versions[-1].version
            return record
        if action == audit_mod.ACTION_REVOKE:
            # A pending revoke marker is always a first-time active->revoked
            # transition (an idempotent repeat revoke appends without a
            # marker), and it adds no version: its pre-image is this same
            # record while still active. Project that rather than hiding an
            # existing key or showing uncommitted revocation state.
            record.status = "active"
            record.reason = None
            record.operator = None
            record.revoked_at = None
            return record
        if action == audit_mod.ACTION_REVOKE_VERSION:
            # A pending version-revoke marker is likewise a first-time
            # transition on ONE version (a repeat revoke appends no marker):
            # its pre-image is this record with that version still active.
            # The marker carries the target version number; without it the
            # change cannot be localized, so the key is hidden rather than
            # projecting uncommitted revocation state.
            target = desc.get("version") if isinstance(desc, dict) else None
            ver = (
                record.get_version(target)
                if isinstance(target, int) and not isinstance(target, bool)
                else None
            )
            if ver is None:
                return None
            ver.status = "active"
            ver.reason = None
            ver.operator = None
            ver.revoked_at = None
            return record
        # create/import new files and any unrecognized marker shape: the
        # safe projection is "not here".
        return None

    def _pending_batch_snapshot_for(self, record: KeyRecord) -> bool:
        """Whether ``record`` belongs to a still-unsettled batch snapshot.

        Markerless key files can still belong to an unfinished batch: an
        in-request rollback restores every old file and only THEN unlinks the
        artifacts, so a failed snapshot/journal removal after a fully verified
        restore leaves the scene markerless. Startup recovery of such a
        surviving (valid) snapshot would restore the captured pre-batch bytes,
        so a fresh rotate/revoke on one of its keys before that cleanup must
        be refused 503 rather than creating a version the next open
        clobbers. A snapshot whose ``batch_rotate`` success event IS durable
        is mere residue (the next open discards it without restoring) and does
        not block. An unreadable ledger blocks conservatively.
        """
        for snapshot_id in self._list_batch_snapshot_ids():
            snapshot = self._read_batch_snapshot(snapshot_id)
            if not isinstance(snapshot, dict):
                # A corrupt snapshot cannot be associated with this key and
                # recovery never rewrites files while it stays corrupt; it
                # does not block unrelated mutations.
                continue
            if snapshot.get("tenant_id") != record.tenant_id:
                continue
            keys = snapshot.get("keys")
            if not isinstance(keys, list):
                continue
            member = any(
                isinstance(entry, dict) and entry.get("key_id") == record.key_id
                for entry in keys
            )
            if not member:
                continue
            try:
                event = self.audit.get_event(snapshot_id)
            except LedgerError:
                return True
            if (
                event is None
                or event.outcome != audit_mod.OUTCOME_SUCCESS
                or event.action != audit_mod.ACTION_BATCH_ROTATE
                or event.tenant_id != record.tenant_id
            ):
                return True
        return False

    def _markerless_batch_view(self, record: KeyRecord):
        """Project a markerless file named by a surviving batch snapshot.

        Markers can vanish on part of a group (a partial rollback/finalize, a
        crash mid-clear, or tampering) while the durable snapshot/journal of a
        batch that never committed survive. Such a file must not expose its
        on-disk (possibly new) versions:

        * the snapshot is missing/unreadable/corrupt/semantically mismatched,
          names another tenant, the event is an action/tenant mismatch, or the
          ledger cannot be read -> ``_HIDE_UNCOMMITTED`` (hide entirely);
        * a trusted complete snapshot names this key -> its validated pre-image
          is returned (tagged as a projection so legacy adoption never rewrites
          the preserved scene);
        * no surviving snapshot names this key -> None (no batch in flight; the
          on-disk record is the committed view).
        """
        for snapshot_id in self._list_batch_snapshot_ids():
            if not is_valid_key_id(snapshot_id):
                continue
            raw_snapshot = self._read_batch_snapshot(snapshot_id)
            if not isinstance(raw_snapshot, dict):
                # A surviving but corrupt snapshot that cannot be tied to this
                # key is conservatively ignored here: the write-set block in
                # _ensure_settled / recovery independently parks the group.
                continue
            tenant_id = raw_snapshot.get("tenant_id")
            if tenant_id != record.tenant_id:
                continue
            keys = raw_snapshot.get("keys")
            if not isinstance(keys, list):
                continue
            if not any(
                isinstance(entry, dict)
                and entry.get("key_id") == record.key_id
                for entry in keys
            ):
                continue
            # This surviving snapshot names the file. The ledger is the commit
            # authority; an outage or a mismatched durable event hides rather
            # than projects either view.
            try:
                event = self.audit.get_event(snapshot_id)
            except LedgerError:
                return _HIDE_UNCOMMITTED
            if event is not None:
                if (
                    event.outcome == audit_mod.OUTCOME_SUCCESS
                    and event.action == audit_mod.ACTION_BATCH_ROTATE
                    and event.tenant_id == record.tenant_id
                ):
                    # Committed residue: the on-disk file is authoritative (it
                    # already has no marker). Do not project the pre-image.
                    continue
                # A durable success with a mismatched action/tenant, or a
                # durable rejection: the batch never provably committed; hide
                # until recovery/operator settles the id collision.
                if event.outcome == audit_mod.OUTCOME_SUCCESS:
                    return _HIDE_UNCOMMITTED
            # Not committed: rebuild the pre-image from the validated snapshot.
            entries = self._validated_batch_snapshot(
                snapshot_id, raw_snapshot, []
            )
            if entries is None:
                return _HIDE_UNCOMMITTED
            for key_id, _raw_bytes, previous_record in entries:
                if key_id == record.key_id:
                    previous_record._unsettled_projection = True
                    return previous_record
            return _HIDE_UNCOMMITTED
        return None

    def _ensure_settled(self, record: KeyRecord) -> None:
        """Refuse a mutation while the file still owes crash recovery.

        A pending outbox marker whose event is NOT durable means a previous
        transaction on this file crashed and its scene is intentionally
        preserved (e.g. a batch-rotation group waiting on a repaired
        snapshot). Writing a new version or a revocation now would overwrite
        the marker and the rollback basis and could interleave recovery with
        a single-key rotate. Such a mutation is refused as a transient
        backend condition (503) until a startup recovery settles the file; a
        durable event behind the marker is just uncleared housekeeping and is
        allowed.

        A markerless file named by a surviving, not-yet-committed batch
        snapshot (rollback restored the files but artifact cleanup failed) is
        refused for the same reason: the next open would otherwise restore
        bytes over the new version.
        """
        marker = record.pending_event
        if (
            isinstance(marker, dict)
            and marker
            and not self._marker_event_durable(marker)
        ):
            raise ProviderUnavailable(
                "key file is awaiting crash recovery"
            )
        if self._pending_batch_snapshot_for(record):
            raise ProviderUnavailable(
                "key file is awaiting crash recovery"
            )

    def get(self, key_id: str, tenant_id: str) -> Optional[KeyRecord]:
        """Return the record's committed view only when it belongs to tenant.

        Unknown key, foreign ownership and a file whose only content is an
        uncommitted transaction all look the same (None), so existence never
        leaks across tenants and an uncommitted current is never exposed. The
        read runs under the key locks so it cannot observe a half-written
        rotation.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        path = self._path_for(key_id)
        with self.key_locks(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                # Same result whether the key is missing or owned by another
                # tenant: never confirm the existence of another tenant's key.
                return None
            return self._committed_record(record)

    @_provider_session
    def rotate(
        self,
        key_id: str,
        tenant_id: str,
        algorithm: str,
        event_id: Optional[str] = None,
        lock_timeout: Optional[float] = None,
        pre_commit=None,
        mirror=None,
        expected_version: Optional[int] = None,
    ) -> Optional[KeyRecord]:
        """Append a new version with fresh material.

        Returns None for an unknown or foreign key. Versions are strictly
        incrementing; the on-disk state is read, extended and written back
        atomically under per-key locks so concurrent rotations never lose a
        version or leave a dangling current pointer.

        An idempotent operation supplies ``event_id`` (its operation_id, so a
        retried/crashed rotation dedupes on one id) and ``lock_timeout``: if
        the per-key lock cannot be taken within it, :class:`LockTimeout` is
        raised before any provider call or write.

        ``expected_version`` is the optional optimistic-concurrency
        precondition: under the same held locks, the committed
        ``current_version`` is compared BEFORE the journal, event, provider
        call or any file write exists; a mismatch raises
        :class:`ExpectedVersionMismatch` with zero side effects, so exactly
        one of several concurrent rotations can pass the same version.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            return None
        path = self._path_for(key_id)
        with self.key_locks(key_id, timeout=lock_timeout):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                return None
            # Never rotate a file that still owes crash recovery: that would
            # overwrite its preserved marker/rollback basis and interleave a
            # single-key rotate with batch recovery.
            self._ensure_settled(record)
            if (
                expected_version is not None
                and record.current_version != expected_version
            ):
                raise ExpectedVersionMismatch(
                    "expected_version %d does not match the committed "
                    "current_version %d"
                    % (expected_version, record.current_version)
                )
            # A version is rotated on the provider that owns the record;
            # switching providers mid-key is refused (503), never silently
            # migrated.
            provider = self._provider_for(record.current.provider_id)
            previous = record.to_json()
            # Mint the committing event and its provision journal *before*
            # the provider call: a crash after the backend mints the new
            # version's handle but before the commit point is reaped at the
            # next open exactly like an import (event absent -> handle
            # deleted, key file left at its prior version).
            next_number = record.current_version + 1
            created_at = datetime.now(timezone.utc).isoformat()
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_ROTATE, key_id,
                audit_mod.OUTCOME_SUCCESS, timestamp=created_at,
                event_id=event_id,
            )
            journal_id, journal_path = self._new_provision_journal(
                event.event_id, event.tenant_id, event.action
            )
            minted_handle = None
            try:
                if mirror is not None:
                    try:
                        mirror.provision(journal_id)
                    except OSError as exc:
                        # Mirror tie-in failed with only an EMPTY journal and
                        # before any provider call: scrub the journal and
                        # strand the bound op pending for a same-id retry.
                        self.drop_provision_journal(journal_id)
                        from .artifacts import ArtifactStrandUnavailable

                        raise ArtifactStrandUnavailable(str(exc), 500)
                triple = provider.rotate(algorithm)
                minted_handle = triple.handle
                self._append_provision(
                    journal_path, provider.provider_id, triple.handle
                )
                if mirror is not None:
                    mirror.add_handle(
                        provider.provider_id, triple.handle
                    )
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
                # _commit_mutation deletes the minted handle itself when the
                # append fails; the provision journal is the durable crash
                # safety net and is retried below on any failure.
                if mirror is not None:
                    # The key file is about to land: the write set is staged.
                    mirror.phase(PHASE_STAGED)
                self._commit_mutation(
                    path, record, event, previous,
                    provider=provider, new_handles=(triple.handle,),
                    journal_id=journal_id,
                    pre_commit=pre_commit,
                )
            except BaseException as exc:
                # Provider fault, validation or ledger/write failure: the
                # version never committed. Delete the in-memory handle
                # directly and reconcile the durable journal (idempotent
                # deletes). If the backend delete cannot be verified the
                # journal stays for the next open and the request answers 503
                # rather than hiding an orphaned backend object.
                from .artifacts import ArtifactStrandUnavailable

                if isinstance(exc, ArtifactStrandUnavailable):
                    # mirror.provision failed before any provider call with
                    # only an empty journal, already dropped: keep the bound
                    # op pending for a same-id retry (no rollback evidence).
                    raise
                if isinstance(exc, ProviderReconnectPending):
                    # No provider call was effectively made (the gate wait
                    # timed out, or the owning provider_id was displaced): no
                    # handle was minted. Drop the empty journal, return the
                    # mirror to a clean bound strand and re-raise the pending
                    # signal so the operation stays PENDING for a same-id
                    # continuation (the guard answers the safe 503).
                    self.drop_provision_journal(journal_id)
                    if mirror is not None:
                        try:
                            mirror.reset_for_pending_retry()
                        except OSError:
                            pass
                    raise
                cleaned = True
                if minted_handle is not None:
                    try:
                        provider.delete(minted_handle)
                    except Exception:
                        cleaned = False
                if not self.rollback_provision_journal(journal_id):
                    cleaned = False
                if not cleaned:
                    raise ProviderUnavailable(
                        "could not delete a handle provisioned by a failed "
                        "rotation; cleanup will be retried at startup"
                    ) from exc
                if mirror is not None:
                    # Full rollback verified by the journal reconciliation:
                    # record the phase so mirror cleanup/startup need not
                    # re-derive it. A failure of this bookkeeping rewrite must
                    # never mask the original fault (the journal is already
                    # gone; the next open retakes the strand from disk).
                    try:
                        mirror.phase(PHASE_ROLLED_BACK)
                    except OSError:
                        pass
                raise
            # Committed: the new handle is owned by the appended version and
            # the durable success event makes the journal obsolete.
            self.drop_provision_journal(journal_id)
            if mirror is not None:
                # The commit point already landed; a bookkeeping rewrite
                # failure must not turn a committed rotation into a reported
                # failure -- after_terminal/startup reconcile from disk.
                try:
                    mirror.phase(PHASE_COMMITTED)
                except OSError:
                    pass
        return record

    # -- whole-key provider migration --------------------------------------
    # A migrate rebinds EVERY version of one existing key from its current
    # provider(s) to the chain's ready provider: each version is exported by
    # its owning provider and imported into the ready one, and the key file is
    # rewritten in place with the fresh provider triples (version numbers,
    # timestamps, algorithm, public key, current pointer and revocation state
    # are all preserved). The move is one outbox transaction:
    #   * migrations/<event_id>.json durably stores the key file's pre-migration
    #     bytes and every OLD (provider_id, handle) pair BEFORE any provider
    #     call, so an uncommitted attempt can always restore the old record
    #     verbatim and a committed one can still reap its old handles;
    #   * a provision journal records every freshly minted handle, so a
    #     pre-commit failure deletes exactly the new backend objects;
    #   * one ``migrate`` audit event (event_id == operation_id) is the commit
    #     point; old handles are deleted only AFTER it (best effort: a failed
    #     delete never unwrites the commit, it retries on replay/startup).
    _MIGRATE_DIR = "migrations"

    def _migration_path(self, event_id: str) -> str:
        return os.path.join(
            self.data_dir, self._MIGRATE_DIR, event_id + ".json"
        )

    def _read_migration_snapshot(self, event_id: str) -> Optional[dict]:
        try:
            with open(self._migration_path(event_id), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    @staticmethod
    def _valid_old_handle_pairs(raw) -> Optional[list]:
        if not isinstance(raw, list):
            return None
        pairs = []
        seen = set()
        for entry in raw:
            if not isinstance(entry, dict):
                return None
            provider_id = entry.get("provider_id")
            handle = entry.get("handle")
            if not (
                isinstance(provider_id, str) and provider_id
                and isinstance(handle, str) and handle
            ):
                return None
            pair = (provider_id, handle)
            if pair in seen:
                return None
            seen.add(pair)
            pairs.append({"provider_id": provider_id, "handle": handle})
        return pairs

    def _validated_migration_snapshot(
        self, snapshot: Optional[dict]
    ) -> Optional[Tuple[str, str, str, bytes, list]]:
        """Validate a migration snapshot; return its facts or None.

        Facts: ``(event_id, tenant_id, key_id, previous_bytes, old_pairs)``.
        The previous image must decode to a KeyRecord with matching key_id and
        tenant, contiguous versions and a sane current pointer -- the same
        strictness batch snapshots enforce, so crash recovery never restores
        guessed bytes.
        """
        if not isinstance(snapshot, dict):
            return None
        event_id = snapshot.get("operation_id")
        tenant_id = snapshot.get("tenant_id")
        key_id = snapshot.get("key_id")
        if not (
            is_valid_key_id(event_id)
            and isinstance(tenant_id, str) and tenant_id
            and is_valid_key_id(key_id)
            and snapshot.get("action") == audit_mod.ACTION_MIGRATE
        ):
            return None
        previous_b64 = snapshot.get("previous_b64")
        if not isinstance(previous_b64, str):
            return None
        try:
            previous_bytes = base64.b64decode(previous_b64, validate=True)
            previous_data = json.loads(previous_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        try:
            previous = KeyRecord.from_json(previous_data)
        except (KeyError, TypeError, ValueError):
            return None
        if (
            previous.key_id != key_id
            or previous.tenant_id != tenant_id
            or not previous.versions
            or [ver.version for ver in previous.versions]
            != list(range(1, len(previous.versions) + 1))
            or not 1 <= previous.current_version <= len(previous.versions)
        ):
            return None
        old_pairs = self._valid_old_handle_pairs(snapshot.get("old_handles"))
        if old_pairs is None:
            return None
        previous_pairs = [
            {"provider_id": ver.provider_id, "handle": ver.handle}
            for ver in previous.versions
        ]
        return (
            event_id, tenant_id, key_id, previous_bytes, old_pairs,
            previous_pairs,
        )

    def _write_migration_snapshot(
        self,
        event: AuditEvent,
        previous_bytes: bytes,
        old_pairs: list,
    ) -> str:
        """Durably record a migrate's previous key file and old handles.

        Written (0600, fsync, atomic rename) before the first provider call.
        """
        directory = os.path.join(self.data_dir, self._MIGRATE_DIR)
        os.makedirs(directory, exist_ok=True)
        path = self._migration_path(event.event_id)
        payload = {
            "operation_id": event.event_id,
            "tenant_id": event.tenant_id,
            "key_id": event.key_id,
            "action": audit_mod.ACTION_MIGRATE,
            "previous_b64": base64.b64encode(previous_bytes).decode("ascii"),
            "old_handles": old_pairs,
        }
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
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
        return path

    def _migration_peer(self, provider_id: str):
        """Resolve a healthy configured chain entry for migrate/cleanup.

        Inside a provider_call lease the bound ready provider is returned
        directly; any other id must be an entry of the configured primary/
        standby chain (built, configured and health-probed with the same
        one-probe cap). A missing, contract-broken or unhealthy entry is the
        fixed provider failure (503), never a silent fallback.
        """
        return provider_mod.migration_peer_provider(provider_id)

    @_provider_session
    def migrate(
        self,
        key_id: str,
        tenant_id: str,
        event_id: Optional[str] = None,
        lock_timeout: Optional[float] = None,
        pre_commit=None,
        mirror=None,
    ) -> Optional[Tuple[KeyRecord, str, list]]:
        """Migrate every version of one key to the ready chain provider.

        Returns ``(record, provider_id, versions)`` on success where
        ``versions`` is the ascending list of version numbers; None for an
        unknown or foreign key. Raises :class:`KeyAlreadyMigrated` (bound 409)
        when every version is already bound to the ready provider.
        Provider/build/health/material/timeout failures raise
        :class:`ProviderUnavailable` (503, fixed client text).

        Version numbers, created_at, algorithm, public_key, current pointer
        and revocation state are preserved verbatim; only the per-version
        ``(provider_id, handle, encrypted_material)`` triples change. Raw key
        material exists only between the source export and the target import
        and is never persisted, audited or returned.
        """
        if not is_valid_key_id(key_id):
            return None
        path = self._path_for(key_id)
        with self.key_locks(key_id, timeout=lock_timeout):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                return None
            self._ensure_settled(record)
            ready = provider_mod.get_provider()
            target_id = ready.provider_id
            moving = [
                ver for ver in record.versions
                if ver.provider_id != target_id
            ]
            if not moving:
                # Bound 409: nothing to move. No provider call was made and
                # no journal, snapshot, handle or event is written.
                raise KeyAlreadyMigrated(key_id)
            previous_bytes = self._read_file_bytes(path)
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_MIGRATE, key_id,
                audit_mod.OUTCOME_SUCCESS, event_id=event_id,
            )
            # Snapshot the old record bytes and every old handle BEFORE the
            # first provider call: rollback can restore verbatim and a
            # committed move can still reap its old backend objects.
            old_pairs = [
                {"provider_id": ver.provider_id, "handle": ver.handle}
                for ver in moving
            ]
            self._write_migration_snapshot(event, previous_bytes, old_pairs)
            journal_id, journal_path = self._new_provision_journal(
                event.event_id, event.tenant_id, event.action
            )
            new_handles = []
            peer_cache = {}

            def peer_for(provider_id: str):
                # One resolved (and health-probed) instance per provider id
                # for this attempt: repeated versions owned by the same
                # provider never rebuild the chain entry.
                if provider_id not in peer_cache:
                    peer_cache[provider_id] = self._migration_peer(provider_id)
                return peer_cache[provider_id]

            try:
                if mirror is not None:
                    try:
                        mirror.provision(journal_id)
                    except OSError as exc:
                        self.drop_provision_journal(journal_id)
                        self._discard_file(self._migration_path(event.event_id))
                        from .artifacts import ArtifactStrandUnavailable

                        raise ArtifactStrandUnavailable(str(exc), 500)
                for ver in moving:
                    source = peer_for(ver.provider_id)
                    exported = source.export_material(ver.handle)
                    # The exported public part must agree with the recorded
                    # one (None for AES256, the PEM for RSA2048); a
                    # disagreement is corrupted backend state, a 503 rather
                    # than a field-level 400.
                    if exported.public_key != ver.public_key:
                        raise ProviderUnavailable(
                            "exported public key does not match the record"
                        )
                    try:
                        triple = ready.import_material(
                            ver.algorithm,
                            ver.public_key,
                            exported.encrypted_material,
                        )
                    except ProviderInvalidMaterial as exc:
                        # Material that does not fit the target algorithm is a
                        # provider failure for a migrate (503), never a 400.
                        raise ProviderUnavailable(
                            "migrated material does not match the key algorithm"
                        ) from exc
                    try:
                        self._append_provision(
                            journal_path, target_id, triple.handle
                        )
                        new_handles.append(triple.handle)
                        if mirror is not None:
                            mirror.add_handle(target_id, triple.handle)
                    except BaseException:
                        # The backend object is minted but its durable
                        # journal entry (or mirror entry) may not have landed:
                        # delete it directly before the shared rollback path
                        # reconciles whatever did land, so it can never orphan.
                        try:
                            ready.delete(triple.handle)
                        except Exception:
                            pass
                        raise
                    # Preserve every immutable fact of the version; only the
                    # provider triple is rebound.
                    ver.provider_id = target_id
                    ver.handle = triple.handle
                    ver.encrypted_material = triple.encrypted_material
                    if triple.public_key is not None:
                        ver.public_key = triple.public_key
                if mirror is not None:
                    mirror.phase(PHASE_STAGED)
                previous = json.loads(previous_bytes.decode("utf-8"))
                staged_versions = sorted(ver.version for ver in record.versions)

                def stage_committed(committed_record):
                    if pre_commit is not None:
                        pre_commit(
                            committed_record, target_id, staged_versions
                        )

                self._commit_mutation(
                    path, record, event, previous,
                    provider=ready, new_handles=tuple(new_handles),
                    journal_id=journal_id,
                    pre_commit=stage_committed,
                )
            except BaseException as exc:
                from .artifacts import ArtifactStrandUnavailable

                if isinstance(exc, ArtifactStrandUnavailable):
                    raise
                if isinstance(exc, ProviderReconnectPending) and not new_handles:
                    # No provider work was effectively made (gate/budget
                    # timeout, a displaced owning id, or a peer probe that
                    # failed BEFORE the first handle): no handle minted. Drop
                    # the empty journal and the unused snapshot, reset the
                    # mirror to a clean bound strand and stay PENDING for a
                    # same-key continuation.
                    self.drop_provision_journal(journal_id)
                    self._discard_file(self._migration_path(event.event_id))
                    if mirror is not None:
                        try:
                            mirror.reset_for_pending_retry()
                        except OSError:
                            pass
                    raise
                cleaned = True
                for handle in new_handles:
                    try:
                        ready.delete(handle)
                    except Exception:
                        cleaned = False
                if not self.rollback_provision_journal(journal_id):
                    cleaned = False
                if not cleaned:
                    # Keep the migration snapshot: startup rollback restores
                    # the old record and reaps every new handle.
                    raise ProviderUnavailable(
                        "could not delete a handle provisioned by a failed "
                        "migration; cleanup will be retried at startup"
                    ) from exc
                self._discard_file(self._migration_path(event.event_id))
                if mirror is not None:
                    try:
                        mirror.phase(PHASE_ROLLED_BACK)
                    except OSError:
                        pass
                raise
            # Commit point durable: the new triples are authoritative. The
            # new handles are owned by the record; drop their journal.
            self.drop_provision_journal(journal_id)
            # Delete the OLD backend objects only now: their deletion is
            # post-commit housekeeping, so a backend hiccup never unwrites the
            # committed migration nor changes the response -- the migration
            # snapshot stays behind and the startup sweep (or the next replay)
            # finishes the idempotent deletes.
            if self._delete_old_migration_handles(
                old_pairs, peers=peer_cache
            ):
                self._discard_file(self._migration_path(event.event_id))
            if mirror is not None:
                try:
                    mirror.phase(PHASE_COMMITTED)
                except OSError:
                    pass
            versions = sorted(ver.version for ver in record.versions)
            return record, target_id, versions

    @staticmethod
    def _discard_file(path: str) -> bool:
        try:
            os.unlink(path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def _delete_old_migration_handles(
        self, old_pairs: list, peers: Optional[dict] = None
    ) -> bool:
        """Best-effort idempotent deletion of a committed migrate's old handles.

        Each old pair is routed to its own (possibly standby) chain provider.
        ``peers`` reuses the attempt's already-resolved/probed instances; a
        None entry resolves lazily. Returns True only when every delete was
        confirmed; a False result leaves the migration snapshot for a
        replay/startup retry.
        """
        cleaned = True
        resolved = dict(peers or {})
        for pair in old_pairs:
            provider_id = pair["provider_id"]
            try:
                if provider_id not in resolved:
                    resolved[provider_id] = self._migration_peer(provider_id)
                resolved[provider_id].delete(pair["handle"])
            except Exception:
                cleaned = False
        return cleaned

    def _recover_migrations(self) -> None:
        """Settle ``migrations/<event_id>.json`` snapshots left by crashes.

        The ledger event named after the snapshot is the authority:

        * a durable matching ``migrate`` success: the rebound key file is
          authoritative -- finish post-commit housekeeping (delete every OLD
          handle idempotently), then drop the snapshot;
        * no event, or a durable rejected terminal with this id: the move never
          committed -- delete every freshly minted handle (the provision
          journal), restore the key file's previous bytes verbatim, clear its
          marker and drop journal + snapshot;
        * an unreadable ledger, an id/action/tenant collision, a corrupt
          snapshot or a failed backend delete preserves the whole scene for
          the next open.
        """
        directory = os.path.join(self.data_dir, self._MIGRATE_DIR)
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            event_id = name[:-5]
            if not is_valid_key_id(event_id):
                continue
            path = os.path.join(directory, name)
            facts = self._validated_migration_snapshot(
                self._read_migration_snapshot(event_id)
            )
            if facts is None:
                # Corrupt snapshot: neither the old image nor the handle sets
                # can be trusted -- preserve everything for resolution.
                continue
            (
                _eid, tenant_id, key_id, previous_bytes,
                old_pairs, previous_pairs,
            ) = facts
            try:
                event = self.audit.get_event(event_id)
            except LedgerError:
                continue
            if event is not None and (
                event.tenant_id != tenant_id
                or event.action != audit_mod.ACTION_MIGRATE
            ):
                # A durable foreign event carries this id: park.
                continue
            key_path = self._path_for(key_id)
            if event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS:
                # Committed: reap the OLD handles, then retire the snapshot.
                # (The key marker and the new-handle journal were settled by
                # _recover_pending_events before this sweep ran.)
                if self._delete_old_migration_handles(old_pairs):
                    self._discard_file(path)
                continue
            # Pre-commit crash/rejection: delete every NEW handle first, then
            # restore the old file bytes only once the backend objects are
            # gone. Any failure preserves the full scene for a later open.
            journal_pairs = set(self.read_provision_journal(event_id))
            if not self._rollback_provision_entries(list(journal_pairs)):
                continue
            with self._key_lock(key_id), self._file_lock(key_id):
                current = self._read_record(key_path)
                old_pair_set = {
                    (pair["provider_id"], pair["handle"])
                    for pair in previous_pairs
                }
                known_pairs = old_pair_set | journal_pairs
                current_pairs = (
                    {
                        (ver.provider_id, ver.handle)
                        for ver in current.versions
                    }
                    if current is not None
                    else set()
                )
                if (
                    current is None
                    or current.key_id != key_id
                    or current.tenant_id != tenant_id
                    or not current_pairs
                    or not current_pairs.issubset(known_pairs)
                ):
                    # Missing key, or the file references triples this
                    # snapshot never knew (e.g. a later, possibly committed
                    # migration governs it): never overwrite committed state
                    # on a guess -- preserve the whole scene for a later open.
                    continue
                live_marker = current.pending_event
                live_marker_id = None
                if isinstance(live_marker, dict):
                    nested = live_marker.get("event")
                    desc = nested if isinstance(nested, dict) else live_marker
                    live_marker_id = (
                        desc.get("event_id") if isinstance(desc, dict) else None
                    )
                if live_marker_id is not None and live_marker_id != event_id:
                    # Another operation's unresolved outbox owns this file: do
                    # not restore across it; preserve the scene.
                    continue
                if current_pairs == old_pair_set:
                    # The file already reflects the pre-move image (the marker
                    # write never landed): clear any stray marker only.
                    if isinstance(current.pending_event, dict):
                        current.pending_event = None
                        try:
                            self._write_atomic(key_path, current.to_json())
                        except OSError:
                            continue
                else:
                    # The file holds triples this uncommitted attempt minted
                    # (possibly only some versions); those handles were just
                    # deleted, so restore the pre-move bytes verbatim.
                    try:
                        self._write_bytes_atomic(key_path, previous_bytes)
                    except OSError:
                        continue
            self.drop_provision_journal(event_id)
            self._discard_file(path)

    # -- atomic batch rotation --------------------------------------------
    # A batch rotates 1-100 existing keys of one tenant as one logical
    # transaction: every key lock is taken first (sorted by key_id, shared
    # deadline), every new version is minted and every file lands carrying the
    # SAME pending marker, and a single batch_rotate audit event (key_id null)
    # is the commit point. A crash/failure before that append restores every
    # file to its pre-batch bytes and deletes every minted handle. Two durable
    # artifacts make recovery exact:
    #   * the provision journal provisions/<event_id>.json records every
    #     minted handle as it appears (shared with rotate/import/restore);
    #   * the snapshot journal batch-rotations/<event_id>.json records every
    #     key's pre-batch file bytes, so an uncommitted group can always be
    #     restored even when this frame no longer holds them.
    BATCH_ROTATED = "rotated"
    BATCH_NOT_FOUND = "not_found"
    _BATCH_DIR = "batch-rotations"

    def _batch_snapshot_path(self, snapshot_id: str) -> str:
        return os.path.join(
            self.data_dir, self._BATCH_DIR, snapshot_id + ".json"
        )

    def _write_batch_snapshot(
        self, snapshot_id: str, tenant_id: str, key_ids: List[str],
        previous_bytes: dict,
    ) -> None:
        """Durably record the pre-batch whole-file bytes of every group key.

        ``previous_bytes`` maps key_id to the key file's literal bytes read
        before the batch. They are stored base64-encoded, so crash recovery
        of an uncommitted group restores each file byte-for-byte rather than
        re-serializing a parsed object. Written before any provider call; a
        group whose snapshot is gone is left untouched rather than guessed at.
        """
        directory = os.path.join(self.data_dir, self._BATCH_DIR)
        os.makedirs(directory, exist_ok=True)
        path = self._batch_snapshot_path(snapshot_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        payload = {
            "event_id": snapshot_id,
            "tenant_id": tenant_id,
            "keys": [
                {
                    "key_id": key_id,
                    "previous_b64": base64.b64encode(
                        previous_bytes[key_id]
                    ).decode("ascii"),
                }
                for key_id in key_ids
            ],
        }
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            # The durable snapshot never landed and no key file references
            # it yet (it is written before any provider call); remove the
            # partial file so a corrupt snapshot cannot outlive the attempt.
            # A failed unlink simply leaves it for the next open, whose
            # corrupt-snapshot rule preserves the scene rather than guessing.
            try:
                os.unlink(path)
            except OSError:
                pass
            raise

    def _read_batch_snapshot(self, snapshot_id: str) -> Optional[dict]:
        try:
            with open(
                self._batch_snapshot_path(snapshot_id), "r", encoding="utf-8"
            ) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not isinstance(
            data.get("keys"), list
        ):
            return None
        return data

    def _discard_batch_snapshot(self, snapshot_id: str) -> None:
        try:
            os.unlink(self._batch_snapshot_path(snapshot_id))
        except FileNotFoundError:
            pass
        except OSError:
            # Startup recovery retries; an in-request failure keeps the
            # snapshot on purpose, so a removal failure is never fatal here.
            pass

    @_provider_session
    def batch_rotate(
        self,
        tenant_id: str,
        items: List[Tuple[str, ...]],
        event_id: Optional[str] = None,
        lock_timeout: Optional[float] = None,
        pre_commit=None,
        mirror=None,
    ) -> Tuple[str, object]:
        """Atomically append one fresh version to many keys.

        ``items`` is a list of ``(key_id, algorithm)`` pairs or ``(key_id,
        algorithm, expected_version)`` triples in REQUEST order; the caller
        has already validated 1-100 unique lowercase UUID4s, supported
        algorithms and positive-integer preconditions. Returns
        ``(BATCH_ROTATED, [(key_id, record), ...])`` in request order, or
        ``(BATCH_NOT_FOUND, missing_key_id)`` when any key is unknown or
        owned by another tenant -- with zero files, events or handles
        changed. The per-key locks (in-process plus fcntl) are taken in
        sorted key_id order against one shared deadline, so a batch and a
        single rotate never interleave on a shared key; a wait beyond
        ``lock_timeout`` raises :class:`LockTimeout` before the journal,
        event or any handle exists.

        Every item's optional ``expected_version`` is an optimistic-
        concurrency precondition: all items are compared against the SAME
        committed view (every record read under the held locks) before the
        journal, event, provider call or any file write exists; any mismatch
        raises :class:`ExpectedVersionMismatch` and fails the WHOLE batch
        with zero side effects.

        Every key keeps the rotate semantics of ``KeyStore.rotate`` (fresh
        material on the provider that owns the record, strictly increasing
        append-only version). The whole batch commits through one outbox
        transaction with a single ``batch_rotate`` event whose key_id is
        null. Any fault before the commit-point append restores every file to
        its pre-batch bytes and deletes every minted handle; a handle delete
        that cannot be verified raises ProviderUnavailable and leaves the
        snapshot/journal for startup to retry.
        """
        request_order = []
        for entry in items:
            if len(entry) == 2:
                key_id, algorithm = entry
                expected_version = None
            else:
                key_id, algorithm, expected_version = entry
            request_order.append((key_id, algorithm, expected_version))
        ordered = sorted(request_order, key=lambda pair: pair[0])
        ordered_ids = [key_id for key_id, _, _ in ordered]
        with self.multi_key_locks(ordered_ids, timeout=lock_timeout):
            records: dict = {}
            previous_bytes: dict = {}
            for key_id, _, expected_version in ordered:
                record = self._read_record(self._path_for(key_id))
                if record is None or record.tenant_id != tenant_id:
                    # Existence/ownership for the WHOLE batch is resolved
                    # before a journal, handle or file write exists.
                    return self.BATCH_NOT_FOUND, key_id
                # A parked crash scene (unresolved, non-durable marker) makes
                # the whole batch a transient 503 rather than overwriting the
                # preserved retry basis.
                self._ensure_settled(record)
                if (
                    expected_version is not None
                    and record.current_version != expected_version
                ):
                    # Every precondition is judged on the same committed
                    # view, before the journal/event/provider/file write:
                    # one mismatch fails the whole batch with zero changes.
                    raise ExpectedVersionMismatch(
                        "expected_version %d does not match the committed "
                        "current_version %d for key %s"
                        % (expected_version, record.current_version, key_id)
                    )
                records[key_id] = record
                path = self._path_for(key_id)
                # Capture the file's exact pre-batch bytes under the held
                # locks: an uncommitted rollback restores these byte-for-byte.
                previous_bytes[key_id] = self._read_file_bytes(path)
                # The owning provider must be active (503 otherwise); versions
                # are never silently moved to another provider.
                self._provider_for(record.current.provider_id)

            created_at = datetime.now(timezone.utc).isoformat()
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_BATCH_ROTATE, None,
                audit_mod.OUTCOME_SUCCESS, timestamp=created_at,
                event_id=event_id,
            )
            journal_id, journal_path = self._new_provision_journal(
                event.event_id, event.tenant_id, event.action
            )
            if mirror is not None:
                try:
                    mirror.provision(journal_id, snapshot=event.event_id)
                except OSError as exc:
                    # The mirror tie-in failed with only an EMPTY journal on
                    # disk and no handle minted or provider called. Scrub the
                    # journal and strand the bound op pending for a same-id
                    # retry, never a failed(500) terminal.
                    self.drop_provision_journal(journal_id)
                    from .artifacts import ArtifactStrandUnavailable

                    raise ArtifactStrandUnavailable(str(exc), 500)
            # Defined before the try so the abort path can union the pairs
            # this frame minted even when the provider faulted mid-batch.
            minted = []
            # Set when append() returned without raising but the post-append
            # ledger fact does not prove THIS batch committed (unreadable
            # ledger, missing event, or a same-id event whose action/tenant
            # differ). append returning normally usually means the line is
            # durable, so such ambiguity must PARK the scene, never roll back:
            # startup recovery makes the commit decision from the ledger.
            commit_unverifiable = False
            try:
                self._write_batch_snapshot(
                    event.event_id, tenant_id, ordered_ids, previous_bytes
                )
                marker = {
                    "_batch_rotate": True,
                    "event": event.to_json(),
                    "tenant_id": tenant_id,
                    "key_ids": ordered_ids,
                    "journal": journal_id,
                    "snapshot": event.event_id,
                }
                for key_id, algorithm, _ in ordered:
                    record = records[key_id]
                    provider = self._provider_for(
                        record.current.provider_id
                    )
                    next_number = record.current_version + 1
                    triple = provider.rotate(algorithm)
                    minted.append((provider, triple.handle))
                    self._append_provision(
                        journal_path, provider.provider_id, triple.handle
                    )
                    if mirror is not None:
                        mirror.add_handle(
                            provider.provider_id, triple.handle
                        )
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
                # Phase 1: every file lands carrying the shared marker.
                for key_id, _, _ in ordered:
                    record = records[key_id]
                    record.pending_event = marker
                    self._write_atomic(
                        self._path_for(key_id), record.to_json()
                    )
                if mirror is not None:
                    # The whole write set is durable and marked: staged.
                    mirror.phase(PHASE_STAGED)
                # The whole write set is durable: stage the exact idempotent
                # response before the single commit-point append.
                if pre_commit is not None:
                    pre_commit(records)
                # Phase 2: the single ledger append is the commit point.
                self.audit.append(event)
                # append() dedupes silently on event_id without comparing
                # action/tenant: a pre-existing durable event with the SAME id
                # but a different action or tenant returns "success" without
                # writing anything. Re-read the durable fact and require the
                # ledger to now hold exactly this batch_rotate success for
                # this tenant before treating the append as the commit point.
                try:
                    committed = self.audit.get_event(event.event_id)
                except LedgerError:
                    # append() itself re-reads the whole ledger and fsynced the
                    # line before returning, so a fresh read error is a
                    # transient outage AFTER a durable commit, not a missing
                    # event: trust the fsynced append and proceed. Startup
                    # recovery reconciles from the ledger when it is readable.
                    committed = event
                if (
                    committed is None
                    or committed.outcome != audit_mod.OUTCOME_SUCCESS
                    or committed.action != audit_mod.ACTION_BATCH_ROTATE
                    or committed.tenant_id != tenant_id
                ):
                    # The read succeeded but the durable fact under this id is
                    # absent or belongs to a different action/tenant: a same-id
                    # collision. Our append was deduped and did NOT write, so
                    # this batch never committed; rolling back would clobber the
                    # foreign record. Park the whole scene for startup instead.
                    commit_unverifiable = True
                    raise LedgerError(
                        "the batch rotation commit event could not be "
                        "confirmed as the expected batch_rotate success event"
                    )
            except BaseException as exc:
                if isinstance(exc, ProviderReconnectPending):
                    # The session never effectively rotated anything: the gate
                    # wait timed out at entry (before the snapshot/journal), or
                    # the in-loop provider-id match found the owning id
                    # displaced before the first rotate (snapshot + empty
                    # journal exist, no handle minted, no event appended).
                    # Scrub the empty artifacts and re-raise so the guard
                    # resets the mirror to a clean bound strand and keeps the
                    # op PENDING for a same-id continuation once the right
                    # provider is back.
                    self.drop_provision_journal(journal_id)
                    snapshot_path = self._batch_snapshot_path(event.event_id)
                    try:
                        os.unlink(snapshot_path)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        # A retained snapshot parks the scene safely; the op
                        # stays pending regardless.
                        pass
                    if mirror is not None:
                        try:
                            mirror.reset_for_pending_retry()
                        except OSError:
                            pass
                    raise
                if commit_unverifiable:
                    # The append returned but the durable fact is missing or
                    # belongs to a different action/tenant: neither commit nor
                    # rollback is provable. Retain the ENTIRE scene (marked
                    # files, snapshot, journal, minted handles) unchanged for
                    # startup recovery; delete nothing and write no event.
                    raise ProviderUnavailable(
                        "could not confirm the batch rotation commit; the "
                        "whole group is retained for startup recovery"
                    ) from exc
                # Establish the commit decision from the ledger before
                # touching anything. The append is the last step, so a
                # durable success event means every phase-1 file and the
                # staged response are already on disk and only marker
                # housekeeping remains; an unreadable ledger proves neither
                # side, so the whole scene is retained rather than risking
                # committed handles/material.
                try:
                    durable = self.audit.get_event(event.event_id)
                except LedgerError:
                    raise ProviderUnavailable(
                        "could not determine whether the batch rotation "
                        "committed; the whole group is retained for startup "
                        "recovery"
                    ) from exc
                if (
                    durable is not None
                    and durable.outcome == audit_mod.OUTCOME_SUCCESS
                    and durable.action == audit_mod.ACTION_BATCH_ROTATE
                    and durable.tenant_id == tenant_id
                ):
                    # The commit point actually passed (e.g. the failure was
                    # clearing a marker after a durable append): finalize the
                    # in-memory records, which match every file on disk, and
                    # answer success rather than rolling committed versions.
                    self._batch_finalize_after_commit(
                        ordered, records, journal_id, event.event_id
                    )
                    if mirror is not None:
                        try:
                            mirror.phase(PHASE_COMMITTED)
                        except OSError:
                            pass
                    return self.BATCH_ROTATED, [
                        (key_id, records[key_id]) for key_id, _, _ in request_order
                    ]
                if (
                    durable is not None
                    and durable.outcome == audit_mod.OUTCOME_SUCCESS
                ):
                    # A durable SUCCESS event carries this event id but its
                    # action or tenant does not match this batch: the id
                    # collides with a different committed mutation, so neither
                    # "committed" nor "roll back" is provable. Mirror startup
                    # recovery and PARK the whole scene -- no handle delete,
                    # no file write-back, no artifact removal, no success
                    # event -- until an operator/startup settles it. Rolling
                    # back here would clobber a foreign committed record.
                    raise ProviderUnavailable(
                        "a durable event with this id does not match the "
                        "batch rotation; the whole group is retained for "
                        "startup recovery"
                    ) from exc
                # Nothing committed: the durable success event is absent.
                # Roll back strictly from the re-read durable snapshot, not
                # from this frame's memory; the helper raises
                # ProviderUnavailable (503) with the whole scene retained if
                # any handle delete cannot be confirmed or any file cannot be
                # restored byte-for-byte. No success audit event is written.
                self._batch_abort_uncommitted(
                    event.event_id, tenant_id, journal_id, minted
                )
                if mirror is not None:
                    # Every new handle deleted and every old file restored:
                    # the rollback was fully verified before artifacts were
                    # dropped. A bookkeeping failure here must not mask the
                    # completed rollback (journal/snapshot already gone).
                    try:
                        mirror.phase(PHASE_ROLLED_BACK)
                    except OSError:
                        pass
                raise

            # Phase 3: commit point passed. Clear markers as best-effort
            # housekeeping; a failure or crash is repaired idempotently on the
            # next open and never rolls the versions back.
            self._batch_finalize_after_commit(
                ordered, records, journal_id, event.event_id
            )
            if mirror is not None:
                # Commit already durable; never let this bookkeeping write
                # change the committed outcome.
                try:
                    mirror.phase(PHASE_COMMITTED)
                except OSError:
                    pass
            return self.BATCH_ROTATED, [
                (key_id, records[key_id]) for key_id, _, _ in request_order
            ]

    def _batch_finalize_after_commit(
        self, ordered, records, journal_id: str, eid: str
    ) -> None:
        """Post-commit marker clear and artifact cleanup for ``batch_rotate``.

        Shared by the normal phase-3 path and the rare failure path that
        discovers the commit-point append actually succeeded: clear every
        file's marker (best effort, repaired on the next open), then drop the
        provision journal and the rollback-only snapshot. New versions are
        never rolled back.
        """
        for key_id, _, _ in ordered:
            record = records[key_id]
            record.pending_event = None
            try:
                self._write_atomic(
                    self._path_for(key_id), record.to_json()
                )
            except OSError:
                pass
        self.drop_provision_journal(journal_id)
        self._discard_batch_snapshot(eid)

    def _batch_abort_uncommitted(
        self,
        eid: str,
        tenant_id: str,
        journal_id: str,
        minted,
    ) -> None:
        """Roll back a batch whose ``batch_rotate`` success event is absent.

        Called on the request path with the COMPLETE write set's in-process
        and fcntl locks already held (sorted by key_id). Nothing is trusted
        from this frame's memory: the on-disk marker scene is rescanned and
        ``batch-rotations/<event_id>.json`` is re-read and fully validated
        (filename/event_id/tenant/complete unique key_ids/journal and snapshot
        references, and every strictly decoded ``previous_b64`` image).

        The new-handle set is the UNION of the in-memory minted pairs, the
        durable provision journal and the delta between the on-disk versions
        and the validated pre-images. Every delete is confirmed FIRST; if any
        cannot be confirmed, no file is rewritten and no artifact (marker,
        journal, snapshot) is cleared -- the whole scene is retained for
        startup recovery and :class:`ProviderUnavailable` is raised. Only once
        every delete succeeds is every old file restored byte-for-byte; the
        journal and snapshot are removed only after every write-back lands. No
        success audit event is ever written by this rollback.
        """
        snapshot_path = self._batch_snapshot_path(eid)
        # Fresh, unlocked observation; the write set is already fully locked.
        files, markers = self._rescan_batch_markers(eid)
        present = os.path.exists(snapshot_path)
        raw_snapshot = self._read_batch_snapshot(eid) if present else None
        entries = None
        if present:
            if raw_snapshot is None or not isinstance(
                raw_snapshot, dict
            ) or raw_snapshot.get("tenant_id") != tenant_id:
                # Corrupt/tampered snapshot or a tenant mismatch: park the
                # whole scene; never guess a write set or touch a handle.
                raise ProviderUnavailable(
                    "batch rollback basis is missing, corrupt or mismatched; "
                    "the whole group is retained for startup recovery"
                )
            entries = self._validated_batch_snapshot(
                eid, raw_snapshot, markers
            )
            if entries is None:
                raise ProviderUnavailable(
                    "batch rollback basis is missing, corrupt or mismatched; "
                    "the whole group is retained for startup recovery"
                )
        else:
            # No durable snapshot: a batch writes key files only AFTER the
            # snapshot landed, so a still-marked file without one cannot be
            # restored from any trusted basis and must park.
            if files:
                raise ProviderUnavailable(
                    "batch snapshot is missing while marked files survive; "
                    "the whole group is retained for startup recovery"
                )

        # Union every source of newly minted handles. The in-memory pairs are
        # mapped to (provider_id, handle) so they merge with the journal and
        # the on-disk/pre-image delta.
        extra = set()
        for provider, handle in minted:
            pid = getattr(provider, "provider_id", None)
            if isinstance(pid, str) and pid and isinstance(handle, str):
                extra.add((pid, handle))
        if not self._delete_batch_group_handles(
            journal_id, entries or [], files, extra=extra
        ):
            # A delete could not be confirmed: per the all-or-nothing rule
            # neither a file nor an artifact may be touched.
            raise ProviderUnavailable(
                "could not confirm deletion of every handle minted by the "
                "failed batch rotation; the whole group is retained for "
                "startup recovery"
            )

        # All new handles confirmed gone: restore the COMPLETE old write set
        # byte-for-byte from the validated snapshot (not memory).
        if entries is not None:
            for key_id, previous_bytes, _previous_record in entries:
                try:
                    self._write_bytes_atomic(
                        self._path_for(key_id), previous_bytes
                    )
                except OSError:
                    # Keep the snapshot/journal and every marker as the retry
                    # basis; never clear anything below.
                    raise ProviderUnavailable(
                        "could not restore a key file of the failed batch "
                        "rotation; the whole group is retained for startup "
                        "recovery"
                    )

        # Every delete and every write-back verified: only now may the
        # rollback artifacts be removed. A lingering journal whose unlink
        # fails is reaped by the startup provision sweep (its event is not
        # durable); the state is already safe.
        self.drop_provision_journal(journal_id)
        if present:
            self._discard_batch_snapshot(eid)

    def _list_batch_snapshot_ids(self) -> List[str]:
        directory = os.path.join(self.data_dir, self._BATCH_DIR)
        try:
            names = os.listdir(directory)
        except OSError:
            return []
        return [name[:-5] for name in names if name.endswith(".json")]

    def batch_recovery_journal_ids(self) -> set:
        """Provision journal ids still owned by an unfinished batch recovery.

        A journal named by a surviving ``_batch_rotate`` marker or by a
        surviving batch snapshot is resolved exclusively by batch-group
        recovery: every new handle is deleted and every old file restored
        before the journal and snapshot are removed *together*. The generic
        provision sweep and the restore orphan sweep must not reap such a
        journal independently, or they would delete handles while the marked
        files and snapshot still need an all-or-nothing rollback -- the
        durable retry basis would be discarded halfway.

        A batch's provision journal is always named after its event id, so a
        marker naming a different journal id is inconsistent (corrupt/tampered)
        and defers nothing beyond the event id it carries: such a group parks
        in batch recovery rather than stalling an unrelated journal.
        """
        owned = set()
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            names = []
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            record = self._read_record(os.path.join(self.data_dir, name))
            marker = getattr(record, "pending_event", None)
            if isinstance(marker, dict) and marker.get("_batch_rotate"):
                event_desc = marker.get("event")
                eid = (
                    event_desc.get("event_id")
                    if isinstance(event_desc, dict)
                    else None
                )
                journal_id = marker.get("journal")
                if is_valid_key_id(eid):
                    owned.add(eid)
                if isinstance(journal_id, str) and is_valid_key_id(
                    journal_id
                ) and journal_id == eid:
                    owned.add(journal_id)
        # A snapshot is named after the event id, which is also its provision
        # journal id, so every surviving snapshot defers that journal.
        owned.update(self._list_batch_snapshot_ids())
        return owned

    def _recover_batch_rotations(self) -> None:
        """Finish or roll back batch rotations interrupted by a crash.

        Recovery is driven by the UNION of two durable artifacts, not by the
        markers alone:

        * key files still carrying a ``_batch_rotate`` marker name the event;
        * ``batch-rotations/<event_id>.json`` holds the COMPLETE write set as
          every key's exact pre-batch file bytes.

        Markers may survive only partially (some files were already restored
        or finalized when the process died) or be entirely absent (a crash
        after the snapshot landed but before the first file, or after a
        rollback that died before removing the snapshot). Either way the
        snapshot supplies the full write set, and the whole set is locked in
        sorted key_id order (in-process lock plus the per-key fcntl lock) so
        recovery never interleaves with a single-key rotate on a shared key.

        Under those locks the ledger decides, exactly once per event:

        * the success event is durable  -> the batch committed: keep every
          new version and clear surviving markers (snapshot not consulted);
        * otherwise                       -> the batch never committed: every
          new handle is confirmed deleted FIRST, and only then is every old
          file restored from the snapshot; provision journal, snapshot and
          markers are removed only after both fully verify.

        A missing or unreadable snapshot while a file still needs resolution,
        an unreachable provider, a failed delete or a failed write-back leaves
        the ENTIRE scene (files, markers, journal, snapshot) for the next
        open; the state is never guessed at.
        """
        marker_groups: dict = {}
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            names = []
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            path = os.path.join(self.data_dir, name)
            record = self._read_record(path)
            marker = getattr(record, "pending_event", None)
            if not isinstance(marker, dict) or not marker.get(
                "_batch_rotate"
            ):
                continue
            event_desc = marker.get("event")
            eid = (
                event_desc.get("event_id")
                if isinstance(event_desc, dict)
                else None
            )
            if not isinstance(eid, str) or not is_valid_key_id(eid):
                # A marker whose event cannot be identified cannot be safely
                # resolved either way; leave it (and its files) untouched.
                continue
            group = marker_groups.get(eid)
            if group is None:
                group = {"files": {}, "markers": []}
                marker_groups[eid] = group
            group["files"][record.key_id] = path
            # Keep the marker verbatim: the snapshot validation must confirm
            # every residual marker agrees with it.
            group["markers"].append(marker)

        # Presence matters separately from readability: a corrupt snapshot
        # file still defers its journal and parks its (marker-bearing) group.
        snapshots: dict = {}
        for snapshot_id in self._list_batch_snapshot_ids():
            snapshots[snapshot_id] = self._read_batch_snapshot(snapshot_id)

        for eid in sorted(set(marker_groups) | set(snapshots)):
            self._recover_batch_unit(
                eid, marker_groups.get(eid), snapshots.get(eid),
                snapshot_present=eid in snapshots,
            )

    def _strict_previous_record(
        self, key_id: str, tenant_id: str, data
    ) -> Optional[KeyRecord]:
        """Validate one snapshot image as a trusted pre-batch KeyRecord.

        The decoded ``previous_b64`` bytes must form a KeyRecord whose
        ``key_id`` and ``tenant_id`` match the snapshot entry, whose versions
        are a non-empty, strictly contiguous 1..n sequence with sane fields,
        whose ``current_version`` validly points at the last version, and
        which carries no pending marker (a snapshot captures a committed
        file, never a file mid-transaction). Anything less returns None so
        the caller treats the snapshot as untrusted and parks the group
        instead of guessing.
        """
        from .crypto import SUPPORTED_ALGORITHMS

        if not isinstance(data, dict):
            return None
        try:
            record = KeyRecord.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None
        if record.key_id != key_id or record.tenant_id != tenant_id:
            return None
        if record.pending_event:
            return None
        if not record.versions:
            return None
        for index, ver in enumerate(record.versions, start=1):
            if ver.version != index:
                return None
            if not isinstance(ver.created_at, str) or not ver.created_at:
                return None
            if ver.algorithm not in SUPPORTED_ALGORITHMS:
                return None
            if not isinstance(ver.provider_id, str) or not ver.provider_id:
                return None
            if not isinstance(ver.handle, str):
                return None
        # current_version must be a valid pointer at the last version.
        if record.current_version != len(record.versions):
            return None
        if record.get_version(record.current_version) is None:
            return None
        return record

    def _validated_batch_snapshot(
        self,
        snapshot_id: str,
        raw_snapshot,
        markers,
    ) -> Optional[list]:
        """Cross-validate the snapshot filename, payload and residual markers.

        Every durable reference of the attempt must agree before the snapshot
        may serve as a rollback write set: the filename event id, the
        payload's ``event_id``/``tenant_id``, the complete unique
        ``key_ids`` set, and each surviving marker's event/journal/snapshot
        references and key set. Every ``previous_b64`` value must decode
        strictly (strict base64 -> UTF-8 JSON -> validated KeyRecord via
        :meth:`_strict_previous_record`).

        Returns the COMPLETE write set as
        ``[(key_id, previous_bytes, KeyRecord), ...]`` sorted by key_id, or
        None when the snapshot is absent/corrupt/semantically mismatched. A
        partial marker set (some files already restored/finalized) still
        validates: the snapshot -- never the surviving files -- defines the
        full write set.
        """
        # The filename *is* the event id; it must be a canonical UUID4.
        if not is_valid_key_id(snapshot_id):
            return None
        if not isinstance(raw_snapshot, dict):
            return None
        if raw_snapshot.get("event_id") != snapshot_id:
            return None
        tenant_id = raw_snapshot.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id:
            return None
        raw_entries = raw_snapshot.get("keys")
        if not isinstance(raw_entries, list) or not raw_entries:
            return None
        entries = []
        seen = set()
        for entry in raw_entries:
            if not isinstance(entry, dict):
                return None
            key_id = entry.get("key_id")
            if not is_valid_key_id(key_id) or key_id in seen:
                return None
            # previous_b64 is mandatory and must decode STRICTLY: lenient
            # base64 or bytes that are not JSON make the snapshot unusable.
            encoded = entry.get("previous_b64")
            if not isinstance(encoded, str):
                return None
            try:
                raw_bytes = base64.b64decode(encoded, validate=True)
                data = json.loads(raw_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None
            record = self._strict_previous_record(key_id, tenant_id, data)
            if record is None:
                return None
            seen.add(key_id)
            entries.append((key_id, raw_bytes, record))
        entries.sort(key=lambda item: item[0])

        # Every residual marker must be consistent with the snapshot and with
        # each other: same event, tenant, journal/snapshot references and the
        # exact complete key set.
        for marker in markers:
            if not isinstance(marker, dict) or not marker.get(
                "_batch_rotate"
            ):
                return None
            event_desc = marker.get("event")
            if not isinstance(event_desc, dict):
                return None
            if event_desc.get("event_id") != snapshot_id:
                return None
            # The marker must describe this tenant's batch_rotate event; an
            # action mismatch means the artifacts do not provably belong to
            # one attempt and the snapshot cannot serve as the rollback basis.
            if event_desc.get("action") != audit_mod.ACTION_BATCH_ROTATE:
                return None
            if event_desc.get("tenant_id") != tenant_id:
                return None
            if marker.get("tenant_id") != tenant_id:
                return None
            # The provision journal and the snapshot are both named after the
            # event id.
            if marker.get("journal") != snapshot_id:
                return None
            if marker.get("snapshot") != snapshot_id:
                return None
            marked = marker.get("key_ids")
            if not isinstance(marked, list):
                return None
            marked_set = set()
            for value in marked:
                if not is_valid_key_id(value) or value in marked_set:
                    return None
                marked_set.add(value)
            # The residual marker's complete unique key set must equal the
            # snapshot's complete write set -- a subset or a mismatch means
            # the artifacts do not provably belong to one attempt.
            if marked_set != seen:
                return None
        return entries

    def _rescan_batch_markers(self, eid: str) -> Tuple[dict, list]:
        """Re-read, under the group locks, the files still carrying event eid.

        Returns ``({key_id: path}, [marker, ...])`` reflecting the on-disk
        scene at decision time. Another process completing the same recovery
        or the concurrent request may have restored/finalized files since the
        unlocked scan, so the committed-vs-rollback decision must use this
        fresh view, never the stale one.
        """
        files: dict = {}
        markers: list = []
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            return files, markers
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            path = os.path.join(self.data_dir, name)
            record = self._read_record(path)
            marker = getattr(record, "pending_event", None)
            if not isinstance(marker, dict) or not marker.get(
                "_batch_rotate"
            ):
                continue
            event_desc = marker.get("event")
            marked_eid = (
                event_desc.get("event_id")
                if isinstance(event_desc, dict)
                else None
            )
            if marked_eid == eid:
                files[record.key_id] = path
                markers.append(marker)
        return files, markers

    @staticmethod
    def _batch_scene_tenant(markers, snapshot) -> Optional[str]:
        """The single tenant named by the residual batch artifacts.

        Returns that tenant id, None when neither a marker nor a snapshot
        names one (orphan-journal-only scene), or the sentinel
        ``_TENANT_MISMATCH`` when surviving artifacts disagree -- such a scene
        must never be finalized as committed.
        """
        tenants = set()
        for marker in markers:
            tenant = marker.get("tenant_id")
            if isinstance(tenant, str) and tenant:
                tenants.add(tenant)
        if isinstance(snapshot, dict):
            tenant = snapshot.get("tenant_id")
            if isinstance(tenant, str) and tenant:
                tenants.add(tenant)
        if not tenants:
            return None
        if len(tenants) > 1:
            return _TENANT_MISMATCH
        return next(iter(tenants))

    def _recover_batch_unit(
        self, eid: str, group: Optional[dict], snapshot: Optional[dict],
        snapshot_present: bool = False,
    ) -> None:
        """Resolve one batch event: commit-finalize or whole-group rollback.

        The whole write set is locked in sorted key_id order (in-process lock
        plus the per-key fcntl lock), so recovery never interleaves with a
        single-key rotate on a shared key. Under those locks the scene and
        the snapshot are re-read and cross-validated, and only then does the
        ledger decide:

        * durable success event -> the batch committed: keep the new
          versions, clear surviving markers, drop journal/snapshot residue;
        * otherwise, with a trusted complete snapshot -> delete every new
          handle (journal plus the on-disk/pre-image delta) FIRST, then
          byte-for-byte restore every old file, and only after both fully
          verify remove journal and snapshot;
        * snapshot missing/corrupt/semantically mismatched -> park the
          ENTIRE scene for a later open: never delete a new handle, rewrite a
          key file, clear a marker or drop the snapshot/journal, and never
          expose the uncommitted current.
        """
        files = dict(group["files"]) if group else {}
        # The lock set covers every still-marked file and (once validated)
        # every key in the snapshot's complete write set.
        pre_entries = self._validated_batch_snapshot(
            eid, snapshot, list(group["markers"]) if group else []
        )
        pre_snapshot_keys = (
            {key_id for key_id, _, _ in pre_entries}
            if pre_entries is not None
            else set()
        )
        lock_keys = sorted(set(files) | pre_snapshot_keys)
        with self.multi_key_locks(lock_keys):
            # Re-read the scene and the snapshot while holding every lock of
            # the write set, so nothing below acts on a stale observation.
            files, markers = self._rescan_batch_markers(eid)
            snapshot_path = self._batch_snapshot_path(eid)
            present_now = os.path.exists(snapshot_path)
            current_snapshot = (
                self._read_batch_snapshot(eid) if present_now else None
            )
            try:
                event = self.audit.get_event(eid)
            except LedgerError:
                # The ledger cannot be read right now; leave everything for a
                # later open rather than guessing committed-vs-not.
                return
            # A durable success only commits THIS batch when the event's
            # action and tenant actually match the surviving artifacts. An
            # action/tenant mismatch (corruption or a colliding id) parks the
            # whole scene: clearing markers on a foreign event would keep
            # uncommitted versions and expose them.
            scene_tenant = self._batch_scene_tenant(markers, current_snapshot)
            if (
                event is not None
                and event.outcome == audit_mod.OUTCOME_SUCCESS
                and event.action == audit_mod.ACTION_BATCH_ROTATE
                and (
                    scene_tenant is None
                    or event.tenant_id == scene_tenant
                )
            ):
                self._batch_finish_committed(eid, files, eid)
                return
            if event is not None and event.outcome == audit_mod.OUTCOME_SUCCESS:
                # Durable but mismatched: do nothing, delete nothing and
                # expose nothing; wait for repair/startup with the scene
                # intact.
                return

            # The success event never landed: the batch is uncommitted. The
            # snapshot is trusted only after its filename, payload and every
            # residual marker fully agree and every pre-batch image parses.
            entries = self._validated_batch_snapshot(
                eid, current_snapshot, markers
            )
            if entries is not None:
                if self._batch_rollback_unit(entries, files, eid, eid):
                    return
                # Handle delete, provider access or file write-back failed:
                # keep the whole scene for the next open.
                return

            # No trusted snapshot.
            if files or present_now:
                # A file still needs its pre-batch bytes but the only source
                # is missing/unreadable/semantically mismatched, or a corrupt
                # snapshot file survives: preserve the ENTIRE scene (files,
                # markers, journal, snapshot) for a later open and never
                # guess, delete a new handle or expose the uncommitted
                # current.
                return

            # No marker references this event and no snapshot file survives:
            # only orphaned handles (the durable journal named after the
            # event) can remain. Reap them from the journal and drop it
            # strictly after success.
            if self.release_journal_handles(eid):
                self.drop_provision_journal(eid)

    def _batch_finish_committed(
        self, eid: str, files: dict, journal_id: str
    ) -> None:
        """Post-commit housekeeping: clear markers, then drop the artifacts.

        The durable success event already makes the new versions authoritative
        and their handles record-owned; nothing here is ever rolled back. The
        snapshot is not consulted (it is rollback-only data) and a corrupt or
        mismatched snapshot does not matter: the durable event is the fact. A
        marker-clear failure leaves that file's marker for the next open.
        """
        for key_id, path in files.items():
            record = self._read_record(path)
            marker = getattr(record, "pending_event", None)
            if record is None or not isinstance(marker, dict):
                continue
            event_desc = marker.get("event")
            marked_eid = (
                event_desc.get("event_id")
                if isinstance(event_desc, dict)
                else None
            )
            if marked_eid != eid:
                continue
            record.pending_event = None
            try:
                self._write_atomic(path, record.to_json())
            except OSError:
                pass
        self.drop_provision_journal(journal_id)
        self._discard_batch_snapshot(eid)

    def _batch_rollback_unit(
        self, entries: list, files: dict, journal_id: str, eid: str
    ) -> bool:
        """Delete all new handles, then restore all old files.

        Returns True only when every handle delete and every file write-back
        has been verified, after which the provision journal and snapshot are
        removed. The write set is the snapshot's COMPLETE validated set (not
        just the files still marked), so a partially-cleared marker group is
        still restored as a whole. Any failure returns False with the whole
        group and both durable artifacts retained for the next open.
        """
        if not self._delete_batch_group_handles(journal_id, entries, files):
            return False
        for key_id, previous_bytes, _previous_record in entries:
            try:
                self._write_bytes_atomic(
                    self._path_for(key_id), previous_bytes
                )
            except OSError:
                return False
        # Old files are all restored and new handles all confirmed gone: now,
        # and only now, may the rollback basis be removed.
        self.drop_provision_journal(journal_id)
        self._discard_batch_snapshot(eid)
        return True

    def _delete_batch_group_handles(
        self, journal_id: str, entries: list, files: dict, extra=()
    ) -> bool:
        """Delete every handle an uncommitted batch minted.

        Handles come from the union of the durable provision journal, the
        delta between the on-disk versions and the validated snapshot pre-batch
        versions (the write set) plus any surviving marked file, and the
        ``extra`` pairs the aborting request frame still holds in memory.
        Every owning provider must be reachable and every delete must verify;
        a single failure makes the whole rollback defer.
        """
        targets = set()
        for pair in extra or ():
            targets.add(pair)
        for provider_id, handle in self.read_provision_journal(journal_id):
            targets.add((provider_id, handle))
        previous_by_key = {}
        for key_id, _previous_bytes, previous_record in entries:
            triples = {
                (ver.provider_id, ver.handle)
                for ver in previous_record.versions
            }
            previous_by_key[key_id] = triples
        candidate_paths = {
            key_id: self._path_for(key_id) for key_id, _, _ in entries
        }
        candidate_paths.update(files)
        for key_id, path in candidate_paths.items():
            record = self._read_record(path)
            if record is None:
                continue
            for ver in record.versions:
                triple = (ver.provider_id, ver.handle)
                if triple not in previous_by_key.get(key_id, set()):
                    targets.add(triple)
        cleaned = True
        for provider_id, handle in targets:
            if not isinstance(provider_id, str) or not provider_id:
                continue
            if not self._delete_provisioned_handle(provider_id, handle):
                cleaned = False
        return cleaned

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
            self._ensure_settled(record)
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

    # -- per-version revocation --------------------------------------------
    # Outcomes of revoke_version: the version is revoked (a first transition
    # or an idempotent repeat), the key/version is unknown for this tenant,
    # or the whole key is already revoked (a version revoke then answers 409
    # and never shadows the key-level reason/operator/timestamp).
    VERSION_REVOKE_OK = "ok"
    VERSION_REVOKE_KEY_NOT_FOUND = "key_not_found"
    VERSION_REVOKE_VERSION_NOT_FOUND = "version_not_found"
    VERSION_REVOKE_KEY_REVOKED = "key_revoked"

    def revoke_version(
        self,
        key_id: str,
        tenant_id: str,
        version: int,
        reason: str,
        operator: str,
    ) -> tuple:
        """Revoke one key version, keeping the first revocation's values.

        Returns ``(status, record, ver)``. A first-time transition commits
        through the same outbox transaction as a whole-key revoke: one
        ``revoke_version`` audit event (its UTC timestamp is the
        ``revoked_at``), the version file carrying a pending marker and a
        rollback on ledger failure, so the event and the file never land
        separately. Repeated or concurrent revokes of an already-revoked
        version are idempotent under the per-key locks: the first
        reason/operator/revoked_at win, the file is never rewritten and NO
        second audit event is appended (a single audit per version). A
        whole-key revocation outranks a version revoke: such a request
        returns VERSION_REVOKE_KEY_REVOKED without writing anything, so the
        key-level facts are never shadowed. An unknown/foreign key or an
        unknown version returns its not-found sentinel (existence never
        leaks); the caller records the rejected attempt.
        """
        if not _KEY_ID_RE.fullmatch(key_id):
            return self.VERSION_REVOKE_KEY_NOT_FOUND, None, None
        path = self._path_for(key_id)
        with self._key_lock(key_id), self._file_lock(key_id):
            record = self._read_record(path)
            if record is None or record.tenant_id != tenant_id:
                return self.VERSION_REVOKE_KEY_NOT_FOUND, None, None
            self._ensure_settled(record)
            ver = record.get_version(version)
            if ver is None:
                return self.VERSION_REVOKE_VERSION_NOT_FOUND, record, None
            # Whole-key revocation takes priority: never layer a version
            # revocation (with different facts) on top of it.
            if record.status == "revoked":
                return self.VERSION_REVOKE_KEY_REVOKED, record, ver
            if ver.status == "revoked":
                # Idempotent repeat/concurrent winner: keep the first values
                # and the single, already-committed audit event.
                return self.VERSION_REVOKE_OK, record, ver
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_REVOKE_VERSION, key_id,
                audit_mod.OUTCOME_SUCCESS,
            )
            previous = record.to_json()
            ver.status = "revoked"
            ver.reason = reason
            ver.operator = operator
            ver.revoked_at = event.timestamp
            # The marker names the targeted version so an uncommitted
            # revocation's crash projection restores exactly that version.
            self._commit_mutation(
                path, record, event, previous,
                marker_extra={"version": version},
            )
        return self.VERSION_REVOKE_OK, record, ver

    def get_version(
        self, key_id: str, tenant_id: str, version: int
    ) -> Optional[tuple]:
        """Return (record, version_record) over the committed view.

        None if the key/version is not accessible or the requested version
        belongs to an uncommitted transaction (it then reads as absent, never
        projected).
        """
        record = self.get(key_id, tenant_id)
        if record is None:
            return None
        ver = record.get_version(version)
        if ver is None:
            return None
        return record, ver

    # -- envelope crypto material ------------------------------------------
    # Outcomes of crypto_material: the version's KEK is ready, the key or
    # version does not exist for this tenant, or the key is revoked.
    CRYPTO_OK = "ok"
    CRYPTO_NOT_FOUND = "not_found"
    CRYPTO_REVOKED = "revoked"

    @staticmethod
    def _kek_for_version(ver: VersionRecord, raw_material: str):
        """Turn exported raw material into an envelope KEK object.

        AES256 yields the raw 32-byte key; RSA2048 yields the loaded private
        key (envelope wrapping uses its public component). Corrupt stored
        material is a backend inconsistency, surfaced as ProviderUnavailable
        (503) -- never as a client-visible 400 and never leaking material.
        """
        if ver.algorithm == "AES256":
            try:
                raw = base64.b64decode(raw_material, validate=True)
            except (ValueError, TypeError) as exc:
                raise ProviderUnavailable(
                    "stored AES256 material is not valid base64"
                ) from exc
            if len(raw) != 32:
                raise ProviderUnavailable(
                    "stored AES256 material does not decode to 32 bytes"
                )
            return raw
        if ver.algorithm == "RSA2048":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            try:
                private_key = serialization.load_pem_private_key(
                    raw_material.encode("utf-8"), password=None
                )
            except (ValueError, TypeError) as exc:
                raise ProviderUnavailable(
                    "stored RSA2048 material is not a PEM private key"
                ) from exc
            if not isinstance(private_key, rsa.RSAPrivateKey) or (
                private_key.key_size != 2048
            ):
                raise ProviderUnavailable(
                    "stored RSA2048 material is not a 2048-bit RSA private key"
                )
            return private_key
        raise ProviderUnavailable(
            "unsupported algorithm for envelope crypto: %r" % ver.algorithm
        )

    @_provider_session
    def crypto_material(
        self,
        key_id: str,
        tenant_id: str,
        version: Optional[int] = None,
        lock_timeout: Optional[float] = None,
        native_unwrap: bool = False,
    ) -> tuple:
        """Resolve a version's key-encryption key for envelope crypto.

        Returns ``(status, record, ver, kek)``: on CRYPTO_OK ``kek`` is the
        raw 32-byte AES key or the loaded RSA private key; ``record``/``ver``
        are the committed view. CRYPTO_NOT_FOUND covers an unknown key, a
        foreign tenant and an unknown version alike (existence never leaks);
        CRYPTO_REVOKED means the key is revoked (every version refuses
        crypto). The read runs under the key locks over the committed
        projection, adopts a raw legacy record exactly like export, and asks
        the owning provider for the material -- a record owned by an inactive
        provider raises ProviderUnavailable (503), never a silent fallback.
        Nothing is persisted and no audit event is written here.

        When ``native_unwrap`` is True and the version's owning provider
        declares the ``unwrap_key`` operation, no material is exported and no
        private key is loaded into this process: the fourth tuple element is
        a :class:`NativeUnwrap` ``(provider, handle)`` pair that the caller
        hands to ``envelope.open_envelope_native``. Providers that do not
        declare the operation take the ordinary export path.

        With a finite ``lock_timeout`` the per-key in-process and fcntl locks
        share one deadline and a wait beyond it raises :class:`LockTimeout`
        before the provider is touched. The idempotent encrypt uses it so a
        contended key answers 503/timed_out with zero side effects.
        """
        if not is_valid_key_id(key_id):
            return self.CRYPTO_NOT_FOUND, None, None, None
        path = self._path_for(key_id)
        with self.key_locks(key_id, timeout=lock_timeout):
            on_disk = self._read_record(path)
            if on_disk is None or on_disk.tenant_id != tenant_id:
                return self.CRYPTO_NOT_FOUND, None, None, None
            # Never crypto against an uncommitted current: project only the
            # durable state (the view, not the file, is trimmed).
            record = self._committed_record(on_disk)
            if record is None:
                return self.CRYPTO_NOT_FOUND, None, None, None
            # Adopt a raw legacy record now, under the key locks and only
            # while the local provider is active (same rule as export).
            self._take_over_legacy(record)
            if record.status == "revoked":
                return self.CRYPTO_REVOKED, record, None, None
            if version is None:
                ver = record.current
            else:
                ver = record.get_version(version)
                if ver is None:
                    return self.CRYPTO_NOT_FOUND, record, None, None
            # A revoked version refuses crypto even while the key as a whole
            # stays active (older/current version revocation). The check
            # precedes every provider contact, so no KMS/HSM is ever called
            # for a revoked version.
            if ver.is_revoked:
                return self.CRYPTO_REVOKED, record, ver, None
            provider = self._provider_for(ver.provider_id)
            if native_unwrap and provider_mod.declares_unwrap_key(provider):
                # Native DEK unwrap: bind the provider/handle only. The DEK
                # never enters this process except transiently inside the
                # provider boundary call; export_material is never invoked
                # and the KEK private key is never loaded here.
                return (
                    self.CRYPTO_OK,
                    record,
                    ver,
                    NativeUnwrap(provider=provider, handle=ver.handle),
                )
            exported = provider.export_material(ver.handle)
            kek = self._kek_for_version(ver, exported.encrypted_material)
            return self.CRYPTO_OK, record, ver, kek

    # Outcomes of rewrap_versions, which resolves two versions of one key in
    # a single locked read: OK / not found / revoked (same semantics as
    # crypto_material).
    REWRAP_OK = "ok"
    REWRAP_NOT_FOUND = "not_found"
    REWRAP_REVOKED = "revoked"

    def rewrap_versions(
        self,
        key_id: str,
        tenant_id: str,
        source_version: int,
        target_version: Optional[int] = None,
    ) -> tuple:
        """Resolve the source and target VERSION records for a rewrap.

        Returns ``(status, record, source_ver, target_ver)``. Both versions
        are read under ONE per-key lock over the committed projection, but no
        provider is probed and no material exported: a same-version 409 and
        a source-algorithm 400 must be answerable while a KMS/HSM is down.
        ``target_version`` defaults to the current version. A missing
        key/version (for either side), a foreign tenant and a revoked key
        share the same indistinct statuses as crypto_material. The caller
        then resolves each KEK with crypto_material exactly once.
        """
        if not is_valid_key_id(key_id):
            return self.REWRAP_NOT_FOUND, None, None, None
        path = self._path_for(key_id)
        with self.key_locks(key_id):
            on_disk = self._read_record(path)
            if on_disk is None or on_disk.tenant_id != tenant_id:
                return self.REWRAP_NOT_FOUND, None, None, None
            record = self._committed_record(on_disk)
            if record is None:
                return self.REWRAP_NOT_FOUND, None, None, None
            self._take_over_legacy(record)
            if record.status == "revoked":
                return self.REWRAP_REVOKED, record, None, None
            source_ver = record.get_version(source_version)
            if source_ver is None:
                return self.REWRAP_NOT_FOUND, record, None, None
            if target_version is None:
                target_ver = record.current
            else:
                target_ver = record.get_version(target_version)
                if target_ver is None:
                    return self.REWRAP_NOT_FOUND, record, None, None
            # Either side being a revoked version refuses the rewrap (the
            # whole key was checked first and outranks a version state); no
            # provider is contacted for either KEK.
            if source_ver.is_revoked or target_ver.is_revoked:
                return self.REWRAP_REVOKED, record, source_ver, target_ver
            return self.REWRAP_OK, record, source_ver, target_ver

    # -- sign / verify ------------------------------------------------------
    # Outcomes shared by sign_message and verification_key: the version
    # is usable, the key/version is not found for this tenant, the key is
    # revoked (every version refuses), or the version is not an RSA2048 one.
    SIGN_OK = "ok"
    SIGN_NOT_FOUND = "not_found"
    SIGN_REVOKED = "revoked"
    SIGN_WRONG_ALGORITHM = "wrong_algorithm"

    def _resolve_signing_version(
        self,
        key_id: str,
        tenant_id: str,
        version: Optional[int],
    ) -> tuple:
        """Resolve the version a sign/verify call acts on.

        Returns ``(status, record, ver)`` with the SIGN_* semantics documented
        on :meth:`sign_message`. The read runs under the key locks over the
        committed projection and adopts a raw legacy record exactly like
        export (only while the local provider is active). Nothing is
        persisted and no audit event is written here.
        """
        if not is_valid_key_id(key_id):
            return self.SIGN_NOT_FOUND, None, None
        path = self._path_for(key_id)
        with self.key_locks(key_id):
            on_disk = self._read_record(path)
            if on_disk is None or on_disk.tenant_id != tenant_id:
                return self.SIGN_NOT_FOUND, None, None
            record = self._committed_record(on_disk)
            if record is None:
                return self.SIGN_NOT_FOUND, None, None
            # Adopt a raw legacy record now, under the key locks and only
            # while the local provider is active (same rule as export).
            self._take_over_legacy(record)
            if record.status == "revoked":
                return self.SIGN_REVOKED, record, None
            if version is None:
                ver = record.current
            else:
                ver = record.get_version(version)
                if ver is None:
                    return self.SIGN_NOT_FOUND, record, None
            # A revoked version refuses signing even while the key as a whole
            # stays active; the check precedes the algorithm gate and every
            # provider contact.
            if ver.is_revoked:
                return self.SIGN_REVOKED, record, ver
            if ver.algorithm != "RSA2048":
                return self.SIGN_WRONG_ALGORITHM, record, ver
            return self.SIGN_OK, record, ver

    @_provider_session
    def sign_message(
        self,
        key_id: str,
        tenant_id: str,
        version: Optional[int],
        message: bytes,
    ) -> tuple:
        """Resolve an RSA2048 version and produce its deterministic signature.

        Returns ``(status, record, ver, signature)``: on SIGN_OK
        ``signature`` is the 256-byte RSASSA-PKCS1-v1_5/SHA-256 signature of
        ``message``. SIGN_NOT_FOUND covers an unknown key, a foreign tenant
        and an unknown version (existence never leaks); SIGN_REVOKED means
        the key is revoked (every version refuses signing);
        SIGN_WRONG_ALGORITHM means the resolved version is not RSA2048.

        Two signing paths, chosen by the version's owning provider:

        * the provider declares the optional ``sign`` operation (KMS/HSM
          native): its ``sign(handle, message)`` is called on the bound
          provider inside this operation's five-second provider-call gate.
          ``export_material`` is NEVER called and no private key enters the
          service process; the returned signature must be exactly
          ``SIGNATURE_BYTES`` bytes and must verify against the version's
          stored public key. A malformed result, a failed verification or
          any provider exception raises ProviderUnavailable (the fixed 503,
          no audit event);
        * otherwise the legacy export path: the material is exported by the
          owning provider and the private key lives in process memory only
          for this one sign.

        A record owned by an inactive provider or corrupt stored material
        raises ProviderUnavailable (503), never a silent fallback. Nothing is
        persisted and no audit event is written here.
        """
        status, record, ver = self._resolve_signing_version(
            key_id, tenant_id, version
        )
        if status != self.SIGN_OK:
            return status, record, ver, None
        provider = self._provider_for(ver.provider_id)
        if provider_mod.declares_sign(provider):
            signature = provider.sign(ver.handle, message)
            if (
                not isinstance(signature, bytes)
                or len(signature) != signing_mod.SIGNATURE_BYTES
            ):
                raise ProviderUnavailable(
                    "provider returned a malformed signature"
                )
            try:
                public_key = signing_mod.load_rsa_public_key(ver.public_key)
            except signing_mod.SigningError as exc:
                raise ProviderUnavailable(str(exc)) from exc
            if not signing_mod.rsa_verify(public_key, message, signature):
                raise ProviderUnavailable(
                    "provider signature failed public-key verification"
                )
            return self.SIGN_OK, record, ver, signature
        exported = provider.export_material(ver.handle)
        try:
            private_key = signing_mod.load_rsa_private_key(
                exported.encrypted_material
            )
        except signing_mod.SigningError as exc:
            # Corrupt stored private material is a backend inconsistency,
            # never a client error: the fixed provider-failure 503.
            raise ProviderUnavailable(str(exc)) from exc
        return (
            self.SIGN_OK,
            record,
            ver,
            signing_mod.rsa_sign(private_key, message),
        )

    def verification_key(
        self,
        key_id: str,
        tenant_id: str,
        version: Optional[int] = None,
    ) -> tuple:
        """Resolve an RSA2048 version's PUBLIC key for signature verification.

        Returns ``(status, record, ver, public_key)`` with the same status
        semantics as :meth:`sign_message`. Verification uses ONLY the
        public PEM stored on the key record: deliberately NOT wrapped in a
        provider session, it never loads, probes or contacts a KMS/HSM
        provider and never adopts a legacy record, so an old version still
        verifies after a restart, a rotation, a migration or a provider
        outage. A corrupt stored public key is a backend inconsistency
        (ProviderUnavailable -> fixed 503), never a client error.
        """
        if not is_valid_key_id(key_id):
            return self.SIGN_NOT_FOUND, None, None, None
        path = self._path_for(key_id)
        with self.key_locks(key_id):
            on_disk = self._read_record(path)
            if on_disk is None or on_disk.tenant_id != tenant_id:
                return self.SIGN_NOT_FOUND, None, None, None
            record = self._committed_record(on_disk)
            if record is None:
                return self.SIGN_NOT_FOUND, None, None, None
            if record.status == "revoked":
                return self.SIGN_REVOKED, record, None, None
            if version is None:
                ver = record.current
            else:
                ver = record.get_version(version)
                if ver is None:
                    return self.SIGN_NOT_FOUND, record, None, None
            # A revoked version refuses verification even while the key as a
            # whole stays active (and no provider is contacted here anyway).
            if ver.is_revoked:
                return self.SIGN_REVOKED, record, ver, None
            if ver.algorithm != "RSA2048":
                return self.SIGN_WRONG_ALGORITHM, record, ver, None
            try:
                public_key = signing_mod.load_rsa_public_key(ver.public_key)
            except signing_mod.SigningError as exc:
                raise ProviderUnavailable(str(exc)) from exc
            return self.SIGN_OK, record, ver, public_key

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
            "status": ver.status,
            "reason": ver.reason,
            "operator": ver.operator,
            "revoked_at": ver.revoked_at,
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

    @_provider_session
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
            on_disk = self._read_record(path)
            if on_disk is None or on_disk.tenant_id != tenant_id:
                return None
            # Never seal an uncommitted current: project only the durable
            # state (the view, not the file, is trimmed).
            record = self._committed_record(on_disk)
            if record is None:
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

    def _adopt_imported_version(self, ver: dict, journal: Optional[str] = None,
                                mirror=None) -> tuple:
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
            if provider_mod.active_is_local():
                target = provider_mod.configure_local(self.data_dir)
            elif provider_mod.local_provider_displaced():
                # A legacy bundle (no provenance block) is local material and
                # a readable committed state names a different active entry
                # while local WAS active earlier: a directed switch displaced
                # it, so a bound import/restore must stay PENDING until local
                # is active again, never terminalize.
                raise ProviderIdentityMismatch(
                    "legacy bundle is owned by the local provider %r, which "
                    "was displaced by a provider switch" % LOCAL_PROVIDER_ID
                )
            else:
                raise ProviderUnavailable(
                    "legacy bundle without a provider block is local-only; "
                    "the local provider is not active"
                )
        else:
            target = self._provider_for(block["provider_id"])
        triple = target.import_material(
            ver["algorithm"], ver["public_key"], ver["private_material"]
        )
        if journal is not None:
            self._append_provision(journal, target.provider_id, triple.handle)
        if mirror is not None:
            # The mirror records the freshly minted handle together with the
            # journal entry, so the two durable artifacts always agree.
            mirror.add_handle(target.provider_id, triple.handle)
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
            # Per-version revocation facts are preserved by import/restore;
            # an older bundle without them defaults to an active version.
            status=ver.get("status", "active"),
            reason=ver.get("reason"),
            operator=ver.get("operator"),
            revoked_at=ver.get("revoked_at"),
        )
        return record, target

    @staticmethod
    def _release_handles(adopted) -> bool:
        """Delete (provider, handle) pairs minted by a failed import.

        Returns True only when every delete succeeded; deletes are idempotent.
        """
        cleaned = True
        for target, handle in adopted:
            try:
                target.delete(handle)
            except Exception:
                cleaned = False
        return cleaned

    def release_record_handles(self, record: KeyRecord, strict: bool = False) -> bool:
        """Delete every provider handle held by a (discarded) record.

        Used when a restore/batch rotation that minted provider objects never
        commits; each version is routed to its owning provider. A
        missing/inactive provider means its handles cannot be reached from
        here, so those versions are skipped by default (the durable journal
        remains the authoritative retry path); only a reachable provider whose
        delete fails makes this report False. With ``strict=True`` an
        unreachable provider is a failure too: the caller (old restore groups
        that have no journal, crash recovery) must then keep the whole group
        of files and markers and retry on the next open.
        """
        cleaned = True
        for ver in record.versions:
            try:
                target = self._provider_for(ver.provider_id)
            except ProviderUnavailable:
                if strict:
                    cleaned = False
                continue
            try:
                target.delete(ver.handle)
            except Exception:
                cleaned = False
        return cleaned

    @_provider_session
    def import_bundle(
        self,
        tenant_id: str,
        payload: dict,
        event_id: Optional[str] = None,
        lock_timeout: Optional[float] = None,
        pre_commit=None,
        mirror=None,
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

        For an idempotent operation the per-key lock is acquired (with
        ``lock_timeout``) **before** the provision journal or any provider
        handle exists, so a timed-out wait writes no key, audit event or
        handle. ``event_id`` names the committing audit event after the
        operation_id.
        """
        key_id = payload["key_id"]
        # Acquire the key lock first: a lock-wait timeout must surface before
        # a journal, handle or event exists.
        with self.key_locks(key_id, timeout=lock_timeout):
            # Mint the committing event up front so the provision journal is
            # named after its event_id: a leftover journal resolves at any
            # startup by asking the ledger whether the event committed.
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_IMPORT, key_id,
                audit_mod.OUTCOME_SUCCESS, event_id=event_id,
            )
            journal_id, journal_path = self._new_provision_journal(
                event.event_id, event.tenant_id, event.action
            )
            committed = False
            adopted = []  # (provider, handle) pairs minted by this attempt
            try:
                if mirror is not None:
                    try:
                        mirror.provision(journal_id)
                    except OSError as exc:
                        # Empty journal, no provider call yet: drop it and
                        # strand the bound op pending for a same-id retry.
                        self.drop_provision_journal(journal_id)
                        from .artifacts import ArtifactStrandUnavailable

                        raise ArtifactStrandUnavailable(str(exc), 500)
                versions = []
                for ver in payload["versions"]:
                    version_record, target = self._adopt_imported_version(
                        ver, journal_path, mirror
                    )
                    versions.append(version_record)
                    adopted.append((target, version_record.handle))
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
                # Conflict recheck only after every version validated and
                # every provider call succeeded; nothing has been written.
                existing = self._read_record(path)
                if existing is not None:
                    return IMPORT_CONFLICT, existing
                # A failure here rolls the just-created file back inside
                # _commit_mutation; the finally block then reconciles the
                # minted handles and the provision journal.
                if mirror is not None:
                    mirror.phase(PHASE_STAGED)
                self._commit_mutation(
                    path, record, event, None,
                    journal_id=journal_id,
                    pre_commit=pre_commit,
                )
                committed = True
                # The handles are owned by the new record and the durable
                # success event makes the journal obsolete.
                self.drop_provision_journal(journal_id)
                if mirror is not None:
                    mirror.phase(PHASE_COMMITTED)
                return IMPORT_CREATED, record
            finally:
                if not committed:
                    # Any non-commit exit (provider failure, malformed
                    # material, refused conflict, aborted transaction):
                    # delete every minted handle and drop the journal; the
                    # durable journal is also the crash safety net for
                    # handles this frame no longer knows about. A failed
                    # delete keeps the journal for startup and turns the
                    # answer into 503 instead of hiding the orphan.
                    pending = isinstance(
                        sys.exc_info()[1], ProviderReconnectPending
                    )
                    if pending:
                        # Reconnect-pending interruption (gate timeout /
                        # displaced provider_id): reconcile any minted handles,
                        # but a cleanup failure merely retains the journal and
                        # parks the scene; re-raise the ORIGINAL pending signal
                        # so the guard keeps the op PENDING (never a terminal
                        # 503) for a same-id continuation.
                        try:
                            self._abort_provision(journal_id, adopted)
                        except ProviderUnavailable:
                            pass
                        if mirror is not None:
                            try:
                                mirror.reset_for_pending_retry()
                            except OSError:
                                pass
                        raise
                    self._abort_provision(journal_id, adopted)

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

    # -- tenant key listing ------------------------------------------------
    def _list_committed(self, tenant_id: str) -> List["KeyRecord"]:
        """Read every tenant key and project its committed state.

        Unsettled records (an in-flight or crashed rotate/revoke/batch/
        restore) are projected by the same ``_committed_record`` rules the
        single-key reads use: an uncommitted trailing version or revocation
        is trimmed, and an unprovable record is hidden. A directory that
        cannot be read is a storage failure (LedgerError -> 500), never an
        silently empty page.
        """
        try:
            names = os.listdir(self.data_dir)
        except OSError as exc:
            raise LedgerError("cannot read key directory: %s" % exc) from exc
        records = []
        for name in names:
            if not (name.endswith(".json") and is_valid_key_id(name[:-5])):
                continue
            record = self._read_record(os.path.join(self.data_dir, name))
            if record is None or record.tenant_id != tenant_id:
                continue
            committed = self._committed_record(record)
            if committed is not None:
                records.append(committed)
        return records

    @staticmethod
    def _list_fingerprint(records: List["KeyRecord"]) -> str:
        """Stable digest identifying one visible key-list snapshot.

        Every projected field the response or the filters expose is folded
        in, so any committed change to the visible set invalidates cursors
        issued against the previous snapshot -- exactly the audit ledger's
        cursor rule.
        """
        digest = hashlib.sha256()
        for record in records:
            digest.update(record.key_id.encode("utf-8"))
            digest.update(b":")
            digest.update(record.created_at.encode("utf-8"))
            digest.update(b":")
            digest.update(str(record.current_version).encode("ascii"))
            digest.update(b":")
            digest.update(record.current.algorithm.encode("utf-8"))
            digest.update(b":")
            digest.update(record.status.encode("utf-8"))
            digest.update(b":")
            digest.update(record.label.encode("utf-8"))
            digest.update(b":")
            digest.update(
                (record.current.public_key or "").encode("utf-8")
            )
            digest.update(b"\n")
        digest.update(b"count=%d" % len(records))
        return digest.hexdigest()

    def list_page(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        algorithm: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> KeyListPage:
        """Return one tenant-isolated, filter-bound, snapshot-bound page.

        Items are the committed projection of the tenant's keys, ordered by
        (created_at, key_id) ascending; ``created_at`` is the first
        version's timestamp while every other projected field (and the
        status/algorithm filters) reads the committed current snapshot.
        Cursors follow the audit ledger's rules: HMAC-signed and bound to
        the tenant, the filters, the limit and the visible snapshot, so a
        tampered, cross-tenant, filter-mismatched or stale cursor raises
        InvalidCursor and a concurrent change can never cause a duplicate
        or a gap within an already-issued page chain.
        """
        anchor = None
        fingerprint = None
        if cursor is not None:
            payload = self.audit._decode_cursor(cursor)
            try:
                if payload.get("t") != tenant_id:
                    raise InvalidCursor("cursor does not match tenant_id")
                if payload.get("s") != status or payload.get("a") != algorithm:
                    raise InvalidCursor("cursor does not match filters")
                if int(payload.get("l", -1)) != limit:
                    raise InvalidCursor("cursor does not match limit")
                anchor = (payload["ts"], payload["kid"])
                fingerprint = payload["f"]
            except (KeyError, TypeError, ValueError) as exc:
                raise InvalidCursor("malformed cursor") from exc

        visible = [
            record
            for record in self._list_committed(tenant_id)
            if (status is None or record.status == status)
            and (algorithm is None or record.current.algorithm == algorithm)
        ]
        visible.sort(key=lambda r: (r.created_at, r.key_id))
        # The snapshot is scoped to exactly the records this tenant and
        # these filters can see: another tenant's activity must not
        # invalidate the cursor, while any change to the visible set does.
        current_fingerprint = self._list_fingerprint(visible)
        if fingerprint is not None and fingerprint != current_fingerprint:
            raise InvalidCursor("cursor snapshot is no longer valid")

        selected = visible
        if anchor is not None:
            selected = [
                r for r in selected if (r.created_at, r.key_id) > anchor
            ]

        page = selected[:limit]
        if len(selected) > limit and page:
            last = page[-1]
            next_cursor = self.audit._encode_cursor(
                {
                    "v": 1,
                    "t": tenant_id,
                    "s": status,
                    "a": algorithm,
                    "l": limit,
                    "ts": last.created_at,
                    "kid": last.key_id,
                    "f": current_fingerprint,
                }
            )
        else:
            next_cursor = None
        return KeyListPage(records=page, next_cursor=next_cursor)

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
        self, tenant_id: str, entry: dict, journal: Optional[str] = None,
        mirror=None,
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
                    ver, journal, mirror
                )
                versions.append(version_record)
                adopted.append((target, version_record.handle))
        except BaseException:
            # A later version failed a provider match or validation; release
            # every handle this record minted for its earlier versions. A
            # failed delete is a provider fault (503): never swallowed, since
            # the durable journal is what startup retries with.
            if not self._release_handles(adopted):
                raise ProviderUnavailable(
                    "could not delete a handle provisioned while restoring"
                )
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
    def _key_locks_deadline(self, key_id: str, deadline) -> Iterator[None]:
        """Take the in-process and fcntl locks against one shared deadline."""
        with self._timed_inproc(key_id, deadline), self._file_lock(
            key_id, deadline
        ):
            yield

    @contextmanager
    def key_locks(self, key_id: str, timeout: Optional[float] = None) -> Iterator[None]:
        """Acquire the in-process and cross-process locks for one key_id.

        With a finite ``timeout`` both locks share one deadline and a wait
        beyond it raises :class:`LockTimeout` with nothing held.
        """
        if timeout is None:
            with self._key_lock(key_id), self._file_lock(key_id):
                yield
        else:
            with self._key_locks_deadline(
                key_id, time.monotonic() + timeout
            ):
                yield

    @contextmanager
    def multi_key_locks(
        self, key_ids, timeout: Optional[float] = None
    ) -> Iterator[None]:
        """Acquire the per-key locks for many key_ids, in sorted order.

        A fixed acquisition order keeps this deadlock-free against the
        restore transaction, which also takes its key locks sorted. With a
        finite ``timeout`` the whole acquisition shares one deadline.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        acquired = []
        try:
            for key_id in sorted(set(key_ids)):
                if deadline is None:
                    lock_cm = self.key_locks(key_id)
                else:
                    lock_cm = self._key_locks_deadline(key_id, deadline)
                lock_cm.__enter__()
                acquired.append(lock_cm)
            yield
        finally:
            for lock_cm in reversed(acquired):
                lock_cm.__exit__(None, None, None)

