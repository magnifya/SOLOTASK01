"""Per-tenant action policies.

A policy document belongs to one tenant and holds an unordered list of rules.
Each rule binds a subject (the X-Operator-Id of the caller, matched
case-sensitively) to a set of key actions and an effect.

Enforcement: a tenant without a stored policy is unrestricted. Once a policy
exists, a request is allowed only when some matching rule says ``allow`` and no
matching rule says ``deny`` (deny wins); anything unmatched is rejected. An
empty rule list therefore rejects every action.
"""

import hashlib
import json
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, List, Optional

from . import audit as audit_mod
from .audit import AuditEvent, AuditLog, LedgerError

try:  # fcntl is POSIX-only; writes still work without cross-process locks.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Actions a policy rule may govern. The policy management endpoints themselves
# (policy_read/policy_update/policy_delete) are intentionally excluded: policy
# administration is exempt from enforcement.
POLICY_ACTIONS = (
    audit_mod.ACTION_CREATE,
    audit_mod.ACTION_READ,
    audit_mod.ACTION_ROTATE,
    audit_mod.ACTION_REVOKE,
    audit_mod.ACTION_IMPORT,
    audit_mod.ACTION_EXPORT,
    audit_mod.ACTION_AUDIT,
)

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
EFFECTS = (EFFECT_ALLOW, EFFECT_DENY)

_FILE_RE = re.compile(r"^policy-([0-9a-f]{64})\.json$")


class InvalidPolicy(ValueError):
    """A policy document failed validation (always surfaced as 400/exit 2)."""


@dataclass
class PolicyRule:
    """One rule: subject + action set + effect."""

    subject: str
    actions: List[str] = field(default_factory=list)
    effect: str = EFFECT_ALLOW

    def to_json(self) -> dict:
        """Serialize to a plain dict suitable for JSON storage."""
        return {
            "subject": self.subject,
            "actions": list(self.actions),
            "effect": self.effect,
        }

    @classmethod
    def from_json(cls, data: dict) -> "PolicyRule":
        return cls(
            subject=data["subject"],
            actions=list(data["actions"]),
            effect=data["effect"],
        )


@dataclass
class PolicyRecord:
    """A tenant's stored policy document."""

    tenant_id: str
    rules: List[PolicyRule] = field(default_factory=list)
    # Outbox markers mirroring KeyRecord: an event pending in the ledger, and
    # for a delete the intention to remove the file once the event is durable.
    pending_event: Optional[dict] = None
    pending_delete: bool = False

    def to_json(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "rules": [rule.to_json() for rule in self.rules],
            "pending_event": self.pending_event,
            "pending_delete": self.pending_delete,
        }

    @classmethod
    def from_json(cls, data: dict) -> "PolicyRecord":
        return cls(
            tenant_id=data["tenant_id"],
            rules=[PolicyRule.from_json(rule) for rule in data.get("rules", [])],
            pending_event=data.get("pending_event"),
            pending_delete=bool(data.get("pending_delete")),
        )

    def to_response(self) -> dict:
        """Body of GET/PUT /v1/policy: {tenant_id, rules}."""
        return {
            "tenant_id": self.tenant_id,
            "rules": [rule.to_json() for rule in self.rules],
        }


def validate_rules(raw) -> List[PolicyRule]:
    """Validate a rules array from a request body; return clean rules.

    Each item needs a non-empty case-sensitive ``subject`` string, a non-empty
    ``actions`` array drawn from POLICY_ACTIONS (duplicate actions collapse),
    and an ``effect`` of allow/deny. Two rules with the same subject, effect
    and action set (order ignored) are rejected as duplicates. Raises
    InvalidPolicy naming the offending field on any problem.
    """
    if not isinstance(raw, list):
        raise InvalidPolicy("field rules must be an array")
    seen = set()
    rules: List[PolicyRule] = []
    for index, item in enumerate(raw):
        where = "rules[%d]" % index
        if not isinstance(item, dict):
            raise InvalidPolicy("field %s must be an object" % where)
        subject = item.get("subject")
        if not isinstance(subject, str) or not subject:
            raise InvalidPolicy(
                "field %s.subject must be a non-empty string" % where
            )
        actions = item.get("actions")
        if not isinstance(actions, list) or not actions:
            raise InvalidPolicy(
                "field %s.actions must be a non-empty array" % where
            )
        clean_actions: List[str] = []
        for action in actions:
            if not isinstance(action, str) or not action:
                raise InvalidPolicy(
                    "field %s.actions must contain only non-empty strings"
                    % where
                )
            if action not in POLICY_ACTIONS:
                raise InvalidPolicy(
                    "field %s.actions has unsupported action %r (allowed: %s)"
                    % (where, action, ", ".join(POLICY_ACTIONS))
                )
            if action not in clean_actions:
                # Repeated actions within one rule collapse (去重); duplicate
                # *rules* are still compared on the deduplicated set.
                clean_actions.append(action)
        effect = item.get("effect")
        if effect not in EFFECTS:
            raise InvalidPolicy(
                "field %s.effect must be one of: %s"
                % (where, ", ".join(EFFECTS))
            )
        fingerprint = (subject, effect, frozenset(clean_actions))
        if fingerprint in seen:
            raise InvalidPolicy(
                "field %s duplicates an earlier rule with the same subject, "
                "effect and actions" % where
            )
        seen.add(fingerprint)
        rules.append(PolicyRule(subject, clean_actions, effect))
    return rules


class PolicyStore:
    """File-backed policy documents, one file per tenant.

    Document file names are derived from a SHA-256 of the tenant id, so an
    arbitrary tenant string can never traverse the data directory. Mutations
    and their audit events commit through the same outbox transaction as key
    mutations: the file lands carrying a pending event, the ledger is appended
    durably, and the marker is cleared; a crash is repaired on open.
    """

    def __init__(self, data_dir: str, audit_log: Optional[AuditLog] = None) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._locks_lock = threading.Lock()
        self._locks: dict = {}
        self.audit = audit_log if audit_log is not None else AuditLog(data_dir)
        self._recover_pending_events()

    # -- paths / locking ---------------------------------------------------
    def _digest(self, tenant_id: str) -> str:
        return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()

    def _path_for(self, tenant_id: str) -> str:
        return os.path.join(self.data_dir, "policy-%s.json" % self._digest(tenant_id))

    def _lock_path_for(self, tenant_id: str) -> str:
        return os.path.join(self.data_dir, "policy-%s.lock" % self._digest(tenant_id))

    def _tenant_lock(self, tenant_id: str) -> threading.Lock:
        with self._locks_lock:
            lock = self._locks.get(tenant_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[tenant_id] = lock
            return lock

    @contextmanager
    def _file_lock(self, tenant_id: str) -> Iterator[None]:
        """Cross-process advisory lock guarding one tenant's document."""
        lock_path = self._lock_path_for(tenant_id)
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
        """Write JSON to path atomically, with owner-only permissions."""
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

    def _read(self, path: str) -> Optional[PolicyRecord]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            return PolicyRecord.from_json(data)
        except (KeyError, TypeError, ValueError):
            return None

    # -- outbox ------------------------------------------------------------
    def _recover_pending_events(self) -> None:
        """Commit or finish documents interrupted by a crashed process."""
        try:
            names = os.listdir(self.data_dir)
        except OSError:
            return
        for name in names:
            match = _FILE_RE.match(name)
            if match is None:
                continue
            tenant_hash = match.group(1)
            path = os.path.join(self.data_dir, name)
            with self._tenant_lock(tenant_hash), self._file_lock(tenant_hash):
                record = self._read(path)
                if record is None or not record.pending_event:
                    continue
                # append() is idempotent on event_id.
                event = AuditEvent.from_json(record.pending_event)
                self.audit.append(event)
                if record.pending_delete:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                else:
                    record.pending_event = None
                    self._write_atomic(path, record.to_json())

    # -- reads -------------------------------------------------------------
    def get(self, tenant_id: str) -> Optional[PolicyRecord]:
        """Return the tenant's policy, or None when none is stored."""
        return self._read(self._path_for(tenant_id))

    def allowed(self, tenant_id: str, operator: str, action: str) -> bool:
        """Enforcement decision; a missing policy allows everything.

        Matching rules are those whose subject equals the operator
        case-sensitively and whose action set contains the action. Deny wins
        over allow; with no match the action is rejected, so a stored policy
        with an empty rule list rejects all actions.
        """
        record = self.get(tenant_id)
        if record is None:
            return True
        allow = False
        for rule in record.rules:
            if rule.subject == operator and action in rule.actions:
                if rule.effect == EFFECT_DENY:
                    return False
                allow = True
        return allow

    # -- mutations ---------------------------------------------------------
    def set(
        self, tenant_id: str, rules: List[PolicyRule], operator: str
    ) -> PolicyRecord:
        """Create or replace a tenant's policy, committed with its event.

        operator is recorded for the request audit trail at the HTTP/CLI
        layer; the ledger event itself carries the standard event fields.
        """
        del operator  # subjects live inside the rules; kept for call-site clarity
        path = self._path_for(tenant_id)
        with self._tenant_lock(tenant_id), self._file_lock(tenant_id):
            existing = self._read(path)
            previous = existing.to_json() if existing is not None else None
            record = PolicyRecord(tenant_id=tenant_id, rules=list(rules))
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_UPDATE, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            record.pending_event = event.to_json()
            self._write_atomic(path, record.to_json())
            try:
                self.audit.append(event)
            except BaseException:
                if previous is None:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                else:
                    self._write_atomic(path, previous)
                raise
            record.pending_event = None
            self._write_atomic(path, record.to_json())
        return record

    def delete(self, tenant_id: str, operator: str) -> bool:
        """Delete a tenant's policy; False when none exists.

        The delete event is appended while a tombstone marker is on disk; the
        file is removed only after the event is durable. A ledger failure
        restores the unmarked file; a crash resumes the removal on next open.
        """
        del operator
        path = self._path_for(tenant_id)
        with self._tenant_lock(tenant_id), self._file_lock(tenant_id):
            record = self._read(path)
            if record is None:
                return False
            previous = record.to_json()
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_DELETE, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            record.pending_event = event.to_json()
            record.pending_delete = True
            self._write_atomic(path, record.to_json())
            try:
                self.audit.append(event)
            except BaseException:
                self._write_atomic(path, previous)
                raise
            try:
                os.unlink(path)
            except OSError as exc:
                raise LedgerError("cannot remove policy file: %s" % exc) from exc
        return True
