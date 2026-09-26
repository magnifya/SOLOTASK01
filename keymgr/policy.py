"""Per-tenant action policies: validation, persistence and enforcement.

A policy document is a list of rules; each rule binds a ``subject`` (the
X-Operator-Id of the caller), a set of ``actions`` and an ``effect`` of
``allow`` or ``deny``. Enforcement, for one (tenant, subject, action):

* a tenant with no document is unrestricted (every action is allowed);
* among the rules whose subject equals the caller and whose actions contain
  the action, any ``deny`` wins over ``allow``;
* if no matching rule exists the action is denied (default deny).

Documents are stored as one JSON file per tenant, written through the same
outbox transaction as key records: the file first lands carrying the audit
event, the ledger append follows, then the marker is cleared; a crash in
between is repaired idempotently on the next open.
"""

import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, Optional

from . import audit as audit_mod
from .audit import AuditEvent, AuditLog, LedgerError

try:  # fcntl is POSIX-only; policy writes still work without it.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

# Actions a policy rule can govern. These are the same action names the audit
# ledger uses (the management actions policy_* are deliberately not governable).
POLICY_ACTIONS = (
    "create",
    "read",
    "rotate",
    "revoke",
    "import",
    "export",
    "migrate",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "audit",
    "list",
)
EFFECTS = ("allow", "deny")
_POLICY_DIR = "policies"


class PolicyError(ValueError):
    """A policy document or rule failed validation (surfaced as 400)."""


@dataclass(frozen=True)
class Rule:
    """One policy rule: an effect on a set of actions for one subject."""

    subject: str
    actions: List[str]
    effect: str

    def to_json(self) -> dict:
        """Serialize to a plain dict; actions are emitted sorted."""
        return {
            "subject": self.subject,
            "actions": list(self.actions),
            "effect": self.effect,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Rule":
        # Documents on disk were validated when written, but validate again
        # on the way in so a hand-edited file can never break enforcement.
        return validate_rule(data)

    def signature(self):
        """Dedup key: same subject/effect with the same unordered action set."""
        return self.subject, self.effect, frozenset(self.actions)


def validate_rule(raw, index: Optional[int] = None) -> Rule:
    """Validate one rule object; raise PolicyError naming the bad field.

    ``index`` prefixes field names with ``rules[i].`` when the rule comes from
    a document; a standalone rule names the bare fields.
    """
    where = "rules[%d]." % index if index is not None else ""

    def err(message: str) -> PolicyError:
        return PolicyError(message)

    if not isinstance(raw, dict):
        raise err("field %s must be an object" % (where.rstrip(".") if index is not None else "rule"))
    known = {"subject", "actions", "effect"}
    unknown = set(raw) - known
    if unknown:
        raise err(
            "unknown field %s%s"
            % (where, sorted(unknown)[0])
        )
    subject = raw.get("subject")
    if not isinstance(subject, str) or not subject:
        raise err("field %ssubject must be a non-empty string" % where)
    effect = raw.get("effect")
    if not isinstance(effect, str) or effect not in EFFECTS:
        raise err(
            "field %seffect must be one of: %s"
            % (where, ", ".join(EFFECTS))
        )
    actions = raw.get("actions")
    if not isinstance(actions, list) or not actions:
        raise err(
            "field %sactions must be a non-empty array" % where
        )
    clean_actions = []
    for action in actions:
        if not isinstance(action, str) or not action:
            raise err(
                "field %sactions must be non-empty strings" % where
            )
        if action not in POLICY_ACTIONS:
            raise err(
                "field %sactions has unknown action %r (allowed: %s)"
                % (where, action, ", ".join(POLICY_ACTIONS))
            )
        if action not in clean_actions:
            # Duplicates within one rule are dropped, not an error: the action
            # set is unordered, so ["read", "read"] carries no extra meaning.
            clean_actions.append(action)
    return Rule(subject=subject, actions=clean_actions, effect=effect)


def validate_rules(raw) -> List[Rule]:
    """Validate a full rules array; [] is valid and means default-deny."""
    if not isinstance(raw, list):
        raise PolicyError("field rules must be an array")
    rules: List[Rule] = []
    seen = set()
    for index, item in enumerate(raw):
        rule = validate_rule(item, index)
        if rule.signature() in seen:
            raise PolicyError(
                "field rules contains a duplicate rule at index %d "
                "(same subject, effect and unordered actions)" % index
            )
        seen.add(rule.signature())
        rules.append(rule)
    return rules


class PolicyStore:
    """File-backed per-tenant policy documents."""

    def __init__(self, data_dir: str, audit_log: Optional[AuditLog] = None) -> None:
        self.data_dir = data_dir
        self.dir_path = os.path.join(data_dir, _POLICY_DIR)
        os.makedirs(self.dir_path, exist_ok=True)
        self.audit = audit_log if audit_log is not None else AuditLog(data_dir)
        self._write_lock = threading.Lock()
        self._recover_pending_events()

    # -- on-disk shape -----------------------------------------------------
    def path_for(self, tenant_id: str) -> str:
        """Public accessor for a tenant's policy document path."""
        return self._path_for(tenant_id)

    def _path_for(self, tenant_id: str) -> str:
        # Tenant ids are free-form strings, so never use them as a filename:
        # key the file by a digest of the tenant instead.
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return os.path.join(self.dir_path, digest + ".json")

    def _lock_path_for(self, tenant_id: str) -> str:
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return os.path.join(self.dir_path, digest + ".lock")

    @contextmanager
    def tenant_lock(
        self, tenant_id: str, timeout: Optional[float] = None
    ) -> Iterator[None]:
        """Serialize all writes to one tenant's policy across processes.

        Pairs the in-process write lock with an exclusive ``fcntl`` lock on a
        per-tenant sidecar file, so a put/delete/restore/backup in another
        process cannot interleave with this one's read-modify-write. With a
        finite ``timeout`` (idempotent restore) the wait is bounded and raises
        :class:`~keymgr.store.LockTimeout` when it elapses.
        """
        import time as _time

        from .store import LockTimeout

        deadline = None if timeout is None else _time.monotonic() + timeout
        if timeout is None:
            self._write_lock.acquire()
        else:
            if not self._write_lock.acquire(timeout=max(timeout, 0.0)):
                raise LockTimeout("policy:" + tenant_id)
        if fcntl is None:  # pragma: no cover - non-POSIX platforms
            try:
                yield
            finally:
                self._write_lock.release()
            return
        fd = os.open(
            self._lock_path_for(tenant_id), os.O_RDWR | os.O_CREAT, 0o600
        )
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
                        remaining = deadline - _time.monotonic()
                        if remaining <= 0:
                            raise LockTimeout("policy:" + tenant_id)
                        _time.sleep(min(0.02, remaining))
            acquired = True
            yield
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            self._write_lock.release()

    def _write_atomic(self, path: str, payload: dict) -> None:
        fd, tmp_path = tempfile.mkstemp(dir=self.dir_path, suffix=".tmp")
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

    def _read_doc(self, path: str):
        """Return (tenant_id, rules, pending_event), or None if unreadable."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        try:
            rules = [Rule.from_json(r) for r in data["rules"]]
            return data["tenant_id"], rules, data.get("pending_event")
        except (KeyError, TypeError, ValueError, PolicyError):
            return None

    def _recover_pending_events(self) -> None:
        """Commit outbox events left pending by a crashed process."""
        try:
            names = os.listdir(self.dir_path)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json") and not name.endswith(".json.del"):
                continue
            path = os.path.join(self.dir_path, name)
            doc = self._read_doc(path)
            if doc is None:
                continue
            tenant_id, rules, pending_event = doc
            if not pending_event:
                # A tombstone left behind after a successful ledger append:
                # finish the delete.
                if name.endswith(".del"):
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                continue
            # A multi-file tenant restore transaction is resolved by the
            # RestoreCoordinator (its manifest drives the shared event).
            if isinstance(pending_event, dict) and pending_event.get("_restore"):
                continue
            event = AuditEvent.from_json(pending_event)
            if name.endswith(".json.del"):                # A delete tombstone. If the original file is still on disk the
                # crash happened before the unlink, so the delete never
                # happened: discard the tombstone without appending. Otherwise
                # finish the transaction (append is idempotent on event_id).
                original = path[: -len(".del")]
                if os.path.exists(original):
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    continue
                self.audit.append(event)
                try:
                    os.unlink(path)
                except OSError:
                    pass
            else:
                # append() is idempotent on event_id.
                self.audit.append(event)
                self._write_atomic(
                    path,
                    {"tenant_id": tenant_id,
                     "rules": [r.to_json() for r in rules],
                     "pending_event": None},
                )

    def _commit_put(self, tenant_id: str, rules: List[Rule],
                    event: AuditEvent, existed: bool, previous: Optional[dict]):
        """Write a document and its event as one logical transaction."""
        path = self._path_for(tenant_id)
        doc = {
            "tenant_id": tenant_id,
            "rules": [r.to_json() for r in rules],
            "pending_event": event.to_json(),
        }
        self._write_atomic(path, doc)
        try:
            self.audit.append(event)
        except BaseException:
            if not existed:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            elif previous is not None:
                self._write_atomic(path, previous)
            raise
        # The durable ledger append is the commit point; clearing the marker
        # is post-commit housekeeping. A failure here leaves the marker for
        # startup recovery and must never roll the document back or fail the
        # request.
        doc["pending_event"] = None
        try:
            self._write_atomic(path, doc)
        except OSError:
            pass

    # -- public API --------------------------------------------------------
    def get(self, tenant_id: str) -> Optional[List[Rule]]:
        """Return the tenant's rules, or None when no document exists."""
        doc = self._read_doc(self._path_for(tenant_id))
        if doc is None:
            return None
        return doc[1]

    def put(self, tenant_id: str, rules: List[Rule]) -> List[Rule]:
        """Replace (or create) the tenant's document and audit policy_update."""
        with self.tenant_lock(tenant_id):
            path = self._path_for(tenant_id)
            existed = os.path.exists(path)
            previous = None
            if existed:
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        previous = json.load(fh)
                except (OSError, ValueError) as exc:
                    raise LedgerError(
                        "cannot read policy document: %s" % exc
                    ) from exc
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_UPDATE, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            self._commit_put(tenant_id, rules, event, existed, previous)
        return rules

    def delete(self, tenant_id: str) -> None:
        """Delete the tenant's document and audit policy_delete.

        Tombstone sequence: write a ``.json.del`` marker carrying the event,
        unlink the document, append the event, then remove the marker. A crash
        between any two steps is repaired on the next open. If the ledger
        append itself fails, the original document is restored byte-for-byte
        and the tombstone discarded, so a failed delete never takes effect.
        Deleting a tenant that has no document still records the event.
        """
        with self.tenant_lock(tenant_id):
            path = self._path_for(tenant_id)
            existed = os.path.exists(path)
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_DELETE, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            if not existed:
                self.audit.append(event)
                return
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    previous = json.load(fh)
            except (OSError, ValueError) as exc:
                raise LedgerError(
                    "cannot read policy document: %s" % exc
                ) from exc
            tombstone = path + ".del"
            self._write_atomic(
                tombstone,
                {"tenant_id": tenant_id, "rules": [],
                 "pending_event": event.to_json()},
            )
            os.unlink(path)
            try:
                # From here on a crash is repaired from the tombstone; the
                # append is idempotent on event_id.
                self.audit.append(event)
            except BaseException:
                # The ledger write failed: roll the delete back so the
                # document and its event never diverge.
                self._write_atomic(path, previous)
                try:
                    os.unlink(tombstone)
                except OSError:
                    pass
                raise
            try:
                os.unlink(tombstone)
            except OSError:
                pass

    def audit_read(self, tenant_id: str) -> None:
        """Record a successful policy_read (the document is never modified)."""
        event = self.audit.new_event(
            tenant_id, audit_mod.ACTION_POLICY_READ, None,
            audit_mod.OUTCOME_SUCCESS,
        )
        self.audit.append(event)

    def is_allowed(self, tenant_id: str, action: str, subject: str) -> bool:
        """Enforce the tenant document for (subject, action).

        No document means unrestricted. Otherwise deny wins, and an action no
        rule matches is denied.
        """
        rules = self.get(tenant_id)
        if rules is None:
            return True
        allowed = False
        for rule in rules:
            if rule.subject != subject or action not in rule.actions:
                continue
            if rule.effect == "deny":
                return False
            allowed = True
        return allowed

    # -- tenant restore hooks ---------------------------------------------
    def owner_of_path(self, path: str) -> Optional[str]:
        """Return the owning tenant_id recorded inside a policy file."""
        doc = self._read_doc(path)
        if doc is None:
            return None
        return doc[0]

    def write_restore_pending(
        self, tenant_id: str, rules: List[Rule], marker: dict
    ) -> None:
        """Atomically write a restored policy document carrying the marker.

        Used by the RestoreCoordinator; the caller guarantees no document
        exists for the tenant and holds the write lock.
        """
        self._write_atomic(
            self._path_for(tenant_id),
            {
                "tenant_id": tenant_id,
                "rules": [r.to_json() for r in rules],
                "pending_event": marker,
            },
        )

    def clear_restore_pending(self, tenant_id: str, rules: List[Rule]) -> None:
        """Rewrite a restored policy document without its pending marker."""
        self._write_atomic(
            self._path_for(tenant_id),
            {
                "tenant_id": tenant_id,
                "rules": [r.to_json() for r in rules],
                "pending_event": None,
            },
        )

    def remove_restore_file(self, tenant_id: str) -> None:
        """Delete a policy document written by a restore being rolled back."""
        try:
            os.unlink(self._path_for(tenant_id))
        except FileNotFoundError:
            pass
