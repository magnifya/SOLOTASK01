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
from dataclasses import dataclass
from typing import List, Optional

from . import audit as audit_mod
from .audit import AuditEvent, AuditLog, LedgerError

# Actions a policy rule can govern. These are the same action names the audit
# ledger uses (the management actions policy_* are deliberately not governable).
POLICY_ACTIONS = (
    "create",
    "read",
    "rotate",
    "revoke",
    "import",
    "export",
    "audit",
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
    def _path_for(self, tenant_id: str) -> str:
        # Tenant ids are free-form strings, so never use them as a filename:
        # key the file by a digest of the tenant instead.
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return os.path.join(self.dir_path, digest + ".json")

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
            event = AuditEvent.from_json(pending_event)
            if name.endswith(".json.del"):
                # A delete tombstone. If the original file is still on disk the
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
        doc["pending_event"] = None
        self._write_atomic(path, doc)

    # -- public API --------------------------------------------------------
    def get(self, tenant_id: str) -> Optional[List[Rule]]:
        """Return the tenant's rules, or None when no document exists."""
        doc = self._read_doc(self._path_for(tenant_id))
        if doc is None:
            return None
        return doc[1]

    def put(self, tenant_id: str, rules: List[Rule]) -> List[Rule]:
        """Replace (or create) the tenant's document and audit policy_update."""
        with self._write_lock:
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
        between any two steps is repaired on the next open. Deleting a tenant
        that has no document still records the management event.
        """
        with self._write_lock:
            path = self._path_for(tenant_id)
            existed = os.path.exists(path)
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_DELETE, None,
                audit_mod.OUTCOME_SUCCESS,
            )
            if not existed:
                self.audit.append(event)
                return
            tombstone = path + ".del"
            self._write_atomic(
                tombstone,
                {"tenant_id": tenant_id, "rules": [],
                 "pending_event": event.to_json()},
            )
            os.unlink(path)
            # From here on a crash is repaired from the tombstone; the append
            # is idempotent on event_id.
            self.audit.append(event)
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

    # -- tenant restore primitives ------------------------------------------
    def write_pending_doc(self, tenant_id: str, rules: List[Rule],
                          event: AuditEvent) -> str:
        """Atomically write a new document carrying the pending event.

        Part of the tenant-restore transaction: the caller holds
        ``_write_lock``, has verified no document exists, and will either
        roll back (unlink the returned path) or clear the marker after the
        shared ledger append.
        """
        path = self._path_for(tenant_id)
        self._write_atomic(
            path,
            {"tenant_id": tenant_id,
             "rules": [r.to_json() for r in rules],
             "pending_event": event.to_json()},
        )
        return path

    def clear_pending_doc(self, tenant_id: str, rules: List[Rule]) -> None:
        """Rewrite a restored document without its outbox marker."""
        self._write_atomic(
            self._path_for(tenant_id),
            {"tenant_id": tenant_id,
             "rules": [r.to_json() for r in rules],
             "pending_event": None},
        )

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
