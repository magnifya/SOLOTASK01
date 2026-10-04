"""Per-tenant action policies: validation, persistence and enforcement.

A policy document is a list of rules; each rule binds a ``subject`` (the
X-Operator-Id of the caller), a set of ``actions``, an ``effect`` of
``allow`` or ``deny`` and, optionally, a set of ``key_ids`` scoping the rule
to specific keys. Enforcement, for one (tenant, subject, action[, key_id]):

* a tenant with no document is unrestricted (every action is allowed);
* a request without a target key context matches only rules that omit
  ``key_ids``; with a target key it matches unscoped rules plus rules whose
  ``key_ids`` contain it;
* among the matching rules whose subject equals the caller and whose actions
  contain the action, any ``deny`` wins over ``allow``;
* if no matching rule exists the action is denied (default deny).

Documents are stored as one JSON file per tenant, written through the same
outbox transaction as key records: the file first lands carrying the audit
event, the ledger append follows, then the marker is cleared; a crash in
between is repaired idempotently on the next open.
"""

import hashlib
import json
import os
import re
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
    "revoke_version",
    "import",
    "export",
    "migrate",
    "encrypt",
    "decrypt",
    "rewrap",
    "wrap_key",
    "unwrap_key",
    "sign",
    "verify",
    "audit",
    "list",
)
EFFECTS = ("allow", "deny")
_POLICY_DIR = "policies"
#: Query value that asserts the tenant currently has no policy document.
EXPECTED_NONE = "none"
#: Opaque revisions are SHA-256 hex digests of the normalized rule content;
#: that shape can never collide with the ``none`` keyword.
REVISION_RE = re.compile(r"^[0-9a-f]{64}$")
#: A scoped key_id shares the canonical lowercase UUID4 shape of a key id.
KEY_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

#: Fixed validation text for a malformed rule key_ids and for a malformed
#: check key_id (part of the HTTP/CLI contract, do not reword).
KEY_IDS_ERROR = (
    "field rules[i].key_ids must be a non-empty array of UUID4 strings "
    "without duplicates"
)
CHECK_KEY_ID_ERROR = "field key_id must be a UUID4 or null"


def is_policy_key_id(value) -> bool:
    """True only for a canonical lowercase UUID4 string."""
    return isinstance(value, str) and bool(KEY_ID_RE.fullmatch(value))


class PolicyError(ValueError):
    """A policy document or rule failed validation (surfaced as 400)."""


class PolicyRevisionConflict(Exception):
    """An expected_revision precondition did not match (surfaced as 409)."""

    def __init__(self, current_revision: Optional[str]) -> None:
        self.current_revision = current_revision
        super().__init__("policy revision conflict")


class PolicyStoreUnavailable(Exception):
    """An existing policy document cannot be read or parsed (fixed 500)."""


#: Check outcomes, stable reason tokens surfaced by POST /v1/policy/check.
REASON_NO_POLICY = "no_policy"
REASON_EXPLICIT_ALLOW = "explicit_allow"
REASON_EXPLICIT_DENY = "explicit_deny"
REASON_DEFAULT_DENY = "default_deny"


def evaluate_rules(rules, subject: str, action: str,
                   key_id: Optional[str] = None) -> dict:
    """Evaluate one (subject, action[, key_id]) against a non-None rule list.

    Subject and action are matched first; the rules kept are then the ones
    that apply to the request target. A request without a key context
    (``key_id is None``) matches only rules that omit ``key_ids``; a request
    with a target key matches unscoped rules plus rules scoped to that key.
    Matching keeps the document's original order. Any matching ``deny``
    wins; with no deny, at least one matching allow permits; otherwise the
    action is denied by default. Returns the matched rules and the reason
    token for the decision.
    """
    matched = [
        rule
        for rule in rules
        if rule.subject == subject
        and action in rule.actions
        and (
            rule.key_ids is None
            or (key_id is not None and key_id in rule.key_ids)
        )
    ]
    if any(rule.effect == "deny" for rule in matched):
        allowed = False
        reason = REASON_EXPLICIT_DENY
    elif matched:
        allowed = True
        reason = REASON_EXPLICIT_ALLOW
    else:
        allowed = False
        reason = REASON_DEFAULT_DENY
    return {
        "allowed": allowed,
        "effect": "allow" if allowed else "deny",
        "reason": reason,
        "rules": matched,
    }


def revision_for_rules(rules) -> str:
    """Compute the opaque, content-addressed revision of a rule list.

    Rules are normalized first (actions and key_ids sorted, rules ordered
    by subject/effect/actions/key_ids), so the same logical document always
    yields the same revision and any change yields a different one. The
    ``key_ids`` slot is emitted only for scoped rules, so a document made
    solely of rules that omit ``key_ids`` hashes exactly as before. Nothing
    about the on-disk layout is reflected in the value.
    """
    normalized = []
    for rule in rules:
        item = {
            "subject": rule.subject,
            "effect": rule.effect,
            "actions": sorted(rule.actions),
        }
        if rule.key_ids is not None:
            item["key_ids"] = sorted(rule.key_ids)
        normalized.append(item)
    normalized.sort(
        key=lambda item: (
            item["subject"],
            item["effect"],
            item["actions"],
            item.get("key_ids") or [],
        )
    )
    blob = json.dumps(
        normalized, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def validate_expected_revision(raw) -> str:
    """Validate an expected_revision precondition value (``none`` or digest)."""
    if not isinstance(raw, str) or (
        raw != EXPECTED_NONE and not REVISION_RE.fullmatch(raw)
    ):
        raise PolicyError(
            "field expected_revision must be a revision from a prior read "
            "or 'none'"
        )
    return raw


@dataclass(frozen=True)
class Rule:
    """One policy rule: an effect on a set of actions for one subject.

    ``key_ids`` is None when the rule is unscoped (applies to every key);
    otherwise it is a frozenset of canonical UUID4 strings naming the keys
    the rule applies to.
    """

    subject: str
    actions: List[str]
    effect: str
    key_ids: Optional[frozenset] = None

    def to_json(self) -> dict:
        """Serialize to a plain dict; actions and key_ids are emitted sorted.

        The ``key_ids`` slot is omitted entirely for unscoped rules, so old
        documents, old backups and old clients keep their exact shape.
        """
        data = {
            "subject": self.subject,
            "actions": list(self.actions),
            "effect": self.effect,
        }
        if self.key_ids is not None:
            data["key_ids"] = sorted(self.key_ids)
        return data

    @classmethod
    def from_json(cls, data: dict) -> "Rule":
        # Documents on disk were validated when written, but validate again
        # on the way in so a hand-edited file can never break enforcement.
        return validate_rule(data)

    def signature(self):
        """Dedup key: same subject/effect/action set/key set.

        The key set is part of the key: an unscoped allow and an allow
        scoped to one key are different rules, as are two rules scoped to
        different key sets.
        """
        return (
            self.subject,
            self.effect,
            frozenset(self.actions),
            self.key_ids,
        )


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
    known = {"subject", "actions", "effect", "key_ids"}
    unknown = set(raw) - known
    if unknown:
        raise err(
            "unknown field %s%s"
            % (where, sorted(unknown)[0])
        )
    # key_ids is optional; its fixed error text is part of the API contract
    # and always names the literal rules[i] slot, for every rule index.
    key_ids = None
    if "key_ids" in raw:
        raw_key_ids = raw["key_ids"]
        if (
            not isinstance(raw_key_ids, list)
            or not raw_key_ids
            or not all(is_policy_key_id(v) for v in raw_key_ids)
            or len(set(raw_key_ids)) != len(raw_key_ids)
        ):
            raise PolicyError(KEY_IDS_ERROR)
        key_ids = frozenset(raw_key_ids)
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
    return Rule(
        subject=subject, actions=clean_actions, effect=effect,
        key_ids=key_ids,
    )


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

    def get_revision(self, tenant_id: str) -> Optional[str]:
        """Return the tenant's current revision, or None when no document."""
        rules = self.get(tenant_id)
        if rules is None:
            return None
        return revision_for_rules(rules)

    def get_strict(self, tenant_id: str) -> Optional[List[Rule]]:
        """Read rules for a policy check: None only when no file exists.

        Unlike :meth:`get`, a document that exists but cannot be read or
        parsed is backend corruption: :class:`PolicyStoreUnavailable` is
        raised so the caller answers a fixed 500 instead of treating the
        tenant as unrestricted.
        """
        path = self._path_for(tenant_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise PolicyStoreUnavailable(
                "cannot read policy document"
            ) from exc
        try:
            return [Rule.from_json(rule) for rule in data["rules"]]
        except (KeyError, TypeError, ValueError, PolicyError) as exc:
            raise PolicyStoreUnavailable(
                "cannot parse policy document"
            ) from exc

    def check(
        self, tenant_id: str, subject: str, action: str,
        key_id: Optional[str] = None,
    ) -> dict:
        """Evaluate one (subject, action[, key_id]) without any side effect.

        No document allows the action (``no_policy``); otherwise the rules
        decide. ``key_id`` None evaluates the key-less context (only
        unscoped rules match). Never writes an audit event, a revision or
        any file.
        """
        rules = self.get_strict(tenant_id)
        if rules is None:
            return {
                "allowed": True,
                "effect": "allow",
                "reason": REASON_NO_POLICY,
                "rules": [],
            }
        return evaluate_rules(rules, subject, action, key_id)

    def _current_state(self, path: str):
        """Return (rules, revision) for an existing document under the lock."""
        doc = self._read_doc(path)
        if doc is None:
            # A document we cannot parse cannot supply a current revision;
            # take the same fixed-500 path as an unreadable put/delete. The
            # original file is never overwritten, and no success or rejection
            # event is written.
            raise PolicyStoreUnavailable("cannot read policy document")
        rules = doc[1]
        return rules, revision_for_rules(rules)

    def _check_expected(
        self, tenant_id: str, action: str,
        expected: Optional[str], current_revision: Optional[str],
        operator_id: Optional[str] = None,
    ) -> bool:
        """Compare a precondition inside the tenant lock.

        A mismatch appends one ``<action>/rejected`` event and returns False;
        the document is never touched. ``expected=None`` always matches.
        """
        if expected is None:
            return True
        wanted = None if expected == EXPECTED_NONE else expected
        if wanted == current_revision:
            return True
        event = self.audit.new_event(
            tenant_id, action, None, audit_mod.OUTCOME_REJECTED,
            operator_id=operator_id,
        )
        self.audit.append(event)
        return False

    def put(
        self, tenant_id: str, rules: List[Rule],
        expected_revision: Optional[str] = None,
        operator_id: Optional[str] = None,
    ) -> tuple:
        """Replace (or create) the tenant's document and audit policy_update.

        ``expected_revision`` optionally preconditions the write: ``None`` is
        unconditional, ``'none'`` requires no existing document and any other
        value must equal the current revision. The compare and the write run
        under one tenant lock; a mismatch raises
        :class:`PolicyRevisionConflict` after recording one rejected event.
        Returns ``(rules, new_revision)``.
        """
        with self.tenant_lock(tenant_id):
            path = self._path_for(tenant_id)
            existed = os.path.exists(path)
            current_revision = None
            if existed:
                _, current_revision = self._current_state(path)
            if not self._check_expected(
                tenant_id, audit_mod.ACTION_POLICY_UPDATE,
                expected_revision, current_revision,
                operator_id=operator_id,
            ):
                raise PolicyRevisionConflict(current_revision)
            previous = None
            if existed:
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        previous = json.load(fh)
                except (OSError, ValueError) as exc:
                    raise PolicyStoreUnavailable(
                        "cannot read policy document: %s" % exc
                    ) from exc
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_UPDATE, None,
                audit_mod.OUTCOME_SUCCESS, operator_id=operator_id,
            )
            self._commit_put(tenant_id, rules, event, existed, previous)
        return rules, revision_for_rules(rules)

    def delete(
        self, tenant_id: str,
        expected_revision: Optional[str] = None,
        operator_id: Optional[str] = None,
    ) -> None:
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
            current_revision = None
            if existed:
                _, current_revision = self._current_state(path)
            if not self._check_expected(
                tenant_id, audit_mod.ACTION_POLICY_DELETE,
                expected_revision, current_revision,
                operator_id=operator_id,
            ):
                raise PolicyRevisionConflict(current_revision)
            event = self.audit.new_event(
                tenant_id, audit_mod.ACTION_POLICY_DELETE, None,
                audit_mod.OUTCOME_SUCCESS, operator_id=operator_id,
            )
            if not existed:
                self.audit.append(event)
                return
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    previous = json.load(fh)
            except (OSError, ValueError) as exc:
                raise PolicyStoreUnavailable(
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

    def audit_read(
        self, tenant_id: str, operator_id: Optional[str] = None
    ) -> None:
        """Record a successful policy_read (the document is never modified)."""
        event = self.audit.new_event(
            tenant_id, audit_mod.ACTION_POLICY_READ, None,
            audit_mod.OUTCOME_SUCCESS, operator_id=operator_id,
        )
        self.audit.append(event)

    def is_allowed(
        self, tenant_id: str, action: str, subject: str,
        key_id: Optional[str] = None,
    ) -> bool:
        """Enforce the tenant document for (subject, action[, key_id]).

        No document means unrestricted. A key-less request (``key_id``
        None) is governed only by unscoped rules; a request naming a target
        key is governed by unscoped rules and rules scoped to that key.
        Otherwise deny wins, and an action no rule matches is denied. An
        existing document that cannot be read or parsed is backend
        corruption: PolicyStoreUnavailable is raised so the caller answers
        a fixed 500 instead of allowing the request through.
        """
        rules = self.get_strict(tenant_id)
        if rules is None:
            return True
        allowed = False
        for rule in rules:
            if rule.subject != subject or action not in rule.actions:
                continue
            if rule.key_ids is not None and (
                key_id is None or key_id not in rule.key_ids
            ):
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
