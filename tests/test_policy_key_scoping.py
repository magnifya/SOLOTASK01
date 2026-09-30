"""Resource (key_ids) granularity for tenant policy rules.

A rule keeps subject/actions/effect and gains an optional ``key_ids``:
omitted means the rule applies to every key; when present it must be a
non-empty array of unique UUID4 strings whose order carries no meaning
(including for the revision). Enforcement matches subject/action first and
filters by the request target key_id; deny beats allow; a request with no
key context matches only unscoped rules. These tests cover validation and
the fixed error text, revision anchoring/order-insensitivity, the check
endpoint's optional key_id (HTTP and CLI), end-to-end enforcement on
single-key endpoints and batch rotate (one denied item fails the whole
batch with zero changes), and tenant-backup-v1 round-trip semantics.
"""

import json
import urllib.error
import urllib.request

import pytest

from keymgr import audit as audit_mod
from keymgr import restore as restore_mod
from keymgr import tenantbundle
from keymgr.audit import AuditLog
from keymgr.policy import (
    PolicyError,
    PolicyStore,
    Rule,
    revision_for_rules,
    validate_rules,
)
from keymgr.store import KeyStore
from test_version_history import _build_server, _make_key, _rotate
from test_recovery_cli import run_cli

K1 = "11111111-1111-4111-8111-111111111111"
K2 = "22222222-2222-4222-8222-222222222222"
BAD_KEY_IDS_MSG = (
    "field rules[0].key_ids must be a non-empty array of UUID4 strings "
    "without duplicates"
)
BAD_KEY_ID_MSG = "field key_id must be a UUID4 or null"


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


# -- validation -------------------------------------------------------------

def test_key_ids_validation_accepts_and_rejects():
    # A unique UUID4 array (any order) is accepted and stored as a tuple.
    rules = validate_rules([
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K2, K1]},
    ])
    assert rules[0].key_ids == (K2, K1)
    # to_json emits key_ids sorted and omits the field when unscoped.
    assert rules[0].to_json() == {
        "subject": "a", "actions": ["read"], "effect": "allow",
        "key_ids": [K1, K2],
    }
    assert Rule("a", ["read"], "allow").to_json() == {
        "subject": "a", "actions": ["read"], "effect": "allow",
    }

    for bad in ([], ["x"], [K1, K1], "nope", None, [1], [K1, "x"], [True]):
        with pytest.raises(PolicyError) as exc:
            validate_rules([
                {"subject": "a", "actions": ["read"], "effect": "allow",
                 "key_ids": bad},
            ])
        assert str(exc.value) == BAD_KEY_IDS_MSG, bad

    # The standalone-rule form names the bare field.
    from keymgr.policy import validate_rule
    with pytest.raises(PolicyError) as exc:
        validate_rule(
            {"subject": "a", "actions": ["read"], "effect": "allow",
             "key_ids": ["x"]}
        )
    assert str(exc.value) == (
        "field key_ids must be a non-empty array of UUID4 strings "
        "without duplicates"
    )

    # Same subject/effect/actions but a different scope are distinct rules;
    # the exact same scope is still a duplicate.
    assert len(validate_rules([
        {"subject": "a", "actions": ["read"], "effect": "allow"},
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K1]},
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K2]},
    ])) == 3
    with pytest.raises(PolicyError):
        validate_rules([
            {"subject": "a", "actions": ["read"], "effect": "allow",
             "key_ids": [K1, K2]},
            {"subject": "a", "actions": ["read"], "effect": "allow",
             "key_ids": [K2, K1]},
        ])


def test_revision_anchors_old_documents_and_ignores_key_order():
    # Documents that omit key_ids keep their exact historical revision.
    old = validate_rules([
        {"subject": "alice", "actions": ["read"], "effect": "allow"},
    ])
    assert revision_for_rules(old) == (
        "581d5bd2e4f7a98aed2bdc99f206f4cdf8598b2d14af6a6b91adb257e96ae7b5"
    )
    # key_ids order is irrelevant to the revision.
    a = validate_rules([
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K1, K2]},
    ])
    b = validate_rules([
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K2, K1]},
    ])
    assert revision_for_rules(a) == revision_for_rules(b)
    # Adding a scope changes the document, hence the revision.
    scoped = validate_rules([
        {"subject": "alice", "actions": ["read"], "effect": "allow",
         "key_ids": [K1]},
    ])
    assert revision_for_rules(scoped) != revision_for_rules(old)
    # Two different scopes differ.
    other = validate_rules([
        {"subject": "alice", "actions": ["read"], "effect": "allow",
         "key_ids": [K2]},
    ])
    assert revision_for_rules(scoped) != revision_for_rules(other)


# -- evaluation semantics ---------------------------------------------------

def test_evaluate_rules_key_scope_and_deny_precedence():
    from keymgr.policy import evaluate_rules
    rules = validate_rules([
        {"subject": "a", "actions": ["rotate"], "effect": "allow",
         "key_ids": [K1]},
        {"subject": "a", "actions": ["rotate"], "effect": "deny",
         "key_ids": [K2]},
        {"subject": "a", "actions": ["read"], "effect": "allow"},
    ])
    assert evaluate_rules(rules, "a", "rotate", K1)["allowed"] is True
    assert evaluate_rules(rules, "a", "rotate", K2)["effect"] == "deny"
    # No key context: the scoped rules never match.
    assert evaluate_rules(rules, "a", "rotate", None)["reason"] == (
        "default_deny"
    )
    # Unscoped rules match both with and without a key context.
    assert evaluate_rules(rules, "a", "read", None)["allowed"] is True
    assert evaluate_rules(rules, "a", "read", K2)["allowed"] is True
    # An unrelated key is not covered by the K1-only allow.
    other = "33333333-3333-4333-8333-333333333333"
    assert evaluate_rules(rules, "a", "rotate", other)["reason"] == (
        "default_deny"
    )

    # A scoped deny beats an unscoped allow for that one key.
    mixed = validate_rules([
        {"subject": "a", "actions": ["read"], "effect": "allow"},
        {"subject": "a", "actions": ["read"], "effect": "deny",
         "key_ids": [K2]},
    ])
    assert evaluate_rules(mixed, "a", "read", K1)["allowed"] is True
    hit = evaluate_rules(mixed, "a", "read", K2)
    assert hit["allowed"] is False and hit["reason"] == "explicit_deny"
    assert [r.effect for r in hit["rules"]] == ["allow", "deny"]
    # A keyless request still sees only the unscoped allow.
    assert evaluate_rules(mixed, "a", "read", None)["allowed"] is True


# -- HTTP / CLI check -------------------------------------------------------

def _check(client, body, tenant="t1", op="alice"):
    return client.call(
        "POST", "/v1/policy/check?tenant_id=%s" % tenant, body, op
    )


def _raw_check(client, raw, tenant="t1", op="alice"):
    req = urllib.request.Request(
        client.base + "/v1/policy/check?tenant_id=%s" % tenant,
        data=raw, method="POST",
        headers={"X-Operator-Id": op, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_check_without_key_id_keeps_historical_shape(stack):
    client = stack.client
    stack.policies.put("t1", [
        Rule("alice", ["read"], "allow", (K1,)),
    ])
    s, b = _check(client, {"subject": "alice", "action": "read"})
    assert s == 200
    assert "key_id" not in b
    assert list(b.keys()) == [
        "tenant_id", "subject", "action", "allowed", "effect", "reason",
        "rules",
    ]
    # The scoped allow does not match a keyless check: default deny.
    assert (b["allowed"], b["reason"]) == (False, "default_deny")


def test_check_with_key_id_filters_and_echoes(stack):
    env = stack
    client = stack.client
    stack.policies.put("t1", [
        Rule("alice", ["read"], "allow", (K1,)),
        Rule("alice", ["read"], "deny", (K2,)),
    ])

    s, b = _check(client, {"subject": "alice", "action": "read",
                           "key_id": K1})
    assert s == 200
    assert b["key_id"] == K1
    assert (b["allowed"], b["effect"], b["reason"]) == (
        True, "allow", "explicit_allow"
    )
    assert [r["key_ids"] for r in b["rules"]] == [[K1]]
    k1_body = b

    s, b = _check(client, {"subject": "alice", "action": "read",
                           "key_id": K2})
    assert b["key_id"] == K2
    assert (b["allowed"], b["reason"]) == (False, "explicit_deny")
    assert [r["key_ids"] for r in b["rules"]] == [[K2]]

    # An explicit null is a provided key context: echoed as null, and scoped
    # rules still do not match.
    s, b = _raw_check(
        client,
        json.dumps({"subject": "alice", "action": "read",
                    "key_id": None}).encode(),
    )
    assert s == 200 and b["key_id"] is None
    assert (b["allowed"], b["reason"]) == (False, "default_deny")

    # A key no rule covers is a default deny (no existence probing).
    s, b = _check(client, {"subject": "alice", "action": "read",
                           "key_id": "33333333-3333-4333-8333-333333333333"})
    assert (b["allowed"], b["reason"], b["rules"]) == (
        False, "default_deny", []
    )

    # No policy document: allowed with key_id present, echoed.
    s, b = _check(client, {"subject": "alice", "action": "read",
                           "key_id": K1}, tenant="t2")
    assert s == 200 and b["key_id"] == K1
    assert (b["allowed"], b["reason"]) == (True, "no_policy")

    # CLI parity for provided and omitted key_id.
    proc = run_cli(
        env, "policy", "--operator", "admin", "check",
        "--tenant-id", "t1", "--subject", "alice", "--action", "read",
        "--key-id", K1,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == k1_body
    proc = run_cli(
        env, "policy", "--operator", "admin", "check",
        "--tenant-id", "t1", "--subject", "alice", "--action", "read",
    )
    assert proc.returncode == 0
    assert "key_id" not in json.loads(proc.stdout)


@pytest.mark.parametrize("value", ["x", 123, [], {}, True, "not-a-uuid"])
def test_check_bad_key_id_is_fixed_400(stack, value):
    client = stack.client
    before = len(stack.audit._read_all())
    s, b = _check(client, {"subject": "a", "action": "read",
                           "key_id": value})
    assert s == 400 and b == {"error": BAD_KEY_ID_MSG}
    # A parameter failure writes no audit event.
    assert len(stack.audit._read_all()) == before

    proc = run_cli(
        stack, "policy", "--operator", "admin", "check",
        "--tenant-id", "t1", "--subject", "a", "--action", "read",
        "--key-id", str(value),
    )
    assert proc.returncode == 2
    assert json.loads(proc.stderr) == {"error": BAD_KEY_ID_MSG}


# -- writing documents with key_ids (HTTP + CLI) ---------------------------

def _put_policy(srv, tenant, rules):
    return srv.client.call(
        "PUT", "/v1/policy?tenant_id=" + tenant,
        {"tenant_id": tenant, "rules": rules}, "admin",
    )


def test_put_scoped_rules_and_reload_preserves_semantics(stack):
    env = stack
    raw = [
        {"subject": "alice", "actions": ["read", "rotate"], "effect": "allow",
         "key_ids": [K2, K1]},
    ]
    s, b = _put_policy(stack, "t1", raw)
    assert s == 200, b
    # Sorted on the wire; revision matches a re-read and a re-store.
    assert b["rules"][0]["key_ids"] == [K1, K2]
    revision = b["revision"]

    s, get = stack.client.call(
        "GET", "/v1/policy?tenant_id=t1", None, "admin"
    )
    assert s == 200 and get["revision"] == revision
    assert get["rules"] == b["rules"]

    # Reopening the store reloads the scoped document with the same revision.
    reopened = PolicyStore(stack.data_dir, stack.audit)
    assert reopened.get_revision("t1") == revision

    # CLI set accepts the same JSON shape and keeps the revision.
    proc = run_cli(
        env, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules", json.dumps(raw),
        "--expected-revision", revision,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["revision"] == revision


@pytest.mark.parametrize("bad", [[], ["x"], [K1, K1], 4, "nope"])
def test_put_bad_key_ids_is_fixed_400_without_change(stack, bad):
    s, first = _put_policy(
        stack, "t1",
        [{"subject": "alice", "actions": ["read"], "effect": "allow"}],
    )
    assert s == 200
    revision = first["revision"]
    mutations_before = [
        (e.action, e.outcome) for e in stack.audit._read_all()
        if e.action in ("policy_update", "policy_delete")
    ]

    s, b = _put_policy(
        stack, "t1",
        [{"subject": "alice", "actions": ["read"], "effect": "allow",
          "key_ids": bad}],
    )
    assert s == 400 and b == {"error": BAD_KEY_IDS_MSG}
    # Nothing changed: same revision and no extra mutation event (the later
    # GET appends only a policy_read).
    s, get = stack.client.call(
        "GET", "/v1/policy?tenant_id=t1", None, "admin"
    )
    assert get["revision"] == revision
    mutations_after = [
        (e.action, e.outcome) for e in stack.audit._read_all()
        if e.action in ("policy_update", "policy_delete")
    ]
    assert mutations_after == mutations_before

    proc = run_cli(
        stack, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules", json.dumps(
            [{"subject": "alice", "actions": ["read"], "effect": "allow",
             "key_ids": bad}]
        ),
    )
    assert proc.returncode == 2
    assert json.loads(proc.stderr) == {"error": BAD_KEY_IDS_MSG}


# -- end-to-end enforcement -------------------------------------------------

def test_scoped_rule_enforced_on_key_endpoints(stack):
    client = stack.client
    # Create the keys while no policy exists.
    k_allowed = _make_key(client, tenant="t1")
    k_other = _make_key(client, tenant="t1")
    stack.policies.put("t1", [
        Rule("alice", ["read"], "allow", (k_allowed,)),
        Rule("alice", ["rotate"], "allow", (k_allowed,)),
    ])

    def rejected():
        return [
            e for e in stack.audit._read_all()
            if e.tenant_id == "t1" and e.outcome == "rejected"
        ]

    # The covered key is readable and rotatable.
    s, b = client.call(
        "GET", "/v1/keys/%s/current?tenant_id=t1" % k_allowed, None, "alice"
    )
    assert s == 200, b
    s, b = client.call(
        "POST", "/v1/keys/%s/rotate" % k_other,
        {"tenant_id": "t1", "algorithm": "AES256"}, "alice",
        headers={"Idempotency-Key": "denied-rotate-1"},
    )
    assert s == 403 and b["error"] == "action not permitted by policy"
    assert b.get("operation_id")
    # The rejected rotate projects the request key_id in its audit event.
    deny_events = [e for e in rejected() if e.action == "rotate"]
    assert len(deny_events) == 1 and deny_events[0].key_id == k_other

    # The other key is unreadable: 403 precedes existence, so the response
    # is identical whether the key exists in this tenant or nowhere.
    s, b = client.call(
        "GET", "/v1/keys/%s/current?tenant_id=t1" % k_other, None, "alice"
    )
    assert s == 403 and b == {"error": "action not permitted by policy"}
    s, b = client.call(
        "GET", "/v1/keys/%s/current?tenant_id=t1"
        % "33333333-3333-4333-8333-333333333333",
        None, "alice",
    )
    assert s == 403 and b == {"error": "action not permitted by policy"}

    # The covered key rotates fine; the denied key is untouched (read
    # straight from the store, since alice is not allowed to read it).
    assert _rotate(client, k_allowed, tenant="t1")["version"] == 2
    assert stack.store.get(k_other, "t1").current.version == 1


def test_scoped_deny_beats_unscoped_allow(stack):
    client = stack.client
    k_locked = _make_key(client, tenant="t1")
    k_open = _make_key(client, tenant="t1")
    stack.policies.put("t1", [
        Rule("alice", ["read"], "allow"),
        Rule("alice", ["read"], "deny", (k_locked,)),
    ])
    for kid, ok in ((k_open, True), (k_locked, False)):
        s, _ = client.call(
            "GET", "/v1/keys/%s/current?tenant_id=t1" % kid, None, "alice"
        )
        assert s == (200 if ok else 403)


def test_scoped_rule_does_not_govern_keyless_actions(stack):
    client = stack.client
    kid = _make_key(client, tenant="t1")
    # Only a scoped read allow: create (no key context) is default-denied,
    # and listing (also keyless) is denied; the scoped rule never matches.
    stack.policies.put("t1", [
        Rule("alice", ["read"], "allow", (kid,)),
    ])
    s, b = client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t1", "algorithm": "AES256", "label": "x"}, "alice",
    )
    assert s == 403 and b == {"error": "action not permitted by policy"}
    s, b = client.call("GET", "/v1/keys?tenant_id=t1", None, "alice")
    assert s == 403


def test_batch_rotate_checks_each_key_and_fails_closed(stack):
    client = stack.client
    k1 = _make_key(client, tenant="t1")
    k2 = _make_key(client, tenant="t1")
    k3 = _make_key(client, tenant="t1")
    # alice may rotate only k1 and k3.
    stack.policies.put("t1", [
        Rule("alice", ["rotate"], "allow", (k1, k3)),
    ])

    def current_versions():
        return {
            kid: stack.store.get(kid, "t1").current.version
            for kid in (k1, k2, k3)
        }

    before = current_versions()

    def batch(ids, key):
        return client.call(
            "POST", "/v1/keys/batch-rotate",
            {"tenant_id": "t1",
             "items": [{"key_id": kid, "algorithm": "AES256"}
                       for kid in ids]},
            "alice", headers={"Idempotency-Key": key},
        )

    # One uncovered item (k2) fails the WHOLE batch with zero changes.
    s, b = batch([k1, k2], "batch-deny-1")
    assert s == 403 and b["error"] == "action not permitted by policy"
    assert b.get("operation_id")
    assert current_versions() == before

    rejected = [
        e for e in stack.audit._read_all()
        if e.tenant_id == "t1" and e.action == "batch_rotate"
        and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id is None

    # The all-covered batch succeeds and rotates exactly its items.
    s, b = batch([k1, k3], "batch-ok-1")
    assert s == 201, b
    assert [item["key_id"] for item in b["items"]] == [k1, k3]
    after = current_versions()
    assert after[k1] == before[k1] + 1
    assert after[k3] == before[k3] + 1
    assert after[k2] == before[k2]

    # Retrying the denied batch with a new idempotency key is denied again,
    # still changing nothing.
    s, b = batch([k2], "batch-deny-2")
    assert s == 403

    # CLI parity: a denied CLI batch exits 3 with the fixed text.
    proc = run_cli(
        stack, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--items", json.dumps(
            [{"key_id": k1, "algorithm": "AES256"},
             {"key_id": k2, "algorithm": "AES256"}]
        ),
        "--idempotency-key", "cli-batch-deny-1",
    )
    assert proc.returncode == 3
    assert json.loads(proc.stderr)["error"] == (
        "action not permitted by policy"
    )


# -- tenant backup/restore --------------------------------------------------

def test_scoped_policy_roundtrips_through_tenant_bundle(tmp_path):
    scoped = [
        {"subject": "alice", "actions": ["read", "rotate"], "effect": "allow",
         "key_ids": [K2, K1]},
        {"subject": "bob", "actions": ["read"], "effect": "deny"},
    ]
    payload = {
        "format": tenantbundle.FORMAT,
        "tenant_id": "t1",
        "keys": [],
        "policy": {"rules": scoped},
    }
    bundle = tenantbundle.encode_bundle(payload, "pw")
    decoded = tenantbundle.decode_bundle(bundle, "pw")
    # key_ids survive, sorted and semantically identical.
    assert decoded["policy"]["rules"][0]["key_ids"] == [K1, K2]
    restored_rules = [Rule.from_json(r) for r in decoded["policy"]["rules"]]
    original = validate_rules(scoped)
    assert revision_for_rules(restored_rules) == revision_for_rules(original)

    # Restoring the payload into a fresh data dir preserves semantics.
    data_dir = str(tmp_path / "restored")
    audit = AuditLog(data_dir)
    store = KeyStore(data_dir, audit)
    policies = PolicyStore(data_dir, audit)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    result = coordinator.restore("t1", decoded)
    assert result.status == restore_mod.RESTORE_CREATED
    assert policies.get_revision("t1") == revision_for_rules(original)
    assert policies.check("t1", "alice", "rotate", K1)["allowed"] is True
    assert policies.check("t1", "alice", "rotate", K2)["allowed"] is True
    other = "33333333-3333-4333-8333-333333333333"
    assert policies.check("t1", "alice", "rotate", other)["reason"] == (
        "default_deny"
    )
    assert policies.check("t1", "bob", "read", K1)["allowed"] is False


def test_old_style_bundle_rules_restore_unscoped(tmp_path):
    # A bundle whose rules omit key_ids (an old tenant-backup-v1) must keep
    # the old semantics: the rule governs every key and keyless requests.
    payload = {
        "format": tenantbundle.FORMAT,
        "tenant_id": "t1",
        "keys": [],
        "policy": {"rules": [
            {"subject": "alice", "actions": ["read"], "effect": "allow"},
        ]},
    }
    decoded = tenantbundle.decode_bundle(
        tenantbundle.encode_bundle(payload, "pw"), "pw"
    )
    rules = [Rule.from_json(r) for r in decoded["policy"]["rules"]]
    assert rules[0].key_ids is None
    assert revision_for_rules(rules) == (
        "581d5bd2e4f7a98aed2bdc99f206f4cdf8598b2d14af6a6b91adb257e96ae7b5"
    )

    data_dir = str(tmp_path / "restored-old")
    audit = AuditLog(data_dir)
    store = KeyStore(data_dir, audit)
    policies = PolicyStore(data_dir, audit)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    assert coordinator.restore("t1", decoded).status == (
        restore_mod.RESTORE_CREATED
    )
    other = "33333333-3333-4333-8333-333333333333"
    assert policies.check("t1", "alice", "read", other)["allowed"] is True
    assert policies.check("t1", "alice", "read", None)["allowed"] is True
