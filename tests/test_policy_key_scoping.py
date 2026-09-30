"""Resource-granular policy rules: optional per-rule ``key_ids``."""

import json

import pytest

from keymgr.policy import (
    CHECK_KEY_ID_ERROR,
    KEY_IDS_ERROR,
    PolicyError,
    PolicyStore,
    Rule,
    evaluate_rules,
    revision_for_rules,
    validate_rule,
    validate_rules,
)
from test_version_history import _build_server, _make_key, _rotate
from test_recovery_cli import run_cli


K1 = "00000000-0000-4000-8000-000000000001"
K2 = "00000000-0000-4000-8000-000000000002"
KEY_IDS_ERROR_TEXT = (
    "field rules[i].key_ids must be a non-empty array of UUID4 strings "
    "without duplicates"
)
CHECK_KEY_ID_ERROR_TEXT = "field key_id must be a UUID4 or null"


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


# -- validation -------------------------------------------------------------

def test_key_ids_must_be_nonempty_unique_uuid4_array():
    good = validate_rule(
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K1, K2]},
    )
    assert good.key_ids == frozenset({K1, K2})
    bad_cases = [
        [],
        [K1, K1],
        [K1, "not-a-uuid"],
        [123],
        [None],
        "x",
        {"a": 1},
        [K1.replace("-", "")],
    ]
    for case in bad_cases:
        with pytest.raises(PolicyError) as exc:
            validate_rule(
                {"subject": "a", "actions": ["read"], "effect": "allow",
                 "key_ids": case},
            )
        assert str(exc.value) == KEY_IDS_ERROR_TEXT, case


def test_key_ids_fixed_error_uses_rules_i_prefix_for_any_index():
    with pytest.raises(PolicyError) as exc:
        validate_rules(
            [
                {"subject": "a", "actions": ["read"], "effect": "allow"},
                {"subject": "b", "actions": ["read"], "effect": "allow",
                 "key_ids": ["x"]},
            ]
        )
    assert str(exc.value) == KEY_IDS_ERROR_TEXT
    assert KEY_IDS_ERROR_TEXT == KEY_IDS_ERROR == (
        "field rules[i].key_ids must be a non-empty array of UUID4 strings "
        "without duplicates"
    )


def test_omitted_key_ids_serializes_without_the_slot():
    rule = validate_rule(
        {"subject": "a", "actions": ["read"], "effect": "allow"}
    )
    assert rule.key_ids is None
    assert "key_ids" not in rule.to_json()
    scoped = validate_rule(
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K2, K1]}
    )
    # Emitted sorted; order on input is irrelevant.
    assert scoped.to_json()["key_ids"] == [K1, K2]


def test_scoped_rules_with_same_subject_effect_actions_are_distinct():
    # An unscoped rule and a scoped rule coexist; two different scopes do
    # too; the exact same scope twice duplicates.
    validate_rules([
        {"subject": "a", "actions": ["read"], "effect": "allow"},
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K1]},
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": [K2]},
    ])
    with pytest.raises(PolicyError):
        validate_rules([
            {"subject": "a", "actions": ["read", "read"], "effect": "allow",
             "key_ids": [K1, K2]},
            {"subject": "a", "actions": ["read"], "effect": "allow",
             "key_ids": [K2, K1]},
        ])


# -- revision ---------------------------------------------------------------

def test_revision_order_independent_and_stable_for_old_documents():
    r1 = [
        Rule("a", ["read"], "allow", frozenset({K2, K1})),
        Rule("b", ["sign", "read"], "deny"),
    ]
    r2 = [
        Rule("b", ["read", "sign"], "deny"),
        Rule("a", ["read"], "allow", frozenset({K1, K2})),
    ]
    assert revision_for_rules(r1) == revision_for_rules(r2)
    # An unscoped document keeps its historical revision exactly.
    old = [Rule("a", ["sign", "read"], "deny"),
           Rule("a", ["read"], "allow")]
    assert revision_for_rules(old) == revision_for_rules([
        Rule("a", ["read"], "allow"),
        Rule("a", ["read", "sign"], "deny"),
    ])
    # Adding a scope changes the revision.
    assert revision_for_rules(
        [Rule("a", ["read"], "allow")]
    ) != revision_for_rules(
        [Rule("a", ["read"], "allow", frozenset({K1}))]
    )


# -- evaluation -------------------------------------------------------------

def _rules():
    return [
        Rule("alice", ["read"], "allow"),                 # unscoped allow
        Rule("bob", ["rotate"], "allow", frozenset({K1})),
        Rule("carol", ["rotate"], "deny", frozenset({K2})),
        Rule("carol", ["rotate"], "allow", frozenset({K1})),
        Rule("dave", ["read"], "deny", frozenset({K1})),
    ]


def test_key_less_context_matches_only_unscoped_rules():
    rules = _rules()
    # Bob's allow is scoped: without a key context it does not match, so a
    # policy exists but no rule matches -> default deny.
    res = evaluate_rules(rules, "bob", "rotate")
    assert (res["allowed"], res["reason"], res["rules"]) == (
        False, "default_deny", []
    )
    res = evaluate_rules(rules, "alice", "read")
    assert res["allowed"] is True and res["reason"] == "explicit_allow"


def test_key_scoped_evaluation_allows_and_denies_per_key():
    rules = _rules()
    assert evaluate_rules(rules, "bob", "rotate", K1)["allowed"] is True
    assert evaluate_rules(rules, "bob", "rotate", K2)["allowed"] is False
    # Carol: explicit allow for K1, explicit deny for K2 (deny wins even
    # though an allow also exists in the document).
    c1 = evaluate_rules(rules, "carol", "rotate", K1)
    assert c1["allowed"] is True and c1["reason"] == "explicit_allow"
    c2 = evaluate_rules(rules, "carol", "rotate", K2)
    assert c2["allowed"] is False and c2["reason"] == "explicit_deny"
    # Dave: only a scoped deny for K1 exists; K2 and the key-less context
    # match no rule at all -> default deny (an unscoped allow is required
    # to permit other keys).
    assert evaluate_rules(rules, "dave", "read", K1)["allowed"] is False
    assert evaluate_rules(rules, "dave", "read", K2)["reason"] == "default_deny"
    assert evaluate_rules(rules, "dave", "read")["reason"] == "default_deny"


# -- HTTP: set/check/enforcement --------------------------------------------

def _put_policy(client, rules, tenant="t1"):
    return client.call("PUT", "/v1/policy?tenant_id=%s" % tenant,
                       {"tenant_id": tenant, "rules": rules})


def test_put_validates_key_ids_with_fixed_400(stack):
    client = stack.client
    s, b = _put_policy(client, [
        {"subject": "a", "actions": ["read"], "effect": "allow",
         "key_ids": ["nope"]},
    ])
    assert s == 400 and b == {"error": KEY_IDS_ERROR_TEXT}
    # No document was created.
    s, b = client.call("GET", "/v1/policy?tenant_id=t1", None)
    assert s == 404


def test_check_with_and_without_key_id(stack):
    client = stack.client
    s, b = _put_policy(client, [
        {"subject": "alice", "actions": ["read"], "effect": "allow"},
        {"subject": "alice", "actions": ["rotate"], "effect": "allow",
         "key_ids": [K1]},
        {"subject": "alice", "actions": ["rotate"], "effect": "deny",
         "key_ids": [K2]},
    ])
    assert s == 200

    def check(body):
        return client.call(
            "POST", "/v1/policy/check?tenant_id=t1", body, "admin"
        )

    # No key_id: legacy response shape, only unscoped rules.
    s, b = check({"subject": "alice", "action": "read"})
    assert s == 200
    assert list(b) == [
        "tenant_id", "subject", "action", "allowed", "effect", "reason",
        "rules",
    ]
    assert b["allowed"] is True

    s, b = check({"subject": "alice", "action": "rotate", "key_id": K1})
    assert s == 200
    assert list(b) == [
        "tenant_id", "subject", "action", "key_id", "allowed", "effect",
        "reason", "rules",
    ]
    assert b["key_id"] == K1 and b["allowed"] is True
    assert b["reason"] == "explicit_allow"
    assert [r["key_ids"] for r in b["rules"]] == [[K1]]

    s, b = check({"subject": "alice", "action": "rotate", "key_id": K2})
    assert b["allowed"] is False and b["reason"] == "explicit_deny"

    s, b = check({"subject": "alice", "action": "rotate", "key_id": None})
    assert s == 200 and b["key_id"] is None
    # No scoped rule matches the null-key context: default deny.
    assert b["allowed"] is False and b["reason"] == "default_deny"

    for bad in (123, "x", "", [], {}, True):
        s, b = check({"subject": "alice", "action": "rotate",
                      "key_id": bad})
        assert s == 400 and b == {"error": CHECK_KEY_ID_ERROR_TEXT}, bad

    s, b = check({"subject": "alice", "action": "rotate",
                  "key_id": K1, "extra": 1})
    assert s == 400


def test_key_scoped_enforcement_on_key_endpoints(stack):
    client = stack.client
    kid_allowed = _make_key(client, tenant="t1")
    # Force the second key id by policy first, then create under an
    # unscoped create allow.
    _put_policy(client, [
        {"subject": "alice", "actions": ["create"], "effect": "allow"},
        {"subject": "alice", "actions": ["read"], "effect": "allow"},
        {"subject": "alice", "actions": ["rotate"], "effect": "allow",
         "key_ids": [kid_allowed]},
    ])
    kid_denied = _make_key(client, tenant="t1")

    # rotate allowed for the scoped key ...
    s, b = client.call(
        "POST", "/v1/keys/%s/rotate" % kid_allowed,
        {"tenant_id": "t1", "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-allowed"},
    )
    assert s == 201, b

    # ... and 403 for the other key (scoped allow does not match it; the
    # policy exists so there is no fall-through).
    s, b = client.call(
        "POST", "/v1/keys/%s/rotate" % kid_denied,
        {"tenant_id": "t1", "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-denied"},
    )
    assert s == 403 and b["error"] == "action not permitted by policy"
    assert "operation_id" in b
    # No version was added to the denied key.
    s, b = client.call(
        "GET", "/v1/keys/%s/current?tenant_id=t1" % kid_denied, None
    )
    assert s == 200 and b["version"] == 1
    rejected = [
        e for e in stack.audit._read_all()
        if e.tenant_id == "t1" and e.outcome == "rejected"
        and e.action == "rotate"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid_denied


def test_batch_rotate_any_denied_item_is_whole_403(stack):
    client = stack.client
    k1 = _make_key(client, tenant="t1")
    k2 = _make_key(client, tenant="t1")
    k3 = _make_key(client, tenant="t1")
    _put_policy(client, [
        {"subject": "alice", "actions": ["create", "read"],
         "effect": "allow"},
        {"subject": "alice", "actions": ["rotate"], "effect": "allow",
         "key_ids": [k1, k3]},
    ])
    s, b = client.call(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1", "items": [
            {"key_id": k1, "algorithm": "AES256"},
            {"key_id": k2, "algorithm": "AES256"},
            {"key_id": k3, "algorithm": "AES256"},
        ]},
        headers={"Idempotency-Key": "batch-denied"},
    )
    assert s == 403, b
    # Nothing rotated.
    for kid in (k1, k2, k3):
        s, body = client.call(
            "GET", "/v1/keys/%s/current?tenant_id=t1" % kid, None
        )
        assert body["version"] == 1
    events = [
        e for e in stack.audit._read_all()
        if e.action == "batch_rotate" and e.outcome == "rejected"
    ]
    assert len(events) == 1 and events[0].key_id is None

    # Allowing k2 as well makes the whole batch succeed.
    _put_policy(client, [
        {"subject": "alice", "actions": ["create"], "effect": "allow"},
        {"subject": "alice", "actions": ["rotate"], "effect": "allow",
         "key_ids": [k1, k2, k3]},
    ])
    s, b = client.call(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1", "items": [
            {"key_id": k1, "algorithm": "AES256"},
            {"key_id": k2, "algorithm": "AES256"},
            {"key_id": k3, "algorithm": "AES256"},
        ]},
        headers={"Idempotency-Key": "batch-ok"},
    )
    assert s == 201 and [i["version"] for i in b["items"]] == [2, 2, 2]


def test_deny_scoped_rule_outranks_unscoped_allow(stack):
    client = stack.client
    kid = _make_key(client, tenant="t1")
    other = _make_key(client, tenant="t1")
    _put_policy(client, [
        {"subject": "alice", "actions": ["create", "read"],
         "effect": "allow"},
        {"subject": "alice", "actions": ["read"], "effect": "deny",
         "key_ids": [kid]},
    ])
    s, b = client.call("GET", "/v1/keys/%s?tenant_id=t1" % kid, None)
    assert s == 403
    s, b = client.call("GET", "/v1/keys/%s?tenant_id=t1" % other, None)
    assert s == 200


# -- CLI --------------------------------------------------------------------

def test_cli_policy_check_key_id_and_set_key_ids(stack):
    env = stack
    rules = [
        {"subject": "alice", "actions": ["read"], "effect": "allow",
         "key_ids": [K1]},
    ]
    proc = run_cli(
        env, "policy", "--operator", "admin", "set", "--tenant-id", "t1",
        "--rules", json.dumps(rules),
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert body["rules"][0]["key_ids"] == [K1]
    rev = body["revision"]

    # Re-setting with the same logical document (reordered) keeps the
    # revision.
    rules_rev = [dict(rules[0], key_ids=list(reversed(rules[0]["key_ids"])))]
    proc = run_cli(
        env, "policy", "--operator", "admin", "set", "--tenant-id", "t1",
        "--rules", json.dumps(rules_rev),
    )
    assert json.loads(proc.stdout)["revision"] == rev

    proc = run_cli(
        env, "policy", "--operator", "admin", "check", "--tenant-id", "t1",
        "--subject", "alice", "--action", "read",
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert "key_id" not in out and out["allowed"] is False

    proc = run_cli(
        env, "policy", "--operator", "admin", "check", "--tenant-id", "t1",
        "--subject", "alice", "--action", "read", "--key-id", K1,
    )
    out = json.loads(proc.stdout)
    assert out["key_id"] == K1 and out["allowed"] is True

    proc = run_cli(
        env, "policy", "--operator", "admin", "check", "--tenant-id", "t1",
        "--subject", "alice", "--action", "read", "--key-id", "bogus",
    )
    assert proc.returncode == 2
    assert json.loads(proc.stderr) == {"error": CHECK_KEY_ID_ERROR_TEXT}

    proc = run_cli(
        env, "policy", "--operator", "admin", "set", "--tenant-id", "t1",
        "--rules", json.dumps([
            {"subject": "a", "actions": ["read"], "effect": "allow",
             "key_ids": ["x"]},
        ]),
    )
    assert proc.returncode == 2
    assert json.loads(proc.stderr) == {"error": KEY_IDS_ERROR_TEXT}


# -- backup/restore round trip ----------------------------------------------

def test_backup_restore_preserves_key_scoped_policy(
    tmp_path, monkeypatch, stack
):
    client = stack.client
    kid = _make_key(client, tenant="t1")
    _put_policy(client, [
        {"subject": "alice", "actions": ["create", "read", "export",
                                         "import"],
         "effect": "allow"},
        {"subject": "alice", "actions": ["rotate"], "effect": "allow",
         "key_ids": [kid]},
    ])
    s, rev_before = client.call("GET", "/v1/policy?tenant_id=t1", None)
    assert s == 200

    s, bundle = client.call(
        "POST", "/v1/backup",
        {"tenant_id": "t1", "passphrase": "pw"},
    )
    assert s == 200

    # verify accepts the key-scoped policy slot.
    s, b = client.call(
        "POST", "/v1/backup/verify",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle["bundle"]},
    )
    assert s == 200 and b["valid"] is True and b["policy_restored"] is True

    # Restore the same tenant into a FRESH data directory (the in-bundle
    # tenant must match the restore target); the key material is local so
    # the bundle is self-contained.
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    gen = _build_server(other_dir, monkeypatch)
    stack2 = next(gen)
    try:
        client2 = stack2.client
        s, b = client2.call(
            "POST", "/v1/restore",
            {"tenant_id": "t1", "passphrase": "pw",
             "bundle": bundle["bundle"]},
            headers={"Idempotency-Key": "restore-scoped"},
        )
        assert s == 201, b
        s, rev_after = client2.call("GET", "/v1/policy?tenant_id=t1", None)
        assert rev_after["rules"] == rev_before["rules"]
        assert rev_after["revision"] == rev_before["revision"]

        restored_kid = b["key_ids"][0]
        s, b = client2.call(
            "POST", "/v1/keys/%s/rotate" % restored_kid,
            {"tenant_id": "t1", "algorithm": "AES256"},
            headers={"Idempotency-Key": "rot-restored"},
        )
        assert s == 201, b
    finally:
        # Runs the fixture generator's shutdown (httpd.shutdown).
        try:
            next(gen)
        except StopIteration:
            pass
