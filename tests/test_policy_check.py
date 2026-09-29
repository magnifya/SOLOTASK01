"""Direct policy checks through HTTP and the policy CLI subcommand."""

import json

import pytest

from keymgr.policy import PolicyStore, Rule

from test_policy_revision import _put
from test_provider_reconnect import OPERATOR, HttpServer
from test_recovery_cli import run_cli


@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield env, server
    server.stop()


def _check(srv, body, tenant="t1", raw=False, headers=None):
    path = "/v1/policy/check?tenant_id=%s" % tenant
    if raw:
        return srv.raw(
            "POST", path, body.encode("utf-8"),
            {"X-Operator-Id": "alice", "Content-Type": "application/json"}
        )
    return srv.request("POST", path, body, OPERATOR | (headers or {}))


def _all_events(env):
    return env.audit_events()


def test_check_without_policy_allows_and_has_no_side_effects(http):
    env, srv = http
    before = _all_events(env)
    status, body = _check(srv, {"subject": "alice", "action": "read"})
    assert status == 200, body
    assert list(body.keys()) == [
        "tenant_id", "subject", "action", "allowed", "effect",
        "reason", "matched_rules",
    ]
    assert body == {
        "tenant_id": "t1",
        "subject": "alice",
        "action": "read",
        "allowed": True,
        "effect": "allow",
        "reason": "no_policy",
        "matched_rules": [],
    }
    assert _all_events(env) == before


def test_check_explicit_allow_deny_default_and_order(http):
    env, srv = http
    _put(srv, [
        {"subject": "alice", "actions": ["read", "list"], "effect": "allow"},
        {"subject": "alice", "actions": ["read"], "effect": "deny"},
        {"subject": "bob", "actions": ["read"], "effect": "allow"},
    ])

    status, body = _check(srv, {"subject": "alice", "action": "list"})
    assert status == 200
    assert body["allowed"] is True
    assert body["effect"] == "allow"
    assert body["reason"] == "explicit_allow"
    assert body["matched_rules"] == [
        {"subject": "alice", "actions": ["read", "list"], "effect": "allow"}
    ]

    status, body = _check(srv, {"subject": "alice", "action": "read"})
    assert status == 200
    assert body["allowed"] is False
    assert body["effect"] == "deny"
    assert body["reason"] == "explicit_deny"
    assert body["matched_rules"] == [
        {"subject": "alice", "actions": ["read", "list"], "effect": "allow"},
        {"subject": "alice", "actions": ["read"], "effect": "deny"},
    ]

    status, body = _check(srv, {"subject": "carol", "action": "read"})
    assert status == 200
    assert body == {
        "tenant_id": "t1",
        "subject": "carol",
        "action": "read",
        "allowed": False,
        "effect": "deny",
        "reason": "default_deny",
        "matched_rules": [],
    }

    _put(srv, [])
    status, body = _check(srv, {"subject": "alice", "action": "read"})
    assert status == 200
    assert body["reason"] == "default_deny"
    assert body["matched_rules"] == []


def test_check_is_tenant_scoped_and_does_not_audit(http):
    env, srv = http
    _put(srv, [
        {"subject": "alice", "actions": ["read"], "effect": "deny"}
    ])
    before = _all_events(env)
    status, body = _check(
        srv, {"subject": "alice", "action": "read"}, tenant="t2"
    )
    assert status == 200
    assert body["tenant_id"] == "t2"
    assert body["reason"] == "no_policy"
    assert body["allowed"] is True
    assert _all_events(env) == before


def test_check_rejects_bad_bodies_without_audit(http):
    env, srv = http
    before = _all_events(env)
    cases = [
        ("{bad", True),
        ("[]", True),
        ({"action": "read"}, False),
        ({"subject": "alice"}, False),
        ({"subject": "alice", "action": "read", "tenant_id": "t1"}, False),
        ({"subject": "", "action": "read"}, False),
        ({"subject": 1, "action": "read"}, False),
        ({"subject": "alice", "action": ""}, False),
        ({"subject": "alice", "action": 1}, False),
        ({"subject": "alice", "action": "policy_read"}, False),
    ]
    for payload, raw in cases:
        status, body_text = _check(srv, payload, raw=raw)
        body = json.loads(body_text) if raw else body_text
        assert status == 400, (payload, body)
        assert "error" in body
    assert _all_events(env) == before


def test_check_tenant_source_conflict_still_audits(http):
    env, srv = http
    status, text = srv.raw(
        "POST",
        "/v1/policy/check?tenant_id=t1",
        json.dumps({"subject": "alice", "action": "read"}).encode("utf-8"),
        {
            "X-Operator-Id": "alice",
            "X-Tenant-Id": "other",
            "Content-Type": "application/json",
        },
    )
    assert status == 400
    assert json.loads(text)["error"].startswith("conflicting tenant_id")
    conflicts = [
        event for event in env.audit_events()
        if event.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1


def test_check_corrupt_policy_is_fixed_500_http_and_cli(http):
    env, srv = http
    _put(srv, [
        {"subject": "alice", "actions": ["read"], "effect": "allow"}
    ])
    policy_path = PolicyStore(env.data_dir).path_for("t1")
    with open(policy_path, "w",
              encoding="utf-8") as fh:
        fh.write("{broken")

    status, body = _check(srv, {"subject": "alice", "action": "read"})
    assert status == 500
    assert body == {"error": "policy store is unavailable"}

    proc = run_cli(
        env, "policy", "--operator", "alice", "check",
        "--tenant-id", "t1", "--subject", "alice", "--action", "read",
    )
    assert proc.returncode == 1
    assert json.loads(proc.stderr) == {
        "error": "policy store is unavailable"
    }


def test_cli_check_matches_http(http):
    env, srv = http
    PolicyStore(env.data_dir).put("t1", [
        Rule(subject="alice", actions=["read", "list"], effect="allow"),
        Rule(subject="alice", actions=["read"], effect="deny"),
    ])
    proc = run_cli(
        env, "policy", "--operator", "alice", "check",
        "--tenant-id", "t1", "--subject", "alice", "--action", "read",
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == _check(
        srv, {"subject": "alice", "action": "read"}
    )[1]

    proc = run_cli(
        env, "policy", "--operator", "alice", "check",
        "--tenant-id", "t1", "--subject", "", "--action", "read",
    )
    assert proc.returncode == 2
    proc = run_cli(
        env, "policy", "--operator", "alice", "check",
        "--tenant-id", "t1", "--subject", "alice", "--action", "nope",
    )
    assert proc.returncode == 2
