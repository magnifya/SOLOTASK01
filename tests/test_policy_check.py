import json
import urllib.error
import urllib.request

import pytest

from keymgr.audit import AuditLog
from keymgr.policy import PolicyStore, Rule
from test_version_history import (
    _build_server, _make_key, _rotate, _history,
)
from test_recovery_cli import run_cli


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


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


def test_http_and_cli_check_scenarios(stack):
    env = stack
    client = stack.client
    s, b = _check(client, {"subject": "alice", "action": "read"})
    assert s == 200 and b == {
        "tenant_id": "t1", "subject": "alice", "action": "read",
        "allowed": True, "effect": "allow", "reason": "no_policy",
        "rules": [],
    }
    proc = run_cli(
        env, "policy", "--operator", "admin", "check",
        "--tenant-id", "t1", "--subject", "alice", "--action", "read",
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == b

    stack.policies.put("t1", [
        Rule("alice", ["read"], "allow"),
        Rule("alice", ["read", "sign"], "deny"),
        Rule("bob", ["read"], "allow"),
    ])
    s, b = _check(client, {"subject": "alice", "action": "read"})
    assert (b["allowed"], b["reason"], b["effect"]) == (
        False, "explicit_deny", "deny"
    )
    assert [r["effect"] for r in b["rules"]] == ["allow", "deny"]
    s, b = _check(client, {"subject": "bob", "action": "read"})
    assert (b["allowed"], b["reason"]) == (True, "explicit_allow")
    s, b = _check(client, {"subject": "carol", "action": "read"})
    assert (b["allowed"], b["reason"], b["rules"]) == (
        False, "default_deny", []
    )
    s, b = _check(client, {"subject": "carol", "action": "read"},
                  tenant="t2")
    assert (b["allowed"], b["reason"]) == (True, "no_policy")

    before = len(stack.audit._read_all())
    cases = [
        b"{bad", [], {}, {"subject": "a"}, {"action": "read"},
        {"subject": "a", "action": "read", "extra": 1},
        {"subject": "", "action": "read"},
        {"subject": 3, "action": "read"},
        {"subject": "a", "action": ""},
        {"subject": "a", "action": "frobnicate"},
        {"subject": "a", "action": 7},
    ]
    for case in cases:
        if isinstance(case, bytes):
            s, b = _raw_check(client, case)
        else:
            s, b = _check(client, case)
        assert s == 400, (case, b)
    assert len(stack.audit._read_all()) == before

    open(stack.policies.path_for("t3"), "w").write("{corrupt")
    s, b = _check(client, {"subject": "a", "action": "read"}, tenant="t3")
    assert s == 500 and b == {"error": "policy store is unavailable"}
    proc = run_cli(
        env, "policy", "--operator", "admin", "check",
        "--tenant-id", "t3", "--subject", "a", "--action", "read",
    )
    assert proc.returncode == 1
    assert json.loads(proc.stderr) == {
        "error": "policy store is unavailable"
    }

    for argv in (
        ["check", "--tenant-id", "t1", "--subject", "", "--action", "read"],
        ["check", "--tenant-id", "t1", "--subject", "a", "--action", "x"],
    ):
        proc = run_cli(
            env, "policy", "--operator", "admin", *argv
        )
        assert proc.returncode == 2


def test_check_writes_no_audit_and_tenant_conflict_does(stack):
    client = stack.client
    _check(client, {"subject": "a", "action": "read"})
    _check(client, {"subject": "a", "action": "read"})
    actions = sorted({e.action for e in stack.audit._read_all()})
    assert actions == []
    s, b = client.call(
        "POST", "/v1/policy/check",
        {"subject": "a", "action": "read"}, "alice",
    )
    assert s == 400
    conflicts = [e for e in stack.audit._read_all()
                 if e.action == "tenant_conflict"]
    assert len(conflicts) == 1


def test_corrupt_key_record_versions_fixed_500(stack):
    client = stack.client
    kid = _make_key(client)
    keypath = stack.store._path_for(kid)
    with open(keypath, "w") as fh:
        fh.write("{bad json")
    s, b = _history(client, kid)
    assert (s, b) == (500, {"error": "audit ledger is unavailable"})
    s, b = client.call(
        "GET", "/v1/keys/%s/versions/1?tenant_id=t" % kid, None
    )
    assert (s, b) == (500, {"error": "audit ledger is unavailable"})
    proc = run_cli(
        stack, "versions", "--tenant-id", "t", "--operator", "alice",
        "--key-id", kid,
    )
    assert proc.returncode == 1
    assert json.loads(proc.stderr) == {
        "error": "audit ledger is unavailable"
    }


def test_cli_cursor_validation_precedes_policy(stack):
    client = stack.client
    stack.policies.put("tpol", [Rule("alice", ["read"], "deny"), Rule("alice", ["rotate"], "allow")])
    rec = stack.store.create("tpol", "AES256", "k")
    pkid = rec.key_id
    _rotate(client, pkid, tenant="tpol")

    def rejected():
        return [e for e in stack.audit._read_all()
                if e.tenant_id == "tpol" and e.outcome == "rejected"]

    before = rejected()
    for cursor in ("", "garbage"):
        proc = run_cli(
            stack, "versions", "--tenant-id", "tpol",
            "--operator", "alice", "--key-id", pkid, "--cursor", cursor,
        )
        assert proc.returncode == 2, cursor
    assert rejected() == before

    # A cursor minted for another tenant/key is a mismatch 400 (exit 2)
    # before the policy denial, with no rejected event.
    kid = _make_key(client)
    _rotate(client, kid)
    s, body = _history(client, kid, limit=1)
    assert s == 200 and body["next_cursor"]
    proc = run_cli(
        stack, "versions", "--tenant-id", "tpol", "--operator", "alice",
        "--key-id", pkid, "--limit", "1", "--cursor", body["next_cursor"],
    )
    assert proc.returncode == 2
    assert rejected() == before

    # An expired cursor (history changed) likewise exits 2 pre-policy.
    pol2 = PolicyStore(stack.data_dir, stack.audit)
    pol2.put("t2", [Rule("alice", ["read", "rotate"], "allow")])
    rec2 = stack.store.create("t2", "AES256", "k2")
    k2 = rec2.key_id
    _rotate(client, k2, tenant="t2")
    s, body = _history(client, k2, tenant="t2", limit=1)
    cursor = body["next_cursor"]
    _rotate(client, k2, tenant="t2")
    proc = run_cli(
        stack, "versions", "--tenant-id", "t2", "--operator", "alice",
        "--key-id", k2, "--limit", "1", "--cursor", cursor,
    )
    assert proc.returncode == 2
