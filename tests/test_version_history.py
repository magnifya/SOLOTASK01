"""GET /v1/keys/{key_id}/versions and the `keymgr versions` CLI.

Covers single- and multi-version history with the merged item projection,
limit/cursor pagination, whole-key and per-version revocation, cursor
invalidation after rotation and revocation, cross-tenant isolation, policy
rejection, parameter validation/audit rules and HTTP/CLI parity.
"""

import itertools
import json
import os
import subprocess
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"X-Operator-Id": operator}
        if data is not None:
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        req = urllib.request.Request(
            self.base + path, data=data, method=method, headers=h
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    yield types.SimpleNamespace(
        data_dir=data_dir, store=store, policies=policies,
        audit=audit_log, client=client,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


_idem_counter = itertools.count(1)


def _idem(prefix="op"):
    return "%s-%d" % (prefix, next(_idem_counter))


def _make_key(client, algorithm="RSA2048", tenant="t", label="k"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": label},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(client, key_id, algorithm="RSA2048", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": _idem("rot")},
    )
    assert status == 201, body
    return body


def _all_pages(client, key_id, tenant, limit):
    items = []
    cursor = None
    while True:
        path = "/v1/keys/%s/versions?tenant_id=%s&limit=%d" % (
            key_id, tenant, limit)
        if cursor is not None:
            path += "&cursor=" + cursor
        status, body = client.call("GET", path)
        assert status == 200, body
        items.extend(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            return items


def test_single_version_history(stack):
    key_id = _make_key(stack.client)
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id)
    assert status == 200
    assert list(body.keys()) == ["items", "next_cursor"]
    assert body["next_cursor"] is None
    (item,) = body["items"]
    assert list(item.keys()) == [
        "key_id", "version", "created_at", "algorithm", "public_key",
        "status", "reason", "operator", "revoked_at", "current",
    ]
    assert item["key_id"] == key_id
    assert item["version"] == 1
    assert item["status"] == "active"
    assert item["reason"] is None
    assert item["operator"] is None
    assert item["revoked_at"] is None
    assert item["current"] is True
    assert item["public_key"].startswith("-----BEGIN PUBLIC KEY-----")


def test_multi_version_pagination_and_current(stack):
    key_id = _make_key(stack.client)
    for _ in range(4):
        _rotate(stack.client, key_id)
    for limit in (1, 2, 3, 5, 100):
        items = _all_pages(stack.client, key_id, "t", limit)
        assert [i["version"] for i in items] == [1, 2, 3, 4, 5]
        assert [i["current"] for i in items] == [
            False, False, False, False, True]
        assert all(i["status"] == "active" for i in items)
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t&limit=2" % key_id)
    assert [i["version"] for i in body["items"]] == [1, 2]
    assert body["next_cursor"]


def test_per_version_revocation_in_history(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    _rotate(stack.client, key_id)
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % key_id,
        {"tenant_id": "t", "reason": "old", "operator": "bob"})
    assert status == 200
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id)
    assert status == 200
    v1, v2, v3 = body["items"]
    assert v1["status"] == "revoked"
    assert v1["reason"] == "old"
    assert v1["operator"] == "bob"
    assert v1["revoked_at"]
    assert v1["current"] is False
    assert v2["status"] == "active"
    assert v3["current"] is True


def test_whole_key_revocation_history_readable(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    stack.client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % key_id,
        {"tenant_id": "t", "reason": "verreason", "operator": "bob"})
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "whole", "operator": "carol"})
    assert status == 200
    whole_revoked_at = body["revoked_at"]
    status, history = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id)
    assert status == 200
    for item in history["items"]:
        assert item["status"] == "revoked"
        assert item["reason"] == "whole"
        assert item["operator"] == "carol"
        assert item["revoked_at"] == whole_revoked_at


def test_cursor_invalidation_after_change(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    status, page1 = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t&limit=1" % key_id)
    assert status == 200
    cursor = page1["next_cursor"]

    _rotate(stack.client, key_id)
    status, body = stack.client.call(
        "GET",
        "/v1/keys/%s/versions?tenant_id=t&limit=1&cursor=%s"
        % (key_id, cursor))
    assert status == 400
    assert body == {"error": "invalid or expired cursor"}

    items = _all_pages(stack.client, key_id, "t", 1)
    assert [i["version"] for i in items] == [1, 2, 3]

    def page2_cursor():
        status, page = stack.client.call(
            "GET", "/v1/keys/%s/versions?tenant_id=t&limit=2" % key_id)
        assert status == 200
        return page["next_cursor"]

    cursor = page2_cursor()
    stack.client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % key_id,
        {"tenant_id": "t", "reason": "x", "operator": "bob"})
    status, _ = stack.client.call(
        "GET",
        "/v1/keys/%s/versions?tenant_id=t&limit=2&cursor=%s"
        % (key_id, cursor))
    assert status == 400

    cursor = page2_cursor()
    stack.client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "y", "operator": "carol"})
    status, _ = stack.client.call(
        "GET",
        "/v1/keys/%s/versions?tenant_id=t&limit=2&cursor=%s"
        % (key_id, cursor))
    assert status == 400


def test_cursor_bound_to_limit_and_tamper(stack):
    key_id = _make_key(stack.client)
    for _ in range(3):
        _rotate(stack.client, key_id)
    status, page = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t&limit=1" % key_id)
    cursor = page["next_cursor"]
    status, _ = stack.client.call(
        "GET",
        "/v1/keys/%s/versions?tenant_id=t&limit=2&cursor=%s"
        % (key_id, cursor))
    assert status == 400
    status, _ = stack.client.call(
        "GET",
        "/v1/keys/%s/versions?tenant_id=t&limit=1&cursor=%sx"
        % (key_id, cursor))
    assert status == 400


def test_unknown_and_cross_tenant_are_404(stack):
    unknown = "00000000-0000-4000-8000-000000000000"
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % unknown)
    assert status == 404
    assert body == {"error": "key not found"}
    key_id = _make_key(stack.client, tenant="t")
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=other" % key_id)
    assert status == 404
    assert body == {"error": "key not found"}


def test_policy_reject_and_success_audit_with_key_id(stack):
    key_id = _make_key(stack.client)
    stack.policies.put(
        "t",
        [Rule(subject="mallory", actions=("read",), effect="deny"),
         Rule(subject="alice", actions=("read",), effect="allow")])
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id,
        operator="mallory")
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    reads = [e for e in stack.audit._read_all()
             if e.tenant_id == "t" and e.action == "read"]
    assert reads[-1].outcome == "rejected"
    assert reads[-1].key_id == key_id
    status, _ = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id)
    assert status == 200
    reads = [e for e in stack.audit._read_all()
             if e.tenant_id == "t" and e.action == "read"]
    assert reads[-1].outcome == "success"
    assert reads[-1].key_id == key_id


def test_parameter_validation_and_audit_rules(stack):
    key_id = _make_key(stack.client)

    def read_and_conflict_events():
        return [e for e in stack.audit._read_all()
                if e.action in ("read", "tenant_conflict")]

    baseline = read_and_conflict_events()
    status, body = stack.client.call(
        "GET", "/v1/keys/not-a-uuid/versions?tenant_id=t")
    assert status == 400
    assert "key_id" in body["error"]
    for query in ("limit=0", "limit=1001", "limit=abc", "limit=",
                  "limit=1&limit=2", "cursor=", "cursor=garbage"):
        status, body = stack.client.call(
            "GET",
            "/v1/keys/%s/versions?tenant_id=t&%s" % (key_id, query))
        assert status == 400, (query, body)
    assert read_and_conflict_events() == baseline

    before = len(stack.audit._read_all())
    status, _ = stack.client.call(
        "GET", "/v1/keys/%s/versions" % key_id,
        headers={"X-Tenant-Id": "t"})
    # A single header source is valid; header + disagreeing query conflicts.
    assert status == 200
    status, _ = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id,
        headers={"X-Tenant-Id": "other"})
    assert status == 400
    conflicts = [e for e in stack.audit._read_all()[before:]
                 if e.action == "tenant_conflict"]
    assert len(conflicts) == 1


def test_cli_matches_http(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)

    def run_cli(*extra, expect_code=0):
        proc = subprocess.run(
            [sys.executable, "-m", "keymgr",
             "--data-dir", stack.data_dir, "versions",
             "--tenant-id", "t", "--operator", "alice",
             "--key-id", key_id] + list(extra),
            cwd=REPO_ROOT, capture_output=True, text=True)
        assert proc.returncode == expect_code, proc.stderr
        return json.loads(proc.stdout if expect_code == 0 else proc.stderr)

    status, http_body = stack.client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % key_id)
    assert status == 200
    assert run_cli() == http_body

    paged = []
    cursor = None
    while True:
        args = ["--limit", "1"]
        if cursor is not None:
            args += ["--cursor", cursor]
        body = run_cli(*args)
        paged.extend(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert paged == http_body["items"]

    # Error mapping: bad parameter -> 2, denial -> 3, unknown -> 4,
    # stale cursor -> 2.
    bad = run_cli("--limit", "0", expect_code=2)
    assert "limit" in bad["error"]
    run_cli("--cursor", "garbage", expect_code=2)
    unknown = "00000000-0000-4000-8000-000000000000"
    proc = subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", stack.data_dir,
         "versions", "--tenant-id", "t", "--operator", "alice",
         "--key-id", unknown],
        cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 4
    assert json.loads(proc.stderr) == {"error": "key not found"}
    stack.policies.put(
        "t", [Rule(subject="alice", actions=("read",), effect="deny")])
    proc = subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", stack.data_dir,
         "versions", "--tenant-id", "t", "--operator", "alice",
         "--key-id", key_id],
        cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 3
