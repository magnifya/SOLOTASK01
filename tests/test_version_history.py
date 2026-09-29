"""GET /v1/keys/{key_id}/versions and the CLI ``versions`` subcommand.

Covers ascending committed-version history with merged single-version and
status fields plus a ``current`` flag, whole-key revocation projecting onto
every item while the history stays readable, signed snapshot-cursor
pagination (no duplicate/gap across pages; invalidated by rotation,
per-version revocation and whole-key revocation; tampered/limit-mismatched
cursors are 400), 400 parameter handling with no audit (except
tenant_conflict on a bad tenant source), 403 read/rejected and 200
read/success events carrying key_id, indistinct 404 for unknown and
cross-tenant keys, fixed 500 body on a corrupt ledger, and HTTP/CLI parity.
"""

import itertools
import json
import os
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import cli
from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore


ITEM_KEYS = [
    "key_id", "version", "created_at", "algorithm", "public_key",
    "status", "reason", "operator", "revoked_at", "current",
]


def _build_server(tmp_path, monkeypatch):
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
    handler = make_handler(
        store, policies, coordinator, op_store, artifact_store
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    stack = types.SimpleNamespace(
        data_dir=data_dir, store=store, policies=policies,
        audit=audit_log, client=client,
    )
    yield stack
    httpd.shutdown()
    provider_mod.reset_for_tests()


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
    yield from _build_server(tmp_path, monkeypatch)


_idem_counter = itertools.count(1)


def _idem(prefix="op"):
    return "%s-%d" % (prefix, next(_idem_counter))


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(client, key_id, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": _idem("rot")},
    )
    assert status == 201, body
    return body


def _history(client, key_id, tenant="t", **params):
    query = "tenant_id=%s" % tenant
    for name, value in params.items():
        query += "&%s=%s" % (name, value)
    return client.call(
        "GET", "/v1/keys/%s/versions?%s" % (key_id, query)
    )


def _events(stack, action="read"):
    return [e for e in stack.audit._read_all() if e.action == action]


def _all_pages(client, key_id, limit, tenant="t"):
    items = []
    cursor = None
    pages = 0
    while True:
        params = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        status, body = _history(client, key_id, tenant=tenant, **params)
        assert status == 200, body
        pages += 1
        items.extend(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    return pages, items


# -- happy path ------------------------------------------------------------
def test_history_item_shape_and_order(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    _rotate(client, kid)

    status, body = _history(client, kid)
    assert status == 200, body
    assert list(body.keys()) == ["items", "next_cursor"]
    assert body["next_cursor"] is None
    items = body["items"]
    assert [it["version"] for it in items] == [1, 2, 3]
    for item in items:
        assert list(item.keys()) == ITEM_KEYS
        assert item["key_id"] == kid
        assert item["status"] == "active"
        assert item["reason"] is None
        assert item["operator"] is None
        assert item["revoked_at"] is None
    assert [it["current"] for it in items] == [False, False, True]

    for item in items:
        _, ver_body = client.call(
            "GET",
            "/v1/keys/%s/versions/%d?tenant_id=t" % (kid, item["version"]),
        )
        _, status_body = client.call(
            "GET",
            "/v1/keys/%s/versions/%d/status?tenant_id=t"
            % (kid, item["version"]),
        )
        for field in ("version", "created_at", "algorithm", "public_key"):
            assert item[field] == ver_body[field]
        for field in ("status", "reason", "operator", "revoked_at"):
            assert item[field] == status_body[field]


def test_history_single_version_key(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = _history(client, kid)
    assert status == 200
    assert len(body["items"]) == 1
    assert body["items"][0]["version"] == 1
    assert body["items"][0]["current"] is True
    assert body["next_cursor"] is None


def test_history_pagination_no_dup_or_gap(stack):
    client = stack.client
    kid = _make_key(client)
    for _ in range(4):
        _rotate(client, kid)

    pages, items = _all_pages(client, kid, 2)
    assert pages == 3
    assert [it["version"] for it in items] == [1, 2, 3, 4, 5]
    assert len({it["version"] for it in items}) == 5

    pages, items = _all_pages(client, kid, 1)
    assert pages == 5
    assert [it["version"] for it in items] == [1, 2, 3, 4, 5]

    pages, items = _all_pages(client, kid, 1000)
    assert pages == 1 and len(items) == 5


# -- revocation projections ------------------------------------------------
def test_history_includes_version_revocation(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid,
        {"tenant_id": "t", "reason": "old", "operator": "bob"},
    )
    assert status == 200

    status, body = _history(client, kid)
    assert status == 200
    v1, v2 = body["items"]
    assert v1["status"] == "revoked"
    assert v1["reason"] == "old"
    assert v1["operator"] == "bob"
    assert v1["revoked_at"]
    assert v1["current"] is False
    assert v2["status"] == "active"
    assert v2["current"] is True
    assert v2["revoked_at"] is None


def test_history_readable_after_whole_key_revoke(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid,
        {"tenant_id": "t", "reason": "old", "operator": "bob"},
    )
    status, key_status = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "compromise", "operator": "carol"},
    )
    assert status == 200

    status, body = _history(client, kid)
    assert status == 200
    items = body["items"]
    assert [it["version"] for it in items] == [1, 2]
    for item in items:
        assert item["status"] == "revoked"
        assert item["reason"] == "compromise"
        assert item["operator"] == "carol"
        assert item["revoked_at"] == key_status["revoked_at"]
    assert [it["current"] for it in items] == [False, True]

    status, _ = client.call(
        "GET", "/v1/keys/%s/versions/1/status?tenant_id=t" % kid
    )
    assert status == 409


# -- cursor invalidation ---------------------------------------------------
def _first_cursor(client, kid, limit):
    status, body = _history(client, kid, limit=limit)
    assert status == 200 and body["next_cursor"]
    return body["next_cursor"]


def test_cursor_invalid_after_rotation(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    cursor = _first_cursor(client, kid, 1)
    _rotate(client, kid)
    status, body = _history(client, kid, limit=1, cursor=cursor)
    assert status == 400
    assert body == {"error": "invalid or expired cursor"}


def test_cursor_invalid_after_version_revoke(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    cursor = _first_cursor(client, kid, 1)
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid,
        {"tenant_id": "t", "reason": "old", "operator": "bob"},
    )
    assert status == 200
    status, body = _history(client, kid, limit=1, cursor=cursor)
    assert status == 400
    assert body == {"error": "invalid or expired cursor"}


def test_cursor_invalid_after_whole_key_revoke(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    cursor = _first_cursor(client, kid, 1)
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "x", "operator": "bob"},
    )
    assert status == 200
    status, body = _history(client, kid, limit=1, cursor=cursor)
    assert status == 400
    assert body == {"error": "invalid or expired cursor"}


def test_cursor_tampered_and_limit_mismatch(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    cursor = _first_cursor(client, kid, 1)

    status, body = _history(client, kid, limit=2, cursor=cursor)
    assert status == 400 and body["error"] == "invalid or expired cursor"

    tampered = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
    status, body = _history(client, kid, limit=1, cursor=tampered)
    assert status == 400 and body["error"] == "invalid or expired cursor"

    status, body = _history(client, kid, limit=1, cursor="not-a-cursor")
    assert status == 400 and body["error"] == "invalid or expired cursor"


# -- errors, audit, isolation ----------------------------------------------
def test_unknown_and_cross_tenant_are_404(stack):
    client = stack.client
    kid = _make_key(client)
    other = "00000000-0000-4000-8000-000000000000"
    status, body = _history(client, other)
    assert status == 404 and body == {"error": "key not found"}

    status, body = _history(client, kid, tenant="other")
    assert status == 404 and body == {"error": "key not found"}

    rejected = _events(stack)
    assert all(e.outcome == "rejected" and e.key_id in (kid, other)
               for e in rejected)
    assert len(rejected) == 2


def test_policy_denial_403_with_key_id(stack):
    client = stack.client
    kid = _make_key(client)
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["read"], effect="deny")]
    )
    status, body = _history(client, kid)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [e for e in _events(stack) if e.outcome == "rejected"]
    assert len(rejected) == 1 and rejected[0].key_id == kid

    status, _ = _history(client, kid, limit=0)
    assert status == 400


def test_success_audits_read_with_key_id(stack):
    client = stack.client
    kid = _make_key(client)
    before = len([e for e in _events(stack) if e.outcome == "success"])
    status, _ = _history(client, kid)
    assert status == 200
    successes = [e for e in _events(stack) if e.outcome == "success"]
    assert len(successes) == before + 1
    assert successes[-1].key_id == kid
    assert successes[-1].tenant_id == "t"


def test_parameter_errors_are_400_without_audit(stack):
    client = stack.client
    kid = _make_key(client)
    base_events = len(stack.audit._read_all())

    bad_key = "not-a-uuid"
    cases = [
        "/v1/keys/%s/versions?tenant_id=t" % bad_key,
        "/v1/keys/%s/versions?tenant_id=t&limit=0" % kid,
        "/v1/keys/%s/versions?tenant_id=t&limit=1001" % kid,
        "/v1/keys/%s/versions?tenant_id=t&limit=abc" % kid,
        "/v1/keys/%s/versions?tenant_id=t&limit=1&limit=2" % kid,
        "/v1/keys/%s/versions?tenant_id=t&cursor=" % kid,
        "/v1/keys/%s/versions?tenant_id=t&cursor=a&cursor=b" % kid,
        "/v1/keys/%s/versions?tenant_id=t&cursor=garbage" % kid,
    ]
    for path in cases:
        status, body = client.call("GET", path)
        assert status == 400, (path, body)
        assert "error" in body
    assert len(stack.audit._read_all()) == base_events

    # A missing tenant source is still a tenant_conflict, then 400.
    status, _ = client.call("GET", "/v1/keys/%s/versions" % kid)
    assert status == 400
    conflicts = [
        e for e in stack.audit._read_all() if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1
    assert conflicts[0].tenant_id is None


def test_corrupt_ledger_is_fixed_500(stack, tmp_path):
    client = stack.client
    kid = _make_key(client)
    ledger = os.path.join(stack.data_dir, "audit.log")
    with open(ledger, "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    status, body = _history(client, kid)
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}


# -- CLI parity ------------------------------------------------------------
def test_cli_versions_matches_http(stack, capsys):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    _rotate(client, kid)
    _, http_body = _history(client, kid)

    rc = cli.main([
        "--data-dir", stack.data_dir, "versions",
        "--tenant-id", "t", "--operator", "alice",
        "--key-id", kid,
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out == http_body


def test_cli_versions_pagination(stack, capsys):
    client = stack.client
    kid = _make_key(client)
    for _ in range(2):
        _rotate(client, kid)

    collected = []
    cursor = None
    for _ in range(10):
        argv = [
            "--data-dir", stack.data_dir, "versions",
            "--tenant-id", "t", "--operator", "alice",
            "--key-id", kid, "--limit", "1",
        ]
        if cursor is not None:
            argv.extend(["--cursor", cursor])
        rc = cli.main(argv)
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        collected.extend(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert [it["version"] for it in collected] == [1, 2, 3]

    _, http_body = _history(client, kid)
    assert collected == http_body["items"]


def test_cli_versions_error_exit_codes(stack, capsys):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)
    _, body = _history(client, kid, limit=1)
    cursor = body["next_cursor"]

    def run(*extra, key_id=kid, operator="alice"):
        capsys.readouterr()
        argv = [
            "--data-dir", stack.data_dir, "versions",
            "--tenant-id", "t", "--operator", operator,
            "--key-id", key_id,
        ]
        argv.extend(extra)
        return cli.main(argv), capsys.readouterr()

    rc, _ = run("--limit", "0")
    assert rc == 2
    rc, _ = run("--limit", "1001")
    assert rc == 2
    rc, _ = run("--cursor", "tampered")
    assert rc == 2
    rc, _ = run("--cursor", cursor, "--limit", "2")
    assert rc == 2
    rc, captured = run(key_id="not-a-uuid")
    assert rc == 2
    rc, captured = run(key_id="00000000-0000-4000-8000-000000000000")
    assert rc == 4
    assert json.loads(captured.err)["error"] == "key not found"

    stack.policies.put(
        "t", [Rule(subject="alice", actions=["read"], effect="deny")]
    )
    rc, captured = run()
    assert rc == 3
    assert json.loads(captured.err)["error"] == (
        "action not permitted by policy"
    )
    denied = [
        e for e in stack.audit._read_all()
        if e.action == "read" and e.outcome == "rejected"
    ]
    assert denied and denied[-1].key_id == kid


def test_existing_reads_unchanged(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid)

    status, current = client.call(
        "GET", "/v1/keys/%s/current?tenant_id=t" % kid
    )
    assert status == 200 and current["version"] == 2
    status, v1 = client.call(
        "GET", "/v1/keys/%s/versions/1?tenant_id=t" % kid
    )
    assert status == 200 and v1["version"] == 1
    status, listing = client.call("GET", "/v1/keys?tenant_id=t")
    assert status == 200 and listing["next_cursor"] is None
    assert len(listing["items"]) == 1
    assert list(listing["items"][0].keys()) == [
        "key_id", "label", "current_version", "algorithm",
        "status", "created_at", "public_key",
    ]
    # The new endpoint must not shadow .../versions/{n} or its status.
    status, st = client.call(
        "GET", "/v1/keys/%s/versions/2/status?tenant_id=t" % kid
    )
    assert status == 200 and st["status"] == "active"
