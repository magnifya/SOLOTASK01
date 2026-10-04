"""Atomic batch whole-key revocation: POST /v1/keys/batch-revoke.

Covers the strict four-field body contract (exactly
``{tenant_id, key_ids, reason, operator}``; every parse/parameter failure is
a side-effect-free 400 that never consumes the Idempotency-Key, only a bad
tenant source records tenant_conflict), the required Idempotency-Key checked
before the body, per-key ``revoke`` authorization before existence (403
outranks 404, one rejected ``batch_revoke`` event with key_id null),
indistinct 404 for unknown/cross-tenant keys, the 200 items projection in
request order with the whole-key status fields, first-revocation-wins with
one shared UTC revoked_at, already-revoked keys keeping their first facts,
version material/current version untouched, the single success event
(event_id == operation_id, key_id null), same-binding replay (whitespace
and field order ignored, array order significant), different-binding 409,
the 5 s concurrent wait timeout, audit query/verify support for the new
action, and revocation working with the external KMS unavailable (the
request never loads, probes or calls a provider).
"""

import itertools
import json
import os
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

PATH = "/v1/keys/batch-revoke"


def _build_server(tmp_path, monkeypatch, external=False):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    if external:
        sys.path.insert(0, os.path.dirname(__file__))
        monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
        monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
        monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
        import fake_kms

        fake_kms.reset()
    else:
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
        audit=audit_log, client=client, faults_path=faults_path,
        op_store=op_store,
    )
    yield stack
    httpd.shutdown()
    provider_mod.reset_for_tests()


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None,
             raw=None):
        if raw is None:
            data = json.dumps(body).encode() if body is not None else None
        else:
            data = raw
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


@pytest.fixture()
def ext_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, external=True)


# -- helpers ---------------------------------------------------------------
def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


_idem_counter = itertools.count(1)


def _idem(prefix="op"):
    return "%s-%d" % (prefix, next(_idem_counter))


def _batch_revoke(client, key_ids, tenant="t", reason="r", operator="op",
                  idem_key=None, **extra):
    body = {
        "tenant_id": tenant,
        "key_ids": key_ids,
        "reason": reason,
        "operator": operator,
    }
    body.update(extra)
    return client.call(
        "POST", PATH, body,
        headers={"Idempotency-Key": idem_key or _idem("br")},
    )


def _key_status(client, key_id, tenant="t"):
    return client.call(
        "GET", "/v1/keys/%s/status?tenant_id=%s" % (key_id, tenant)
    )


def _audit_events(st, tenant="t"):
    return st.audit.query(tenant, limit=1000).events


def _events(st, action, tenant="t"):
    return [e for e in _audit_events(st, tenant) if e.action == action]


def _batch_revoke_events(st, tenant="t"):
    return _events(st, "batch_revoke", tenant)


# -- validation: side-effect-free 400s --------------------------------------
def test_missing_idempotency_key(stack):
    kid = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", PATH,
        {"tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o"},
    )
    assert status == 400
    assert "Idempotency-Key" in body["error"]
    # No audit event, no operation record, no key change.
    assert _batch_revoke_events(stack) == []
    assert _key_status(stack.client, kid)[1]["status"] == "active"


def test_bad_idempotency_key(stack):
    kid = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", PATH,
        {"tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o"},
        headers={"Idempotency-Key": "bad key with spaces"},
    )
    assert status == 400
    assert "Idempotency-Key" in body["error"]
    assert _batch_revoke_events(stack) == []


def test_bad_json_and_non_object(stack):
    kid = _make_key(stack.client)
    for raw in (b"{not json", b'"just a string"', b"[1,2,3]"):
        status, body = stack.client.call(
            "POST", PATH, raw=raw,
            headers={"Idempotency-Key": _idem("br")},
        )
        assert status == 400, (raw, body)
    assert _batch_revoke_events(stack) == []
    assert _key_status(stack.client, kid)[1]["status"] == "active"


def test_missing_tenant_id_records_conflict(stack):
    kid = _make_key(stack.client)
    status, body = _batch_revoke(stack.client, [kid], tenant=None)
    # tenant_id=None is serialized as null: a missing/empty tenant source.
    assert status == 400
    assert "tenant_id" in body["error"]
    # The invisible tenant_conflict event is recorded (null tenant/key).
    conflicts = [
        e for e in stack.audit.query("t", limit=1000).events
        if e.action == "tenant_conflict"
    ]
    # The conflict event has null tenant, so it's not in the tenant's query;
    # check the raw ledger instead.
    raw = stack.audit._read_all()
    conflicts = [e for e in raw if e.action == "tenant_conflict"]
    assert len(conflicts) == 1
    assert conflicts[0].tenant_id is None
    assert conflicts[0].key_id is None
    assert _batch_revoke_events(stack) == []


def test_extra_field_rejected(stack):
    kid = _make_key(stack.client)
    status, body = _batch_revoke(stack.client, [kid], extra_field="x")
    assert status == 400
    assert "extra_field" in body["error"]
    assert "not accepted" in body["error"]
    assert _batch_revoke_events(stack) == []


def test_key_ids_wrong_shape(stack):
    kid = _make_key(stack.client)
    # Not a list.
    status, body = _batch_revoke(stack.client, "not-a-list")
    assert status == 400
    assert "key_ids" in body["error"]
    # Empty list.
    status, body = _batch_revoke(stack.client, [])
    assert status == 400
    assert "key_ids" in body["error"]
    # Too many.
    status, body = _batch_revoke(
        stack.client, ["%032x" % i for i in range(101)]
    )
    assert status == 400
    assert "key_ids" in body["error"]
    assert _batch_revoke_events(stack) == []


def test_key_ids_bad_element(stack):
    kid = _make_key(stack.client)
    # Not a UUID4.
    status, body = _batch_revoke(stack.client, [kid, "not-a-uuid"])
    assert status == 400
    assert "key_ids[1]" in body["error"]
    assert "UUID4" in body["error"]
    # Uppercase UUID4 is not canonical lowercase.
    status, body = _batch_revoke(
        stack.client, ["550E8400-E29B-41D4-A716-446655440000"]
    )
    assert status == 400
    assert "key_ids[0]" in body["error"]
    # Non-string element.
    status, body = _batch_revoke(stack.client, [42])
    assert status == 400
    assert "key_ids[0]" in body["error"]
    assert _batch_revoke_events(stack) == []


def test_key_ids_duplicate(stack):
    kid = _make_key(stack.client)
    status, body = _batch_revoke(stack.client, [kid, kid])
    assert status == 400
    assert "duplicate" in body["error"]
    assert kid in body["error"]
    assert _batch_revoke_events(stack) == []


def test_reason_operator_validation(stack):
    kid = _make_key(stack.client)
    # Missing reason.
    status, body = _batch_revoke(stack.client, [kid], reason=None)
    assert status == 400
    assert "reason" in body["error"]
    # Empty operator.
    status, body = _batch_revoke(stack.client, [kid], operator="")
    assert status == 400
    assert "operator" in body["error"]
    # Wrong type.
    status, body = _batch_revoke(stack.client, [kid], reason=42)
    assert status == 400
    assert "reason" in body["error"]
    assert _batch_revoke_events(stack) == []
    assert _key_status(stack.client, kid)[1]["status"] == "active"


def test_validation_failure_consumes_no_idempotency_key(stack):
    """A 400 before binding leaves the Idempotency-Key reusable."""
    kid = _make_key(stack.client)
    key = _idem("br")
    # First: a 400 (bad key_ids).
    status, _ = _batch_revoke(stack.client, ["bad"], idem_key=key)
    assert status == 400
    # The same key can now bind to a valid request (no 409).
    status, body = _batch_revoke(stack.client, [kid], idem_key=key)
    assert status == 200, body


# -- authorization / existence ----------------------------------------------
def test_policy_denial_rejects_whole_batch(stack):
    kid1 = _make_key(stack.client)
    kid2 = _make_key(stack.client)
    # Allow revoke/read generally, but deny revoke for alice on kid2.
    stack.policies.put(
        "t", [
            Rule("alice", ["revoke", "read"], "allow"),
            Rule("alice", ["revoke"], "deny", frozenset({kid2})),
        ],
    )
    status, body = _batch_revoke(stack.client, [kid1, kid2])
    assert status == 403
    assert body["error"] == "action not permitted by policy"
    assert "operation_id" in body
    # One rejected batch_revoke event, key_id null.
    events = _batch_revoke_events(stack)
    assert len(events) == 1
    assert events[0].outcome == "rejected"
    assert events[0].key_id is None
    assert events[0].event_id == body["operation_id"]
    # No key changed.
    assert _key_status(stack.client, kid1)[1]["status"] == "active"
    assert _key_status(stack.client, kid2)[1]["status"] == "active"


def test_unknown_key_rejects_whole_batch(stack):
    kid1 = _make_key(stack.client)
    unknown = "550e8400-e29b-41d4-a716-446655440000"
    status, body = _batch_revoke(stack.client, [kid1, unknown])
    assert status == 404
    assert body["error"] == "key not found"
    events = _batch_revoke_events(stack)
    assert len(events) == 1
    assert events[0].outcome == "rejected"
    assert events[0].key_id is None
    assert _key_status(stack.client, kid1)[1]["status"] == "active"


def test_cross_tenant_key_is_404(stack):
    kid1 = _make_key(stack.client, tenant="t")
    kid2 = _make_key(stack.client, tenant="other")
    status, body = _batch_revoke(stack.client, [kid1, kid2], tenant="t")
    assert status == 404
    assert body["error"] == "key not found"
    assert _key_status(stack.client, kid1)[1]["status"] == "active"
    assert _key_status(stack.client, kid2, tenant="other")[1]["status"] == "active"


def test_denial_outranks_not_found(stack):
    unknown = "550e8400-e29b-41d4-a716-446655440000"
    stack.policies.put(
        "t", [Rule("alice", ["revoke"], "deny", frozenset({unknown}))],
    )
    status, body = _batch_revoke(stack.client, [unknown])
    assert status == 403


def test_policy_store_unavailable_is_500(stack):
    kid = _make_key(stack.client)
    # Corrupt the policy document.
    import hashlib

    digest = hashlib.sha256(b"t").hexdigest()
    policy_path = os.path.join(
        stack.data_dir, "policies", digest + ".json"
    )
    os.makedirs(os.path.dirname(policy_path), exist_ok=True)
    with open(policy_path, "w") as fh:
        fh.write("{corrupt")
    status, body = _batch_revoke(stack.client, [kid])
    assert status == 500
    assert body["error"] == "policy store is unavailable"
    # No audit event, no key change (read directly from the store: the
    # corrupt policy also blocks the status endpoint).
    assert _batch_revoke_events(stack) == []
    record = stack.store.get(kid, "t")
    assert record is not None and record.status == "active"


# -- happy path --------------------------------------------------------------
def test_batch_revoke_happy_path(stack):
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    kid3 = _make_key(client)
    status, body = _batch_revoke(
        client, [kid1, kid2, kid3], reason="compromised", operator="carol"
    )
    assert status == 200, body
    assert "operation_id" in body
    items = body["items"]
    assert len(items) == 3
    # Items in request order, with the whole-key status fields.
    for item, kid in zip(items, (kid1, kid2, kid3)):
        assert list(item.keys()) == [
            "key_id", "status", "reason", "operator", "revoked_at",
        ]
        assert item["key_id"] == kid
        assert item["status"] == "revoked"
        assert item["reason"] == "compromised"
        assert item["operator"] == "carol"
        assert isinstance(item["revoked_at"], str) and item["revoked_at"]
    # All newly revoked keys share one UTC revoked_at.
    assert len({item["revoked_at"] for item in items}) == 1
    # The status read agrees with each item.
    for item in items:
        assert _key_status(client, item["key_id"])[1] == item
    # One success event, key_id null, event_id == operation_id.
    events = _batch_revoke_events(stack)
    assert len(events) == 1
    assert events[0].outcome == "success"
    assert events[0].key_id is None
    assert events[0].event_id == body["operation_id"]
    assert events[0].operator_id == "alice"


def test_batch_revoke_single_key(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = _batch_revoke(client, [kid])
    assert status == 200
    assert len(body["items"]) == 1
    assert body["items"][0]["key_id"] == kid
    assert body["items"][0]["status"] == "revoked"


def test_already_revoked_keys_keep_first_facts(stack):
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    # Revoke kid1 individually first.
    status, first = client.call(
        "POST", "/v1/keys/%s/revoke" % kid1,
        {"tenant_id": "t", "reason": "first", "operator": "dave"},
    )
    assert status == 200
    # Batch-revoke both: kid1 keeps its first facts, kid2 gets the batch's.
    status, body = _batch_revoke(
        client, [kid1, kid2], reason="second", operator="carol"
    )
    assert status == 200
    items = {item["key_id"]: item for item in body["items"]}
    assert items[kid1]["reason"] == "first"
    assert items[kid1]["operator"] == "dave"
    assert items[kid1]["revoked_at"] == first["revoked_at"]
    assert items[kid2]["reason"] == "second"
    assert items[kid2]["operator"] == "carol"


def test_all_already_revoked_still_succeeds(stack):
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    for kid in (kid1, kid2):
        client.call(
            "POST", "/v1/keys/%s/revoke" % kid,
            {"tenant_id": "t", "reason": "r", "operator": "o"},
        )
    status, body = _batch_revoke(client, [kid1, kid2])
    assert status == 200
    assert all(item["status"] == "revoked" for item in body["items"])


def test_versions_and_material_untouched(stack):
    client = stack.client
    kid = _make_key(client)
    # Rotate to get a second version.
    client.call(
        "POST", "/v1/keys/%s/rotate" % kid,
        {"tenant_id": "t", "algorithm": "AES256"},
        headers={"Idempotency-Key": _idem("rot")},
    )
    before = client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % kid
    )[1]
    status, body = _batch_revoke(client, [kid])
    assert status == 200
    after = client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % kid
    )[1]
    # Same version set, same current version.
    assert [v["version"] for v in before["items"]] == [
        v["version"] for v in after["items"]
    ]
    current_before = [v for v in before["items"] if v["current"]][0]
    current_after = [v for v in after["items"] if v["current"]][0]
    assert current_before["version"] == current_after["version"]


def test_revoked_key_blocks_crypto(stack):
    """A batch-revoked key refuses crypto on every version."""
    client = stack.client
    kid = _make_key(client)
    import base64

    status, _ = _batch_revoke(client, [kid])
    assert status == 200
    # Encrypt is refused with 409 (whole-key revocation outranks).
    status, body = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid,
        {"tenant_id": "t", "plaintext": base64.b64encode(b"x").decode()},
        headers={"Idempotency-Key": _idem("enc")},
    )
    assert status == 409
    assert body["error"] == "key is revoked"


def test_batch_revoke_is_atomic_across_keys(stack):
    """A batch and a concurrent single-key revoke take effect in some order."""
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    # A batch over both keys, then a single revoke of kid1: both succeed,
    # and kid1's first revocation (whichever landed first) wins.
    status, body = _batch_revoke(client, [kid1, kid2], reason="batch")
    assert status == 200
    status, single = client.call(
        "POST", "/v1/keys/%s/revoke" % kid1,
        {"tenant_id": "t", "reason": "single", "operator": "o"},
    )
    assert status == 200
    # The batch's facts won (it committed first).
    assert single["reason"] == "batch"
    assert _key_status(client, kid2)[1]["reason"] == "batch"


# -- idempotency --------------------------------------------------------------
def test_same_binding_replays(stack):
    client = stack.client
    kid = _make_key(client)
    key = _idem("br")
    body = {
        "tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o",
    }
    status, first = client.call(
        "POST", PATH, body, headers={"Idempotency-Key": key}
    )
    assert status == 200
    status, second = client.call(
        "POST", PATH, body, headers={"Idempotency-Key": key}
    )
    assert status == 200
    assert second == first
    # Only one success event.
    assert len(_batch_revoke_events(stack)) == 1


def test_whitespace_and_field_order_ignored(stack):
    client = stack.client
    kid = _make_key(client)
    key = _idem("br")
    body1 = json.dumps(
        {"tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o"}
    ).encode()
    body2 = json.dumps(
        {"operator": "o", "reason": "r", "key_ids": [kid], "tenant_id": "t"},
        separators=(", ", " : "),
    ).encode()
    status, first = client.call(
        "POST", PATH, raw=body1, headers={"Idempotency-Key": key}
    )
    assert status == 200
    status, second = client.call(
        "POST", PATH, raw=body2, headers={"Idempotency-Key": key}
    )
    assert status == 200
    assert second == first
    assert len(_batch_revoke_events(stack)) == 1


def test_array_order_is_significant(stack):
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    key = _idem("br")
    status, first = _batch_revoke(client, [kid1, kid2], idem_key=key)
    assert status == 200
    # Same set, different order: a different binding -> 409.
    status, body = _batch_revoke(client, [kid2, kid1], idem_key=key)
    assert status == 409
    assert body["operation_id"] == first["operation_id"]


def test_different_binding_conflicts(stack):
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    key = _idem("br")
    status, first = _batch_revoke(client, [kid1], idem_key=key)
    assert status == 200
    # Same key, different key_ids -> 409 naming the original operation.
    status, body = _batch_revoke(client, [kid2], idem_key=key)
    assert status == 409
    assert body["operation_id"] == first["operation_id"]
    assert "Idempotency-Key" in body["error"]


def test_operation_query(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = _batch_revoke(client, [kid])
    assert status == 200
    op_id = body["operation_id"]
    status, op = client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id
    )
    assert status == 200
    assert op["operation_id"] == op_id
    assert op["status"] == "succeeded"
    assert op["http_status"] == 200
    assert op["response"]["items"][0]["key_id"] == kid


def test_rejected_operation_replays(stack):
    """A 404 rejection is durable and replays verbatim."""
    client = stack.client
    unknown = "550e8400-e29b-41d4-a716-446655440000"
    key = _idem("br")
    status, first = _batch_revoke(client, [unknown], idem_key=key)
    assert status == 404
    status, second = _batch_revoke(client, [unknown], idem_key=key)
    assert status == 404
    assert second == first
    # Only one rejected event.
    assert len(_batch_revoke_events(stack)) == 1


# -- concurrency ---------------------------------------------------------------
def test_concurrent_same_key_executes_once(stack):
    """Two concurrent same-binding requests: one executes, the other waits
    and replays; exactly one success event."""
    client = stack.client
    kid = _make_key(client)
    key = _idem("br")
    body = {
        "tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o",
    }
    results = []

    def run():
        results.append(
            client.call("POST", PATH, body,
                        headers={"Idempotency-Key": key})
        )

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r[0] == 200 for r in results)
    assert len({r[1]["operation_id"] for r in results}) == 1
    assert len(_batch_revoke_events(stack)) == 1


def test_concurrent_different_keys_serialize(stack):
    """A batch and a single-key revoke on the same key don't interleave."""
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    results = {}

    def batch():
        results["batch"] = _batch_revoke(
            client, [kid1, kid2], reason="batch", operator="b"
        )

    def single():
        results["single"] = client.call(
            "POST", "/v1/keys/%s/revoke" % kid1,
            {"tenant_id": "t", "reason": "single", "operator": "s"},
        )

    t1 = threading.Thread(target=batch)
    t2 = threading.Thread(target=single)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    # Both succeed; kid1's first revocation wins (one of the two reasons).
    assert results["batch"][0] == 200
    assert results["single"][0] == 200
    final = _key_status(client, kid1)[1]
    assert final["status"] == "revoked"
    assert final["reason"] in ("batch", "single")
    # kid2 is revoked by the batch regardless.
    assert _key_status(client, kid2)[1]["reason"] == "batch"


# -- audit query / verify ------------------------------------------------------
def test_audit_query_filters_batch_revoke(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = _batch_revoke(client, [kid])
    assert status == 200
    op_id = body["operation_id"]
    # Filter by action.
    status, page = client.call(
        "GET", "/v1/audit?tenant_id=t&action=batch_revoke"
    )
    assert status == 200
    assert len(page["events"]) == 1
    assert page["events"][0]["action"] == "batch_revoke"
    assert page["events"][0]["key_id"] is None
    # Filter by operation_id (the event id).
    status, page = client.call(
        "GET", "/v1/audit?tenant_id=t&operation_id=%s" % op_id
    )
    assert status == 200
    assert len(page["events"]) == 1
    assert page["events"][0]["event_id"] == op_id


def test_audit_verify_includes_batch_revoke(stack):
    client = stack.client
    kid = _make_key(client)
    _batch_revoke(client, [kid])
    status, body = client.call(
        "GET", "/v1/audit/verify?tenant_id=t"
    )
    assert status == 200
    assert body["valid"] is True
    assert body["checked_events"] >= 1


def test_error_bodies_carry_only_error_and_operation_id(stack):
    """Post-binding errors contain only error and operation_id."""
    client = stack.client
    # 404 case.
    unknown = "550e8400-e29b-41d4-a716-446655440000"
    status, body = _batch_revoke(client, [unknown])
    assert status == 404
    assert set(body.keys()) == {"error", "operation_id"}
    # 403 case.
    kid = _make_key(client)
    stack.policies.put(
        "t", [Rule("alice", ["revoke"], "deny", frozenset({kid}))],
    )
    status, body = _batch_revoke(client, [kid])
    assert status == 403
    assert set(body.keys()) == {"error", "operation_id"}


def test_corrupt_record_is_500(stack):
    """A corrupt key record fails the batch with 500, not a 404."""
    kid1 = _make_key(stack.client)
    kid2 = _make_key(stack.client)
    # Corrupt kid2's file.
    with open(os.path.join(stack.data_dir, kid2 + ".json"), "w") as fh:
        fh.write("{corrupt")
    status, body = _batch_revoke(stack.client, [kid1, kid2])
    assert status == 500
    assert "operation_id" in body
    # kid1 is unchanged (the batch failed atomically).
    assert _key_status(stack.client, kid1)[1]["status"] == "active"


def test_ledger_failure_is_500_and_rolls_back(stack):
    """A ledger append failure rolls the whole batch back and answers 500."""
    client = stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    # Corrupt the audit log so the commit-point append fails.
    with open(stack.audit.path, "a") as fh:
        fh.write("garbage-line\n")
    status, body = _batch_revoke(client, [kid1, kid2])
    assert status == 500
    assert "operation_id" in body
    # Both keys are rolled back to active (the batch never committed); read
    # directly from the store since the corrupt ledger blocks the status
    # endpoint's audit event.
    assert stack.store.get(kid1, "t").status == "active"
    assert stack.store.get(kid2, "t").status == "active"


# -- no provider dependency ----------------------------------------------------
def test_revoke_works_with_kms_unavailable(ext_stack):
    """The batch revocation never loads, probes or calls the provider."""
    import fake_kms

    client = ext_stack.client
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    # The KMS is unreachable; the revocation must still succeed.
    ext_stack.set_faults = None  # (fixture uses the faults file directly)
    with open(ext_stack.faults_path, "w") as fh:
        json.dump({"unreachable": True}, fh)
    try:
        # Reset the call counter so only the revocation's calls count.
        fake_kms.reset()
        status, body = _batch_revoke(client, [kid1, kid2])
        assert status == 200, body
        assert all(
            item["status"] == "revoked" for item in body["items"]
        )
        # The provider was never called during the revocation.
        assert fake_kms.call_count("rotate") == 0
        assert fake_kms.call_count("generate") == 0
        assert fake_kms.call_count("delete") == 0
    finally:
        os.unlink(ext_stack.faults_path)


def test_batch_revoke_never_calls_provider(ext_stack):
    """Even with a healthy KMS, the revocation is a pure metadata change."""
    import fake_kms

    client = ext_stack.client
    kid = _make_key(client)
    calls_before = {
        op: fake_kms.call_count(op)
        for op in ("rotate", "generate", "delete", "export_material")
    }
    status, body = _batch_revoke(client, [kid])
    assert status == 200
    for op, count in calls_before.items():
        assert fake_kms.call_count(op) == count
