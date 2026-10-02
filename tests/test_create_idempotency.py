"""Idempotency for POST /v1/keys (optional Idempotency-Key).

Covers the two algorithms, the header contract (present/optional, empty,
duplicate, illegal), the unchanged legacy behavior without the header,
side-effect-free pre-bind 400s (bad JSON, non-object body, missing/extra/
wrong-typed fields, bad algorithm), same-binding replay (same key_id,
algorithm, public_key, operation_id and audit; the provider is not invoked
twice; JSON whitespace and key order ignored), same-key/different-binding
409 naming the original operation, authorization (one create/rejected ->
403 replay; one create/success with event_id == operation_id), the fixed
provider-unavailable 503 (no audit, retry continues exactly once), the 5 s
concurrent wait timeout, GET-operation pending hiding, and crash
consistency: a committed operation replays its original complete 201 after
restart even when the key was rotated afterwards; an uncommitted operation
rolls the new key/handle back and replays failed(500); unconfirmed cleanup
keeps the evidence and stays pending with a 500.
"""

import glob
import json
import os
import threading
import time
import types
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer

import pytest

from keymgr import operations as operations_mod
from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.provider import ProviderUnavailable
from keymgr.server import make_handler
from keymgr.store import KeyStore

PATH = "/v1/keys"


def _build(tmp_path):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    return (
        data_dir, audit_log, store, policies, coordinator, op_store,
        artifact_store,
    )


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, headers=None,
             operator="alice", raw=None):
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
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    parts = _build(tmp_path)
    (data_dir, audit_log, store, policies, coordinator, op_store,
     art) = parts
    handler = make_handler(store, policies, coordinator, op_store, art)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    yield types.SimpleNamespace(
        data_dir=data_dir, audit=audit_log, store=store, policies=policies,
        op_store=op_store, artifacts=art, client=client, tmp=tmp_path,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _body(algorithm="AES256", label="k", tenant="t"):
    return {"tenant_id": tenant, "algorithm": algorithm, "label": label}


def _create(stack, idem_key, algorithm="AES256", label="k", tenant="t",
            operator="alice", body=None):
    headers = {"Idempotency-Key": idem_key}
    return stack.client.call(
        "POST", PATH, body or _body(algorithm, label, tenant),
        headers=headers, operator=operator,
    )


def _restart(ns):
    data_dir = ns.data_dir
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    ns.audit, ns.store, ns.policies = audit_log, store, policies
    ns.op_store, ns.artifacts = op_store, artifact_store
    return store, policies, coordinator, op_store, artifact_store


def _serve(ns, parts):
    store, policies, coordinator, op_store, art = parts
    handler = make_handler(store, policies, coordinator, op_store, art)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, Client("http://127.0.0.1:%d" % httpd.server_address[1])


def _create_events(ns):
    return [
        e for e in ns.audit._read_all()
        if e.action == "create" and e.outcome == "success"
    ]


# ------------------------------------------------------- legacy / no header
def test_no_header_keeps_legacy_behavior(stack):
    status, body = stack.client.call("POST", PATH, _body())
    assert status == 201
    assert set(body) == {"key_id", "algorithm", "public_key"}
    assert "operation_id" not in body
    # Every no-header request still mints a fresh key (non-idempotent).
    status2, body2 = stack.client.call("POST", PATH, _body())
    assert status2 == 201 and body2["key_id"] != body["key_id"]
    # No operation records or mirror directory were created.
    assert not glob.glob(os.path.join(stack.data_dir, "operations", "*.json"))
    assert not os.path.exists(
        os.path.join(stack.data_dir, "operation-artifacts")
    )


@pytest.mark.parametrize("algorithm,public_key", [
    ("AES256", None),
    ("RSA2048", "pem"),
])
def test_idempotent_create_both_algorithms(stack, algorithm, public_key):
    status, body = _create(stack, "key-%s" % algorithm, algorithm=algorithm)
    assert status == 201
    assert set(body) == {"key_id", "algorithm", "public_key", "operation_id"}
    assert body["algorithm"] == algorithm
    if algorithm == "AES256":
        assert body["public_key"] is None
    else:
        assert body["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    # A fresh key starts at active version 1.
    record = stack.store.get(body["key_id"], "t")
    assert record.current_version == 1 and record.status == "active"
    # Exactly one create/success event, named after the operation_id.
    events = _create_events(stack)
    assert len(events) == 1
    assert events[0].event_id == body["operation_id"]
    assert events[0].key_id == body["key_id"]


def test_empty_label_is_accepted(stack):
    status, body = _create(stack, "empty-label", label="")
    assert status == 201
    record = stack.store.get(body["key_id"], "t")
    assert record.label == ""


def test_replay_ignores_json_whitespace_and_key_order(stack):
    import http.client

    status, first = _create(stack, "replay-1", label="L")
    assert status == 201
    host, port = stack.client.base.replace("http://", "").split(":")
    conn = http.client.HTTPConnection(host, int(port))
        # Same binding expressed with different key order + whitespace.
    raw = b'{ "label":  "L" ,  "tenant_id":"t" , "algorithm":"AES256" }'
    conn.request(
        "POST", PATH, raw,
        {"X-Operator-Id": "alice", "Content-Type": "application/json",
         "Idempotency-Key": "replay-1"},
    )
    resp = conn.getresponse()
    again = json.loads(resp.read())
    assert resp.status == 201 and again == first
    # The provider minted exactly one key; exactly one success event.
    assert len(_create_events(stack)) == 1


def test_same_key_different_binding_is_409(stack):
    status, first = _create(stack, "shared", algorithm="AES256")
    assert status == 201
    # Every binding element change is a conflict: label differs.
    status, body = _create(stack, "shared", algorithm="AES256", label="other")
    assert status == 409
    assert set(body) == {"error", "operation_id"}
    assert body["operation_id"] == first["operation_id"]
    # tenant differs
    status, body = _create(stack, "shared", algorithm="AES256", tenant="t2")
    assert status == 409 and body["operation_id"] == first["operation_id"]
    # operator differs
    status, body = _create(
        stack, "shared", algorithm="AES256", operator="bob"
    )
    assert status == 409 and body["operation_id"] == first["operation_id"]
    # algorithm differs
    status, body = _create(stack, "shared", algorithm="RSA2048")
    assert status == 409 and body["operation_id"] == first["operation_id"]
    # No extra keys were created and no extra audit event was appended.
    assert len(_create_events(stack)) == 1


# --------------------------------------------------------- header / pre-bind
def _audit_actions(stack):
    return [e.action for e in stack.audit._read_all()]


@pytest.mark.parametrize("value", ["", "with space", "slash/x", "caf\u00e9",
                                  "x" * 129])
def test_illegal_idempotency_key_is_400_naming_header(stack, value):
    status, body = stack.client.call(
        "POST", PATH, _body(), headers={"Idempotency-Key": value},
    )
    assert status == 400 and "Idempotency-Key" in body["error"]
    assert set(body) == {"error"}
    # No audit, no operation, no key file beyond nothing.
    assert _audit_actions(stack) == []
    assert not glob.glob(os.path.join(stack.data_dir, "operations", "*.json"))


def test_duplicate_idempotency_key_header_is_400(stack):
    import http.client

    host, port = stack.client.base.replace("http://", "").split(":")
    conn = http.client.HTTPConnection(host, int(port))
    raw = json.dumps(_body()).encode()
    conn.putrequest("POST", PATH)
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Idempotency-Key", "a")
    conn.putheader("Idempotency-Key", "b")
    conn.putheader("Content-Length", str(len(raw)))
    conn.endheaders(raw)
    resp = conn.getresponse()
    assert resp.status == 400
    assert "Idempotency-Key" in resp.read().decode()
    assert _audit_actions(stack) == []


@pytest.mark.parametrize("raw,expect_field", [
    (b"{", None),
    (b"[1, 2, 3]", None),
    (b'"string"', None),
    (b"null", None),
    (b'{"tenant_id":"t","algorithm":"AES256"}', "label"),
    (b'{"tenant_id":"t","label":"k"}', "algorithm"),
    (b'{"algorithm":"AES256","label":"k"}', "tenant_id"),
    (b'{"tenant_id":"","algorithm":"AES256","label":"k"}', "tenant_id"),
    (b'{"tenant_id":"t","algorithm":"AES256","label":3}', "label"),
    (b'{"tenant_id":"t","algorithm":7,"label":"k"}', "algorithm"),
    (b'{"tenant_id":7,"algorithm":"AES256","label":"k"}', "tenant_id"),
    (b'{"tenant_id":"t","algorithm":"AES128","label":"k"}', "algorithm"),
    (b'{"tenant_id":"t","algorithm":"aes256","label":"k"}', "algorithm"),
    (b'{"tenant_id":"t","algorithm":"AES256","label":"k","extra":1}',
     "extra"),
    (b'{"tenant_id":"t","algorithm":"AES256","label":"k","tenant":9}',
     "tenant"),
    (b'true', None),
])
def test_bad_bodies_are_400_with_no_side_effects(stack, raw, expect_field):
    status, body = stack.client.call(
        "POST", PATH, raw=raw, headers={"Idempotency-Key": "bind-1"},
    )
    assert status == 400, body
    if expect_field is not None:
        assert expect_field in body["error"]
    assert set(body) == {"error"}
    # The key is never consumed: the same header with a valid body binds and
    # succeeds, and no audit/operation/key side effect happened before it.
    status, ok = stack.client.call(
        "POST", PATH, _body(), headers={"Idempotency-Key": "bind-1"},
    )
    assert status == 201, ok
    assert [e.action for e in _create_events(stack)] == ["create"]


def test_bad_body_does_not_write_audit_even_with_known_tenant(stack):
    status, body = stack.client.call(
        "POST", PATH,
        raw=b'{"tenant_id":"t","algorithm":"AES256","label":9}',
        headers={"Idempotency-Key": "z"},
    )
    assert status == 400 and "label" in body["error"]
    assert _audit_actions(stack) == []


def test_tenant_conflict_still_records_invisible_event(stack):
    # Header/body tenant disagreement pre-bind: 400 naming tenant_id and the
    # invisible tenant_conflict event is still written.
    status, body = stack.client.call(
        "POST", PATH, _body(tenant="t"),
        headers={"Idempotency-Key": "k", "X-Tenant-Id": "other"},
    )
    assert status == 400 and "tenant_id" in body["error"]
    events = stack.audit._read_all()
    assert [e.action for e in events] == ["tenant_conflict"]
    assert events[0].tenant_id is None
    # The conflict never consumed the idempotency key.
    status, ok = _create(stack, "k", tenant="other")
    assert status == 201, ok


def test_tenant_header_and_body_agree(stack):
    status, body = stack.client.call(
        "POST", PATH, _body(tenant="t"),
        headers={"Idempotency-Key": "agree", "X-Tenant-Id": "t"},
    )
    assert status == 201


# --------------------------------------------------------------- authorization
def test_policy_rejection_is_403_recorded_and_replayed(stack):
    stack.policies.put("t", [Rule("alice", ["create"], "deny")])
    status, body = _create(stack, "denied")
    assert status == 403
    assert set(body) == {"error", "operation_id"}
    op_id = body["operation_id"]
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "create" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].event_id == op_id
    assert rejected[0].key_id is None
    # A replay returns the same 403 and records no second event.
    status, again = _create(stack, "denied")
    assert status == 403 and again == body
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "create" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    # GET operation shows the failed terminal with the 403 body.
    status, got = stack.client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id
    )
    assert status == 200 and got["status"] == "failed"
    assert got["http_status"] == 403 and got["response"] == body


def test_other_tenant_cannot_read_operation(stack):
    status, body = _create(stack, "scoped")
    assert status == 201
    status, _ = stack.client.call(
        "GET", "/v1/operations/%s?tenant_id=other" % body["operation_id"]
    )
    assert status == 404


def test_different_operator_cannot_read_operation(stack):
    status, body = _create(stack, "scoped2")
    assert status == 201
    status, _ = stack.client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % body["operation_id"],
        operator="bob",
    )
    assert status == 404


# ---------------------------------------------------------- provider failures
def test_provider_unavailable_is_503_pending_no_audit_then_runs_once(
    stack, monkeypatch
):
    provider = provider_mod.get_provider()
    original_generate = provider.generate

    def broken_generate(algorithm):
        raise ProviderUnavailable("injected outage")

    monkeypatch.setattr(provider, "generate", broken_generate)
    status, body = _create(stack, "outage")
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    assert set(body) == {"error", "operation_id"}
    op_id = body["operation_id"]
    # No audit event; the operation stays pending and hides its response.
    assert _audit_actions(stack) == []
    record = stack.op_store._read_record(op_id)
    assert record.status == "pending"
    status, got = stack.client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id
    )
    assert got["status"] == "pending" and got["http_status"] is None
    assert got["response"] is None
    # No key file or orphaned handle survived the failed attempt.
    key_files = [
        n for n in os.listdir(stack.data_dir)
        if n.endswith(".json") and len(n) == 41
    ]
    assert key_files == []
    assert not glob.glob(os.path.join(stack.data_dir, "provisions", "*.json"))

    # Provider recovers; the identical retry runs exactly once and succeeds.
    monkeypatch.setattr(provider, "generate", original_generate)
    status, ok = _create(stack, "outage")
    assert status == 201 and ok["operation_id"] == op_id
    events = _create_events(stack)
    assert len(events) == 1 and events[0].event_id == op_id
    # One more retry is a pure replay; generate is not invoked again.
    calls = [0]

    def counting_generate(algorithm):
        calls[0] += 1
        return original_generate(algorithm)

    monkeypatch.setattr(provider, "generate", counting_generate)
    status, replay = _create(stack, "outage")
    assert status == 201 and replay == ok
    assert calls[0] == 0


# --------------------------------------------------------------- concurrency
def test_concurrent_same_key_executes_once(stack):
    provider = provider_mod.get_provider()
    release = threading.Event()
    entered = threading.Event()
    original_generate = provider.generate

    def blocking_generate(algorithm):
        entered.set()
        assert release.wait(timeout=10)
        return original_generate(algorithm)

    provider.generate = blocking_generate
    results = []

    def request():
        results.append(_create(stack, "concurrent-1"))

    try:
        first = threading.Thread(target=request)
        first.start()
        assert entered.wait(timeout=5)
        second = threading.Thread(target=request)
        second.start()
        time.sleep(0.3)
        release.set()
        first.join(timeout=10)
        second.join(timeout=10)
    finally:
        provider.generate = original_generate
        release.set()

    assert len(results) == 2
    assert all(status == 201 for status, _ in results)
    assert results[0][1] == results[1][1]
    # Exactly one key, one operation, one audit event; one provider call.
    assert len(_create_events(stack)) == 1
    key_ids = {b["key_id"] for _, b in results}
    assert key_ids == {results[0][1]["key_id"]}


def test_concurrent_wait_over_five_seconds_is_503_and_writes_nothing(
    stack, monkeypatch
):
    # Shorten the waiter poll deadline so the suite stays fast; the waiter
    # writes nothing (its record stays pending) and answers timed_out.
    monkeypatch.setattr(
        OperationStore.await_terminal,
        "__defaults__",
        (0.6,),
    )
    provider = provider_mod.get_provider()
    release = threading.Event()
    entered = threading.Event()
    original_generate = provider.generate

    def blocking_generate(algorithm):
        entered.set()
        assert release.wait(timeout=10)
        return original_generate(algorithm)

    provider.generate = blocking_generate
    try:
        owner_result = []

        def owner():
            owner_result.append(_create(stack, "slow-key"))

        first = threading.Thread(target=owner)
        first.start()
        assert entered.wait(timeout=5)

        status, waiter = _create(stack, "slow-key")
        assert status == 503
        assert waiter["error"] == "operation timed out waiting for a lock"
        assert set(waiter) == {"error", "operation_id"}
        waiter_op = waiter["operation_id"]
        record = stack.op_store._read_record(waiter_op)
        # The waiter writes NOTHING: the owner's record stays pending
        # and the 503 answer persisted no state of its own.
        assert record.status == "pending" and record.http_status is None
        assert stack.audit.get_event(waiter_op) is None

        release.set()
        first.join(timeout=10)
        assert owner_result and owner_result[0][0] == 201
        # The owner's success still carries the SAME operation id; a later
        # retry replays the committed 201.
        status, body = _create(stack, "slow-key")
        assert status == 201
        assert body["operation_id"] == waiter_op
    finally:
        provider.generate = original_generate
        release.set()


# ------------------------------------------------------------- crash recovery
def test_committed_create_replays_original_201_after_restart_and_rotation(
    stack
):
    status, first = _create(stack, "durable", algorithm="RSA2048")
    assert status == 201
    op_id = first["operation_id"]
    key_id = first["key_id"]

    # Rotate the key (version 2, new algorithm/public key) and revoke nothing.
    status, rotated = stack.client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t", "algorithm": "RSA2048"},
        headers={"Idempotency-Key": "rotate-1"},
    )
    assert status == 201 and rotated["version"] == 2
    assert rotated["public_key"] != first["public_key"]

    # Restart like a new process; the committed create finalizes/replays from
    # the durable event + staged result.
    parts = _restart(stack)
    record = stack.op_store._read_record(op_id)
    assert record.status == "succeeded"
    assert record.http_status == 201
    assert record.response == first
    # The replay keeps the ORIGINAL version-1 algorithm and public key.
    assert record.response["algorithm"] == "RSA2048"
    assert record.response["public_key"] == first["public_key"]
    assert record.response["key_id"] == key_id

    # An HTTP retry after the rotation still replays the exact first 201.
    httpd, client = _serve(stack, parts)
    try:
        status, again = client.call(
            "POST", PATH, _body(algorithm="RSA2048"),
            headers={"Idempotency-Key": "durable"},
        )
        assert status == 201 and again == first
        # The mirror was cleaned after the verified commit.
        assert not os.path.exists(stack.artifacts.path_for(op_id))
    finally:
        httpd.shutdown()


def _craft_committed_create_scene(ns, algorithm="AES256"):
    """Bind + stage a create, append its success event (commit point), but
    never run finish(): exactly the crash window after the ledger append."""
    begin = ns.op_store.begin(
        "t", "alice", PATH,
        operations_mod.normalize_body(_body(algorithm=algorithm)),
        "post-crash",
    )
    op = begin.record
    key_id = str(uuid.uuid4())
    ns.op_store.update_details(
        op, {"kind": "create", "key_id": key_id, "algorithm": algorithm}
    )
    mirror = ns.artifacts.create(op)
    mirror.describe({"kind": "create", "write_set": [key_id]})

    def stage_success(committed_record):
        body = committed_record.to_create_response()
        body["operation_id"] = op.operation_id
        ns.op_store.stage_terminal(op, 201, body)

    record = ns.store.create(
        "t", algorithm, "k",
        event_id=op.operation_id, key_id=key_id,
        pre_commit=stage_success, mirror=mirror,
    )
    return op, record


def test_restart_commits_staged_scene_and_replays(stack):
    op, record = _craft_committed_create_scene(stack, "AES256")
    assert os.path.exists(stack.store._path_for(record.key_id))
    parts = _restart(stack)
    finished = stack.op_store._read_record(op.operation_id)
    assert finished.status == "succeeded"
    assert finished.http_status == 201
    body = finished.response
    assert set(body) == {"key_id", "algorithm", "public_key", "operation_id"}
    assert body["key_id"] == record.key_id
    assert body["algorithm"] == "AES256" and body["public_key"] is None
    assert body["operation_id"] == op.operation_id
    # The key is readable at version 1 and the journal/mirror are gone.
    assert stack.store.get(record.key_id, "t").current_version == 1
    assert not os.path.exists(stack.artifacts.path_for(op.operation_id))


def _craft_uncommitted_create_scene(ns, algorithm="AES256"):
    """Bind + journal + key marker of a create, WITHOUT its ledger event.

    Mirrors the crash window before the commit point: the marker names the
    operation id, the provision journal records the one minted handle, and
    the mirror is at its staged write-set phase. Startup recovery must then
    delete the handle, remove the key file and journal, drop the mirror and
    let the operation store finalize failed(500).
    """
    from datetime import datetime, timezone

    from keymgr.store import KeyRecord, VersionRecord

    begin = ns.op_store.begin(
        "t", "alice", PATH,
        operations_mod.normalize_body(_body(algorithm=algorithm)),
        "uncommitted",
    )
    op = begin.record
    key_id = str(uuid.uuid4())
    ns.op_store.update_details(
        op, {"kind": "create", "key_id": key_id, "algorithm": algorithm}
    )
    mirror = ns.artifacts.create(op)
    mirror.describe({"kind": "create", "write_set": [key_id]})

    store = ns.store
    provider = store._provider()
    event = store.audit.new_event(
        "t", "create", key_id, "success", event_id=op.operation_id,
    )
    journal_id, journal_path = store._new_provision_journal(
        event.event_id, event.tenant_id, event.action
    )
    triple = provider.generate(algorithm)
    store._append_provision(
        journal_path, provider.provider_id, triple.handle
    )
    record = KeyRecord(
        key_id=key_id, tenant_id="t", label="k",
        versions=[VersionRecord(
            version=1,
            created_at=datetime.now(timezone.utc).isoformat(),
            algorithm=algorithm, public_key=triple.public_key,
            provider_id=provider.provider_id, handle=triple.handle,
            encrypted_material=triple.encrypted_material,
        )],
        current_version=1,
    )
    # Crash window BEFORE the key-file marker lands: the journal proves the
    # minted handle, but no key file exists yet. The mirror is parked at the
    # provisioning phase exactly as the live attempt left it.
    mirror.add_handle(provider.provider_id, triple.handle)
    return op, record, triple.handle, journal_id, mirror


def test_uncommitted_create_rolls_back_and_replays_failed_500(stack):
    op, record, handle, journal_id, mirror = (
        _craft_uncommitted_create_scene(stack)
    )
    parts = _restart(stack)
    # Startup recovery: no ledger event -> the orphaned handle is deleted,
    # the journal and mirror are dropped, and the operation is failed(500).
    finished = stack.op_store._read_record(op.operation_id)
    assert finished.status == "failed" and finished.http_status == 500
    assert set(finished.response) == {"error", "operation_id"}
    assert finished.response["operation_id"] == op.operation_id
    assert not os.path.exists(stack.store._path_for(record.key_id))
    assert not os.path.exists(stack.store._provision_path(journal_id))
    assert not os.path.exists(stack.artifacts.path_for(op.operation_id))
    # No event ever reached the ledger.
    assert stack.audit.get_event(op.operation_id) is None

    # An HTTP retry with the same key now REPLAYS the stored 500 (it never
    # regenerates a key or books an event).
    httpd, client = _serve(stack, parts)
    try:
        status, body = client.call(
            "POST", PATH, _body(),
            headers={"Idempotency-Key": "uncommitted"},
        )
        assert status == 500
        assert set(body) == {"error", "operation_id"}
        assert body["operation_id"] == op.operation_id
        assert _create_events(stack) == []
        assert not os.path.exists(stack.store._path_for(record.key_id))
    finally:
        httpd.shutdown()


def test_unconfirmed_cleanup_keeps_evidence_pending_and_returns_500(stack,
                                                                   monkeypatch):
    # The ledger commit fails AFTER the key file + minted handle landed, and
    # the backend cannot confirm the handle delete: evidence is retained and
    # the operation stays pending with a material-safe 500. Restart while the
    # backend is still unreachable keeps the scene parked pending; a same-key
    # request answers 500 and generates nothing. Once the backend recovers,
    # restart settles the rollback and a retry then REPLAYS failed(500).
    provider = provider_mod.get_provider()

    def fail_delete(handle):
        raise ProviderUnavailable("injected delete outage")

    def fail_append(event):
        raise RuntimeError("boom")

    monkeypatch.setattr(provider, "delete", fail_delete)
    monkeypatch.setattr(stack.audit, "append", fail_append)
    status, body = _create(stack, "parked")
    assert status == 500
    assert set(body) == {"error", "operation_id"}
    op_id = body["operation_id"]

    # The operation stays PENDING; journal and mirror survive as clues.
    record = stack.op_store._read_record(op_id)
    assert record.status == "pending"
    assert glob.glob(os.path.join(stack.data_dir, "provisions", "*.json"))
    assert os.path.exists(stack.artifacts.path_for(op_id))

    # Restart with deletion STILL failing: the scene remains parked.
    parts = _restart(stack)
    assert stack.op_store._read_record(op_id).status == "pending"
    httpd, client = _serve(stack, parts)
    try:
        status, again = client.call(
            "POST", PATH, _body(),
            headers={"Idempotency-Key": "parked"},
        )
        assert status == 500
        assert set(again) == {"error", "operation_id"}
        assert stack.op_store._read_record(op_id).status == "pending"
    finally:
        httpd.shutdown()

    # Backend healthy again: startup completes the rollback (handle deleted,
    # file removed, journal/mirror dropped) and finalizes failed(500); the
    # same-key request replays that 500 without minting anything new.
    monkeypatch.undo()
    parts = _restart(stack)
    finished = stack.op_store._read_record(op_id)
    assert finished.status == "failed" and finished.http_status == 500
    assert not glob.glob(os.path.join(stack.data_dir, "provisions", "*.json"))
    httpd, client = _serve(stack, parts)
    try:
        status, again = client.call(
            "POST", PATH, _body(),
            headers={"Idempotency-Key": "parked"},
        )
        assert status == 500 and again["operation_id"] == op_id
        assert _create_events(stack) == []
    finally:
        httpd.shutdown()


def test_material_never_enters_response_audit_operation_or_error(stack):
    status, body = _create(stack, "clean", algorithm="RSA2048")
    assert status == 201
    # Response has only the public projection.
    assert set(body) == {"key_id", "algorithm", "public_key", "operation_id"}
    # Operation record and mirror carry no private material/handle/blob.
    op_id = body["operation_id"]
    record_raw = open(
        os.path.join(stack.data_dir, "operations", op_id + ".json"),
        encoding="utf-8",
    ).read()
    on_disk_key = open(
        stack.store._path_for(body["key_id"]), encoding="utf-8"
    ).read()
    handle = json.loads(on_disk_key)["versions"][0]["handle"]
    assert handle
    assert handle not in record_raw
    assert "encrypted_material" not in record_raw
    for event in stack.audit._read_all():
        line = json.dumps(event.to_json() if hasattr(event, "to_json")
                          else event)
        assert handle not in line
    # Public key PEM is allowed in the response; the private half is not.
    assert "PRIVATE KEY" not in json.dumps(body)


def test_missing_mirror_after_restart_keeps_pending_then_retry(stack):
    # Crash in the exact window where the bound operation record landed but
    # its mirror creation failed (no evidence anywhere): restart keeps it
    # pending, and the same-key request takes the clean strand over and
    # creates the key once under the same operation_id.
    begin = stack.op_store.begin(
        "t", "alice", PATH,
        operations_mod.normalize_body(_body()), "strand",
    )
    op = begin.record
    assert op.status == "pending"
    assert not os.path.exists(stack.artifacts.path_for(op.operation_id))
    parts = _restart(stack)
    assert stack.op_store._read_record(op.operation_id).status == "pending"
    httpd, client = _serve(stack, parts)
    try:
        status, body = client.call(
            "POST", PATH, _body(),
            headers={"Idempotency-Key": "strand"},
        )
        assert status == 201 and body["operation_id"] == op.operation_id
        events = _create_events(stack)
        assert len(events) == 1 and events[0].event_id == op.operation_id
    finally:
        httpd.shutdown()




# ----------------------------------------------- external provider (fake KMS)
def _serve_env(env):
    audit_log = AuditLog(env.data_dir)
    store = KeyStore(env.data_dir, audit_log)
    policies = PolicyStore(env.data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(env.data_dir, audit_log)
    art = ArtifactStore(env.data_dir, store, audit_log)
    art.settle_pending(op_store)
    op_store.recover_pending(is_parked=art.is_parked)
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(store, policies, coordinator, op_store, art),
    )
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    return httpd, client, op_store, audit_log


def test_external_provider_failed_load_is_terminal_503_then_replays(env):
    # A provider that cannot be loaded/healthy-activated is the existing
    # durable terminal-503 convention: one create/rejected event named after
    # the operation_id, zero artifacts, and a retry replays the same 503.
    httpd, client, op_store, audit_log = _serve_env(env)
    try:
        env.set_faults({"unreachable": True})
        status, body = client.call(
            "POST", PATH, _body(algorithm="RSA2048"),
            headers={"Idempotency-Key": "ext-down"},
        )
        assert status == 503
        assert body["error"] == "key management provider is unavailable"
        assert set(body) == {"error", "operation_id"}
        op_id = body["operation_id"]
        record = op_store._read_record(op_id)
        assert record.status == "failed" and record.http_status == 503
        rejected = [
            e for e in audit_log._read_all()
            if e.event_id == op_id
        ]
        assert len(rejected) == 1 and rejected[0].action == "create"
        assert rejected[0].outcome == "rejected"
        # No key file, provision journal, mirror or backend handle remains.
        key_files = [
            n for n in os.listdir(env.data_dir)
            if n.endswith(".json") and len(n) == 41
        ]
        assert key_files == []
        assert not glob.glob(
            os.path.join(env.data_dir, "provisions", "*.json")
        )
        assert env.kms_handles() == set()

        # Retry after recovery replays the stored 503 verbatim; the provider
        # is not invoked a second time.
        env.clear_faults()
        status, again = client.call(
            "POST", PATH, _body(algorithm="RSA2048"),
            headers={"Idempotency-Key": "ext-down"},
        )
        assert status == 503 and again == body
        assert len([e for e in audit_log._read_all()
                    if e.event_id == op_id]) == 1
        assert env.kms_handles() == set()
    finally:
        httpd.shutdown()


def test_external_provider_call_failure_stays_pending_then_runs_once(env):
    # The provider activates healthy, then its generate() call fails AFTER
    # activation (a transient backend outage of a bound active provider):
    # the create stays pending with the fixed 503 and no audit; once the
    # backend recovers the identical retry creates the key exactly once.
    httpd, client, op_store, audit_log = _serve_env(env)
    try:
        # One healthy call so the fake provider is the active provider.
        status, warm = client.call("POST", PATH, _body())
        assert status == 201
        # Now make every BACKEND operation fail (the provider still builds
        # and health-checks fine).
        env.set_faults({"fail": {"generate": True, "delete": True}})
        status, body = client.call(
            "POST", PATH, _body(algorithm="RSA2048"),
            headers={"Idempotency-Key": "ext-call"},
        )
        assert status == 503
        assert body["error"] == "key management provider is unavailable"
        op_id = body["operation_id"]
        assert op_store._read_record(op_id).status == "pending"
        assert [e for e in audit_log._read_all()
                if e.event_id == op_id] == []

        env.clear_faults()
        status, ok = client.call(
            "POST", PATH, _body(algorithm="RSA2048"),
            headers={"Idempotency-Key": "ext-call"},
        )
        assert status == 201 and ok["operation_id"] == op_id
        successes = [
            e for e in audit_log._read_all()
            if e.event_id == op_id
        ]
        assert len(successes) == 1 and successes[0].action == "create"
    finally:
        httpd.shutdown()
        env.clear_faults()
