"""Idempotency for POST /v1/keys (optional Idempotency-Key).

Requests without the header (and the CLI ``gen`` command) keep the legacy
non-idempotent behavior: every call creates a fresh key. A request carrying
an Idempotency-Key binds globally to one operation: same-binding retries
replay the first 201 (and its algorithm/public key even after a later
rotation), any changed binding element answers 409 naming the original
operation, and concurrent same-key requests execute the creation exactly
once (a waiter past 5 s gets 503 and writes nothing).

Pre-bind validation errors (bad/empty/duplicate/illegal key, bad JSON, a
non-object body, missing/extra/ill-typed fields, an unsupported algorithm)
are 400s that consume no key and write no audit; the tenant-source failure
still records the invisible tenant_conflict event. Post-bind a policy denial
is one create/rejected event (403 replay), a provider outage is the fixed 503
with no audit and a retryable pending operation, a policy-store outage is the
fixed 500 with no audit and a retryable pending operation, and a ledger/key
store failure is a 500 whose body contains only error+operation_id. A restart
replays a committed create's full 201 (later rotations never rewrite it),
while a demonstrably uncommitted attempt rolls the new key/handle back and
replays 500; private material, handles and wrapping never reach a response,
the audit ledger or the operation record.
"""

import glob
import http.client
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

from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.provider import ProviderUnavailable
from keymgr.server import make_handler
from keymgr.store import KeyStore


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
    return (data_dir, audit_log, store, policies, coordinator, op_store,
            artifact_store)


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
    data_dir, audit_log, store, policies, coordinator, op_store, art = parts
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


def _is_uuid4(value):
    try:
        return uuid.UUID(str(value)).version == 4
    except (ValueError, AttributeError, TypeError):
        return False


def _body(**overrides):
    body = {"tenant_id": "t", "algorithm": "AES256", "label": ""}
    body.update(overrides)
    return body


def _create(c, key, operator="alice", **overrides):
    return c.call(
        "POST", "/v1/keys", _body(**overrides),
        headers={"Idempotency-Key": key}, operator=operator,
    )


def _restart(ns):
    """Reopen every store over the same directory (a new process)."""
    data_dir = ns.data_dir
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    return types.SimpleNamespace(
        data_dir=data_dir, audit=audit_log, store=store, policies=policies,
        op_store=op_store, artifacts=artifact_store,
        coordinator=coordinator,
    )


def _serve(ns):
    handler = make_handler(
        ns.store, ns.policies, ns.coordinator, ns.op_store, ns.artifacts
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    return httpd, client


# ------------------------------------------------------------- legacy path
def test_no_header_still_creates_fresh_keys(stack):
    c = stack.client
    status, first = c.call("POST", "/v1/keys", _body())
    assert status == 201
    assert list(first.keys()) == ["key_id", "algorithm", "public_key"]
    assert "operation_id" not in first
    status, second = c.call("POST", "/v1/keys", _body())
    assert status == 201 and second["key_id"] != first["key_id"]
    # Two ordinary create/success events, no operation artifacts.
    assert [e.action for e in stack.audit._read_all()] == [
        "create", "create"
    ]
    assert not os.path.exists(
        os.path.join(stack.data_dir, "operation-artifacts")
    )


@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_create_201_shape_and_version_one(stack, algorithm):
    c = stack.client
    status, out = _create(c, "one", algorithm=algorithm, label="lbl")
    assert status == 201
    assert list(out.keys()) == ["key_id", "algorithm", "public_key",
                                "operation_id"]
    assert _is_uuid4(out["key_id"]) and _is_uuid4(out["operation_id"])
    assert out["algorithm"] == algorithm
    if algorithm == "AES256":
        assert out["public_key"] is None
    else:
        assert isinstance(out["public_key"], str)
        assert out["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    key = stack.store.get(out["key_id"], "t")
    assert key is not None and key.current_version == 1
    # Exactly one create/success event whose event_id IS the operation_id.
    events = [e for e in stack.audit._read_all() if e.tenant_id == "t"]
    assert len(events) == 1
    assert events[0].action == "create"
    assert events[0].outcome == "success"
    assert events[0].event_id == out["operation_id"]
    assert events[0].key_id == out["key_id"]


# --------------------------------------------------------- header contract
@pytest.mark.parametrize("value", ["", "with space", "a/b", "caf\u00e9",
                                  "x" * 129])
def test_illegal_key_is_400_naming_header(stack, value):
    c = stack.client
    status, out = _create(c, value)
    assert status == 400 and "Idempotency-Key" in out["error"]
    assert set(out) == {"error"}
    assert not glob.glob(os.path.join(stack.data_dir, "operations", "*.json"))
    assert stack.audit._read_all() == []


def test_duplicate_key_header_is_400(stack):
    conn = http.client.HTTPConnection(
        "127.0.0.1", stack.client.base.rsplit(":", 1)[1]
    )
    raw = json.dumps(_body()).encode()
    conn.putrequest("POST", "/v1/keys")
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Idempotency-Key", "a")
    conn.putheader("Idempotency-Key", "b")
    conn.putheader("Content-Length", str(len(raw)))
    conn.endheaders(raw)
    resp = conn.getresponse()
    assert resp.status == 400
    out = json.loads(resp.read())
    assert "Idempotency-Key" in out["error"]
    assert stack.audit._read_all() == []


def test_pre_bind_400s_consume_no_key_and_write_no_audit(stack):
    c = stack.client
    cases = [
        ("k-badjson", {}, b"{not json"),
        ("k-list", {}, b"[1,2,3]"),
        ("k-null", {}, b"null"),
        ("k-missing-label", {"tenant_id": "t", "algorithm": "AES256"}, None),
        ("k-missing-algo", {"tenant_id": "t", "label": ""}, None),
        ("k-missing-tenant", {"algorithm": "AES256", "label": ""}, None),
        ("k-extra", _body(x=1), None),
        ("k-bad-algo", _body(algorithm="RSA4096"), None),
        ("k-label-type", _body(label=3), None),
        ("k-algo-type", _body(algorithm=7), None),
        ("k-tenant-type", _body(tenant_id=5), None),
        ("k-empty-tenant", _body(tenant_id=""), None),
        ("k-empty-label-nonstr", _body(label=None), None),
    ]
    for key, body, raw in cases:
        status, out = c.call(
            "POST", "/v1/keys", body,
            headers={"Idempotency-Key": key}, raw=raw,
        )
        assert status == 400, (key, out)
    # The two tenant-source failures (missing, empty/non-string tenant_id)
    # still record the invisible tenant_conflict; every other parameter
    # failure writes nothing.
    conflicts = [e for e in stack.audit._read_all()
                 if e.action == "tenant_conflict"]
    assert len(conflicts) == 3
    # Every key remains unbound: a later valid request with one of them wins.
    status, out = _create(c, "k-extra")
    assert status == 201 and _is_uuid4(out["operation_id"])
    # Only the one successful create follows the tenant_conflict events.
    assert [e.action for e in stack.audit._read_all()
            if e.action != "tenant_conflict"] == ["create"]


def test_missing_tenant_still_records_tenant_conflict(stack):
    c = stack.client
    status, out = c.call(
        "POST", "/v1/keys", {"algorithm": "AES256", "label": ""},
        headers={"Idempotency-Key": "k-tc"},
    )
    assert status == 400 and "tenant_id" in out["error"]
    actions = [(e.action, e.tenant_id, e.key_id)
               for e in stack.audit._read_all()]
    assert actions == [("tenant_conflict", None, None)]
    # The key is still reusable.
    status, out = _create(c, "k-tc")
    assert status == 201


# ----------------------------------------------------------------- replay
def test_same_binding_replays_ignoring_whitespace_and_order(stack):
    c = stack.client
    status, first = _create(c, "dup")
    assert status == 201
    for raw in (
        b'{ "tenant_id" : "t" , "algorithm" : "AES256" , "label" : "" }',
        b'{"label":"","algorithm":"AES256","tenant_id":"t"}',
    ):
        status, again = c.call(
            "POST", "/v1/keys", None,
            headers={"Idempotency-Key": "dup"}, raw=raw,
        )
        assert status == 201 and again == first
    # One key, one event.
    key_files = glob.glob(os.path.join(stack.data_dir, "*.json"))
    assert len([p for p in key_files
                if len(os.path.basename(p)) == 41]) == 1
    events = [e for e in stack.audit._read_all() if e.action == "create"]
    assert len(events) == 1


@pytest.mark.parametrize("change", [
    {"tenant_id": "other"},
    {"label": "different"},
    {"algorithm": "RSA2048"},
])
def test_changed_body_element_is_409_with_original_operation(
    stack, change
):
    c = stack.client
    status, first = _create(c, "same")
    assert status == 201
    status, out = c.call(
        "POST", "/v1/keys", _body(**change),
        headers={"Idempotency-Key": "same"},
    )
    assert status == 409
    assert set(out) == {"error", "operation_id"}
    assert out["operation_id"] == first["operation_id"]
    assert "Idempotency-Key" in out["error"]


def test_changed_operator_is_409(stack):
    c = stack.client
    status, first = _create(c, "op")
    assert status == 201
    status, out = _create(c, "op", operator="bob")
    assert status == 409
    assert out["operation_id"] == first["operation_id"]


def test_409_writes_no_event_and_original_replay_untouched(stack):
    c = stack.client
    status, first = _create(c, "k")
    status, _ = _create(c, "k", label="x")
    assert status == 409
    status, replay = _create(c, "k")
    assert status == 201 and replay == first
    assert len([e for e in stack.audit._read_all()
                if e.action == "create"]) == 1


def test_get_operation_reads_create_and_hides_pending(stack):
    c = stack.client
    status, out = _create(c, "get")
    op_id = out["operation_id"]
    status, view = c.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id, None
    )
    assert status == 200
    assert view == {
        "operation_id": op_id,
        "tenant_id": "t",
        "status": "succeeded",
        "http_status": 201,
        "response": out,
    }
    # Another tenant/operator cannot see it (404, no existence leak).
    status, _ = c.call(
        "GET", "/v1/operations/%s?tenant_id=other" % op_id, None
    )
    assert status == 404


# --------------------------------------------------------- policy rejection
def test_policy_denial_is_403_recorded_once_and_replayed(stack):
    c = stack.client
    stack.policies.put("t", [
        Rule(subject="alice", actions=["create"], effect="deny")
    ])
    status, out = _create(c, "deny")
    assert status == 403
    assert set(out) == {"error", "operation_id"}
    assert out["error"] == "action not permitted by policy"
    op_id = out["operation_id"]
    rejected = [e for e in stack.audit._read_all()
                if e.event_id == op_id]
    assert len(rejected) == 1
    assert rejected[0].action == "create"
    assert rejected[0].outcome == "rejected"
    # Replay: same 403/body, no second event, no key.
    status, again = _create(c, "deny")
    assert status == 403 and again == out
    assert len([e for e in stack.audit._read_all()
                if e.event_id == op_id]) == 1
    assert glob.glob(os.path.join(stack.data_dir, "*.json")) == [] or not [
        p for p in glob.glob(os.path.join(stack.data_dir, "*.json"))
        if len(os.path.basename(p)) == 41
    ]


# ------------------------------------------------------------ concurrency
def test_concurrent_same_key_executes_once(stack):
    c = stack.client
    provider = stack.store._provider()
    original = type(provider).generate
    gate = threading.Event()

    def slow_generate(self, algorithm):
        gate.wait(10)
        return original(self, algorithm)

    type(provider).generate = slow_generate
    results = []

    def worker():
        results.append(_create(c, "race"))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    gate.set()
    for t in threads:
        t.join()
    type(provider).generate = original

    assert len(results) == 4
    assert all(status == 201 for status, _ in results)
    key_ids = {body["key_id"] for _, body in results}
    op_ids = {body["operation_id"] for _, body in results}
    assert key_ids == {next(iter(key_ids))}
    assert len(op_ids) == 1
    events = [e for e in stack.audit._read_all() if e.action == "create"]
    assert len(events) == 1
    assert events[0].key_id == next(iter(key_ids))


def test_waiter_past_five_seconds_gets_503_and_writes_nothing(
    stack, monkeypatch
):
    from keymgr import operations as operations_mod

    c = stack.client
    monkeypatch.setattr(operations_mod, "LOCK_WAIT_SECONDS", 0.5)
    provider = stack.store._provider()
    original = type(provider).generate
    gate = threading.Event()

    def slow_generate(self, algorithm):
        gate.wait(10)
        return original(self, algorithm)

    type(provider).generate = slow_generate
    outcome = {}

    def owner():
        outcome["owner"] = _create(c, "wait")

    def waiter():
        time.sleep(0.2)
        outcome["waiter"] = _create(c, "wait")

    t_owner = threading.Thread(target=owner)
    t_waiter = threading.Thread(target=waiter)
    t_owner.start()
    t_waiter.start()
    t_waiter.join()
    gate.set()
    t_owner.join()
    type(provider).generate = original

    status, body = outcome["waiter"]
    assert status == 503
    assert body["error"] == "operation timed out waiting for a lock"
    assert set(body) == {"error", "operation_id"}
    owner_status, owner_body = outcome["owner"]
    assert owner_status == 201
    # The waiter wrote no event; only the owner's success exists.
    events = [e for e in stack.audit._read_all() if e.action == "create"]
    assert len(events) == 1
    assert events[0].event_id == owner_body["operation_id"]


# ----------------------------------------------- provider / policy failures
def test_provider_unavailable_is_503_no_audit_and_retry_creates_once(
    stack, monkeypatch
):
    c = stack.client
    provider = stack.store._provider()
    original_generate = type(provider).generate

    def fail_generate(self, algorithm):
        raise ProviderUnavailable("backend down")

    monkeypatch.setattr(type(provider), "generate", fail_generate)
    status, out = _create(c, "provdown", algorithm="RSA2048")
    assert status == 503
    assert out == {
        "error": "key management provider is unavailable",
        "operation_id": out["operation_id"],
    }
    assert _is_uuid4(out["operation_id"])
    assert stack.audit._read_all() == []
    record = stack.op_store._read_record(out["operation_id"])
    assert record is not None and record.status == "pending"

    # Provider recovers: the same-key retry continues under the same op and
    # creates the key exactly once.
    monkeypatch.undo()
    assert type(provider).generate is original_generate
    status, again = _create(c, "provdown", algorithm="RSA2048")
    assert status == 201
    assert again["operation_id"] == out["operation_id"]
    events = [e for e in stack.audit._read_all()
              if e.event_id == again["operation_id"]]
    assert len(events) == 1 and events[0].outcome == "success"


def test_provider_failure_then_takeover_reuses_key_id(stack):
    # A provider outage leaves a clean BOUND strand (journal dropped, no
    # event); the same-key request takes it over under the SAME
    # operation_id AND the original prospective key_id, creating once.
    c = stack.client
    provider = stack.store._provider()
    original_generate = type(provider).generate
    state = {"fail": True}

    def maybe_fail(self, algorithm):
        if state["fail"]:
            raise ProviderUnavailable("backend down")
        return original_generate(self, algorithm)

    type(provider).generate = maybe_fail
    try:
        status, out = _create(c, "takeover")
        assert status == 503
        op_id = out["operation_id"]
        record = stack.op_store._read_record(op_id)
        key_id = (record.details or {})["key_id"]
        assert record.status == "pending"
        state["fail"] = False
        status, again = _create(c, "takeover")
        assert status == 201
        assert again["operation_id"] == op_id
        assert again["key_id"] == key_id
        assert len([e for e in stack.audit._read_all()
                    if e.event_id == op_id]) == 1
    finally:
        type(provider).generate = original_generate


def test_policy_store_unavailable_is_500_fixed_text_and_retries(
    stack, monkeypatch
):
    from keymgr.policy import PolicyStoreUnavailable

    c = stack.client

    def fail_allowed(*args, **kwargs):
        raise PolicyStoreUnavailable("corrupt")

    monkeypatch.setattr(stack.policies, "is_allowed", fail_allowed)
    status, out = _create(c, "poldown")
    assert status == 500
    assert out == {
        "error": "policy store is unavailable",
        "operation_id": out["operation_id"],
    }
    assert stack.audit._read_all() == []
    record = stack.op_store._read_record(out["operation_id"])
    assert record.status == "pending"

    monkeypatch.undo()
    status, again = _create(c, "poldown")
    assert status == 201
    assert again["operation_id"] == out["operation_id"]


def test_ledger_failure_rolls_key_back_and_answers_500(stack, monkeypatch):
    from keymgr.audit import LedgerError

    c = stack.client
    audit = stack.audit
    original_append = audit.append
    calls = {"n": 0}

    def failing_append(event, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise LedgerError("disk full")
        return original_append(event, *args, **kwargs)

    monkeypatch.setattr(audit, "append", failing_append)
    status, out = _create(c, "ledger")
    assert status == 500
    assert set(out) == {"error", "operation_id"}
    assert out["error"] == "audit ledger is unavailable"
    record = stack.op_store._read_record(out["operation_id"])
    assert record.status == "failed" and record.http_status == 500
    # The key file and minted handle were rolled back: no key file for the
    # attempt and the local registry kept no orphan handle.
    key_files = [
        p for p in glob.glob(os.path.join(stack.data_dir, "*.json"))
        if len(os.path.basename(p)) == 41
    ]
    assert key_files == []
    registry = os.path.join(stack.data_dir, "local-registry.json")
    assert json.load(open(registry)) == {}


def test_bound_error_bodies_contain_only_error_and_operation_id(stack):
    c = stack.client
    stack.policies.put("t", [
        Rule(subject="alice", actions=["create"], effect="deny")
    ])
    status, out = _create(c, "body-shape")
    assert status == 403 and set(out) == {"error", "operation_id"}
    status, out = c.call(
        "POST", "/v1/keys", _body(label="other"),
        headers={"Idempotency-Key": "body-shape"},
    )
    assert status == 409 and set(out) == {"error", "operation_id"}


# --------------------------------------------------------- crash consistency
@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_restart_replays_committed_create_and_rotation_keeps_v1(
    stack, algorithm
):
    c = stack.client
    status, first = _create(c, "commit-%s" % algorithm, algorithm=algorithm)
    assert status == 201
    op_id = first["operation_id"]
    key_id = first["key_id"]

    # Restart: the committed operation is recovered to succeeded.
    restarted = _restart(stack)
    record = restarted.op_store.get(op_id, "t", "alice")
    assert record.status == "succeeded" and record.http_status == 201
    httpd, c2 = _serve(restarted)
    try:
        status, replayed = _create(c2, "commit-%s" % algorithm,
                                   algorithm=algorithm)
        assert status == 201 and replayed == first

        # Rotate the key; the create replay MUST keep v1's algorithm/public
        # key (and the same key_id/operation_id).
        status, rotated = c2.call(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t", "algorithm": algorithm},
            headers={"Idempotency-Key": "rot-%s" % algorithm},
        )
        assert status == 201 and rotated["version"] == 2
        status, after = _create(c2, "commit-%s" % algorithm,
                                algorithm=algorithm)
        assert status == 201
        assert after == first
        assert after["public_key"] != rotated["public_key"] or algorithm == "AES256"
        stored = restarted.store.get(key_id, "t")
        assert stored.current_version == 2
        assert after["public_key"] == stored.versions[0].public_key
    finally:
        httpd.shutdown()

    # Still exactly one create/success event.
    creates = [e for e in restarted.audit._read_all()
               if e.event_id == op_id]
    assert len(creates) == 1 and creates[0].outcome == "success"


def _craft_uncommitted_create_scene(ns, op_id=None, key_id=None):
    """Crash after the handle was minted, before the event committed.

    Binds a pending mirrored ``create`` operation, creates its provision
    journal with one minted handle and leaves NO key file / ledger event --
    exactly the scene of a process killed between handle minting and commit.
    Returns ``(operation_id, key_id, handle)``.
    """
    op_id = op_id or str(uuid.uuid4())
    key_id = key_id or str(uuid.uuid4())
    store = ns.store
    op_store = ns.op_store
    artifacts = ns.artifacts
    from keymgr.operations import OperationRecord
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    normalized = json.dumps(
        {"algorithm": "AES256", "label": "", "tenant_id": "t"},
        sort_keys=True, separators=(",", ":"),
    )
    record = OperationRecord(
        op_id, "t", "alice", "/v1/keys", normalized, "crash-key",
        details={"kind": "create", "key_id": key_id,
                 "algorithm": "AES256", "label": ""},
        mirror_required=True, created_at=now, updated_at=now,
    )
    op_store._write_record(record)
    index = op_store._load_index()
    index["bindings"][op_store._scope("t", "alice", "crash-key")] = op_id
    op_store._write_atomic(op_store._index_path, index)

    mirror = artifacts.create(record)
    mirror.describe({"kind": "create", "write_set": [key_id]})
    provider = store._provider()
    journal_id, journal_path = store._new_provision_journal(
        op_id, "t", "create"
    )
    triple = provider.generate("AES256")
    store._append_provision(
        journal_path, provider.provider_id, triple.handle
    )
    mirror.provision(journal_id)
    mirror.add_handle(provider.provider_id, triple.handle)
    return op_id, key_id, triple.handle


def test_uncommitted_create_recovers_as_failed_500_and_replays(stack):
    op_id, key_id, handle = _craft_uncommitted_create_scene(stack)

    # Restart: outbox recovery deletes the orphan handle/journal, the mirror
    # settles, and the operation is finalized failed(500).
    restarted = _restart(stack)
    record = restarted.op_store.get(op_id, "t", "alice")
    assert record.status == "failed" and record.http_status == 500
    assert record.response == {
        "error": "operation interrupted before commit",
        "operation_id": op_id,
    }
    # No new key file, no surviving journal/mirror, no ledger event.
    assert not os.path.exists(restarted.store._path_for(key_id))
    assert not os.path.exists(restarted.store._provision_path(op_id))
    mirror_files = [
        n for n in os.listdir(
            os.path.join(restarted.data_dir, "operation-artifacts")
        )
        if n.endswith(".json")
    ]
    assert op_id + ".json" not in mirror_files
    assert restarted.audit.get_event(op_id) is None

    httpd, c = _serve(restarted)
    try:
        status, out = c.call(
            "POST", "/v1/keys", _body(),
            headers={"Idempotency-Key": "crash-key"},
        )
        assert status == 500
        assert set(out) == {"error", "operation_id"}
        assert out["operation_id"] == op_id
    finally:
        httpd.shutdown()
    # Replaying the failed terminal books nothing and mints no key.
    assert not os.path.exists(restarted.store._path_for(key_id))
    assert restarted.audit.get_event(op_id) is None


def test_unconfirmed_rollback_keeps_pending_with_recovery_clues(
    stack, monkeypatch
):
    # A backend handle delete that cannot be confirmed parks the whole scene
    # (journal + mirror survive) and keeps the operation pending.
    op_id, key_id, handle = _craft_uncommitted_create_scene(stack)
    provider = stack.store._provider()

    def failing_delete(self, handle):
        raise RuntimeError("backend unreachable")

    monkeypatch.setattr(type(provider), "delete", failing_delete)
    restarted = _restart(stack)
    record = restarted.op_store.get(op_id, "t", "alice")
    assert record.status == "pending"
    # Recovery clues survive.
    assert os.path.exists(restarted.store._provision_path(op_id))
    assert os.path.exists(
        os.path.join(
            restarted.data_dir, "operation-artifacts", op_id + ".json"
        )
    )


# ----------------------------------------------------------- secrecy checks
def test_private_material_handle_never_leave_the_boundary(stack, monkeypatch):
    c = stack.client
    status, out = _create(c, "secret", algorithm="RSA2048")
    assert status == 201
    op_id = out["operation_id"]
    record_text = open(
        os.path.join(stack.data_dir, "operations", op_id + ".json"),
        encoding="utf-8",
    ).read()
    record_json = json.loads(record_text)
    # The operation record stores no handle/material/wrapping, and its
    # response is exactly the public projection.
    assert "encrypted_material" not in record_text
    assert "handle" not in json.dumps(record_json.get("response", {}))
    assert record_json["response"] == out
    # Every audit event projection likewise lacks the private fields.
    for event in stack.audit._read_all():
        blob = json.dumps(event.to_json())
        assert "encrypted_material" not in blob
        assert "private_material" not in blob
    # The 403 error body carries only error + operation_id.
    stack.policies.put("td", [
        Rule(subject="alice", actions=["create"], effect="deny")
    ])
    status, denied = c.call(
        "POST", "/v1/keys", _body(tenant_id="td"),
        headers={"Idempotency-Key": "secret-deny"},
    )
    assert status == 403 and set(denied) == {"error", "operation_id"}
    # A provider fault (fresh tenant) keeps the detail server-side.
    provider = stack.store._provider()

    def fail_generate(self, algorithm):
        raise ProviderUnavailable("boom-details-must-not-leak")

    monkeypatch.setattr(type(provider), "generate", fail_generate)
    status, unavailable = c.call(
        "POST", "/v1/keys", _body(tenant_id="tp"),
        headers={"Idempotency-Key": "secret-prov"},
    )
    assert status == 503
    assert unavailable == {
        "error": "key management provider is unavailable",
        "operation_id": unavailable["operation_id"],
    }
    assert "boom-details" not in json.dumps(unavailable)
