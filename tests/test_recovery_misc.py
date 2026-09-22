"""Remaining recovery-coordination scenarios: concurrency, provider-id
mismatch, corrupt artifacts, empty-restore markers and the HTTP surface."""

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from keymgr import audit as audit_mod
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.provider import ProviderUnavailable
from keymgr.restore import RestoreCoordinator
from keymgr.store import KeyStore, LockTimeout

from test_recovery_batch import _craft_batch_scene, _make_keys
from test_recovery_rotate import _make_key


# -- same-key concurrency ----------------------------------------------------
def test_same_key_concurrent_rotate_times_out(env):
    key_id = _make_key(env)
    store = env.open_store()
    env.set_faults({"sleep": {"rotate": 2.0}})
    done = []

    def slow_rotate():
        store.rotate(key_id, "t1", "AES256", lock_timeout=10.0)
        done.append(True)

    thread = threading.Thread(target=slow_rotate)
    thread.start()
    try:
        time.sleep(0.3)  # the slow rotate now holds the key locks
        with pytest.raises(LockTimeout):
            store.rotate(key_id, "t1", "AES256", lock_timeout=0.5)
    finally:
        thread.join()
    assert done == [True]
    assert store.get(key_id, "t1").current_version == 2


def test_batch_and_single_rotate_on_same_key_are_mutually_exclusive(env):
    keys = _make_keys(env)
    store = env.open_store()
    env.set_faults({"sleep": {"rotate": 2.0}})
    done = []

    def slow_batch():
        store.batch_rotate(
            "t1", [(k, "AES256") for k in keys], lock_timeout=10.0
        )
        done.append(True)

    thread = threading.Thread(target=slow_batch)
    thread.start()
    try:
        time.sleep(0.3)  # the batch now holds every key lock of the group
        with pytest.raises(LockTimeout):
            store.rotate(keys[0], "t1", "AES256", lock_timeout=0.5)
    finally:
        thread.join()
    assert done == [True]
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 2


# -- provider_id mismatch ----------------------------------------------------
def test_batch_recovery_with_foreign_provider_id_preserves_scene(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    # Sabotage the journal: entries name a provider that is not active.
    # (Paths computed directly: opening a store would run recovery first.)
    journal_path = os.path.join(
        env.data_dir, "provisions", scene.journal_id + ".json"
    )
    with open(journal_path, "w", encoding="utf-8") as fh:
        for handle in scene.handles:
            fh.write(
                json.dumps({"provider_id": "otherkms", "handle": handle}) + "\n"
            )

    store = env.open_store()  # recovery cannot confirm the deletes

    # The whole scene is retained for a later process/operator: markers,
    # journal and snapshot survive and no file is restored while a delete
    # cannot be confirmed. (The minted handles themselves were reaped via
    # the on-disk/pre-image delta, so no orphan backend objects remain.)
    assert os.path.exists(store._provision_path(scene.journal_id))
    assert os.path.exists(store._batch_snapshot_path(scene.event_id))
    raw = store._read_record(store._path_for(keys[0]))
    assert raw.pending_event is not None
    # Reads hide the uncommitted current by projecting the snapshot pre-image.
    assert store.get(keys[0], "t1").current_version == 1


def test_batch_rotate_record_of_inactive_provider_is_503(env):
    keys = _make_keys(env)
    store = env.open_store()
    # Re-label one record as owned by an inactive provider.
    path = store._path_for(keys[0])
    record = store._read_record(path)
    for ver in record.versions:
        ver.provider_id = "otherkms"
    store._write_atomic(path, record.to_json())

    store = env.open_store()
    before = env.kms_handles()
    with pytest.raises(ProviderUnavailable):
        store.batch_rotate(
            "t1", [(k, "AES256") for k in keys], lock_timeout=1.0
        )
    # Zero side effects: no handles, no versions, no artifacts.
    assert env.kms_handles() == before
    assert store.get(keys[1], "t1").current_version == 1


# -- corrupt snapshot ----------------------------------------------------------
def test_corrupt_snapshot_parks_batch_scene(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    snapshot_path = os.path.join(
        env.data_dir, "batch-rotations", scene.event_id + ".json"
    )
    with open(snapshot_path, "w", encoding="utf-8") as fh:
        fh.write("{not json")

    store = env.open_store()

    # Parked: nothing deleted, nothing restored, artifacts retained.
    assert os.path.exists(store._provision_path(scene.journal_id))
    assert os.path.exists(snapshot_path)
    for handle in scene.handles:
        assert handle in env.kms_handles()
    # The uncommitted current is never exposed.
    assert store.get(keys[0], "t1") is None


# -- empty restore marker ------------------------------------------------------
def _empty_marker(env, tenant="t1", event=True):
    digest = hashlib.sha256(tenant.encode("utf-8")).hexdigest()
    path = os.path.join(env.data_dir, "restore-empty-%s.json" % digest)
    marker = {
        "_restore": True,
        "_empty": True,
        "event": None,
        "tenant_id": tenant,
        "key_ids": [],
        "policy": False,
    }
    if event:
        ledger = AuditLog(env.data_dir)
        ev = ledger.new_event(
            tenant, audit_mod.ACTION_IMPORT, None, audit_mod.OUTCOME_SUCCESS
        )
        marker["event"] = ev.to_json()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(marker, fh)
    return path, marker


def _recover(env):
    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    RestoreCoordinator(store, policies)
    return store


def test_empty_restore_marker_without_event_is_removed(env):
    path, marker = _empty_marker(env)
    _recover(env)
    assert not os.path.exists(path)


def test_empty_restore_marker_committed_is_finalized(env):
    path, marker = _empty_marker(env)
    ledger = AuditLog(env.data_dir)
    from keymgr.audit import AuditEvent

    ledger.append(AuditEvent.from_json(marker["event"]))
    _recover(env)
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as fh:
        finalized = json.load(fh)
    assert finalized["event"] is None


# -- HTTP surface --------------------------------------------------------------
class HttpServer:
    def __init__(self, env):
        from keymgr.server import make_handler
        from http.server import ThreadingHTTPServer

        audit_log = AuditLog(env.data_dir)
        store = KeyStore(env.data_dir, audit_log)
        policy_store = PolicyStore(env.data_dir, audit_log)
        coordinator = RestoreCoordinator(store, policy_store)
        operation_store = OperationStore(env.data_dir, audit_log)
        operation_store.recover_pending()
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(store, policy_store, coordinator, operation_store),
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield server
    server.stop()


def _create_key_http(http, tenant="t1"):
    status, body = http.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": "AES256", "label": "k"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 201, body
    return body["key_id"]


def test_http_rotate_provider_down_is_503_with_fixed_text(http, env):
    key_id = _create_key_http(http)
    env.set_faults({"unreachable": True})
    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "http-rot-1"},
    )
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    operation_id = body["operation_id"]
    env.clear_faults()

    # GET operation replays the first status/response; retry replays too.
    status, op = http.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        {"X-Operator-Id": "alice", "X-Tenant-Id": "t1"},
    )
    assert status == 200
    assert op["operation_id"] == operation_id
    assert op["status"] == "failed"
    assert op["http_status"] == 503
    assert op["response"]["error"] == "key management provider is unavailable"

    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "http-rot-1"},
    )
    assert status == 503
    assert body["operation_id"] == operation_id


def test_http_same_key_wait_times_out_without_side_effects(http, env):
    key_id = _create_key_http(http)
    # The first rotate holds the key locks inside the slow provider call.
    env.set_faults({"sleep": {"rotate": 8.0}})
    outcome = {}

    def first():
        outcome["first"] = http.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "http-rot-slow"},
        )

    thread = threading.Thread(target=first)
    thread.start()
    try:
        time.sleep(1.0)  # the first request is now executing
        status, body = http.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "http-rot-slow"},
        )
        # Waiting on the in-flight owner beyond 5s answers timed_out.
        assert status == 503
        assert body["error"] == "operation timed out waiting for a lock"
        operation_id = body["operation_id"]
    finally:
        thread.join()
    env.clear_faults()
    assert outcome["first"][0] == 201

    # The waiter wrote nothing; the owner's operation is the one that
    # committed, and a later retry replays its success.
    status, op = http.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        {"X-Operator-Id": "alice", "X-Tenant-Id": "t1"},
    )
    assert status == 200
    assert op["status"] == "succeeded"
    assert op["http_status"] == 201


def test_http_rotate_success_replays_and_hides_secrets(http, env):
    key_id = _create_key_http(http)
    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "http-rot-2"},
    )
    assert status == 201
    operation_id = body["operation_id"]
    assert body["version"] == 2

    status, retry = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "http-rot-2"},
    )
    assert status == 201
    assert retry == body

    status, op = http.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        {"X-Operator-Id": "alice", "X-Tenant-Id": "t1"},
    )
    assert status == 200
    assert op["status"] == "succeeded"
    serialized = json.dumps(op) + json.dumps(body)
    assert "encrypted_material" not in serialized
    assert "handle" not in serialized
    for handle in env.kms_handles():
        assert handle not in serialized

    # Another tenant cannot see the operation.
    status, _ = http.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        {"X-Operator-Id": "alice", "X-Tenant-Id": "t2"},
    )
    assert status == 404
