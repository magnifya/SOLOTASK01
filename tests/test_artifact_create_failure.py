"""Regression tests for operation-artifact mirror creation failures.

When rotate/import/restore/batch-rotate have durably bound their
Idempotency-Key but fail to create the 0600 operation-artifact mirror
BEFORE the first provider call (OSError, temp-file replace failure, the
mirror directory not being usable), the operation must NOT be finalized as
failed/500 and no provider, key, handle or audit event may be touched. The
fully bound operation stays ``pending`` and the request answers a
material-free 503. A same-key retry (after a restart, and across the HTTP
and CLI entries) rebuilds the mirror, reuses the SAME operation_id and runs
the attempt exactly once; success, rejection, conflict and provider failure
keep their original single accounting. A missing/corrupt mirror parks the
operation at restart until the evidence can be cross-checked -- except that
a durable confirming event always commits.
"""

import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from keymgr import audit as audit_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr import restore as restore_mod
from keymgr.server import _resolve_committed_operation, make_handler
from keymgr.store import KeyStore
from http.server import ThreadingHTTPServer

from test_recovery_cli import run_cli
from test_recovery_rotate import _craft_rotate_marker_scene, _make_key


H_OPERATOR = {"X-Operator-Id": "alice"}
H_TENANT = {"X-Operator-Id": "alice", "X-Tenant-Id": "t1"}
PRIVATE_MARKERS = ("encrypted_material", "private_material", "passphrase",
                   "handle")


class Server:
    """In-process HTTP server over one data dir (like a fresh process)."""

    def __init__(self, env):
        audit_log = AuditLog(env.data_dir)
        self.store = KeyStore(env.data_dir, audit_log)
        self.policies = PolicyStore(env.data_dir, audit_log)
        self.coordinator = restore_mod.RestoreCoordinator(
            self.store, self.policies
        )
        self.op_store = OperationStore(env.data_dir, audit_log)
        self.art = ArtifactStore(env.data_dir, self.store, audit_log)
        self.art.settle_pending(self.op_store)
        self.op_store.recover_pending(
            lambda rec, event: _resolve_committed_operation(
                self.store, self.policies, rec, event
            ),
            is_parked=self.art.is_parked,
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                self.store, self.policies, self.coordinator, self.op_store,
                self.art,
            ),
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
def server(env):
    srv = Server(env)
    yield srv
    srv.stop()


def _create_key(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        H_OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _arm_mirror_fault(monkeypatch):
    """Make the FIRST mirror write fail with an OSError, then pass through."""
    state = {"armed": True}
    original = ArtifactStore.write_descriptor

    def failing(self, descriptor):
        if state["armed"]:
            raise OSError("simulated mirror write failure")
        return original(self, descriptor)

    monkeypatch.setattr(ArtifactStore, "write_descriptor", failing)
    return state


def _events(env, action=None):
    events = env.audit_events()
    if action is not None:
        events = [e for e in events if e.action == action]
    return events


def _assert_clean_503(status, body, operation_id):
    assert status == 503
    assert set(body.keys()) == {"error", "operation_id"}
    assert body["operation_id"] == operation_id
    rendered = json.dumps(body)
    for marker in PRIVATE_MARKERS:
        assert marker not in rendered


# -- single-key rotate ---------------------------------------------------------
def test_rotate_mirror_create_failure_keeps_pending_and_retries(
    server, env, monkeypatch
):
    key_id = _create_key(server)
    handles_before = env.kms_handles()
    fault = _arm_mirror_fault(monkeypatch)

    status, body = server.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "rot-fail-1"},
    )
    _assert_clean_503(status, body, body["operation_id"])
    operation_id = body["operation_id"]

    # No provider was called, no handle minted and nothing was audited.
    assert env.kms_handles() == handles_before
    assert [e for e in _events(env) if e.event_id == operation_id] == []

    # The fully bound operation is still pending and hides the uncommitted
    # current (version stays 1).
    status, op = server.request(
        "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
    )
    assert status == 200
    assert op["status"] == "pending"
    assert op["http_status"] is None
    assert op["response"] is None
    status, current = server.request(
        "GET", "/v1/keys/%s/current" % key_id, None, H_TENANT
    )
    assert current["version"] == 1

    # Recover: the same Idempotency-Key retries the SAME operation_id once.
    fault["armed"] = False
    status, body = server.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "rot-fail-1"},
    )
    assert status == 201, body
    assert body["operation_id"] == operation_id
    assert body["version"] == 2

    # Exactly one rotate success event for this operation, ever.
    rotate_events = [
        e for e in _events(env, audit_mod.ACTION_ROTATE)
        if e.event_id == operation_id
    ]
    assert len(rotate_events) == 1
    assert rotate_events[0].outcome == audit_mod.OUTCOME_SUCCESS

    status, op = server.request(
        "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
    )
    assert op["status"] == "succeeded"
    assert op["http_status"] == 201
    assert not os.path.exists(
        os.path.join(env.data_dir, "operation-artifacts",
                     operation_id + ".json")
    )


def test_rotate_mirror_directory_not_usable_is_pending_503(
    server, env
):
    # A real, non-monkeypatched OSError: the lazy mirror directory cannot be
    # created because a FILE occupies its path (temp replacement / directory
    # unusable class of failure).
    key_id = _create_key(server)
    blocking_file = os.path.join(env.data_dir, "operation-artifacts")
    with open(blocking_file, "w", encoding="utf-8") as fh:
        fh.write("not a directory")
    try:
        status, body = server.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "rot-dir-1"},
        )
        operation_id = body["operation_id"]
        assert status == 503
        status, op = server.request(
            "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
        )
        assert op["status"] == "pending"
    finally:
        os.unlink(blocking_file)

    # Once the directory is usable the same key completes the operation.
    status, body = server.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "rot-dir-1"},
    )
    assert status == 201
    assert body["operation_id"] == operation_id
    assert body["version"] == 2


# -- batch rotate --------------------------------------------------------------
def test_batch_rotate_mirror_failure_retries_same_operation(
    server, env, monkeypatch
):
    keys = [_create_key(server), _create_key(server)]
    items = [{"key_id": k, "algorithm": "AES256"} for k in keys]
    handles_before = env.kms_handles()
    fault = _arm_mirror_fault(monkeypatch)

    status, body = server.request(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1", "items": items},
        {"X-Operator-Id": "alice", "Idempotency-Key": "batch-fail-1"},
    )
    operation_id = body["operation_id"]
    _assert_clean_503(status, body, operation_id)
    assert env.kms_handles() == handles_before
    for key_id in keys:
        status, current = server.request(
            "GET", "/v1/keys/%s/current" % key_id, None, H_TENANT
        )
        assert current["version"] == 1
    assert _events(env, audit_mod.ACTION_BATCH_ROTATE) == []

    fault["armed"] = False
    status, body = server.request(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1", "items": items},
        {"X-Operator-Id": "alice", "Idempotency-Key": "batch-fail-1"},
    )
    assert status == 201, body
    assert body["operation_id"] == operation_id
    assert [item["version"] for item in body["items"]] == [2, 2]
    batch_events = [
        e for e in _events(env, audit_mod.ACTION_BATCH_ROTATE)
        if e.event_id == operation_id
    ]
    assert len(batch_events) == 1
    assert all(e.key_id is None for e in batch_events)


# -- import --------------------------------------------------------------------
def _export_bundle(server, key_id, passphrase="pw"):
    status, body = server.request(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t1", "passphrase": passphrase},
        H_OPERATOR,
    )
    assert status == 200, body
    return body["bundle"]


def test_import_mirror_failure_retries_same_operation(
    server, env, monkeypatch
):
    key_id = _create_key(server)
    bundle = _export_bundle(server, key_id)

    import_dir = env.data_dir + "-import"
    os.makedirs(import_dir, exist_ok=True)
    import_env = type(env)(import_dir, env.state_path, env.faults_path)
    imp_server = Server(import_env)
    try:
        fault = _arm_mirror_fault(monkeypatch)
        status, body = imp_server.request(
            "POST", "/v1/keys/import",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "imp-fail-1"},
        )
        operation_id = body["operation_id"]
        _assert_clean_503(status, body, operation_id)
        # The key must not be visible while the import is uncommitted.
        status, _ = imp_server.request(
            "GET", "/v1/keys/%s/current" % key_id, None, H_TENANT
        )
        assert status == 404
        assert _events(import_env, audit_mod.ACTION_IMPORT) == []

        fault["armed"] = False
        status, body = imp_server.request(
            "POST", "/v1/keys/import",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "imp-fail-1"},
        )
        assert status == 201, body
        assert body["operation_id"] == operation_id
        assert body["key_id"] == key_id
        import_events = [
            e for e in _events(import_env, audit_mod.ACTION_IMPORT)
            if e.event_id == operation_id
        ]
        assert len(import_events) == 1
    finally:
        imp_server.stop()


# -- restore -------------------------------------------------------------------
def test_restore_mirror_failure_retries_same_operation(
    server, env, monkeypatch
):
    key_id = _create_key(server)
    status, backup = server.request(
        "POST", "/v1/backup",
        {"tenant_id": "t1", "passphrase": "pw"}, H_OPERATOR
    )
    assert status == 200, backup
    bundle = backup["bundle"]

    restore_dir = env.data_dir + "-restore"
    os.makedirs(restore_dir, exist_ok=True)
    restore_env = type(env)(restore_dir, env.state_path, env.faults_path)
    rest_server = Server(restore_env)
    try:
        fault = _arm_mirror_fault(monkeypatch)
        status, body = rest_server.request(
            "POST", "/v1/restore",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "rest-fail-1"},
        )
        operation_id = body["operation_id"]
        _assert_clean_503(status, body, operation_id)
        assert not os.path.exists(
            os.path.join(restore_dir, key_id + ".json")
        )
        assert _events(restore_env, audit_mod.ACTION_IMPORT) == []

        fault["armed"] = False
        status, body = rest_server.request(
            "POST", "/v1/restore",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "rest-fail-1"},
        )
        assert status == 201, body
        assert body["operation_id"] == operation_id
        assert body["key_ids"] == [key_id]
        import_events = [
            e for e in _events(restore_env, audit_mod.ACTION_IMPORT)
            if e.event_id == operation_id
        ]
        assert len(import_events) == 1
    finally:
        rest_server.stop()


# -- restart with a missing mirror ---------------------------------------------
def test_pending_missing_mirror_stays_pending_after_restart_then_retries(
    env, monkeypatch
):
    first = Server(env)
    key_id = _create_key(first)
    fault = _arm_mirror_fault(monkeypatch)
    status, body = first.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "rot-restart-1"},
    )
    operation_id = body["operation_id"]
    assert status == 503
    # The mirror was never created.
    assert not os.path.exists(
        os.path.join(env.data_dir, "operation-artifacts",
                     operation_id + ".json")
    )
    first.stop()
    fault["armed"] = False

    # A new process: strict missing-mirror recovery keeps it pending rather
    # than guessing a failed rollback.
    second = Server(env)
    try:
        status, op = second.request(
            "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
        )
        assert status == 200
        assert op["status"] == "pending"
        assert op["http_status"] is None

        status, body = second.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "rot-restart-1"},
        )
        assert status == 201
        assert body["operation_id"] == operation_id
        assert body["version"] == 2
        rotate_events = [
            e for e in _events(env, audit_mod.ACTION_ROTATE)
            if e.event_id == operation_id
        ]
        assert len(rotate_events) == 1
    finally:
        second.stop()


# -- corrupt mirror with a durable commit still commits ------------------------
def test_corrupt_mirror_with_durable_event_finalizes_success(env):
    key_id = _make_key(env)
    event_id, handle, _journal = _craft_rotate_marker_scene(env, key_id)

    audit = AuditLog(env.data_dir)
    op_store = OperationStore(env.data_dir, audit)
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    from keymgr.operations import OperationRecord

    record = OperationRecord(
        operation_id=event_id,
        tenant_id="t1",
        operator_id="alice",
        path="/v1/keys/%s/rotate" % key_id,
        request_body=json.dumps(
            {"tenant_id": "t1", "algorithm": "AES256"},
            sort_keys=True, separators=(",", ":"),
        ),
        idempotency_key="corrupt-commit-1",
        created_at=now, updated_at=now,
        details={"kind": "rotate", "key_id": key_id, "algorithm": "AES256"},
        mirror_required=True,
    )
    op_store._write_record(record)

    art_dir = os.path.join(env.data_dir, "operation-artifacts")
    os.makedirs(art_dir, exist_ok=True)
    with open(os.path.join(art_dir, event_id + ".json"), "w",
              encoding="utf-8") as fh:
        fh.write("{torn mirror")

    # New process: the durable success event outranks the corrupt mirror, so
    # the operation finalizes succeeded even though the mirror is retained.
    audit = AuditLog(env.data_dir)
    store = env.open_store()
    art = ArtifactStore(env.data_dir, store, audit)
    op2 = OperationStore(env.data_dir, audit)
    art.settle_pending(op2)
    assert not art.is_parked(event_id)
    op2.recover_pending(
        lambda rec, event: _resolve_committed_operation(
            store, PolicyStore(env.data_dir, audit), rec, event
        ),
        is_parked=art.is_parked,
    )
    final = op2.get(event_id, "t1", "alice")
    assert final.status == "succeeded"
    assert final.http_status == 201
    assert handle in env.kms_handles()  # committed handle retained


# -- takeover with residual evidence (provider unreachable) --------------------
def test_takeover_parks_while_handle_delete_fails_then_executes(env):
    from keymgr.artifacts import PHASE_PROVISIONING

    key_id = _make_key(env)
    audit = AuditLog(env.data_dir)

    # Bind a pending mirror-required operation (then release its lease, as a
    # crashed process would).
    op_store = OperationStore(env.data_dir, audit)
    normalized = json.dumps(
        {"tenant_id": "t1", "algorithm": "AES256"},
        sort_keys=True, separators=(",", ":"),
    )
    begin = op_store.begin(
        "t1", "alice", "/v1/keys/%s/rotate" % key_id,
        normalized, "take-down-1",
    )
    operation_id = begin.record.operation_id
    op_store.release_lease(begin.lease_fd)

    # Craft the crashed attempt's evidence: a provisioning mirror, a journal
    # and one freshly minted handle, but NO commit event.
    store = env.open_store()
    provider = store._provider()
    _journal_id, journal_path = store._new_provision_journal(
        operation_id, "t1", audit_mod.ACTION_ROTATE
    )
    triple = provider.rotate("AES256")
    store._append_provision(
        journal_path, provider.provider_id, triple.handle
    )
    art_setup = ArtifactStore(env.data_dir, None, audit)
    mirror = art_setup.create(begin.record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror.provision(operation_id)
    mirror.add_handle(provider.provider_id, triple.handle)
    mirror.phase(PHASE_PROVISIONING)
    assert triple.handle in env.kms_handles()

    # Provider unreachable: the takeover must roll back nothing it cannot
    # confirm, keep the whole evidence set and answer a material-free 503.
    env.set_faults({"unreachable": True})
    srv = Server(env)
    try:
        status, op = srv.request(
            "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
        )
        assert op["status"] == "pending"
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "take-down-1"},
        )
        assert status == 503
        assert set(body.keys()) == {"error", "operation_id"}
        assert body["operation_id"] == operation_id
        assert triple.handle in env.kms_handles()
        assert os.path.exists(store._provision_path(operation_id))
        status, current = srv.request(
            "GET", "/v1/keys/%s/current" % key_id, None, H_TENANT
        )
        assert current["version"] == 1  # uncommitted current stays hidden

    finally:
        srv.stop()

    # Healthy again: a fresh process reaps the orphan handle, drops the
    # journal and finalizes the interrupted (mirror-bearing) attempt
    # failed(500) exactly as startup would. A retry replays that failure under
    # the SAME operation_id -- it never runs a second rotation, the version
    # stays 1 and no rotate success event is ever recorded.
    env.clear_faults()
    srv = Server(env)
    try:
        status, op = srv.request(
            "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
        )
        assert op["status"] == "failed"
        assert op["http_status"] == 500

        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "take-down-1"},
        )
        assert status == 500, body
        assert body["operation_id"] == operation_id
        assert triple.handle not in env.kms_handles()  # orphan reaped
        status, current = srv.request(
            "GET", "/v1/keys/%s/current" % key_id, None, H_TENANT
        )
        assert current["version"] == 1
        assert [
            e for e in _events(env, audit_mod.ACTION_ROTATE)
            if e.event_id == operation_id
        ] == []
    finally:
        srv.stop()


# -- cross-entry HTTP -> CLI ---------------------------------------------------
def test_http_mirror_failure_then_cli_retry_reuses_operation(
    env, monkeypatch
):
    first = Server(env)
    key_id = _create_key(first)
    fault = _arm_mirror_fault(monkeypatch)
    status, body = first.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "cross-http-cli"},
    )
    operation_id = body["operation_id"]
    assert status == 503
    first.stop()
    fault["armed"] = False

    # A CLI process (different entry, same data dir) takes over the pending
    # operation and commits it under the same operation_id.
    proc = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cross-http-cli",
    )
    assert proc.returncode == 0, proc.stderr
    replayed = json.loads(proc.stdout)
    assert replayed["operation_id"] == operation_id
    assert replayed["version"] == 2
    rotate_events = [
        e for e in _events(env, audit_mod.ACTION_ROTATE)
        if e.event_id == operation_id
    ]
    assert len(rotate_events) == 1


# -- cross-entry CLI -> HTTP (CLI failure via unusable mirror dir) -------------
def test_cli_mirror_failure_then_http_retry_reuses_operation(env):
    # Create the key via CLI.
    proc = run_cli(
        env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    key_id = json.loads(proc.stdout)["key_id"]

    # Block the lazy mirror directory with a regular file: the CLI bind
    # succeeds but the mirror create raises OSError, so it must exit 1 and
    # leave the operation pending (never failed/500).
    blocking_file = os.path.join(env.data_dir, "operation-artifacts")
    with open(blocking_file, "w", encoding="utf-8") as fh:
        fh.write("blocked")
    proc = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cross-cli-http",
    )
    assert proc.returncode == 1
    failed = json.loads(proc.stderr)
    operation_id = failed["operation_id"]
    os.unlink(blocking_file)

    srv = Server(env)
    try:
        status, op = srv.request(
            "GET", "/v1/operations/%s" % operation_id, None, H_TENANT
        )
        assert op["status"] == "pending"

        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "cross-cli-http"},
        )
        assert status == 201
        assert body["operation_id"] == operation_id
        assert body["version"] == 2
    finally:
        srv.stop()
