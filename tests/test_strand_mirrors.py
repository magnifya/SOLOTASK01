"""Regression tests for the operation artifact-mirror failure window.

Covers rotate/import/restore/batch-rotate when the 0600
``operation-artifacts/<id>.json`` mirror cannot be created (an OSError making
the directory, temp file or atomic rename) AFTER the Idempotency-Key bound but
BEFORE the first provider call, and when the mirror later goes missing or is
found corrupt after a process restart:

* the bound operation keeps its full context and stays ``pending`` -- it is
  never finalized failed/500, and no provider, key, handle or audit is
  written;
* the response is a material-safe 500/503 carrying only ``error`` and
  ``operation_id``;
* an HTTP then CLI (and CLI then HTTP) retry REUSES the same operation_id and
  records success/rejection/conflict/provider-failure exactly once;
* a restart and GET recognize a missing/corrupt mirror, keep the operation
  parked and hide the uncommitted current;
* a post-commit mirror cleanup failure never rewrites the committed result.
"""

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore, STATUS_PENDING, STATUS_SUCCEEDED
from keymgr.policy import PolicyStore
from keymgr.restore import RestoreCoordinator
from keymgr.store import KeyStore

from test_recovery_cli import run_cli


# -- in-process HTTP server with fault injection -----------------------------
class HttpTestServer:
    """A real HTTP server with handles to its stores for fault injection."""

    def __init__(self, data_dir):
        audit_log = AuditLog(data_dir)
        self.store = KeyStore(data_dir, audit_log)
        policy_store = PolicyStore(data_dir, audit_log)
        coordinator = RestoreCoordinator(self.store, policy_store)
        self.op_store = OperationStore(data_dir, audit_log)
        self.artifact_store = ArtifactStore(data_dir, self.store, audit_log)
        self.artifact_store.settle_pending(self.op_store)
        self.op_store.recover_pending(is_parked=self.artifact_store.is_parked)
        from keymgr.server import make_handler

        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                self.store, policy_store, coordinator, self.op_store,
                self.artifact_store,
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


class MirrorWriteFault:
    """Force write_descriptor to raise OSError on selected 1-based calls."""

    def __init__(self, artifact_store, fail_calls):
        self.artifact_store = artifact_store
        self.fail_calls = set(fail_calls)
        self.calls = 0
        self._original = artifact_store.write_descriptor

    def install(self):
        fault = self
        original = self._original

        def failing(descriptor):
            fault.calls += 1
            if fault.calls in fault.fail_calls:
                raise OSError("injected mirror write failure")
            return original(descriptor)

        self.artifact_store.write_descriptor = failing
        return self

    def remove(self):
        self.artifact_store.write_descriptor = self._original


import pytest


@pytest.fixture()
def server(env):
    srv = HttpTestServer(env.data_dir)
    yield env, srv
    srv.stop()


def _create_key(srv, tenant="t1"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": "AES256", "label": "k"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 201, body
    return body["key_id"]


def _op_get(srv, operation_id, tenant="t1", operator="alice"):
    return srv.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        {"X-Operator-Id": operator, "X-Tenant-Id": tenant},
    )


# -- mirror creation OSError: rotate -----------------------------------------
def test_rotate_mirror_creation_failure_parks_then_retry_succeeds(server):
    env, srv = server
    key_id = _create_key(srv)
    handles_before = env.kms_handles()

    fault = MirrorWriteFault(srv.artifact_store, {1}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-rot"},
        )
    finally:
        fault.remove()

    # Bound but the mirror never landed: a material-safe 500, operation left
    # pending, no provider/key/handle/audit touched.
    assert status == 500, body
    assert set(body.keys()) == {"error", "operation_id"}
    operation_id = body["operation_id"]
    assert "handle" not in json.dumps(body)
    assert "encrypted_material" not in json.dumps(body)

    status, op = _op_get(srv, operation_id)
    assert status == 200
    assert op["status"] == STATUS_PENDING
    assert op["http_status"] is None and op["response"] is None
    assert srv.store.get(key_id, "t1").current_version == 1
    assert env.kms_handles() == handles_before
    # No event for the stranded operation (the key's create event is fine).
    assert [e.event_id for e in env.audit_events()
            if e.event_id == operation_id] == []
    status, body2 = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-rot"},
    )
    assert status == 201, body2
    assert body2["operation_id"] == operation_id
    assert body2["version"] == 2
    assert srv.store.get(key_id, "t1").current_version == 2

    # Exactly one rotate event for the operation.
    events = [e for e in env.audit_events() if e.action == "rotate"]
    assert [e.event_id for e in events] == [operation_id]


# -- mirror describe (second durable write) OSError --------------------------
def test_rotate_describe_failure_parks_with_bound_mirror(server):
    env, srv = server
    key_id = _create_key(srv)
    handles_before = env.kms_handles()

    # Call 1 = create(bound), call 2 = describe(kind/write set). Failing the
    # second leaves a valid bound mirror but strands before the provider.
    fault = MirrorWriteFault(srv.artifact_store, {2}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-desc"},
        )
    finally:
        fault.remove()

    assert status == 500, body
    operation_id = body["operation_id"]
    status, op = _op_get(srv, operation_id)
    assert op["status"] == STATUS_PENDING
    assert srv.store.get(key_id, "t1").current_version == 1
    assert env.kms_handles() == handles_before
    assert [e.event_id for e in env.audit_events()
            if e.event_id == operation_id] == []
    # The intact bound mirror is retained as the parked attempt's index.
    assert os.path.exists(
        os.path.join(env.data_dir, "operation-artifacts",
                     operation_id + ".json")
    )

    # Retry takes the bound strand over and succeeds once.
    status, body2 = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-desc"},
    )
    assert status == 201
    assert body2["operation_id"] == operation_id
    assert [e.event_id for e in env.audit_events() if e.action == "rotate"] == [
        operation_id
    ]


# -- batch-rotate mirror creation failure ------------------------------------
def test_batch_rotate_mirror_creation_failure_then_retry(server):
    env, srv = server
    key_a = _create_key(srv)
    key_b = _create_key(srv)
    handles_before = env.kms_handles()

    fault = MirrorWriteFault(srv.artifact_store, {1}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/batch-rotate",
            {"tenant_id": "t1",
             "items": [{"key_id": key_a, "algorithm": "AES256"},
                       {"key_id": key_b, "algorithm": "AES256"}]},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-batch"},
        )
    finally:
        fault.remove()

    assert status == 500
    operation_id = body["operation_id"]
    assert srv.store.get(key_a, "t1").current_version == 1
    assert srv.store.get(key_b, "t1").current_version == 1
    assert env.kms_handles() == handles_before
    assert [e.event_id for e in env.audit_events()
            if e.event_id == operation_id] == []
    status, op = _op_get(srv, operation_id)
    assert op["status"] == STATUS_PENDING

    status, body2 = srv.request(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1",
         "items": [{"key_id": key_a, "algorithm": "AES256"},
                   {"key_id": key_b, "algorithm": "AES256"}]},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-batch"},
    )
    assert status == 201
    assert body2["operation_id"] == operation_id
    assert [i["version"] for i in body2["items"]] == [2, 2]
    assert [e.event_id for e in env.audit_events()
            if e.action == "batch_rotate"] == [operation_id]


# -- import mirror creation failure ------------------------------------------
def _export_bundle(srv, key_id):
    status, body = srv.request(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t1", "passphrase": "pw"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 200, body
    return body["bundle"]


def test_import_mirror_creation_failure_then_http_retry(env):
    src = HttpTestServer(env.data_dir)
    try:
        key_id = _create_key(src)
        bundle = _export_bundle(src, key_id)
    finally:
        src.stop()

    dst_dir = env.data_dir + "-imp"
    os.makedirs(dst_dir, exist_ok=True)
    dst = HttpTestServer(dst_dir)
    try:
        handles_before = env.kms_handles()
        fault = MirrorWriteFault(dst.artifact_store, {1}).install()
        try:
            status, body = dst.request(
                "POST", "/v1/keys/import",
                {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
                {"X-Operator-Id": "alice", "Idempotency-Key": "strand-imp"},
            )
        finally:
            fault.remove()
        assert status == 500, body
        operation_id = body["operation_id"]
        status, op = _op_get(dst, operation_id)
        assert op["status"] == STATUS_PENDING
        assert dst.store.get(key_id, "t1") is None
        assert env.kms_handles() == handles_before

        status, body2 = dst.request(
            "POST", "/v1/keys/import",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-imp"},
        )
        assert status == 201
        assert body2["operation_id"] == operation_id
        assert body2["key_id"] == key_id
        dst_events = AuditLog(dst_dir)._read_all()
        assert [e.event_id for e in dst_events
                if e.tenant_id == "t1" and e.action == "import"] == [
            operation_id
        ]
    finally:
        dst.stop()


# -- restore mirror creation failure -----------------------------------------
def test_restore_mirror_creation_failure_then_http_retry(env):
    src = HttpTestServer(env.data_dir)
    try:
        _create_key(src, tenant="t9")
        status, backup = src.request(
            "POST", "/v1/backup",
            {"tenant_id": "t9", "passphrase": "pw"},
            {"X-Operator-Id": "alice"},
        )
        assert status == 200
        bundle = backup["bundle"]
    finally:
        src.stop()

    dst_dir = env.data_dir + "-rest"
    os.makedirs(dst_dir, exist_ok=True)
    dst = HttpTestServer(dst_dir)
    try:
        fault = MirrorWriteFault(dst.artifact_store, {1}).install()
        try:
            status, body = dst.request(
                "POST", "/v1/restore",
                {"tenant_id": "t9", "passphrase": "pw", "bundle": bundle},
                {"X-Operator-Id": "alice", "Idempotency-Key": "strand-rest"},
            )
        finally:
            fault.remove()
        assert status == 500, body
        operation_id = body["operation_id"]
        status, op = _op_get(dst, operation_id, tenant="t9")
        assert op["status"] == STATUS_PENDING

        status, body2 = dst.request(
            "POST", "/v1/restore",
            {"tenant_id": "t9", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-rest"},
        )
        assert status == 201
        assert body2["operation_id"] == operation_id
        assert len(body2["key_ids"]) == 1
        dst_events = AuditLog(dst_dir)._read_all()
        assert [e.event_id for e in dst_events
                if e.tenant_id == "t9" and e.action == "import"] == [
            operation_id
        ]
    finally:
        dst.stop()


# -- empty restore strand (distinct restore-empty marker path) ----------------
def test_empty_restore_strand_then_retry_commits_once(env):
    import keymgr.tenantbundle as tenantbundle

    # Build an empty-tenant backup bundle directly.
    src_dir = env.data_dir + "-emptysrc"
    os.makedirs(src_dir, exist_ok=True)
    src_audit = AuditLog(src_dir)
    src_store = KeyStore(src_dir, src_audit)
    from keymgr.policy import PolicyStore as _PS
    from keymgr.restore import RestoreCoordinator as _RC

    bundle = _RC(src_store, _PS(src_dir, src_audit)).backup_bundle("t7", "pw")
    assert tenantbundle.decode_bundle(bundle, "pw")["keys"] == []

    dst_dir = env.data_dir + "-emptydst"
    os.makedirs(dst_dir, exist_ok=True)
    dst = HttpTestServer(dst_dir)
    try:
        fault = MirrorWriteFault(dst.artifact_store, {1}).install()
        try:
            status, body = dst.request(
                "POST", "/v1/restore",
                {"tenant_id": "t7", "passphrase": "pw", "bundle": bundle},
                {"X-Operator-Id": "alice", "Idempotency-Key": "strand-empty"},
            )
        finally:
            fault.remove()
        assert status == 500, body
        operation_id = body["operation_id"]
        status, op = _op_get(dst, operation_id, tenant="t7")
        assert op["status"] == STATUS_PENDING
        # No empty-restore marker survives a pre-provider strand.
        assert not [
            n for n in os.listdir(dst_dir) if n.startswith("restore-empty-")
        ]

        status, body2 = dst.request(
            "POST", "/v1/restore",
            {"tenant_id": "t7", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-empty"},
        )
        assert status == 201
        assert body2["operation_id"] == operation_id
        assert body2["key_ids"] == []
        assert body2["policy_restored"] is False
        events = AuditLog(dst_dir)._read_all()
        assert [e.event_id for e in events
                if e.tenant_id == "t7" and e.action == "import"] == [
            operation_id
        ]
    finally:
        dst.stop()

def test_http_strand_then_cli_retry_reuses_operation_id(server):
    env, srv = server
    key_id = _create_key(srv)

    fault = MirrorWriteFault(srv.artifact_store, {1}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "x-http-cli"},
        )
    finally:
        fault.remove()
    assert status == 500
    operation_id = body["operation_id"]

    # A CLI process (fresh process equivalent) sees the parked pending op and
    # takes it over under the same operation_id.
    proc = run_cli(
        type(env)(env.data_dir, env.state_path, env.faults_path),
        "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "x-http-cli",
    )
    assert proc.returncode == 0, proc.stderr
    cli_body = json.loads(proc.stdout)
    assert cli_body["operation_id"] == operation_id
    assert cli_body["version"] == 2

    # HTTP replay of the same key now returns that exact result; only one
    # rotate event exists.
    status, replay = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "x-http-cli"},
    )
    assert status == 201
    assert replay["operation_id"] == operation_id
    assert [e.event_id for e in env.audit_events() if e.action == "rotate"] == [
        operation_id
    ]


# -- cross-entry: a bound pending op is taken over by CLI, then replayed by HTTP
def test_cli_takes_over_stranded_binding_then_http_replays(env):
    from keymgr.operations import normalize_body

    data_dir = env.data_dir
    srv = HttpTestServer(data_dir)
    try:
        key_id = _create_key(srv)
        # Bind the idempotency key to a pending operation with NO mirror,
        # exactly as a failed mirror creation would leave it.
        normalized = normalize_body(
            {"tenant_id": "t1", "algorithm": "AES256"}
        )
        op_store = OperationStore(data_dir, AuditLog(data_dir))
        begin = op_store.begin(
            "t1", "alice", "/v1/keys/%s/rotate" % key_id,
            normalized, "x-cli-http",
        )
        operation_id = begin.record.operation_id
        assert begin.record.mirror_required is True
        assert not os.path.exists(
            os.path.join(data_dir, "operation-artifacts",
                         operation_id + ".json")
        )

        # The CLI process takes the clean strand over under the same id.
        proc = run_cli(
            type(env)(data_dir, env.state_path, env.faults_path),
            "rotate", "--tenant-id", "t1", "--key-id", key_id,
            "--algorithm", "AES256", "--operator", "alice",
            "--idempotency-key", "x-cli-http",
        )
        assert proc.returncode == 0, proc.stderr
        cli_body = json.loads(proc.stdout)
        assert cli_body["operation_id"] == operation_id
        assert cli_body["version"] == 2

        # HTTP replays the committed result verbatim; still one event.
        status, replay = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "x-cli-http"},
        )
        assert status == 201
        assert replay["operation_id"] == operation_id
        assert [e.event_id for e in env.audit_events() if e.action == "rotate"] == [
            operation_id
        ]
    finally:
        srv.stop()

def test_restart_with_missing_mirror_keeps_pending_then_retry(env):
    data_dir = env.data_dir
    srv = HttpTestServer(data_dir)
    try:
        key_id = _create_key(srv)
        fault = MirrorWriteFault(srv.artifact_store, {1}).install()
        try:
            status, body = srv.request(
                "POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": "t1", "algorithm": "AES256"},
                {"X-Operator-Id": "alice", "Idempotency-Key": "restart-miss"},
            )
        finally:
            fault.remove()
        assert status == 500
        operation_id = body["operation_id"]
    finally:
        srv.stop()

    # No mirror exists for the bound operation (creation failed before rename).
    assert not os.path.exists(
        os.path.join(data_dir, "operation-artifacts", operation_id + ".json")
    )

    # A brand-new process runs startup settlement + recovery: the op must stay
    # pending (never failed(500)) and the uncommitted current stays hidden.
    srv2 = HttpTestServer(data_dir)
    try:
        status, op = _op_get(srv2, operation_id)
        assert status == 200
        assert op["status"] == STATUS_PENDING
        assert op["http_status"] is None
        assert srv2.store.get(key_id, "t1").current_version == 1

        status, body2 = srv2.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "restart-miss"},
        )
        assert status == 201
        assert body2["operation_id"] == operation_id
        assert body2["version"] == 2
        status, op = _op_get(srv2, operation_id)
        assert op["status"] == STATUS_SUCCEEDED
    finally:
        srv2.stop()


# -- process restart with a corrupt mirror ------------------------------------
def test_restart_with_corrupt_mirror_parks_and_hides_current(env):
    data_dir = env.data_dir
    srv = HttpTestServer(data_dir)
    try:
        key_id = _create_key(srv)
        # Strand with an intact bound mirror (describe failure), then corrupt
        # the mirror bytes to simulate a torn/unreadable mirror at restart.
        fault = MirrorWriteFault(srv.artifact_store, {2}).install()
        try:
            status, body = srv.request(
                "POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": "t1", "algorithm": "AES256"},
                {"X-Operator-Id": "alice", "Idempotency-Key": "restart-bad"},
            )
        finally:
            fault.remove()
        assert status == 500
        operation_id = body["operation_id"]
        mirror_path = os.path.join(
            data_dir, "operation-artifacts", operation_id + ".json"
        )
        with open(mirror_path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
    finally:
        srv.stop()

    srv2 = HttpTestServer(data_dir)
    try:
        # Corrupt mirror: parked pending, never failed, current stays at v1.
        status, op = _op_get(srv2, operation_id)
        assert op["status"] == STATUS_PENDING
        assert srv2.store.get(key_id, "t1").current_version == 1

        # A live request must not overwrite a corrupt mirror: it answers 503
        # and keeps the evidence; the op is still pending.
        status, body2 = srv2.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "restart-bad"},
        )
        assert status == 503
        assert body2["operation_id"] == operation_id
        status, op = _op_get(srv2, operation_id)
        assert op["status"] == STATUS_PENDING
        assert srv2.store.get(key_id, "t1").current_version == 1
        with open(mirror_path, "r", encoding="utf-8") as fh:
            assert fh.read() == "{not valid json"
    finally:
        srv2.stop()


# -- cleanup failure after commit must not change the committed result --------
def test_committed_result_survives_mirror_cleanup_failure(server):
    env, srv = server
    key_id = _create_key(srv)

    real_discard = srv.artifact_store.discard
    discard_called = threading.Event()

    def failing_discard(operation_id):
        # Simulate a failed mirror unlink at request cleanup time.
        discard_called.set()
        return False

    srv.artifact_store.discard = failing_discard
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "cleanup-fail"},
        )
        # The handler thread runs the post-response mirror cleanup
        # asynchronously: wait until it actually invoked the failing
        # discard before restoring the real one, so the mirror is
        # guaranteed to survive.
        assert discard_called.wait(5)
    finally:
        srv.artifact_store.discard = real_discard

    assert status == 201, body
    operation_id = body["operation_id"]
    assert body["version"] == 2
    # The committed operation is still succeeded despite the mirror surviving.
    status, op = _op_get(srv, operation_id)
    assert op["status"] == STATUS_SUCCEEDED
    assert op["http_status"] == 201
    mirror_path = os.path.join(
        env.data_dir, "operation-artifacts", operation_id + ".json"
    )
    assert os.path.exists(mirror_path)

    # A retry replays the committed 201 unchanged.
    status, replay = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "cleanup-fail"},
    )
    assert status == 201
    assert replay == body

    # The next process settles the surviving committed mirror and the op
    # remains succeeded; the version is preserved exactly once.
    srv.stop()
    srv2 = HttpTestServer(env.data_dir)
    try:
        assert not os.path.exists(mirror_path)
        status, op = _op_get(srv2, operation_id)
        assert op["status"] == STATUS_SUCCEEDED
        assert srv2.store.get(key_id, "t1").current_version == 2
        assert [e.event_id for e in env.audit_events()
                if e.action == "rotate"] == [operation_id]
    finally:
        srv2.stop()


# -- a strand followed by a same-tenant import conflict (409) ------------------
def test_strand_then_import_conflict_booked_once(env):
    import keymgr.keybundle as keybundle

    src = HttpTestServer(env.data_dir)
    try:
        key_id = _create_key(src)
        bundle = _export_bundle(src, key_id)
    finally:
        src.stop()
    decoded = keybundle.decode_bundle(bundle, "pw")

    dst_dir = env.data_dir + "-impconflict"
    os.makedirs(dst_dir, exist_ok=True)
    dst = HttpTestServer(dst_dir)
    try:
        fault = MirrorWriteFault(dst.artifact_store, {1}).install()
        try:
            status, body = dst.request(
                "POST", "/v1/keys/import",
                {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
                {"X-Operator-Id": "alice", "Idempotency-Key": "strand-conf"},
            )
        finally:
            fault.remove()
        assert status == 500
        operation_id = body["operation_id"]

        # The same key now appears for this tenant out-of-band, so the retried
        # import must book a 409 conflict (once) for the SAME operation.
        dst.store.import_bundle("t1", decoded)
        status, conflict = dst.request(
            "POST", "/v1/keys/import",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-conf"},
        )
        assert status == 409
        assert conflict["operation_id"] == operation_id

        status, replay = dst.request(
            "POST", "/v1/keys/import",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-conf"},
        )
        assert status == 409
        assert replay == conflict
        status, op = _op_get(dst, operation_id)
        assert op["status"] == "conflict" and op["http_status"] == 409
        # One rejection event named after the operation; no second key.
        events = AuditLog(dst_dir)._read_all()
        assert [e.event_id for e in events
                if e.event_id == operation_id] == [operation_id]
    finally:
        dst.stop()


# -- private fields never leave the service on the strand window --------------
def test_strand_failure_and_retry_never_leak_material(server):
    env, srv = server
    key_id = _create_key(srv)
    fault = MirrorWriteFault(srv.artifact_store, {1}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "leak-1"},
        )
    finally:
        fault.remove()
    operation_id = body["operation_id"]
    status, op = _op_get(srv, operation_id)

    serialized = json.dumps(body) + json.dumps(op)
    assert "encrypted_material" not in serialized
    assert "passphrase" not in serialized
    for handle in env.kms_handles():
        assert handle not in serialized


# -- a strand followed by a rejection is booked once and replayed -------------
def test_strand_then_policy_rejection_booked_once(server):
    env, srv = server
    key_id = _create_key(srv)

    fault = MirrorWriteFault(srv.artifact_store, {1}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-deny"},
        )
    finally:
        fault.remove()
    assert status == 500
    operation_id = body["operation_id"]

    # Deny rotate for alice, then retry: the same op records the 403 once.
    policies = PolicyStore(env.data_dir, AuditLog(env.data_dir))
    from keymgr.policy import Rule

    policies.put(
        "t1",
        [Rule.from_json(
            {"subject": "alice", "actions": ["rotate"], "effect": "deny"}
        )],
    )
    status, denied = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-deny"},
    )
    assert status == 403
    assert denied["operation_id"] == operation_id

    # A further retry replays the 403 verbatim, never re-evaluating or writing
    # a second rejection event.
    status, replay = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-deny"},
    )
    assert status == 403
    assert replay == denied
    assert srv.store.get(key_id, "t1").current_version == 1
    assert [e.event_id for e in env.audit_events()
            if e.event_id == operation_id] == [operation_id]


# -- a strand followed by a provider failure is a durable 503, then replayed --
def test_strand_then_provider_failure_booked_once(server):
    env, srv = server
    key_id = _create_key(srv)

    fault = MirrorWriteFault(srv.artifact_store, {1}).install()
    try:
        status, body = srv.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "strand-prov"},
        )
    finally:
        fault.remove()
    assert status == 500
    operation_id = body["operation_id"]

    env.set_faults({"unreachable": True})
    status, down = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-prov"},
    )
    env.clear_faults()
    assert status == 503
    assert down == {
        "error": "key management provider is unavailable",
        "operation_id": operation_id,
    }

    # Provider healthy again: the durable 503 terminal REPLAYS rather than
    # re-executing, so no rotate happens and the op stays failed/503.
    status, replay = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "strand-prov"},
    )
    assert status == 503
    assert replay == down
    assert srv.store.get(key_id, "t1").current_version == 1
    status, op = _op_get(srv, operation_id)
    assert op["status"] == "failed" and op["http_status"] == 503
    assert [e.event_id for e in env.audit_events()
            if e.event_id == operation_id] == [operation_id]
