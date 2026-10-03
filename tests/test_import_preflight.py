"""POST /v1/keys/import/preflight: side-effect-free import dry run."""

import base64
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import operations as operations_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.server import make_handler
from keymgr.store import KeyStore

OPERATOR = {"X-Operator-Id": "alice"}
PATH = "/v1/keys/import/preflight"


class HttpServer:
    def __init__(self, env):
        audit_log = AuditLog(env.data_dir)
        store = KeyStore(env.data_dir, audit_log)
        policy_store = PolicyStore(env.data_dir, audit_log)
        coordinator = restore_mod.RestoreCoordinator(store, policy_store)
        operation_store = OperationStore(env.data_dir, audit_log)
        artifact_store = ArtifactStore(env.data_dir, store, audit_log)
        artifact_store.settle_pending(operation_store)
        operation_store.recover_pending(is_parked=artifact_store.is_parked)
        self.env = env
        self.store = store
        self.coordinator = coordinator
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                store, policy_store, coordinator, operation_store,
                artifact_store,
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
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield server
    server.stop()


@pytest.fixture()
def pair(env, tmp_path):
    """Two servers on separate data dirs sharing the fake KMS backend."""
    first = HttpServer(env)
    other_dir = str(tmp_path / "other-data")
    os.makedirs(other_dir, exist_ok=True)
    from types import SimpleNamespace

    second = HttpServer(SimpleNamespace(data_dir=other_dir))
    yield first, second
    first.stop()
    second.stop()


def _create_key(srv, tenant="t1", algorithm="AES256", label="k"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": label},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _export(srv, key_id, tenant="t1", passphrase="pw"):
    status, body = srv.request(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": tenant, "passphrase": passphrase},
        OPERATOR,
    )
    assert status == 200, body
    return body["bundle"]


def _preflight(srv, tenant, bundle, passphrase="pw", headers=None):
    return srv.request(
        "POST", PATH,
        {"tenant_id": tenant, "passphrase": passphrase, "bundle": bundle},
        headers or OPERATOR,
    )


def _put_policy(srv, tenant, rules):
    return srv.request(
        "PUT", "/v1/policy?tenant_id=" + tenant,
        {"tenant_id": tenant, "rules": rules}, OPERATOR
    )


def _event_tuples(srv):
    return [
        (e.action, e.outcome, e.tenant_id, e.key_id)
        for e in AuditLog(srv.env.data_dir)._read_all()
    ]


def _data_artifacts(data_dir):
    """All files except advisory lock sidecars under the data directory."""
    found = set()
    for root, _dirs, files in os.walk(data_dir):
        for name in files:
            if name.endswith(".lock"):
                continue
            found.add(os.path.relpath(os.path.join(root, name), data_dir))
    return found


# -- success / occupancy semantics ------------------------------------------
def test_preflight_clean_target_is_ready(pair):
    src, dst = pair
    key_id = _create_key(src, "t1", label="label-a")
    bundle = _export(src, key_id, "t1")
    handles_before = src.env.kms_handles()
    events_before = _event_tuples(dst)
    artifacts_before = _data_artifacts(dst.env.data_dir)
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200, body
    assert body == {
        "key_id": key_id,
        "label": "label-a",
        "current_version": 1,
        "version_count": 1,
        "status": "active",
        "ready": True,
    }
    # No audit event, no provider handle, no new file (lock sidecars aside).
    assert _event_tuples(dst) == events_before
    assert src.env.kms_handles() == handles_before
    assert _data_artifacts(dst.env.data_dir) == artifacts_before


def test_preflight_summary_reflects_bundle_versions(pair):
    src, dst = pair
    key_id = _create_key(src, "t1", label="multi")
    for index in range(2):
        status, _ = src.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {**OPERATOR, "Idempotency-Key": "rot-%d" % index},
        )
        assert status == 201
    bundle = _export(src, key_id, "t1")
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200, body
    assert body["key_id"] == key_id
    assert body["label"] == "multi"
    assert body["current_version"] == 3
    assert body["version_count"] == 3
    assert body["status"] == "active"
    assert body["ready"] is True


def test_preflight_same_tenant_occupancy_is_not_ready(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body["ready"] is False
    assert body["key_id"] == key_id


def test_preflight_same_tenant_revoked_key_is_not_ready(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    status, _ = http.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t1", "reason": "retired", "operator": "alice"},
        OPERATOR,
    )
    assert status == 200
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    # A revoked key still occupies the identifier.
    assert body["ready"] is False
    # The summary still comes from the (pre-revocation) bundle.
    assert body["status"] == "active"


def test_preflight_revoked_bundle_reports_its_status(pair):
    src, dst = pair
    key_id = _create_key(src, "t1")
    status, _ = src.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t1", "reason": "retired", "operator": "alice"},
        OPERATOR,
    )
    assert status == 200
    bundle = _export(src, key_id, "t1")
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200, body
    assert body["status"] == "revoked"
    assert body["ready"] is True


def test_preflight_foreign_occupancy_is_404(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    events_before = _event_tuples(http)
    status, body = _preflight(http, "t2", bundle)
    assert status == 404
    assert body == {"error": "key not found"}
    assert _event_tuples(http) == events_before


def test_preflight_idempotency_header_is_ignored(pair):
    src, dst = pair
    key_id = _create_key(src, "t1")
    bundle = _export(src, key_id, "t1")
    status, body = _preflight(
        dst, "t1", bundle,
        headers={**OPERATOR, "Idempotency-Key": "not-bound"},
    )
    assert status == 200, body
    assert body["ready"] is True
    assert "operation_id" not in body
    # No operation record was bound or persisted.
    operations_dir = os.path.join(dst.env.data_dir, "operations")
    assert not os.path.exists(operations_dir) or not os.listdir(
        operations_dir
    )
    # A repeated call with the same header is not a replay/conflict.
    status, body = _preflight(
        dst, "t1", bundle,
        headers={**OPERATOR, "Idempotency-Key": "not-bound"},
    )
    assert status == 200
    assert body["ready"] is True


# -- 400 validation -----------------------------------------------------------
def test_preflight_wrong_passphrase_is_fixed_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    events_before = _event_tuples(http)
    status, body = _preflight(http, "t2", bundle, passphrase="nope")
    assert status == 400
    assert body == {"error": "invalid key export"}
    assert _event_tuples(http) == events_before


def test_preflight_tampered_bundle_is_fixed_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    raw = bytearray(
        base64.urlsafe_b64decode(bundle + "=" * (-len(bundle) % 4))
    )
    raw[-1] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode(
        "ascii"
    )
    status, body = _preflight(http, "t2", tampered)
    assert status == 400
    assert body == {"error": "invalid key export"}


@pytest.mark.parametrize("bad_bundle", ["not-base64", "@@@@", "aaa="])
def test_preflight_malformed_bundle_is_fixed_400(http, bad_bundle):
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bad_bundle},
        OPERATOR,
    )
    assert status == 400
    assert body == {"error": "invalid key export"}


def test_preflight_invalid_bundle_contents_are_fixed_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    from keymgr import keybundle

    payload = keybundle.decode_bundle(bundle, "pw")
    # Break the contiguous 1..N version sequence.
    payload["versions"] = payload["versions"] + [
        dict(payload["versions"][0], version=7)
    ]
    payload["current_version"] = 7
    resealed = keybundle.encode_bundle(payload, "pw")
    status, body = _preflight(http, "t2", resealed)
    assert status == 400
    assert body == {"error": "invalid key export"}


def test_preflight_rejects_unknown_fields(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    status, body = http.request(
        "POST", PATH,
        {
            "tenant_id": "t2",
            "passphrase": "pw",
            "bundle": bundle,
            "extra": 1,
        },
        OPERATOR,
    )
    assert status == 400
    assert body["error"] == "field extra is not accepted by this endpoint"


@pytest.mark.parametrize(
    "field,value",
    [
        ("passphrase", ""),
        ("passphrase", 5),
        ("bundle", ""),
        ("bundle", 7),
    ],
)
def test_preflight_field_errors(http, field, value):
    payload = {"tenant_id": "t1", "passphrase": "pw", "bundle": "b"}
    payload[field] = value
    status, body = http.request("POST", PATH, payload, OPERATOR)
    assert status == 400
    assert field in body["error"]
    assert "invalid key export" not in body["error"]


def test_preflight_missing_tenant_still_records_tenant_conflict(http):
    status, body = http.request(
        "POST", PATH, {"passphrase": "pw", "bundle": "b"}, OPERATOR
    )
    assert status == 400
    assert body["error"] == "field tenant_id must be a non-empty string"
    actions = [(e.action, e.outcome) for e in http.env.audit_events()]
    assert ("tenant_conflict", "rejected") in actions


def test_preflight_conflicting_tenant_sources_are_400(http):
    status, body = http.request(
        "POST", PATH + "?tenant_id=t1",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": "b"},
        {**OPERATOR, "X-Tenant-Id": "t3"},
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    actions = [(e.action, e.outcome) for e in http.env.audit_events()]
    assert ("tenant_conflict", "rejected") in actions


def test_preflight_missing_operator_is_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t2", "passphrase": "pw", "bundle": bundle},
    )
    assert status == 400
    assert "X-Operator-Id" in body["error"]


# -- 403 policy -----------------------------------------------------------------
def test_preflight_denied_import_is_403_with_one_rejected_event(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    _put_policy(
        http, "t2",
        [{"subject": "alice", "actions": ["import"], "effect": "deny"}],
    )
    status, body = _preflight(http, "t2", bundle)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in http.env.audit_events()
        if e.action == "import" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].tenant_id == "t2"
    # The rejection event carries the in-bundle key_id.
    assert rejected[0].key_id == key_id
    assert _preflight(http, "t2", bundle)[0] == 403
    rejected = [
        e for e in http.env.audit_events()
        if e.action == "import" and e.outcome == "rejected"
    ]
    assert len(rejected) == 2


def test_preflight_key_scoped_rule_applies_to_bundle_key_id(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    # Deny import only for this key_id; an unscoped allow alone would pass.
    _put_policy(
        http, "t2",
        [
            {"subject": "alice", "actions": ["import"], "effect": "allow"},
            {"subject": "alice", "actions": ["import"], "effect": "deny",
             "key_ids": [key_id]},
        ],
    )
    status, body = _preflight(http, "t2", bundle)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}


def test_preflight_denial_happens_before_foreign_404(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    _put_policy(
        http, "t2",
        [{"subject": "alice", "actions": ["import"], "effect": "deny"}],
    )
    # t2 is denied AND the key_id is occupied by t1: 403 wins.
    status, body = _preflight(http, "t2", bundle)
    assert status == 403
    assert body["error"] == "action not permitted by policy"


# -- 500 unavailable -------------------------------------------------------------
def test_preflight_corrupt_record_is_fixed_500(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    with open(os.path.join(http.env.data_dir, key_id + ".json"), "w") as fh:
        fh.write("not json")
    status, body = _preflight(http, "t1", bundle)
    assert status == 500
    assert body == {"error": "key import preflight unavailable"}


def test_preflight_lock_wait_timeout_is_fixed_500(http, monkeypatch):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id, "t1")
    monkeypatch.setattr(operations_mod, "LOCK_WAIT_SECONDS", 0.2)
    with http.store.key_locks(key_id):
        status, body = _preflight(http, "t2", bundle)
    assert status == 500
    assert body == {"error": "key import preflight unavailable"}


# -- consistency with a real import ---------------------------------------------
def test_preflight_then_import_succeeds_and_repreflight_conflicts(pair):
    src, dst = pair
    key_id = _create_key(src, "t1")
    bundle = _export(src, key_id, "t1")
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200 and body["ready"] is True
    status, _ = dst.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {**OPERATOR, "Idempotency-Key": "import-1"},
    )
    assert status == 201
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200 and body["ready"] is False


def test_preflight_is_linearizable_against_concurrent_import(pair, monkeypatch):
    import time

    src, dst = pair
    key_id = _create_key(src, "t1")
    bundle = _export(src, key_id, "t1")

    original_locks = type(dst.store).key_locks

    from contextlib import contextmanager

    @contextmanager
    def slow_locks(self, k, timeout=None):
        with original_locks(self, k, timeout):
            time.sleep(0.3)
            yield

    monkeypatch.setattr(type(dst.store), "key_locks", slow_locks)

    results = []

    def do_import():
        results.append(
            ("import",) + dst.request(
                "POST", "/v1/keys/import",
                {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
                {**OPERATOR, "Idempotency-Key": "import-conc"},
            )
        )

    thread = threading.Thread(target=do_import)
    thread.start()
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        status, body = _preflight(dst, "t1", bundle)
        assert status == 200, body
        assert body["ready"] in (True, False)
        results.append(("preflight", status, body["ready"]))
        time.sleep(0.02)
    thread.join()
    import_results = [item for item in results if item[0] == "import"]
    assert import_results and import_results[0][1] == 201
    # The committed import is eventually observed as occupied.
    assert any(
        item[0] == "preflight" and item[2] is False for item in results
    )
