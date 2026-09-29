"""HTTP contract for POST /v1/restore/preflight."""

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import audit as audit_mod
from keymgr import tenantbundle
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.restore import RestoreCoordinator
from keymgr.server import make_handler
from keymgr.store import KeyStore

PATH = "/v1/restore/preflight"


class HttpServer:
    def __init__(self, env):
        audit_log = AuditLog(env.data_dir)
        store = KeyStore(env.data_dir, audit_log)
        policy_store = PolicyStore(env.data_dir, audit_log)
        coordinator = RestoreCoordinator(store, policy_store)
        operation_store = OperationStore(env.data_dir, audit_log)
        artifact_store = ArtifactStore(env.data_dir, store, audit_log)
        artifact_store.settle_pending(operation_store)
        operation_store.recover_pending(is_parked=artifact_store.is_parked)
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
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield server
    server.stop()


def _headers(operator="alice", **extra):
    headers = {"X-Operator-Id": operator}
    headers.update(extra)
    return headers


def _rule(operator="alice", effect="allow"):
    # Backup goes through the export action; allow both so test backups
    # succeed while an import-only policy still exists for the tenant.
    actions = ["export", "import"] if effect == "allow" else ["import"]
    return {"subject": operator, "actions": actions, "effect": effect}


def _create_key(http, tenant="t1", label="k"):
    status, body = http.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": "AES256", "label": label},
        _headers(),
    )
    assert status == 201, body
    return body["key_id"]


def _backup(http, tenant="t1", passphrase="pw"):
    status, body = http.request(
        "POST", "/v1/backup",
        {"tenant_id": tenant, "passphrase": passphrase},
        _headers(),
    )
    assert status == 200, body
    return body["bundle"]


def _put_policy(http, tenant, rules, operator="alice"):
    status, body = http.request(
        "PUT", "/v1/policy", {"tenant_id": tenant, "rules": rules},
        _headers(operator),
    )
    assert status == 200, body


def _preflight(http, tenant, bundle, passphrase="pw", headers=None,
               extra_body=None):
    body = {"tenant_id": tenant, "passphrase": passphrase, "bundle": bundle}
    if extra_body:
        body.update(extra_body)
    return http.request(
        "POST", PATH, body, headers if headers is not None else _headers()
    )


def _empty_bundle(tenant_id, passphrase="pw", policy=None):
    return tenantbundle.encode_bundle(
        {
            "format": tenantbundle.FORMAT,
            "tenant_id": tenant_id,
            "keys": [],
            "policy": policy,
        },
        passphrase,
    )


def _bundle_with_foreign_keys(env, tenant_id, key_ids, passphrase="pw"):
    store = KeyStore(env.data_dir, AuditLog(env.data_dir))
    entries = [
        store.backup_entry(store.read_raw(key_id)) for key_id in key_ids
    ]
    return tenantbundle.encode_bundle(
        {
            "format": tenantbundle.FORMAT,
            "tenant_id": tenant_id,
            "keys": entries,
            "policy": None,
        },
        passphrase,
    )


# -- happy paths ---------------------------------------------------------------
def test_empty_tenant_backup_preflights_ready(http):
    bundle = _backup(http, "empty-tenant")
    status, body = _preflight(http, "empty-tenant", bundle)
    assert status == 200, body
    assert body == {
        "key_ids": [],
        "policy_restored": False,
        "ready": True,
        "conflicts": [],
    }


def test_full_bundle_preflight_ready_with_sorted_key_ids(http):
    key_a = _create_key(http, "t1", "a")
    key_b = _create_key(http, "t1", "b")
    _put_policy(http, "t1", [_rule()])
    bundle = _backup(http, "t1")
    # Against the owning tenant every key and the policy conflict.
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body["ready"] is False
    # The same payload re-sealed for a fresh tenant with unused key ids
    # (the originals are owned by t1, which would be foreign occupation)
    # is fully ready.
    import uuid
    raw = tenantbundle.decode_bundle(bundle, "pw")
    raw["tenant_id"] = "fresh"
    for entry in raw["keys"]:
        entry["key_id"] = str(uuid.uuid4())
    fresh_bundle = tenantbundle.encode_bundle(raw, "pw")
    fresh_ids = sorted(entry["key_id"] for entry in raw["keys"])
    status, body = _preflight(http, "fresh", fresh_bundle)
    assert status == 200, body
    assert body["ready"] is True
    assert body["conflicts"] == []
    assert body["key_ids"] == fresh_ids
    assert body["policy_restored"] is True


def test_requires_no_idempotency_key(http):
    bundle = _backup(http, "t1")
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert "operation_id" not in body


# -- conflicts -----------------------------------------------------------------
def test_same_tenant_conflicts_list_keys_then_policy(http):
    key_a = _create_key(http, "t1", "a")
    key_b = _create_key(http, "t1", "b")
    _put_policy(http, "t1", [_rule()])
    bundle = _backup(http, "t1")
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body["ready"] is False
    assert body["policy_restored"] is True
    kinds = [c["kind"] for c in body["conflicts"]]
    assert kinds == ["key", "key", "policy"]
    key_conflicts = [
        c["key_id"] for c in body["conflicts"] if c["kind"] == "key"
    ]
    assert key_conflicts == sorted([key_a, key_b])
    for conflict in body["conflicts"]:
        if conflict["kind"] == "key":
            assert set(conflict) == {"kind", "key_id"}
        else:
            assert conflict == {"kind": "policy"}


def test_policy_conflict_reported_even_for_empty_bundle(http):
    _put_policy(http, "t1", [_rule()])
    bundle = _empty_bundle("t1")
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body["ready"] is False
    assert body["conflicts"] == [{"kind": "policy"}]


def test_bundle_carrying_policy_reports_policy_restored(http):
    bundle = _empty_bundle("t1", policy={"rules": [_rule()]})
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body == {
        "key_ids": [],
        "policy_restored": True,
        "ready": True,
        "conflicts": [],
    }


def test_foreign_key_occupation_is_404(http, env):
    foreign_key = _create_key(http, "t2")
    bundle = _bundle_with_foreign_keys(env, "t1", [foreign_key])
    status, body = _preflight(http, "t1", bundle)
    assert status == 404, body
    assert body == {"error": "tenant backup not found"}


def test_foreign_bundle_tenant_mismatch_is_404(http):
    bundle = _backup(http, "t1")
    status, body = _preflight(http, "t2", bundle)
    assert status == 404, body
    assert body == {"error": "tenant backup not found"}


# -- invalid bundles -----------------------------------------------------------
def test_wrong_passphrase_is_opaque_400(http):
    bundle = _backup(http, "t1")
    status, body = _preflight(http, "t1", bundle, passphrase="nope")
    assert status == 400, body
    assert body == {"error": "invalid tenant backup"}


def test_tampered_bundle_is_opaque_400(http):
    bundle = _backup(http, "t1")
    status, body = _preflight(http, "t1", bundle[:-4] + "AAAA")
    assert status == 400, body
    assert body == {"error": "invalid tenant backup"}


def test_garbage_bundle_is_opaque_400(http):
    status, body = _preflight(http, "t1", "not-a-bundle")
    assert status == 400, body
    assert body == {"error": "invalid tenant backup"}


# -- request validation --------------------------------------------------------
def test_missing_fields_are_400(http):
    status, body = http.request(
        "POST", PATH, {"tenant_id": "t1", "passphrase": "pw"}, _headers()
    )
    assert status == 400
    assert body["error"] == "field bundle must be a non-empty string"

    status, body = http.request(
        "POST", PATH, {"tenant_id": "t1", "bundle": "x"}, _headers()
    )
    assert status == 400
    assert body["error"] == "field passphrase must be a non-empty string"

    status, body = http.request(
        "POST", PATH, {"passphrase": "pw", "bundle": "x"}, _headers()
    )
    assert status == 400
    assert body["error"] == "field tenant_id must be a non-empty string"


def test_unknown_body_field_rejected(http):
    bundle = _backup(http, "t1")
    status, body = _preflight(http, "t1", bundle, extra_body={"nope": 1})
    assert status == 400
    assert body["error"] == "field nope is not accepted by this endpoint"


def test_conflicting_tenant_sources_400_and_records_conflict(http, env):
    bundle = _backup(http, "t1")
    before = len(env.audit_events())
    status, body = _preflight(
        http, "t1", bundle, headers=_headers(**{"X-Tenant-Id": "t2"})
    )
    assert status == 400, body
    events = env.audit_events()[before:]
    assert len(events) == 1
    assert events[0].action == audit_mod.ACTION_TENANT_CONFLICT
    assert events[0].outcome == audit_mod.OUTCOME_REJECTED


def test_missing_operator_is_400(http):
    bundle = _backup(http, "t1")
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {},
    )
    assert status == 400
    assert body["error"] == "missing required header: X-Operator-Id"


# -- authorization -------------------------------------------------------------
def test_import_deny_is_403_and_records_one_rejected_event(http, env):
    # Export stays allowed (so the backup can be produced) while import is
    # denied: preflight authorizes the restore import action only.
    _put_policy(http, "t1", [
        {"subject": "alice", "actions": ["export"], "effect": "allow"},
        {"subject": "alice", "actions": ["import"], "effect": "deny"},
    ])
    bundle = _backup(http, "t1")
    before = len(env.audit_events())
    status, body = _preflight(http, "t1", bundle)
    assert status == 403, body
    assert body == {"error": "action not permitted by policy"}
    events = env.audit_events()[before:]
    assert len(events) == 1
    event = events[0]
    assert event.action == audit_mod.ACTION_IMPORT
    assert event.outcome == audit_mod.OUTCOME_REJECTED
    assert event.tenant_id == "t1"
    assert event.key_id is None

    status, body = _preflight(http, "t1", bundle)
    assert status == 403
    assert len(env.audit_events()[before:]) == 2


# -- no traces / concurrency ---------------------------------------------------
def test_successful_preflight_leaves_no_events_or_markers(http, env):
    _create_key(http, "t1")
    ready_bundle = _backup(http, "fresh")
    before = len(env.audit_events())
    for _ in range(3):
        status, body = _preflight(http, "fresh", ready_bundle)
        assert status == 200 and body["ready"] is True
    assert len(env.audit_events()) == before
    leftovers = [
        name for name in os.listdir(env.data_dir)
        if "preflight" in name or name.startswith("restore-empty-")
    ]
    assert leftovers == []
    ops_dir = os.path.join(env.data_dir, "operations")
    if os.path.isdir(ops_dir):
        assert os.listdir(ops_dir) == []


def test_preflight_waits_for_in_progress_restore_lock(http):
    bundle = _backup(http, "t1")
    done = threading.Event()
    result = {}

    def run():
        result["status"], result["body"] = _preflight(http, "t1", bundle)
        done.set()

    lock_cm = http.coordinator._cross_process_restore_lock()
    lock_cm.__enter__()
    try:
        thread = threading.Thread(target=run)
        thread.start()
        time.sleep(0.3)
        # A restore transaction holding the restore lock is in progress: the
        # preflight view must wait rather than race it.
        assert not done.is_set()
    finally:
        lock_cm.__exit__(None, None, None)
    thread.join(5.0)
    assert done.is_set()
    assert result["status"] == 200
    assert result["body"]["ready"] is True
