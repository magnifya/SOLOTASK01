"""POST /v1/restore/preflight: side-effect-free restore conflict checks."""

import base64
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import restore as restore_mod
from keymgr import tenantbundle
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.server import make_handler
from keymgr.store import KeyStore

OPERATOR = {"X-Operator-Id": "alice"}
PATH = "/v1/restore/preflight"


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


def _create_key(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _backup(srv, tenant, passphrase="pw"):
    status, body = srv.request(
        "POST", "/v1/backup",
        {"tenant_id": tenant, "passphrase": passphrase},
        OPERATOR,
    )
    assert status == 200, body
    return body["bundle"]


def _preflight(srv, tenant, bundle, passphrase="pw"):
    return srv.request(
        "POST", PATH,
        {"tenant_id": tenant, "passphrase": passphrase, "bundle": bundle},
        OPERATOR,
    )


def _restore(srv, tenant, bundle, key="restore-1"):
    return srv.request(
        "POST", "/v1/restore",
        {"tenant_id": tenant, "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": key},
    )


def _reseal_for(tenant, bundle, passphrase="pw"):
    payload = tenantbundle.decode_bundle(bundle, passphrase)
    payload["tenant_id"] = tenant
    return tenantbundle.encode_bundle(payload, passphrase)


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


# -- success / conflict semantics -------------------------------------------
def test_preflight_clean_target_is_ready(pair):
    src, dst = pair
    _create_key(src, "t1")
    _create_key(src, "t1")
    bundle = _backup(src, "t1")
    handles_before = src.env.kms_handles()
    events_before = _event_tuples(dst)
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200, body
    assert body["policy_restored"] is False
    assert body["ready"] is True
    assert body["conflicts"] == []
    assert body["key_ids"] == sorted(body["key_ids"])
    assert len(body["key_ids"]) == 2
    assert _event_tuples(dst) == events_before
    assert src.env.kms_handles() == handles_before
    # No key file, policy document, empty-restore marker or handle journal.
    names = os.listdir(dst.env.data_dir)
    assert not [n for n in names if n.endswith(".json") and n[:1].isdigit()]
    assert not [n for n in names if n.startswith("restore-empty-")]
    assert not os.path.exists(os.path.join(dst.env.data_dir, "provisions"))
    assert not [
        n
        for n in os.listdir(os.path.join(dst.env.data_dir, "policies"))
        if not n.endswith(".lock")
    ]


def test_preflight_empty_bundle_is_ready(http):
    bundle = _backup(http, "empty")
    status, body = _preflight(http, "empty", bundle)
    assert status == 200, body
    assert body == {
        "key_ids": [],
        "policy_restored": False,
        "ready": True,
        "conflicts": [],
    }


def test_preflight_same_tenant_key_and_policy_conflicts(pair):
    src, dst = pair
    kid_a = _create_key(src, "t1")
    kid_b = _create_key(src, "t1")
    _put_policy(
        src, "t1",
        [{"subject": "alice", "actions": ["import", "export"],
          "effect": "allow"}],
    )
    bundle = _backup(src, "t1")
    assert _restore(dst, "t1", bundle, "restore-into-dst")[0] == 201
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200, body
    assert body["ready"] is False
    assert body["policy_restored"] is True
    key_ids = sorted([kid_a, kid_b])
    key_conflicts = [c for c in body["conflicts"] if c["type"] == "key"]
    assert [c["key_id"] for c in key_conflicts] == key_ids
    assert body["conflicts"][-1] == {"type": "policy"}
    assert sum(c["type"] == "policy" for c in body["conflicts"]) == 1


def test_preflight_key_only_conflicts_when_bundle_has_no_policy(pair):
    src, dst = pair
    _create_key(src, "t1")
    bundle = _backup(src, "t1")
    assert _restore(dst, "t1", bundle, "restore-into-dst")[0] == 201
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200
    assert body["ready"] is False
    assert body["policy_restored"] is False
    assert [c["type"] for c in body["conflicts"]] == ["key"]
    assert body["conflicts"][0]["key_id"] in body["key_ids"]


# -- 404 foreign occupation ---------------------------------------------------
def test_preflight_foreign_key_owner_is_404(http):
    _create_key(http, "t1")
    bundle_t1 = _backup(http, "t1")
    bundle_t2 = _reseal_for("t2", bundle_t1)
    # Fresh key ids would collide with nothing on this server only after
    # t1's records are gone, so re-seal with new ids for the t2 restore.
    payload = tenantbundle.decode_bundle(bundle_t2, "pw")
    import uuid

    for key in payload["keys"]:
        key["key_id"] = str(uuid.uuid4())
    bundle_t2 = tenantbundle.encode_bundle(payload, "pw")
    assert _restore(http, "t2", bundle_t2, "r-t2")[0] == 201
    # The original ids are now occupied by t2; a t3-sealed original bundle
    # hits a foreign owner.
    bundle_t3 = _reseal_for("t3", bundle_t1)
    status, body = _preflight(http, "t3", bundle_t3)
    assert status == 404
    assert body == {"error": "tenant backup not found"}


def test_preflight_bundle_for_other_tenant_is_404(pair):
    src, dst = pair
    _create_key(src, "t1")
    bundle = _backup(src, "t1")
    before = _event_tuples(dst)
    status, body = _preflight(dst, "t2", bundle)
    assert status == 404
    assert body == {"error": "tenant backup not found"}
    assert _event_tuples(dst) == before


# -- 400 validation ------------------------------------------------------------
def test_preflight_wrong_passphrase_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    events_before = _event_tuples(http)
    status, body = _preflight(http, "t1", bundle, passphrase="nope")
    assert status == 400
    assert body == {"error": "invalid tenant backup"}
    assert _event_tuples(http) == events_before


def test_preflight_tampered_bundle_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    raw = bytearray(base64.b64decode(bundle))
    raw[-1] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    status, body = _preflight(http, "t1", tampered)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


@pytest.mark.parametrize("bad_bundle", ["not-base64", "@@@@", "aaa="])
def test_preflight_malformed_bundle_is_fixed_400(http, bad_bundle):
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bad_bundle},
        OPERATOR,
    )
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_preflight_empty_bundle_field_is_400(http):
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": ""},
        OPERATOR,
    )
    assert status == 400
    assert body["error"] == "field bundle must be a non-empty string"


def test_preflight_rejects_unknown_fields(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    status, body = http.request(
        "POST", PATH,
        {
            "tenant_id": "t1",
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
        ("bundle", 7),
    ],
)
def test_preflight_field_errors(http, field, value):
    payload = {"tenant_id": "t1", "passphrase": "pw", "bundle": "b"}
    payload[field] = value
    status, body = http.request("POST", PATH, payload, OPERATOR)
    assert status == 400
    assert "invalid tenant backup" not in body["error"]


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


# -- 403 policy ---------------------------------------------------------------
def test_preflight_denied_import_is_403_with_one_rejected_event(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    _put_policy(
        http, "t1",
        [{"subject": "alice", "actions": ["import"], "effect": "deny"}],
    )
    status, body = _preflight(http, "t1", bundle)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in http.env.audit_events()
        if e.action == "import" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].tenant_id == "t1"
    assert rejected[0].key_id is None
    assert _preflight(http, "t1", bundle)[0] == 403
    rejected = [
        e for e in http.env.audit_events()
        if e.action == "import" and e.outcome == "rejected"
    ]
    assert len(rejected) == 2


def test_preflight_denial_happens_before_foreign_tenant_404(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    _put_policy(
        http, "t2",
        [{"subject": "alice", "actions": ["import"], "effect": "deny"}],
    )
    status, body = _preflight(http, "t2", bundle)
    assert status == 403
    assert body["error"] == "action not permitted by policy"


# -- consistency with a real restore ------------------------------------------
def test_preflight_then_restore_succeeds_and_repreflight_conflicts(pair):
    src, dst = pair
    kids = sorted(_create_key(src, "t1") for _ in range(3))
    _put_policy(
        src, "t1",
        [{"subject": "alice", "actions": ["import", "export"],
          "effect": "allow"}],
    )
    bundle = _backup(src, "t1")
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200 and body["ready"] is True
    assert body["key_ids"] == kids
    status, _ = _restore(dst, "t1", bundle, "restore-t1")
    assert status == 201
    status, body = _preflight(dst, "t1", bundle)
    assert status == 200 and body["ready"] is False
    assert [c["type"] for c in body["conflicts"]] == [
        "key", "key", "key", "policy"
    ]


def test_preflight_is_linearizable_against_concurrent_restore(pair, monkeypatch):
    import time
    from contextlib import contextmanager

    src, dst = pair
    for _ in range(3):
        _create_key(src, "t1")
    _put_policy(
        src, "t1",
        [{"subject": "alice", "actions": ["import", "export"],
          "effect": "allow"}],
    )
    bundle = _backup(src, "t1")

    original_locks = type(dst.coordinator)._restore_locks

    @contextmanager
    def slow_locks(tenant_id, key_ids, timeout):
        with original_locks(dst.coordinator, tenant_id, key_ids, timeout):
            time.sleep(0.4)
            yield

    monkeypatch.setattr(dst.coordinator, "_restore_locks", slow_locks)

    results = []

    def do_restore():
        results.append(
            ("restore",) + _restore(dst, "t1", bundle, "restore-conc")
        )

    thread = threading.Thread(target=do_restore)
    thread.start()
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        status, body = _preflight(dst, "t1", bundle)
        assert status == 200, body
        if body["ready"]:
            assert body["conflicts"] == []
        else:
            # The whole write set or none: never a partial restore.
            assert [c["type"] for c in body["conflicts"]] == [
                "key", "key", "key", "policy"
            ]
        results.append(("preflight", status, body["ready"]))
        time.sleep(0.02)
    thread.join()
    assert results[0][0] == "restore" or any(
        item[0] == "preflight" and item[2] for item in results
    )
    assert any(
        item[0] == "preflight" and not item[2] for item in results
    )
    assert results[-1][1] == 201 if results[-1][0] == "restore" else True
    restore_results = [item for item in results if item[0] == "restore"]
    assert restore_results and restore_results[0][1] == 201
