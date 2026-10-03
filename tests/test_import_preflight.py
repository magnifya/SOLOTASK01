"""POST /v1/keys/import/preflight: side-effect-free import dry run."""

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import keybundle
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

    def request(self, method, path, body=None, headers=None, raw=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = raw if raw is not None else (
            None if body is None else json.dumps(body).encode("utf-8")
        )
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
    merged = dict(OPERATOR)
    merged.update(headers or {})
    return srv.request(
        "POST", PATH,
        {"tenant_id": tenant, "passphrase": passphrase, "bundle": bundle},
        merged,
    )


def _put_policy(srv, tenant, rules):
    return srv.request(
        "PUT", "/v1/policy?tenant_id=" + tenant,
        {"tenant_id": tenant, "rules": rules}, OPERATOR
    )


def _data_artifacts(data_dir):
    """All files except advisory lock sidecars under the data directory."""
    found = set()
    for root, _dirs, files in os.walk(data_dir):
        for name in files:
            if name.endswith(".lock"):
                continue
            found.add(os.path.relpath(os.path.join(root, name), data_dir))
    return found


# -- success / occupancy semantics -------------------------------------------
def test_preflight_free_target_is_ready(http):
    key_id = _create_key(http, "t1", label="source")
    bundle = _export(http, key_id)
    # A second data dir is not needed: preflight the bundle against a
    # tenant that does not own the key_id... but the same server is enough
    # for the free case once the bundle targets a fresh key_id.
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-0000000000aa"
    free_bundle = keybundle.encode_bundle(payload, "pw")
    events_before = list(http.env.audit_events())
    artifacts_before = _data_artifacts(http.env.data_dir)
    handles_before = http.env.kms_handles()
    status, body = _preflight(http, "t2", free_bundle)
    assert status == 200, body
    assert body == {
        "key_id": "00000000-0000-4000-8000-0000000000aa",
        "label": "source",
        "current_version": 1,
        "version_count": 1,
        "status": "active",
        "ready": True,
    }
    # No audit event, no file, no provider handle, no operation record.
    assert list(http.env.audit_events()) == events_before
    assert _data_artifacts(http.env.data_dir) == artifacts_before
    assert http.env.kms_handles() == handles_before


def test_preflight_same_tenant_occupation_is_not_ready(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body["key_id"] == key_id
    assert body["ready"] is False


def test_preflight_revoked_key_still_counts_as_occupied(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    status, _ = http.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t1", "reason": "retired", "operator": "alice"},
        OPERATOR,
    )
    assert status == 200
    status, body = _preflight(http, "t1", bundle)
    assert status == 200, body
    assert body["ready"] is False


def test_preflight_foreign_tenant_occupation_is_404(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    events_before = list(http.env.audit_events())
    status, body = _preflight(http, "t2", bundle)
    assert status == 404
    assert body == {"error": "key not found"}
    assert list(http.env.audit_events()) == events_before


def test_preflight_summary_comes_from_the_bundle(http):
    key_id = _create_key(http, "t1", label="rotated")
    status, _ = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        dict(OPERATOR, **{"Idempotency-Key": "rot-1"}),
    )
    assert status == 201
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-0000000000bb"
    free_bundle = keybundle.encode_bundle(payload, "pw")
    status, body = _preflight(http, "t1", free_bundle)
    assert status == 200, body
    assert body["version_count"] == 2
    assert body["current_version"] == 2
    assert body["label"] == "rotated"
    assert body["status"] == "active"
    assert body["ready"] is True


def test_preflight_then_import_succeeds_and_repreflight_conflicts(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-0000000000cc"
    free_bundle = keybundle.encode_bundle(payload, "pw")
    assert _preflight(http, "t2", free_bundle)[1]["ready"] is True
    status, body = http.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": free_bundle},
        dict(OPERATOR, **{"Idempotency-Key": "imp-1"}),
    )
    assert status == 201, body
    status, body = _preflight(http, "t2", free_bundle)
    assert status == 200, body
    assert body["ready"] is False


# -- 400 request/bundle errors ------------------------------------------------
def test_preflight_wrong_passphrase_is_fixed_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    status, body = _preflight(http, "t1", bundle, passphrase="nope")
    assert status == 400
    assert body == {"error": "invalid key export"}


def test_preflight_tampered_bundle_is_fixed_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    tampered = bundle[:-4] + ("AAAA" if bundle[-4:] != "AAAA" else "BBBB")
    status, body = _preflight(http, "t1", tampered)
    assert status == 400
    assert body == {"error": "invalid key export"}


def test_preflight_bad_base64_is_fixed_400(http):
    status, body = _preflight(http, "t1", "!!!not-base64!!!")
    assert status == 400
    assert body == {"error": "invalid key export"}


def test_preflight_invalid_bundle_fields_are_fixed_400(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["current_version"] = 7
    status, body = _preflight(
        http, "t1", keybundle.encode_bundle(payload, "pw")
    )
    assert status == 400
    assert body == {"error": "invalid key export"}


def test_preflight_legacy_bundle_without_new_fields_is_accepted(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-0000000000dd"
    for ver in payload["versions"]:
        ver.pop("provider", None)
        for field in ("status", "reason", "operator", "revoked_at"):
            ver.pop(field, None)
    legacy = keybundle.encode_bundle(payload, "pw")
    status, body = _preflight(http, "t1", legacy)
    assert status == 200, body
    assert body["ready"] is True
    assert body["version_count"] == 1


def test_preflight_request_field_errors(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    status, body = http.request(
        "POST", PATH, {"passphrase": "pw", "bundle": bundle}, OPERATOR,
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    status, body = http.request(
        "POST", PATH, {"tenant_id": "t1", "bundle": bundle}, OPERATOR,
    )
    assert status == 400
    assert "passphrase" in body["error"]
    status, body = http.request(
        "POST", PATH, {"tenant_id": "t1", "passphrase": "pw"}, OPERATOR,
    )
    assert status == 400
    assert "bundle" in body["error"]
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle,
         "extra": 1},
        OPERATOR,
    )
    assert status == 400
    assert "extra" in body["error"]
    status, body = http.request(
        "POST", PATH, None, OPERATOR, raw=b"not json",
    )
    assert status == 400


def test_preflight_tenant_sources_must_agree(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    status, body = http.request(
        "POST", PATH + "?tenant_id=t2",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        OPERATOR,
    )
    assert status == 400
    assert "tenant_id" in body["error"]


# -- 403 policy ---------------------------------------------------------------
def test_preflight_denied_import_is_403_with_one_rejected_event(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
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
    assert rejected[0].key_id == key_id


def test_preflight_key_scoped_rule_applies_to_bundle_key_id(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-0000000000ee"
    scoped = keybundle.encode_bundle(payload, "pw")
    _put_policy(
        http, "t2",
        [{"subject": "alice", "actions": ["import"], "effect": "allow"},
         {"subject": "alice", "actions": ["import"], "effect": "deny",
          "key_ids": ["00000000-0000-4000-8000-0000000000ee"]}],
    )
    # The in-bundle key_id matches the scoped deny: rejected.
    status, body = _preflight(http, "t2", scoped)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    # The same bundle naming any other key_id is allowed.
    payload["key_id"] = "00000000-0000-4000-8000-0000000000ef"
    status, body = _preflight(
        http, "t2", keybundle.encode_bundle(payload, "pw")
    )
    assert status == 200, body
    assert body["ready"] is True


# -- 500 unavailable ----------------------------------------------------------
def test_preflight_corrupt_target_record_is_fixed_500(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-000000000099"
    target_bundle = keybundle.encode_bundle(payload, "pw")
    # A corrupt file already occupies the target key_id's path: the
    # preflight cannot judge occupancy and must fail, never report ready.
    with open(
        os.path.join(
            http.env.data_dir,
            "00000000-0000-4000-8000-000000000099.json",
        ),
        "w",
        encoding="utf-8",
    ) as fh:
        fh.write("{not json")
    status, body = _preflight(http, "t1", target_bundle)
    assert status == 500
    assert body == {"error": "key import preflight unavailable"}


# -- idempotency header is ignored --------------------------------------------
def test_preflight_ignores_idempotency_key(http):
    key_id = _create_key(http, "t1")
    bundle = _export(http, key_id)
    payload = keybundle.decode_bundle(bundle, "pw")
    payload["key_id"] = "00000000-0000-4000-8000-0000000000ff"
    free_bundle = keybundle.encode_bundle(payload, "pw")
    headers = {"Idempotency-Key": "pre-1"}
    status, body = _preflight(http, "t2", free_bundle, headers=headers)
    assert status == 200, body
    assert body["ready"] is True
    assert "operation_id" not in body
    # The key was never bound: the same Idempotency-Key still works for a
    # real import and no operation record was created by the preflight.
    status, body = http.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": free_bundle},
        dict(OPERATOR, **{"Idempotency-Key": "pre-1"}),
    )
    assert status == 201, body
