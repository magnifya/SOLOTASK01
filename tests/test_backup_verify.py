"""POST /v1/backup/verify and `keymgr backup verify`: read-only checks."""

import base64
import json
import os
import subprocess
import sys
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
PATH = "/v1/backup/verify"


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


def _create_key(srv, tenant="t1"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": "RSA2048", "label": "k"},
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


def _verify(srv, tenant, bundle, passphrase="pw", headers=None):
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


def _payload(bundle, passphrase="pw"):
    return tenantbundle.decode_bundle(bundle, passphrase)


def _reseal(payload, passphrase="pw"):
    return tenantbundle.encode_bundle(payload, passphrase)


# -- success ----------------------------------------------------------------
def test_verify_empty_bundle_is_valid(http):
    bundle = _backup(http, "empty")
    events_before = _event_tuples(http)
    status, body = _verify(http, "empty", bundle)
    assert status == 200, body
    assert body == {
        "valid": True,
        "tenant_id": "empty",
        "key_ids": [],
        "policy_restored": False,
    }
    assert _event_tuples(http) == events_before


def test_verify_valid_bundle_lists_sorted_key_ids(http):
    kids = sorted(_create_key(http, "t1") for _ in range(3))
    _put_policy(
        http, "t1",
        [{"subject": "alice", "actions": ["export"], "effect": "allow"}],
    )
    bundle = _backup(http, "t1")
    handles_before = http.env.kms_handles()
    events_before = _event_tuples(http)
    status, body = _verify(http, "t1", bundle)
    assert status == 200, body
    assert body["valid"] is True
    assert body["tenant_id"] == "t1"
    assert body["key_ids"] == kids
    assert body["policy_restored"] is True
    assert _event_tuples(http) == events_before
    assert http.env.kms_handles() == handles_before


def test_verify_bundle_without_policy_reports_false(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    status, body = _verify(http, "t1", bundle)
    assert status == 200, body
    assert body["policy_restored"] is False
    assert len(body["key_ids"]) == 1


# -- 400 invalid bundle -----------------------------------------------------
def test_verify_wrong_passphrase_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    events_before = _event_tuples(http)
    status, body = _verify(http, "t1", bundle, passphrase="nope")
    assert status == 400
    assert body == {"error": "invalid tenant backup"}
    assert _event_tuples(http) == events_before


def test_verify_tampered_bundle_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    raw = bytearray(base64.urlsafe_b64decode(bundle + "=="))
    raw[-1] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode(
        "ascii"
    )
    status, body = _verify(http, "t1", tampered)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


@pytest.mark.parametrize("bad_bundle", ["not-base64", "@@@@", "aaa="])
def test_verify_malformed_bundle_is_fixed_400(http, bad_bundle):
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bad_bundle},
        OPERATOR,
    )
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_bad_json_payload_is_400(http):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (http.port, PATH),
        data=b"{not json",
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Operator-Id", "alice")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=10)
    assert exc_info.value.code == 400


def test_verify_illegal_version_gap_is_400(http):
    _create_key(http, "t1")
    payload = _payload(_backup(http, "t1"))
    key = payload["keys"][0]
    key["versions"] = [v for v in key["versions"] if v["version"] != 1]
    status, body = _verify(http, "t1", _reseal(payload))
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_current_version_mismatch_is_400(http):
    _create_key(http, "t1")
    payload = _payload(_backup(http, "t1"))
    payload["keys"][0]["current_version"] = 99
    status, body = _verify(http, "t1", _reseal(payload))
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_duplicate_key_id_is_400(http):
    _create_key(http, "t1")
    _create_key(http, "t1")
    payload = _payload(_backup(http, "t1"))
    payload["keys"][1]["key_id"] = payload["keys"][0]["key_id"]
    status, body = _verify(http, "t1", _reseal(payload))
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_illegal_format_tag_is_400(http):
    _create_key(http, "t1")
    payload = _payload(_backup(http, "t1"))
    payload["format"] = "tenant-backup-v2"
    status, body = _verify(http, "t1", _reseal(payload))
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_illegal_policy_structure_is_400(http):
    _create_key(http, "t1")
    payload = _payload(_backup(http, "t1"))
    payload["policy"] = {"rules": "not-an-array"}
    status, body = _verify(http, "t1", _reseal(payload))
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_illegal_policy_rule_fields_are_400(http):
    _create_key(http, "t1")
    payload = _payload(_backup(http, "t1"))
    payload["policy"] = {
        "rules": [{"subject": "alice", "effect": "allow"}]
    }
    status, body = _verify(http, "t1", _reseal(payload))
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


# -- request shape ----------------------------------------------------------
def test_verify_rejects_unknown_fields(http):
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
        ("bundle", ""),
        ("bundle", 7),
    ],
)
def test_verify_field_errors(http, field, value):
    payload = {"tenant_id": "t1", "passphrase": "pw", "bundle": "b"}
    payload[field] = value
    status, body = http.request("POST", PATH, payload, OPERATOR)
    assert status == 400
    assert "invalid tenant backup" not in body["error"]


def test_verify_missing_bundle_field_is_400(http):
    status, body = http.request(
        "POST", PATH, {"tenant_id": "t1", "passphrase": "pw"}, OPERATOR
    )
    assert status == 400
    assert body["error"] == "field bundle must be a non-empty string"


def test_verify_missing_tenant_still_records_tenant_conflict(http):
    status, body = http.request(
        "POST", PATH, {"passphrase": "pw", "bundle": "b"}, OPERATOR
    )
    assert status == 400
    assert body["error"] == "field tenant_id must be a non-empty string"
    actions = [(e.action, e.outcome) for e in http.env.audit_events()]
    assert ("tenant_conflict", "rejected") in actions


def test_verify_conflicting_tenant_sources_are_400(http):
    status, body = http.request(
        "POST", PATH + "?tenant_id=t1",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": "b"},
        {**OPERATOR, "X-Tenant-Id": "t3"},
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    actions = [(e.action, e.outcome) for e in http.env.audit_events()]
    assert ("tenant_conflict", "rejected") in actions


def test_verify_missing_operator_is_400(http):
    status, _ = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": "b"},
        {},
    )
    assert status == 400


# -- 404 cross tenant -------------------------------------------------------
def test_verify_bundle_for_other_tenant_is_404(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    events_before = _event_tuples(http)
    status, body = _verify(http, "t2", bundle)
    assert status == 404
    assert body == {"error": "tenant backup not found"}
    assert _event_tuples(http) == events_before


# -- 403 policy -------------------------------------------------------------
def test_verify_denied_export_is_403_with_one_rejected_event(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    _put_policy(
        http, "t1",
        [{"subject": "alice", "actions": ["export"], "effect": "deny"}],
    )
    status, body = _verify(http, "t1", bundle)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in http.env.audit_events()
        if e.action == "export" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].tenant_id == "t1"
    assert rejected[0].key_id is None
    assert _verify(http, "t1", bundle)[0] == 403
    rejected = [
        e for e in http.env.audit_events()
        if e.action == "export" and e.outcome == "rejected"
    ]
    assert len(rejected) == 2


def test_verify_denial_happens_before_foreign_tenant_404(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    _put_policy(
        http, "t2",
        [{"subject": "alice", "actions": ["export"], "effect": "deny"}],
    )
    status, body = _verify(http, "t2", bundle)
    assert status == 403
    assert body == {"error": "action not permitted by policy"}


# -- read-only side-effect guarantee ----------------------------------------
def test_verify_creates_no_files_policies_or_handles(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")

    def snapshot():
        found = set()
        for root, _dirs, files in os.walk(http.env.data_dir):
            for name in files:
                if name.endswith(".lock"):
                    continue
                found.add(
                    os.path.relpath(os.path.join(root, name),
                                    http.env.data_dir)
                )
        return found

    before = snapshot()
    handles_before = http.env.kms_handles()
    assert _verify(http, "t1", bundle)[0] == 200
    assert snapshot() == before
    assert http.env.kms_handles() == handles_before


# -- CLI parity -------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cli(env, *args):
    env_vars = dict(os.environ)
    env_vars["PYTHONPATH"] = (
        REPO_ROOT + os.pathsep + env_vars.get("PYTHONPATH", "")
    )
    proc = subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", env.data_dir,
         "backup", "verify", *args],
        cwd=REPO_ROOT,
        env=env_vars,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def test_cli_verify_matches_http_valid_empty_and_invalid(env):
    # Seed a tenant with a key and a policy through a throwaway server.
    server = HttpServer(env)
    try:
        kids = sorted(_create_key(server, "t1") for _ in range(2))
        _put_policy(
            server, "t1",
            [{"subject": "alice", "actions": ["export", "import"],
              "effect": "allow"}],
        )
        bundle = _backup(server, "t1")
        empty_bundle = _backup(server, "empty")
        events_before = _event_tuples(server)
        handles_before = env.kms_handles()
    finally:
        server.stop()

    code, out, err = _cli(
        env, "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
    )
    assert code == 0 and err == ""
    assert json.loads(out) == {
        "valid": True,
        "tenant_id": "t1",
        "key_ids": kids,
        "policy_restored": True,
    }
    code, out, err = _cli(
        env, "--tenant-id", "empty", "--passphrase", "pw",
        "--bundle", empty_bundle, "--operator", "alice",
    )
    assert code == 0
    assert json.loads(out)["key_ids"] == []
    assert json.loads(out)["policy_restored"] is False

    # Wrong passphrase -> exit 2, fixed body.
    code, _out, err = _cli(
        env, "--tenant-id", "t1", "--passphrase", "nope",
        "--bundle", bundle, "--operator", "alice",
    )
    assert code == 2
    assert json.loads(err) == {"error": "invalid tenant backup"}

    # Tampered -> exit 2.
    raw = bytearray(base64.urlsafe_b64decode(bundle + "=="))
    raw[-1] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode(
        "ascii"
    )
    code, _out, err = _cli(
        env, "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", tampered, "--operator", "alice",
    )
    assert code == 2
    assert json.loads(err) == {"error": "invalid tenant backup"}

    # Cross tenant -> exit 4.
    code, _out, err = _cli(
        env, "--tenant-id", "t2", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
    )
    assert code == 4
    assert json.loads(err) == {"error": "tenant backup not found"}

    # Invalid version structure -> exit 2.
    payload = _payload(bundle)
    payload["keys"][0]["current_version"] = 99
    code, _out, err = _cli(
        env, "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", _reseal(payload), "--operator", "alice",
    )
    assert code == 2
    assert json.loads(err) == {"error": "invalid tenant backup"}

    # Invalid policy structure -> exit 2.
    payload = _payload(bundle)
    payload["policy"] = {"rules": "nope"}
    code, _out, err = _cli(
        env, "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", _reseal(payload), "--operator", "alice",
    )
    assert code == 2
    assert json.loads(err) == {"error": "invalid tenant backup"}

    # Success path wrote no audit events, no files and no handles.
    server2 = HttpServer(env)
    try:
        assert _event_tuples(server2) == events_before
    finally:
        server2.stop()
    assert env.kms_handles() == handles_before


def test_cli_verify_policy_denial_is_exit_3(env):
    server = HttpServer(env)
    try:
        _create_key(server, "t1")
        bundle = _backup(server, "t1")
        _put_policy(
            server, "t1",
            [{"subject": "alice", "actions": ["export"], "effect": "deny"}],
        )
    finally:
        server.stop()
    code, _out, err = _cli(
        env, "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
    )
    assert code == 3
    assert json.loads(err) == {"error": "action not permitted by policy"}
    rejected = [
        e for e in env.audit_events()
        if e.action == "export" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
