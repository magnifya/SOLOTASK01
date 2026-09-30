"""POST /v1/backup/verify and `keymgr backup verify`: read-only bundle checks."""

import base64
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import cli, restore as restore_mod, tenantbundle
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


def _create_key(srv, tenant="t1", algorithm="RSA2048"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(srv, tenant, key_id, idem):
    status, body = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": "RSA2048"},
        {**OPERATOR, "Idempotency-Key": idem},
    )
    assert status in (200, 201), body
    return body


def _revoke(srv, tenant, key_id):
    status, body = srv.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": tenant, "reason": "done", "operator": "alice"},
        OPERATOR,
    )
    assert status == 200, body


def _backup(srv, tenant, passphrase="pw"):
    status, body = srv.request(
        "POST", "/v1/backup",
        {"tenant_id": tenant, "passphrase": passphrase}, OPERATOR
    )
    assert status == 200, body
    return body["bundle"]


def _verify(srv, tenant, bundle, passphrase="pw", headers=None):
    return srv.request(
        "POST", PATH,
        {"tenant_id": tenant, "passphrase": passphrase, "bundle": bundle},
        headers or OPERATOR,
    )


def _mutated(bundle, mutate, passphrase="pw"):
    payload = tenantbundle.decode_bundle(bundle, passphrase)
    mutate(payload)
    return tenantbundle.encode_bundle(payload, passphrase)


def _tamper(bundle):
    """Flip one ciphertext byte, preserving url-safe base64 framing."""
    raw = bytearray(base64.urlsafe_b64decode(bundle + "=" * (-len(bundle) % 4)))
    raw[-1] ^= 0x01
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


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
    found = set()
    for root, _dirs, files in os.walk(data_dir):
        for name in files:
            if name.endswith(".lock"):
                continue
            found.add(os.path.relpath(os.path.join(root, name), data_dir))
    return found


# -- success ------------------------------------------------------------------
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


def test_verify_valid_bundle_lists_sorted_keys_and_policy(http):
    kids = sorted(_create_key(http, "t1", "RSA2048") for _ in range(3))
    _revoke(http, "t1", kids[0])
    _put_policy(
        http, "t1",
        [{"subject": "alice", "actions": ["import", "export"],
          "effect": "allow"}],
    )
    bundle = _backup(http, "t1")
    handles_before = http.env.kms_handles()
    files_before = _data_artifacts(http.env.data_dir)
    events_before = _event_tuples(http)
    status, body = _verify(http, "t1", bundle)
    assert status == 200, body
    assert body["valid"] is True
    assert body["tenant_id"] == "t1"
    assert body["key_ids"] == kids
    assert body["policy_restored"] is True
    # Pure read: no events, files or provider handles change.
    assert _event_tuples(http) == events_before
    assert _data_artifacts(http.env.data_dir) == files_before
    assert http.env.kms_handles() == handles_before


def test_verify_accepts_contiguous_versions_and_revocation_fields(http):
    key_id = _create_key(http, "t1", "RSA2048")
    _rotate(http, "t1", key_id, "rot-1")
    _revoke(http, "t1", key_id)
    bundle = _backup(http, "t1")
    status, body = _verify(http, "t1", bundle)
    assert status == 200, body
    assert body["key_ids"] == [key_id]


# -- 400 fixed invalid tenant backup ------------------------------------------
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
    tampered = _tamper(_backup(http, "t1"))
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


def test_verify_wrong_format_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _mutated(
        _backup(http, "t1"), lambda p: p.update(format="nope")
    )
    status, body = _verify(http, "t1", bundle)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_current_version_mismatch_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _mutated(
        _backup(http, "t1"),
        lambda p: p["keys"][0].__setitem__("current_version", 99),
    )
    status, body = _verify(http, "t1", bundle)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_version_gap_is_fixed_400(http):
    key_id = _create_key(http, "t1", "RSA2048")
    _rotate(http, "t1", key_id, "rot-gap")

    def drop_v1(payload):
        versions = payload["keys"][0]["versions"]
        payload["keys"][0]["versions"] = [
            v for v in versions if v["version"] != 1
        ]

    bundle = _mutated(_backup(http, "t1"), drop_v1)
    status, body = _verify(http, "t1", bundle)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_bad_revocation_fields_is_fixed_400(http):
    _create_key(http, "t1")
    bundle = _mutated(
        _backup(http, "t1"),
        lambda p: p["keys"][0].__setitem__("status", "bogus"),
    )
    status, body = _verify(http, "t1", bundle)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


def test_verify_duplicate_key_id_is_fixed_400(http):
    _create_key(http, "t1")

    def duplicate(payload):
        payload["keys"].append(dict(payload["keys"][0]))

    bundle = _mutated(_backup(http, "t1"), duplicate)
    status, body = _verify(http, "t1", bundle)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


@pytest.mark.parametrize(
    "rules",
    [
        [{"subject": "alice", "actions": ["export"], "effect": "maybe"}],
        [{"subject": "alice", "actions": "export", "effect": "allow"}],
        [{"subject": 5, "actions": ["export"], "effect": "allow"}],
    ],
)
def test_verify_illegal_policy_rules_are_fixed_400(http, rules):
    _create_key(http, "t1")
    bundle = _mutated(
        _backup(http, "t1"),
        lambda p: p.__setitem__("policy", {"rules": rules}),
    )
    status, body = _verify(http, "t1", bundle)
    assert status == 400
    assert body == {"error": "invalid tenant backup"}


# -- 404 cross tenant ----------------------------------------------------------
def test_verify_bundle_for_other_tenant_is_404(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    before = _event_tuples(http)
    status, body = _verify(http, "t2", bundle)
    assert status == 404
    assert body == {"error": "tenant backup not found"}
    assert _event_tuples(http) == before


# -- request field / identity / tenant source 400 -----------------------------
def test_verify_empty_bundle_field_is_400(http):
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": ""},
        OPERATOR,
    )
    assert status == 400
    assert body["error"] == "field bundle must be a non-empty string"


def test_verify_rejects_unknown_fields(http):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    status, body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw",
         "bundle": bundle, "extra": 1},
        OPERATOR,
    )
    assert status == 400
    assert body["error"] == "field extra is not accepted by this endpoint"


@pytest.mark.parametrize(
    "field,value",
    [("passphrase", ""), ("passphrase", 5), ("bundle", 7)],
)
def test_verify_field_errors(http, field, value):
    payload = {"tenant_id": "t1", "passphrase": "pw", "bundle": "b"}
    payload[field] = value
    status, body = http.request("POST", PATH, payload, OPERATOR)
    assert status == 400
    assert body["error"] != "invalid tenant backup"


def test_verify_missing_operator_is_400(http):
    status, _body = http.request(
        "POST", PATH,
        {"tenant_id": "t1", "passphrase": "pw", "bundle": "b"},
    )
    assert status == 400


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


# -- 403 policy ----------------------------------------------------------------
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


# -- CLI parity ---------------------------------------------------------------
def _cli_verify(env, tenant, bundle, passphrase="pw", operator="alice"):
    code = cli.main(
        [
            "--data-dir", env.data_dir,
            "backup", "verify",
            "--tenant-id", tenant,
            "--operator", operator,
            "--passphrase", passphrase,
            "--bundle", bundle,
        ]
    )
    return code


def _cli_streams(capsys):
    captured = capsys.readouterr()
    out = json.loads(captured.out) if captured.out.strip() else None
    err = json.loads(captured.err) if captured.err.strip() else None
    return out, err


@pytest.mark.parametrize(
    "case",
    ["empty", "valid", "wrong_passphrase", "tampered", "cross_tenant",
     "illegal_version", "illegal_policy", "policy_denied"],
)
def test_cli_verify_matches_http(http, capsys, case):
    """Every documented scenario answers with the same JSON and exit code."""
    if case == "empty":
        bundle = _backup(http, "empty")
        http_status, http_body = _verify(http, "empty", bundle)
        code = _cli_verify(http.env, "empty", bundle)
        expected_code = 0
    elif case == "valid":
        _create_key(http, "t1", "RSA2048")
        _put_policy(
            http, "t1",
            [{"subject": "alice", "actions": ["export"],
              "effect": "allow"}],
        )
        bundle = _backup(http, "t1")
        http_status, http_body = _verify(http, "t1", bundle)
        code = _cli_verify(http.env, "t1", bundle)
        expected_code = 0
    elif case == "wrong_passphrase":
        _create_key(http, "t1")
        bundle = _backup(http, "t1")
        http_status, http_body = _verify(
            http, "t1", bundle, passphrase="nope"
        )
        code = _cli_verify(http.env, "t1", bundle, passphrase="nope")
        expected_code = 2
    elif case == "tampered":
        _create_key(http, "t1")
        bundle = _tamper(_backup(http, "t1"))
        http_status, http_body = _verify(http, "t1", bundle)
        code = _cli_verify(http.env, "t1", bundle)
        expected_code = 2
    elif case == "cross_tenant":
        _create_key(http, "t1")
        bundle = _backup(http, "t1")
        http_status, http_body = _verify(http, "t2", bundle)
        code = _cli_verify(http.env, "t2", bundle)
        expected_code = 4
    elif case == "illegal_version":
        _create_key(http, "t1")
        bundle = _mutated(
            _backup(http, "t1"),
            lambda p: p["keys"][0].__setitem__("current_version", 99),
        )
        http_status, http_body = _verify(http, "t1", bundle)
        code = _cli_verify(http.env, "t1", bundle)
        expected_code = 2
    elif case == "illegal_policy":
        _create_key(http, "t1")
        bundle = _mutated(
            _backup(http, "t1"),
            lambda p: p.__setitem__(
                "policy",
                {"rules": [{"subject": "alice", "actions": ["export"],
                            "effect": "maybe"}]},
            ),
        )
        http_status, http_body = _verify(http, "t1", bundle)
        code = _cli_verify(http.env, "t1", bundle)
        expected_code = 2
    else:  # policy_denied
        _create_key(http, "t1")
        bundle = _backup(http, "t1")
        _put_policy(
            http, "t1",
            [{"subject": "alice", "actions": ["export"],
              "effect": "deny"}],
        )
        http_status, http_body = _verify(http, "t1", bundle)
        code = _cli_verify(http.env, "t1", bundle)
        expected_code = 3

    out, err = _cli_streams(capsys)
    assert code == expected_code
    assert code == {200: 0, 400: 2, 403: 3, 404: 4}[http_status]
    cli_body = out if expected_code == 0 else err
    assert cli_body == http_body


def test_cli_verify_success_writes_no_audit(http, capsys):
    _create_key(http, "t1")
    bundle = _backup(http, "t1")
    before = _event_tuples(http)
    code = _cli_verify(http.env, "t1", bundle)
    assert code == 0
    out, _err = _cli_streams(capsys)
    assert out == {
        "valid": True,
        "tenant_id": "t1",
        "key_ids": out["key_ids"],
        "policy_restored": False,
    }
    assert out["key_ids"] == sorted(out["key_ids"])
    assert _event_tuples(http) == before


def test_cli_plain_backup_still_works(http, capsys):
    # The new verify subparser must not change the existing backup command.
    code = cli.main(
        [
            "--data-dir", http.env.data_dir,
            "backup", "--tenant-id", "plain",
            "--operator", "alice", "--passphrase", "pw",
        ]
    )
    assert code == 0
    out, _err = _cli_streams(capsys)
    assert out["format"] == tenantbundle.FORMAT
    assert isinstance(out["bundle"], str) and out["bundle"]
