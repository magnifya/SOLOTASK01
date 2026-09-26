"""POST /v1/keys/{key_id}/sign and .../verify (RSA-2048, PKCS#1 v1.5 SHA-256).

Covers the fixed response key orders, deterministic signatures, the
``{"valid": false}`` non-match result, empty messages, signing/verifying old
versions after rotation and after a process restart, the 400 body contract
(extra fields, UUID4, base64, non-positive-integer version -- none of which is
audited), the 403/404/409 business rejections with same-name rejected audit
events carrying key_id, the 503 fixed provider wording on a sign backend
fault (not audited), and the guarantee that verification needs ONLY the
stored public key (it still succeeds while the KMS/HSM is down) and that
message/signature/private material never reach the audit ledger.

There is deliberately no CLI for sign/verify (the HTTP entry point is the
only one), and neither endpoint takes an Idempotency-Key.
"""

import base64
import json
import os
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _build_server(tmp_path, monkeypatch, external=False):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    if external:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
        monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
        monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
        monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
        import fake_kms

        fake_kms.reset()
    else:
        monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    handler = make_handler(
        store, policies, coordinator, op_store, artifact_store
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    stack = types.SimpleNamespace(
        data_dir=data_dir, store=store, policies=policies,
        audit=audit_log, client=client, faults_path=faults_path,
    )
    yield stack
    httpd.shutdown()
    provider_mod.reset_for_tests()


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None,
             raw=None):
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
    yield from _build_server(tmp_path, monkeypatch)


@pytest.fixture()
def ext_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, external=True)


def _make_key(client, algorithm="RSA2048", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(client, key_id, tenant="t", key="rot-1"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": "RSA2048"},
        headers={"Idempotency-Key": key},
    )
    assert status == 201, body
    return body


def _audit_events(stack, tenant="t"):
    return stack.audit.query(tenant, limit=1000).events


# -- happy path -------------------------------------------------------------
def test_sign_returns_fixed_key_order_and_canonical_base64(stack):
    key_id = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": b64(b"hello")},
    )
    assert status == 200, body
    assert list(body.keys()) == ["key_id", "version", "signature"]
    assert body["key_id"] == key_id
    assert body["version"] == 1
    # Canonical standard base64: decodes with validate=True to 256 bytes.
    raw = base64.b64decode(body["signature"], validate=True)
    assert len(raw) == 256


def test_sign_is_deterministic(stack):
    key_id = _make_key(stack.client)
    _, first = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": b64(b"same message")},
    )
    _, second = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": b64(b"same message")},
    )
    assert first["signature"] == second["signature"]


def test_sign_empty_message(stack):
    key_id = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": ""},
    )
    assert status == 200, body
    assert len(base64.b64decode(body["signature"], validate=True)) == 256


def test_verify_accepts_matching_signature(stack):
    key_id = _make_key(stack.client)
    message = b64(b"verify me")
    _, signed = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message,
         "signature": signed["signature"]},
    )
    assert status == 200
    assert body == {"valid": True}


def test_verify_rejects_non_matching_values_as_false(stack):
    key_id = _make_key(stack.client)
    message = b64(b"verify me")
    _, signed = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    # Tampered 256-byte signature.
    tampered = bytearray(base64.b64decode(signed["signature"]))
    tampered[0] ^= 0x01
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message,
         "signature": b64(bytes(tampered))},
    )
    assert (status, body) == (200, {"valid": False})
    # Different message.
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": b64(b"other"),
         "signature": signed["signature"]},
    )
    assert (status, body) == (200, {"valid": False})
    # Wrong-length / empty signature is a non-match, not an error.
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message, "signature": b64(b"short")},
    )
    assert (status, body) == (200, {"valid": False})
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message, "signature": ""},
    )
    assert (status, body) == (200, {"valid": False})


def test_explicit_version_selects_old_version_and_verify_empty_message(stack):
    key_id = _make_key(stack.client)
    _, v1 = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": ""},
    )
    assert v1["version"] == 1
    _rotate(stack.client, key_id)
    # Pinning version 1 re-signs with version 1 material (same deterministic
    # signature), and the current default now resolves to version 2.
    _, again = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "version": 1, "message": ""},
    )
    assert again["version"] == 1
    assert again["signature"] == v1["signature"]
    _, current = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": ""},
    )
    assert current["version"] == 2


def test_old_version_verifies_after_restart(stack, tmp_path, monkeypatch):
    key_id = _make_key(stack.client)
    message = b64(b"persistent")
    _, v1 = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    _rotate(stack.client, key_id)
    # Simulate a process restart: a fresh stack over the same data dir.
    data_dir = stack.data_dir
    provider_mod.reset_for_tests()
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifacts = ArtifactStore(data_dir, store, audit_log)
    artifacts.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifacts.is_parked)
    handler = make_handler(store, policies, coordinator, op_store, artifacts)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
        status, body = client.call(
            "POST", "/v1/keys/%s/verify" % key_id,
            {"tenant_id": "t", "version": 1, "message": message,
             "signature": v1["signature"]},
        )
        assert (status, body) == (200, {"valid": True})
    finally:
        httpd.shutdown()


# -- body validation: 400, never audited ------------------------------------
def _sign_events(stack):
    return [
        e for e in _audit_events(stack)
        if e.action in ("sign", "verify")
    ]


def test_body_400s_are_not_audited(stack):
    key_id = _make_key(stack.client)
    message = b64(b"x")
    cases = [
        ({"tenant_id": "t", "message": message, "version": 0},
         "version"),
        ({"tenant_id": "t", "message": message, "version": -3},
         "version"),
        ({"tenant_id": "t", "message": message, "version": "1"},
         "version"),
        ({"tenant_id": "t", "message": message, "version": True},
         "version"),
        ({"tenant_id": "t"}, "message"),
        ({"tenant_id": "t", "message": 123}, "message"),
        ({"tenant_id": "t", "message": "not base64!"}, "message"),
        ({"tenant_id": "t", "message": "ab cd"}, "message"),
        ({"tenant_id": "t", "message": message, "extra": 1}, "extra"),
    ]
    for body, field in cases:
        status, err = stack.client.call(
            "POST", "/v1/keys/%s/sign" % key_id, body
        )
        assert status == 400, body
        assert field in err["error"], err
    # verify-specific shape failures.
    status, err = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message},
    )
    assert status == 400 and "signature" in err["error"]
    status, err = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message, "signature": 7},
    )
    assert status == 400 and "signature" in err["error"]
    status, err = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message, "signature": "a*b"},
    )
    assert status == 400 and "signature" in err["error"]
    # No sign/verify events from any of these parameter failures.
    assert _sign_events(stack) == []


def test_raw_json_and_tenant_400s(stack):
    key_id = _make_key(stack.client)
    # Bad JSON is a plain 400 that is NOT audited (neither a sign/verify
    # event nor an invisible tenant_conflict).
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id, None, raw=b"{not json"
    )
    assert status == 400
    # A non-object body is the same plain, unaudited 400.
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id, None, raw=b"[1,2,3]"
    )
    assert status == 400
    # Neither parse failure wrote a tenant_conflict nor a sign/verify event.
    assert [
        e for e in _audit_events(stack)
        if e.action in ("sign", "verify", "tenant_conflict")
    ] == []
    # Missing/empty tenant.
    status, err = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id, {"message": b64(b"x")}
    )
    assert status == 400 and "tenant_id" in err["error"]
    status, err = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "", "message": b64(b"x")},
    )
    assert status == 400 and "tenant_id" in err["error"]
    # Malformed key_id.
    status, err = stack.client.call(
        "POST", "/v1/keys/1234/sign",
        {"tenant_id": "t", "message": b64(b"x")},
    )
    assert status == 400 and "key_id" in err["error"]


def test_tenant_header_agreeing_with_body_is_accepted(stack):
    key_id = _make_key(stack.client)
    # A single X-Tenant-Id header agreeing with the body is fine (the
    # general identity rule); an Idempotency-Key is not required.
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": b64(b"x")},
        headers={"X-Tenant-Id": "t"},
    )
    assert status == 200, body


# -- business rejections ----------------------------------------------------
def test_aes256_version_is_409_for_both(stack):
    aes = _make_key(stack.client, algorithm="AES256")
    message = b64(b"x")
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/sign" % aes,
        {"tenant_id": "t", "message": message},
    )
    assert status == 409, body
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/verify" % aes,
        {"tenant_id": "t", "message": message, "signature": b64(b"0" * 256)},
    )
    assert status == 409, body


def test_revoked_version_is_409_including_old_versions(stack):
    key_id = _make_key(stack.client)
    message = b64(b"x")
    _, signed = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    _rotate(stack.client, key_id)
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "done", "operator": "alice"},
    )
    assert status == 200
    # Current and old versions alike refuse after revocation.
    assert stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )[0] == 409
    assert stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "version": 1, "message": message},
    )[0] == 409
    assert stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "version": 1, "message": message,
         "signature": signed["signature"]},
    )[0] == 409


def test_unknown_foreign_key_and_version_are_404(stack):
    key_id = _make_key(stack.client)
    message = b64(b"x")
    # Unknown key.
    unknown = "00000000-0000-4000-8000-000000000000"
    assert stack.client.call(
        "POST", "/v1/keys/%s/sign" % unknown,
        {"tenant_id": "t", "message": message},
    )[0] == 404
    # Cross-tenant access looks identical.
    assert stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "other", "message": message},
    )[0] == 404
    assert stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "other", "message": message,
         "signature": b64(b"0" * 256)},
    )[0] == 404
    # Unknown version.
    assert stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "version": 99, "message": message},
    )[0] == 404
    assert stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "version": 99, "message": message,
         "signature": b64(b"0" * 256)},
    )[0] == 404


def test_policy_denial_is_403_and_audited_with_key_id(stack):
    key_id = _make_key(stack.client)
    message = b64(b"x")
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["sign"], effect="deny")]
    )
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    assert status == 403, body
    rejected = [
        e for e in _audit_events(stack)
        if e.action == "sign" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id == key_id

    # verify governed independently by the "verify" action.
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["verify"], effect="deny")]
    )
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message,
         "signature": b64(b"0" * 256)},
    )
    assert status == 403
    rejected = [
        e for e in _audit_events(stack)
        if e.action == "verify" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id == key_id


# -- audit content ----------------------------------------------------------
def test_success_events_carry_key_id_and_no_message_or_signature(stack):
    key_id = _make_key(stack.client)
    message = b64(b"ledger secret")
    _, signed = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message,
         "signature": signed["signature"]},
    )
    success = [
        e for e in _audit_events(stack)
        if e.outcome == "success" and e.action in ("sign", "verify")
    ]
    assert [(e.action, e.key_id) for e in success] == [
        ("sign", key_id), ("verify", key_id)
    ]
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert b"ledger secret" not in raw
    assert signed["signature"].encode() not in raw


def test_non_matching_verify_is_still_a_success_event(stack):
    key_id = _make_key(stack.client)
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": b64(b"x"),
         "signature": b64(b"not a real signature")},
    )
    assert status == 200
    events = [
        e for e in _audit_events(stack) if e.action == "verify"
    ]
    assert len(events) == 1 and events[0].outcome == "success"


# -- provider failures ------------------------------------------------------
def test_sign_provider_failure_is_503_and_not_audited(ext_stack):
    client = ext_stack.client
    key_id = _make_key(client)
    message = b64(b"hi")
    status, signed = client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    assert status == 200
    with open(ext_stack.faults_path, "w") as fh:
        json.dump({"fail": {"export_material": True}}, fh)
    status, body = client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    # Exactly one sign event (the earlier success): the 503 wrote nothing.
    sign_events = [
        e for e in _audit_events(ext_stack) if e.action == "sign"
    ]
    assert len(sign_events) == 1
    assert sign_events[0].outcome == "success"


def test_verify_uses_only_public_key_and_survives_provider_outage(ext_stack):
    client = ext_stack.client
    key_id = _make_key(client)
    message = b64(b"hi")
    _, signed = client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": message},
    )
    with open(ext_stack.faults_path, "w") as fh:
        json.dump({"fail": {"export_material": True}}, fh)
    # Verification never touches the provider: still 200 with valid=true.
    status, body = client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "message": message,
         "signature": signed["signature"]},
    )
    assert (status, body) == (200, {"valid": True})


def test_no_idempotency_key_required(stack):
    # A sign succeeds without the header that encrypt/rotate mandate; an
    # Idempotency-Key is simply ignored as an unrelated extra header.
    key_id = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": b64(b"x")},
        headers={"Idempotency-Key": "ignored-123"},
    )
    assert status == 200, body
    assert "operation_id" not in body
