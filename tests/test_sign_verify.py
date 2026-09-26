"""RSA2048 sign/verify tests: crypto helpers and the HTTP API.

Covers deterministic RSASSA-PKCS1-v1_5/SHA-256 signing, public-key-only
verification (old versions keep verifying across rotation and restart),
field-naming 400s (not audited), 403/404/409 rules, the fixed 503 provider
wording, and audit events that never carry the message or signature.
"""

import base64
import json
import threading
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer

import pytest

from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.crypto import generate_key, rsa2048_sign, rsa2048_verify
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


# ------------------------------------------------------------------- crypto
def _rsa_private():
    from cryptography.hazmat.primitives import serialization

    generated = generate_key("RSA2048")
    return serialization.load_pem_private_key(
        generated.private_material.encode("utf-8"), password=None
    ), generated.public_material


def test_sign_verify_roundtrip_and_deterministic():
    private, public_pem = _rsa_private()
    sig1 = rsa2048_sign(private, b"hello")
    sig2 = rsa2048_sign(private, b"hello")
    assert sig1 == sig2  # PKCS1v15 is deterministic
    assert rsa2048_verify(public_pem, b"hello", sig1) is True
    assert rsa2048_verify(public_pem, b"hellp", sig1) is False
    assert rsa2048_verify(public_pem, b"hello", sig1[:-1] + b"\x00") is False


def test_sign_verify_empty_message():
    private, public_pem = _rsa_private()
    sig = rsa2048_sign(private, b"")
    assert rsa2048_verify(public_pem, b"", sig) is True


def test_verify_rejects_bad_public_material():
    with pytest.raises(ValueError):
        rsa2048_verify("not a pem", b"m", b"s")
    with pytest.raises(ValueError):
        rsa2048_verify(None, b"m", b"s")


def test_sign_rejects_non_rsa_key():
    with pytest.raises(ValueError):
        rsa2048_sign(object(), b"m")


# --------------------------------------------------------------- HTTP layer
@pytest.fixture()
def local_stack(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    data_dir = str(tmp_path / "data")
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    yield store, policies, data_dir
    provider_mod.reset_for_tests()


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"X-Operator-Id": operator}
        if data is not None:
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        req = urllib.request.Request(
            self.base + path, data=data, method=method, headers=h
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


def _serve(store, policies, data_dir):
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, store.audit)
    artifact_store = ArtifactStore(data_dir, store, store.audit)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return Client("http://127.0.0.1:%d" % httpd.server_address[1]), httpd


@pytest.fixture()
def http_server(local_stack):
    store, policies, data_dir = local_stack
    client, httpd = _serve(store, policies, data_dir)
    yield client, store, policies
    httpd.shutdown()


def _make_key(client, tenant="t", algorithm="RSA2048"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _sign(client, kid, tenant, message, **extra):
    body = {"tenant_id": tenant, "message": b64(message)}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/sign" % kid, body)


def _verify(client, kid, tenant, message, signature, **extra):
    body = {"tenant_id": tenant, "message": b64(message),
            "signature": signature}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/verify" % kid, body)


def _events(store, action=None):
    return store.audit.query("t", action=action, limit=1000).events


# ------------------------------------------------------------------ success
def test_sign_response_shape_and_verifies(http_server):
    client, _store, _policies = http_server
    kid = _make_key(client)
    status, body = _sign(client, kid, "t", b"payload")
    assert status == 200
    assert list(body.keys()) == ["key_id", "version", "signature"]
    assert body["key_id"] == kid and body["version"] == 1
    signature = base64.b64decode(body["signature"])
    status, out = _verify(client, kid, "t", b"payload", body["signature"])
    assert status == 200 and list(out.keys()) == ["valid"]
    assert out["valid"] is True
    # The signature also verifies against the advertised public key.
    status, meta = client.call("GET", "/v1/keys/%s?tenant_id=t" % kid,
                               body=None)
    assert status == 200
    assert rsa2048_verify(meta["public_key"], b"payload", signature) is True


def test_sign_is_deterministic_and_empty_message_ok(http_server):
    client, _store, _policies = http_server
    kid = _make_key(client)
    _s1, first = _sign(client, kid, "t", b"same")
    _s2, second = _sign(client, kid, "t", b"same")
    assert first["signature"] == second["signature"]
    status, body = _sign(client, kid, "t", b"")
    assert status == 200
    status, out = _verify(client, kid, "t", b"", body["signature"])
    assert status == 200 and out["valid"] is True


def test_verify_mismatch_is_false_not_error(http_server):
    client, _store, _policies = http_server
    kid = _make_key(client)
    _s, body = _sign(client, kid, "t", b"original")
    status, out = _verify(client, kid, "t", b"tampered", body["signature"])
    assert status == 200 and out["valid"] is False
    other = _make_key(client)
    _s, other_body = _sign(client, other, "t", b"original")
    status, out = _verify(client, kid, "t", b"original",
                          other_body["signature"])
    assert status == 200 and out["valid"] is False


def test_old_versions_verify_across_rotation(http_server):
    client, store, _policies = http_server
    kid = _make_key(client)
    _s, v1 = _sign(client, kid, "t", b"version one")
    assert v1["version"] == 1
    status, _ = client.call(
        "POST", "/v1/keys/%s/rotate" % kid,
        {"tenant_id": "t", "algorithm": "RSA2048"},
        headers={"Idempotency-Key": "rotate-sign-1"},
    )
    assert status == 201
    # Default is now current (v2); v1 signatures still verify on v1 only.
    _s, v2 = _sign(client, kid, "t", b"version two")
    assert v2["version"] == 2
    status, out = _verify(client, kid, "t", b"version one", v1["signature"],
                          version=1)
    assert status == 200 and out["valid"] is True
    status, out = _verify(client, kid, "t", b"version one", v1["signature"])
    assert status == 200 and out["valid"] is False
    status, out = _verify(client, kid, "t", b"version two", v2["signature"],
                          version=1)
    assert status == 200 and out["valid"] is False


def test_verify_survives_restart(local_stack):
    store, policies, data_dir = local_stack
    client, httpd = _serve(store, policies, data_dir)
    kid = _make_key(client)
    _s, body = _sign(client, kid, "t", b"durable")
    httpd.shutdown()
    # A fresh store/server over the same data dir is a process restart.
    store2 = KeyStore(data_dir, AuditLog(data_dir))
    policies2 = PolicyStore(data_dir, store2.audit)
    client2, httpd2 = _serve(store2, policies2, data_dir)
    try:
        status, out = _verify(client2, kid, "t", b"durable",
                              body["signature"])
        assert status == 200 and out["valid"] is True
    finally:
        httpd2.shutdown()


# --------------------------------------------------------------------- 400s
def test_field_errors_are_400_and_not_audited(http_server):
    client, store, _policies = http_server
    kid = _make_key(client)
    before = len(store.audit._read_all())

    status, out = _sign(client, kid, "t", b"x", extra=1)
    assert status == 400 and "extra" in out["error"]
    for bad_version in (0, -1, "1", 1.5, True):
        status, out = _sign(client, kid, "t", b"x", version=bad_version)
        assert status == 400 and "version" in out["error"]
    status, out = client.call("POST", "/v1/keys/%s/sign" % kid,
                              {"tenant_id": "t"})
    assert status == 400 and "message" in out["error"]
    status, out = client.call("POST", "/v1/keys/%s/sign" % kid,
                              {"tenant_id": "t", "message": "!!!"})
    assert status == 400 and "message" in out["error"]
    status, out = client.call("POST", "/v1/keys/%s/sign" % kid,
                              {"tenant_id": "t", "message": 7})
    assert status == 400 and "message" in out["error"]
    status, out = _verify(client, kid, "t", b"x", "!!!")
    assert status == 400 and "signature" in out["error"]
    status, out = client.call(
        "POST", "/v1/keys/%s/verify" % kid,
        {"tenant_id": "t", "message": b64(b"x")},
    )
    assert status == 400 and "signature" in out["error"]

    # Body/field 400s wrote nothing to the ledger.
    assert len(store.audit._read_all()) == before

    # A malformed key_id follows the identity rules: 400 plus tenant_conflict.
    status, out = _sign(client, "not-a-uuid", "t", b"x")
    assert status == 400 and "key_id" in out["error"]
    events = store.audit._read_all()
    assert len(events) == before + 1
    assert events[-1].action == "tenant_conflict"


def test_identity_conflicts_still_recorded(http_server):
    client, store, _policies = http_server
    kid = _make_key(client)
    before = len(store.audit._read_all())
    status, out = client.call("POST", "/v1/keys/%s/sign" % kid,
                              {"tenant_id": "t", "message": b64(b"x")},
                              headers={"X-Tenant-Id": "other"})
    assert status == 400 and "tenant_id" in out["error"]
    events = store.audit._read_all()
    assert len(events) == before + 1
    assert events[-1].action == "tenant_conflict"


# ------------------------------------------------------- 403 / 404 / 409
def test_policy_denial_is_403_and_audited(http_server):
    client, store, policies = http_server
    kid = _make_key(client)
    policies.put("t", [Rule(subject="alice", actions=["sign", "verify"],
                            effect="deny")])
    status, out = _sign(client, kid, "t", b"x")
    assert status == 403
    status, out = _verify(client, kid, "t", b"x", b64(b"y"))
    assert status == 403
    rejected = [e for e in store.audit._read_all()
                if e.outcome == "rejected"]
    assert {(e.action, e.key_id) for e in rejected} == {
        ("sign", kid), ("verify", kid)
    }


def test_unknown_cross_tenant_and_version_are_404(http_server):
    client, _store, _policies = http_server
    kid = _make_key(client)
    missing = str(uuid.uuid4())
    for path_kid, tenant in ((missing, "t"), (kid, "other")):
        status, _ = _sign(client, path_kid, tenant, b"x")
        assert status == 404
        status, _ = _verify(client, path_kid, tenant, b"x", b64(b"y"))
        assert status == 404
    status, _ = _sign(client, kid, "t", b"x", version=99)
    assert status == 404
    status, _ = _verify(client, kid, "t", b"x", b64(b"y"), version=99)
    assert status == 404


def test_aes256_and_revoked_are_409(http_server):
    client, _store, _policies = http_server
    aes = _make_key(client, algorithm="AES256")
    status, _ = _sign(client, aes, "t", b"x")
    assert status == 409
    status, _ = _verify(client, aes, "t", b"x", b64(b"y"))
    assert status == 409
    kid = _make_key(client)
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "r", "operator": "alice"},
    )
    assert status == 200
    status, _ = _sign(client, kid, "t", b"x")
    assert status == 409
    status, _ = _verify(client, kid, "t", b"x", b64(b"y"))
    assert status == 409


# --------------------------------------------------------------------- 503
def test_sign_provider_failure_is_503_verify_still_works(env):
    # env fixture wires the fake external KMS.
    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    client, httpd = _serve(store, policies, env.data_dir)
    try:
        kid = _make_key(client)
        _s, body = _sign(client, kid, "t", b"msg")
        env.set_faults({"unreachable": True})
        status, out = _sign(client, kid, "t", b"msg")
        assert status == 503
        assert out == {"error": "key management provider is unavailable"}
        # Verify uses only the stored public key: no provider, no 503.
        status, out = _verify(client, kid, "t", b"msg", body["signature"])
        assert status == 200 and out["valid"] is True
    finally:
        httpd.shutdown()


# -------------------------------------------------------------------- audit
def test_audit_success_events_carry_no_message_or_signature(http_server):
    client, store, _policies = http_server
    kid = _make_key(client)
    _s, body = _sign(client, kid, "t", b"secret-message")
    _v, _out = _verify(client, kid, "t", b"secret-message",
                       body["signature"])
    sign_events = _events(store, "sign")
    verify_events = _events(store, "verify")
    assert [(e.outcome, e.key_id) for e in sign_events] == [("success", kid)]
    assert [(e.outcome, e.key_id) for e in verify_events] == [("success", kid)]
    with open(store.audit.path, "rb") as fh:
        ledger = fh.read()
    assert b"secret-message" not in ledger
    assert body["signature"].encode("ascii") not in ledger
