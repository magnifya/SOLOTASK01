"""Envelope encryption tests: crypto module, store accessor and HTTP API.

Covers AES256 (AES-GCM DEK wrap) and RSA2048 (RSA-OAEP-SHA256 wrap), the
keymgr-envelope-v1 token shape, AAD binding, tamper and field-naming 400s,
404/409 tenant and revocation rules, 503 provider wording, policy audit
(rejected/success, metadata only) and a consistent view across rotation.
"""

import base64
import json
import os
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import envelope as env_mod
from keymgr import provider as provider_mod
from keymgr.audit import AuditLog
from keymgr.crypto import generate_key
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr import restore as restore_mod
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


# Monotonic source of distinct Idempotency-Keys for the (now idempotent)
# encrypt endpoint; tests that need a replay pass an explicit key.
_IDEM_SEQ = iter(range(10_000_000))


def _fresh_idem():
    return "encrypt-key-%d" % next(_IDEM_SEQ)


# ---------------------------------------------------------------- envelope
def test_envelope_aes_roundtrip_with_aad():
    kek = base64.b64decode(generate_key("AES256").private_material)
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=2, algorithm="AES256", kek=kek,
        plaintext=b"top secret", aad=b"context",
    )
    opened = env_mod.decode_envelope(token)
    assert opened.key_id == "11111111-1111-4111-8111-111111111111"
    assert opened.version == 2
    assert opened.algorithm == "AES256"
    assert opened.wrap == env_mod.WRAP_AES_GCM
    assert opened.aad == b"context"
    assert env_mod.open_envelope(opened, kek) == b"top secret"


def test_envelope_aes_without_aad_roundtrips_empty():
    kek = base64.b64decode(generate_key("AES256").private_material)
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", kek=kek, plaintext=b"",
    )
    opened = env_mod.decode_envelope(token)
    assert opened.aad == b""
    assert env_mod.open_envelope(opened, kek) == b""


def test_envelope_rsa_roundtrip():
    from cryptography.hazmat.primitives import serialization

    generated = generate_key("RSA2048")
    priv = serialization.load_pem_private_key(
        generated.private_material.encode("utf-8"), password=None
    )
    token = env_mod.encode_envelope(
        key_id="22222222-2222-4222-8222-222222222222",
        version=1, algorithm="RSA2048", kek=priv, plaintext=b"rsa payload",
    )
    opened = env_mod.decode_envelope(token)
    assert opened.wrap == env_mod.WRAP_RSA_OAEP_SHA256
    assert opened.wrap_nonce is None
    assert len(opened.wrapped_key) == 256
    assert env_mod.open_envelope(opened, priv) == b"rsa payload"


def test_envelope_tamper_is_authentication_error():
    kek = base64.b64decode(generate_key("AES256").private_material)
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", kek=kek,
        plaintext=b"x", aad=b"a",
    )
    obj = json.loads(base64.b64decode(token))
    obj["ciphertext"] = b64(b"\x00" * len(base64.b64decode(obj["ciphertext"])))
    bad = b64(json.dumps(obj, sort_keys=True).encode("utf-8"))
    with pytest.raises(env_mod.EnvelopeError, match="field envelope"):
        env_mod.open_envelope(env_mod.decode_envelope(bad), kek)


def test_envelope_wrong_kek_is_authentication_error():
    import base64 as _b64

    kek1 = _b64.b64decode(generate_key("AES256").private_material)
    kek2 = _b64.b64decode(generate_key("AES256").private_material)
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", kek=kek1, plaintext=b"x",
    )
    with pytest.raises(env_mod.EnvelopeError, match="field envelope"):
        env_mod.open_envelope(env_mod.decode_envelope(token), kek2)


def test_envelope_never_contains_plaintext_or_kek():
    kek = base64.b64decode(generate_key("AES256").private_material)
    secret = b"never-appear-in-token"
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", kek=kek, plaintext=secret,
    )
    assert secret not in base64.b64decode(token)
    obj = json.loads(base64.b64decode(token))
    assert set(obj) == {
        "format", "key_id", "version", "algorithm", "enc", "wrap",
        "nonce", "tag", "ciphertext", "wrapped_key", "wrap_nonce", "aad",
    }


@pytest.mark.parametrize(
    "token",
    [
        "not-base64!!!",
        b64(b"not json"),
        b64(json.dumps({"format": "other"}).encode()),
        b64(json.dumps({"format": env_mod.FORMAT}).encode()),
    ],
)
def test_envelope_malformed_tokens(token):
    with pytest.raises(env_mod.EnvelopeError):
        env_mod.decode_envelope(token)


# ------------------------------------------------------------- store layer
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


def test_crypto_material_statuses(local_stack):
    store, _policies, _dir = local_stack
    aes = store.create("t", "AES256", "k")
    rsa = store.create("t", "RSA2048", "r")
    status, _r, ver, kek = store.crypto_material(aes.key_id, "t")
    assert status == KeyStore.CRYPTO_OK and ver.version == 1 and len(kek) == 32
    status, _r, ver, kek = store.crypto_material(rsa.key_id, "t")
    assert status == KeyStore.CRYPTO_OK and ver.algorithm == "RSA2048"

    assert store.crypto_material(aes.key_id, "other")[0] == KeyStore.CRYPTO_NOT_FOUND
    assert store.crypto_material(aes.key_id, "t", 99)[0] == KeyStore.CRYPTO_NOT_FOUND
    store.revoke(aes.key_id, "t", "reason", "op")
    assert store.crypto_material(aes.key_id, "t")[0] == KeyStore.CRYPTO_REVOKED
    assert store.crypto_material(aes.key_id, "t", 1)[0] == KeyStore.CRYPTO_REVOKED


# --------------------------------------------------------------- HTTP API
@pytest.fixture()
def http_server(local_stack):
    store, policies, data_dir = local_stack
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, store.audit)
    from keymgr.artifacts import ArtifactStore

    artifact_store = ArtifactStore(data_dir, store, store.audit)
    handler = make_handler(
        store, policies, coordinator, op_store, artifact_store
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    import threading

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    yield client, store, policies, op_store, data_dir
    httpd.shutdown()


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice",
             headers=None, tenant_via=None, idem=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"X-Operator-Id": operator}
        if data is not None:
            h["Content-Type"] = "application/json"
        if idem is not None:
            h["Idempotency-Key"] = idem
        if headers:
            h.update(headers)
        url = self.base + path
        if tenant_via is not None:
            url += "?tenant_id=" + tenant_via
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


def _make_key(client, tenant="t", algorithm="AES256"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _encrypt(client, kid, tenant, plaintext, *, idem=None, **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body, idem=idem or _fresh_idem()
    )


def _decrypt(client, kid, tenant, token, **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/decrypt" % kid, body)


def test_http_aes_roundtrip_with_aad(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client, algorithm="AES256")
    status, body = _encrypt(client, kid, "t", b"payload", aad=b64(b"ctx"))
    assert status == 200 and body["format"] == env_mod.FORMAT
    status, dec = _decrypt(client, kid, "t", body["envelope"], aad=b64(b"ctx"))
    assert status == 200 and base64.b64decode(dec["plaintext"]) == b"payload"


def test_http_rsa_roundtrip(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client, algorithm="RSA2048")
    status, body = _encrypt(client, kid, "t", b"rsa-payload")
    assert status == 200
    obj = json.loads(base64.b64decode(body["envelope"]))
    assert obj["wrap"] == env_mod.WRAP_RSA_OAEP_SHA256
    status, dec = _decrypt(client, kid, "t", body["envelope"])
    assert base64.b64decode(dec["plaintext"]) == b"rsa-payload"


def test_http_default_current_and_pinned_version(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    # Without a rotation path (needs the operation store here) use the store.
    from keymgr import operations as operations_mod

    # Rotate directly through the store (the HTTP rotate requires the full
    # operation wiring; version selection logic is what is under test here).
    _store.rotate(kid, "t", "AES256")
    status, body = _encrypt(client, kid, "t", b"v2-current")
    assert status == 200
    assert json.loads(base64.b64decode(body["envelope"]))["version"] == 2
    status, dec = _decrypt(client, kid, "t", body["envelope"])
    assert status == 200 and base64.b64decode(dec["plaintext"]) == b"v2-current"

    status, body = _encrypt(client, kid, "t", b"v1-pinned", version=1)
    assert status == 200
    assert json.loads(base64.b64decode(body["envelope"]))["version"] == 1
    status, dec = _decrypt(client, kid, "t", body["envelope"])
    assert status == 200 and base64.b64decode(dec["plaintext"]) == b"v1-pinned"


def test_http_rotation_keeps_old_envelopes_readable(http_server):
    client, store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    status, v1_token = _encrypt(client, kid, "t", b"before-rotation")
    assert status == 200
    store.rotate(kid, "t", "AES256")
    # The v1 envelope still decrypts with v1 material after rotation.
    status, dec = _decrypt(client, kid, "t", v1_token["envelope"])
    assert status == 200
    assert base64.b64decode(dec["plaintext"]) == b"before-rotation"


def test_http_field_validation_400(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    cases_encrypt = [
        ({"tenant_id": "t"}, "plaintext"),
        ({"tenant_id": "t", "plaintext": "!!!"}, "plaintext"),
        ({"tenant_id": "t", "plaintext": b64(b"x"), "aad": "!!!"}, "aad"),
        ({"tenant_id": "t", "plaintext": b64(b"x"), "version": 0}, "version"),
        ({"tenant_id": "t", "plaintext": b64(b"x"), "version": "1.5"},
         "version"),
    ]
    # Every one of these is a pre-bind 400: the same Idempotency-Key may be
    # presented on every request without it ever becoming bound.
    for body, field in cases_encrypt:
        status, out = client.call(
            "POST", "/v1/keys/%s/encrypt" % kid, body, idem="never-bound"
        )
        assert status == 400 and field in out["error"], (body, out)
        assert "operation_id" not in out

    status, out = client.call(
        "POST", "/v1/keys/%s/decrypt" % kid, {"tenant_id": "t"}
    )
    assert status == 400 and "envelope" in out["error"]
    status, out = _decrypt(client, kid, "t", "not-base64!!!")
    assert status == 400 and "envelope" in out["error"]


def test_http_encrypt_idempotency_key_validation_is_400(http_server):
    client, store, _policies, op_store, data_dir = http_server
    kid = _make_key(client)
    body = {"tenant_id": "t", "plaintext": b64(b"x")}
    good_path = "/v1/keys/%s/encrypt" % kid

    # Missing header.
    status, out = client.call("POST", good_path, body)
    assert status == 400 and "Idempotency-Key" in out["error"]
    # Empty value.
    status, out = client.call("POST", good_path, body, idem="")
    assert status == 400 and "Idempotency-Key" in out["error"]
    # Illegal alphabet / too long.
    for bad in ("has space", "slash/x", "x" * 129):
        status, out = client.call("POST", good_path, body, idem=bad)
        assert status == 400 and "Idempotency-Key" in out["error"], bad
    # Duplicate header: send two Idempotency-Key lines over a raw connection
    # (urllib folds repeated headers into one comma-joined value).
    import http.client
    from urllib.parse import urlsplit

    parts_u = urlsplit(client.base)
    raw_body = json.dumps(body).encode()
    conn = http.client.HTTPConnection(parts_u.hostname, parts_u.port, timeout=10)
    conn.putrequest("POST", good_path)
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(raw_body)))
    conn.putheader("Idempotency-Key", "a")
    conn.putheader("Idempotency-Key", "b")
    conn.endheaders(raw_body)
    resp = conn.getresponse()
    status = resp.status
    out = json.loads(resp.read())
    assert status == 400 and "Idempotency-Key" in out["error"]
    conn.close()

    # Zero side effects: no operation files were created and no encrypt audit
    # event exists.
    import os

    op_files = [
        n for n in os.listdir(op_store.dir_path)
        if n != "index.json" and n.endswith(".json")
    ]
    assert op_files == []
    events = store.audit.query("t", action="encrypt", limit=1000).events
    assert events == []
    # And the rejected key value remains free to bind on a corrected request.
    status, success = _encrypt(client, kid, "t", b"x", idem="valid-now")
    assert status == 200 and success["operation_id"]
    # The earlier empty/illegal attempt never consumed it either.
    status, out = client.call("POST", good_path, body, idem="valid-now")
    assert status == 200 and out["envelope"] == success["envelope"]


def test_http_aad_mismatch_and_tamper_400(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    status, body = _encrypt(client, kid, "t", b"x", aad=b64(b"ctx"))
    assert status == 200
    # Sealed with ctx, presented without aad.
    status, out = _decrypt(client, kid, "t", body["envelope"])
    assert status == 400 and "aad" in out["error"]
    # Flip the GCM tag.
    obj = json.loads(base64.b64decode(body["envelope"]))
    obj["tag"] = b64(b"\x00" * 16)
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, out = _decrypt(
        client, kid, "t", tampered, aad=b64(b"ctx")
    )
    assert status == 400 and "envelope" in out["error"]


def test_http_envelope_key_id_mismatch_400(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid1 = _make_key(client)
    kid2 = _make_key(client)
    status, body = _encrypt(client, kid1, "t", b"x")
    assert status == 200
    status, out = _decrypt(client, kid2, "t", body["envelope"])
    assert status == 400 and "envelope" in out["error"]


def test_http_unknown_and_cross_tenant_404(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client, tenant="t")
    unknown = "33333333-3333-4333-8333-333333333333"
    status, out = client.call(
        "POST", "/v1/keys/%s/encrypt" % unknown,
        {"tenant_id": "t", "plaintext": b64(b"x")}, idem=_fresh_idem(),
    )
    assert status == 404 and out["error"] == "key not found"
    assert set(out) == {"error", "operation_id"} and out["operation_id"]
    # A structurally valid envelope naming the unknown key also reads as a
    # missing key (parameter validation precedes existence).
    token = env_mod.encode_envelope(
        key_id=unknown, version=1, algorithm="AES256",
        kek=b"\x11" * 32, plaintext=b"x",
    )
    status, out = client.call(
        "POST", "/v1/keys/%s/decrypt" % unknown,
        {"tenant_id": "t", "envelope": token},
    )
    assert status == 404 and out == {"error": "key not found"}
    # Cross-tenant looks identical to a missing key.
    status, out = _encrypt(
        client, kid, "other", b"x", operator="bob"
    )
    assert status == 404 and out["error"] == "key not found"
    # Unknown version on an existing key is a 404 as well.
    status, out = _encrypt(client, kid, "t", b"x", version=42)
    assert status == 404 and out["error"] == "key not found"


def test_http_revoked_key_409_for_both_actions(http_server):
    client, store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    status, body = _encrypt(client, kid, "t", b"x")
    assert status == 200
    store.revoke(kid, "t", "compromise", "alice")
    status, out = _encrypt(client, kid, "t", b"x")
    assert status == 409 and "revoked" in out["error"]
    assert set(out) == {"error", "operation_id"}
    status, out = _decrypt(client, kid, "t", body["envelope"])
    assert status == 409 and out == {"error": "key is revoked"}


def test_http_policy_denial_audits_rejected(http_server):
    client, store, policies, _ops, _dir = http_server
    kid = _make_key(client)
    # First seal a structurally valid envelope while everything is allowed.
    status, sealed = _encrypt(client, kid, "t", b"x")
    assert status == 200
    # Then restrict alice to create/read only.
    policies.put(
        "t",
        [Rule("alice", ["create", "read"], "allow")],
    )
    status, out = _encrypt(client, kid, "t", b"x")
    assert status == 403
    assert out["error"] == "action not permitted by policy"
    assert set(out) == {"error", "operation_id"} and out["operation_id"]
    status, out = _decrypt(client, kid, "t", sealed["envelope"])
    assert status == 403
    page = _store_events(http_server, action="encrypt")
    # A successful encrypt preceded the policy change; the rejection is the
    # final encrypt event.
    assert (page[-1].action, page[-1].outcome) == ("encrypt", "rejected")
    # The rejected event carries metadata only.
    event = page[0].to_response()
    assert set(event) == {
        "event_id", "tenant_id", "action", "key_id", "outcome", "timestamp"
    }
    assert event["key_id"] == kid


def test_http_success_audits_metadata_only_and_no_material(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    secret = b"material-never-in-audit-log"
    status, body = _encrypt(
        client, kid, "t", secret, aad=b64(b"aad-secret")
    )
    assert status == 200
    status, _dec = _decrypt(
        client, kid, "t", body["envelope"], aad=b64(b"aad-secret")
    )
    assert status == 200
    events = _store_events(http_server)
    by_action = {e.action: e for e in events}
    assert by_action["encrypt"].outcome == "success"
    assert by_action["decrypt"].outcome == "success"
    # The audit projection has no field capable of carrying material.
    for event in events:
        assert set(event.to_response()) == {
            "event_id", "tenant_id", "action", "key_id", "outcome",
            "timestamp",
        }
    # And nothing about the plaintext/aad is in the ledger bytes.
    with open(_store.audit.path, "rb") as fh:
        ledger = fh.read()
    assert secret not in ledger
    assert b"aad-secret" not in ledger


def test_http_provider_unavailable_is_503_safe_wording(env, monkeypatch):
    # env fixture wires the fake external KMS.
    from keymgr.policy import PolicyStore
    from keymgr import restore as restore_mod
    from keymgr.operations import OperationStore
    from keymgr.artifacts import ArtifactStore

    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(env.data_dir, store.audit)
    artifact_store = ArtifactStore(env.data_dir, store, store.audit)
    handler = make_handler(
        store, policies, coordinator, op_store, artifact_store
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    import threading

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
        kid = _make_key(client)
        # A well-shaped envelope is needed so the request reaches the
        # provider on decrypt.
        status, body = _encrypt(client, kid, "t", b"x")
        assert status == 200
        env.set_faults({"unreachable": True})
        status, out = _encrypt(client, kid, "t", b"x")
        assert status == 503
        assert out["error"] == "key management provider is unavailable"
        assert set(out) == {"error", "operation_id"} and out["operation_id"]
        status, out = _decrypt(client, kid, "t", body["envelope"])
        assert status == 503
        assert out == {"error": "key management provider is unavailable"}
    finally:
        httpd.shutdown()


def _store_events(http_server, action=None):
    _store = http_server[1]
    page = _store.audit.query("t", action=action, limit=1000)
    return page.events


# --------------------------------------------- encrypt idempotency contract
def _op_body(client, op_id):
    tenant = "?tenant_id=t"
    status, body = client.call(
        "GET", "/v1/operations/%s%s" % (op_id, tenant), None
    )
    return status, body


def test_http_encrypt_success_body_order_and_get_operation(http_server):
    client, _store, _policies, op_store, _dir = http_server
    kid = _make_key(client)
    status, body = _encrypt(client, kid, "t", b"payload", idem="k1")
    assert status == 200
    # Exact key order: format, envelope, operation_id.
    assert list(body) == ["format", "envelope", "operation_id"]
    assert body["format"] == env_mod.FORMAT and body["envelope"]
    op_id = body["operation_id"]

    # GET operation requires the same tenant and operator.
    status, got = _op_body(client, op_id)
    assert status == 200
    assert list(got) == [
        "operation_id", "tenant_id", "status", "http_status", "response"
    ]
    assert got["operation_id"] == op_id
    assert got["tenant_id"] == "t"
    assert got["status"] == "succeeded"
    assert got["http_status"] == 200
    assert got["response"] == body

    # Unknown id and a cross-tenant/operator lookup both answer 404.
    missing = "44444444-4444-4444-8444-444444444444"
    status, out = client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % missing, None
    )
    assert status == 404
    status, out = client.call(
        "GET", "/v1/operations/%s?tenant_id=other" % op_id, None,
        operator="bob",
    )
    assert status == 404


def test_http_encrypt_same_key_replays_response_and_audit(http_server):
    client, store, _policies, op_store, _dir = http_server
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = {"tenant_id": "t", "plaintext": b64(b"replay-me")}

    status, first = client.call("POST", path, body, idem="replay")
    assert status == 200
    op_id = first["operation_id"]
    # An identical replay returns the SAME envelope (and operation_id) ...
    status, second = client.call("POST", path, body, idem="replay")
    assert status == 200
    assert second == first
    # ... even from a fresh process whose in-memory state is gone.
    store2 = KeyStore(_dir, AuditLog(_dir))
    from keymgr.policy import PolicyStore as _PS
    from keymgr import restore as _rm
    from keymgr.operations import OperationStore as _OS
    from keymgr.artifacts import ArtifactStore as _AS

    policies2 = _PS(_dir, store2.audit)
    ops2 = _OS(_dir, store2.audit)
    art2 = _AS(_dir, store2, store2.audit)
    handler2 = make_handler(
        store2, policies2, _rm.RestoreCoordinator(store2, policies2),
        ops2, art2,
    )
    httpd2 = ThreadingHTTPServer(("127.0.0.1", 0), handler2)
    httpd2.daemon_threads = True
    import threading

    t2 = threading.Thread(target=httpd2.serve_forever, daemon=True)
    t2.start()
    try:
        client2 = Client("http://127.0.0.1:%d" % httpd2.server_address[1])
        status, third = client2.call("POST", path, body, idem="replay")
        assert status == 200 and third == first
    finally:
        httpd2.shutdown()

    # Exactly one encrypt event for the whole operation, named by operation_id.
    events = store.audit.query("t", action="encrypt", limit=1000).events
    assert len(events) == 1
    assert events[0].event_id == op_id
    assert events[0].outcome == "success"


def test_http_encrypt_different_request_same_key_is_409_with_id(http_server):
    client, _store, _policies, _ops, _dir = http_server
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body1 = {"tenant_id": "t", "plaintext": b64(b"one")}
    body2 = {"tenant_id": "t", "plaintext": b64(b"two")}

    status, first = client.call("POST", path, body1, idem="shared")
    assert status == 200
    # Same key, different plaintext binding: 409 naming the original op, and
    # the second binding is not executed (no second event).
    status, conflict = client.call("POST", path, body2, idem="shared")
    assert status == 409
    assert conflict["operation_id"] == first["operation_id"]
    assert set(conflict) == {"error", "operation_id"}
    # Replaying body1 still answers the original success.
    status, again = client.call("POST", path, body1, idem="shared")
    assert status == 200 and again == first
    events = _store_events(http_server, action="encrypt")
    assert len(events) == 1


def test_http_encrypt_terminal_403_replays_and_single_event(http_server):
    client, store, policies, _ops, _dir = http_server
    kid = _make_key(client)
    policies.put("t", [Rule("alice", ["create", "read"], "allow")])
    path = "/v1/keys/%s/encrypt" % kid
    body = {"tenant_id": "t", "plaintext": b64(b"x")}

    status, first = client.call("POST", path, body, idem="denied")
    assert status == 403
    op_id = first["operation_id"]
    # The replay is the stored terminal verbatim; no new audit event.
    status, second = client.call("POST", path, body, idem="denied")
    assert status == 403 and second == first
    events = store.audit.query("t", action="encrypt", limit=1000).events
    assert len(events) == 1
    assert events[0].event_id == op_id and events[0].outcome == "rejected"


def test_http_encrypt_pending_hides_envelope_then_finishes(http_server):
    client, store, _policies, op_store, data_dir = http_server
    from keymgr.artifacts import ArtifactStore

    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = {"tenant_id": "t", "plaintext": b64(b"x")}

    # Bind the key and leave the operation pending without executing. The
    # server binds on the redacted body (plaintext replaced by its digest), so
    # mirror that exactly to represent an in-flight encrypt.
    import hashlib
    import threading
    from keymgr.operations import normalize_body

    redacted = {
        "tenant_id": "t",
        "plaintext": hashlib.sha256(b"x").hexdigest(),
    }
    begin = op_store.begin(
        "t", "alice", path, normalize_body(redacted), "pending-key"
    )
    op_id = begin.record.operation_id
    assert begin.kind == "new"

    # While pending: GET hides http_status and response (the envelope with it).
    status, got = _op_body(client, op_id)
    assert status == 200
    assert got["status"] == "pending"
    assert got["http_status"] is None and got["response"] is None

    finish_body = {
        "format": env_mod.FORMAT,
        "envelope": "STORED-TOKEN",
        "operation_id": op_id,
    }
    # Hold the attempt claim so the concurrent same-key request cannot take
    # the strand over; it must WAIT for the owner instead. A fresh
    # ArtifactStore shares the cross-process fcntl claim even in-process.
    claim_art = ArtifactStore(data_dir, store, store.audit)
    claim = claim_art._claim(op_id, blocking=True)
    claim.__enter__()

    def waiter():
        waiter_result.append(
            client.call("POST", path, body, idem="pending-key")
        )

    waiter_result = []
    th = threading.Thread(target=waiter)
    th.start()
    # Owner reaches a terminal, then drops the claim: the waiter replays the
    # stored 200 verbatim rather than executing its own encryption.
    op_store.finish(begin.record, "succeeded", 200, finish_body)
    claim.__exit__(None, None, None)
    th.join(timeout=10)
    assert waiter_result and waiter_result[0][0] == 200
    assert waiter_result[0][1] == finish_body
    # The manual finish wrote no audit event and the waiter executed nothing.
    events = store.audit.query("t", action="encrypt", limit=1000).events
    assert events == []


def test_http_encrypt_no_secret_in_records_or_audit(http_server):
    client, store, _policies, op_store, data_dir = http_server
    kid = _make_key(client)
    secret = b"do-not-persist-plaintext"
    aad_secret = b"do-not-persist-aad"
    status, body = _encrypt(
        client, kid, "t", secret, idem="secret-check",
        aad=b64(aad_secret),
    )
    assert status == 200
    import os
    import glob

    # The operation record stores the canonical request (which carries the
    # base64 plaintext/aad as the binding) but the persisted terminal response
    # and the ledger must never contain the secret material.
    op_blob = b""
    for pathname in glob.glob(os.path.join(op_store.dir_path, "*.json")):
        with open(pathname, "rb") as fh:
            op_blob += fh.read()
    assert secret not in op_blob and aad_secret not in op_blob
    # The terminal response carries the envelope only, never raw plaintext.
    with open(store.audit.path, "rb") as fh:
        ledger = fh.read()
    assert secret not in ledger and aad_secret not in ledger
    assert b"STORED" not in ledger


# ------------------------------------------------- restart / provider switch
def test_envelope_decrypt_survives_restart(local_stack):
    store, _policies, data_dir = local_stack
    aes = store.create("t", "AES256", "k")
    status, _r, ver, kek = store.crypto_material(aes.key_id, "t")
    assert status == KeyStore.CRYPTO_OK
    token = env_mod.encode_envelope(
        key_id=aes.key_id, version=1, algorithm="AES256",
        kek=kek, plaintext=b"persist-me",
    )
    store.rotate(aes.key_id, "t", "AES256")
    # A brand-new process (new KeyStore over the same directory) must give a
    # consistent view: the v1 envelope still opens with v1 material.
    reopened = KeyStore(data_dir, AuditLog(data_dir))
    status, _r, ver, kek = reopened.crypto_material(aes.key_id, "t", 1)
    assert status == KeyStore.CRYPTO_OK and ver.version == 1
    opened = env_mod.decode_envelope(token)
    assert env_mod.open_envelope(opened, kek) == b"persist-me"


def test_envelope_refuses_when_owning_provider_inactive(
    local_stack, monkeypatch
):
    store, _policies, data_dir = local_stack
    aes = store.create("t", "AES256", "k")
    # A local-owned record must never be handled after switching to an
    # external module:factory provider: no fallback, a ProviderUnavailable
    # (HTTP 503) instead.
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv(
        "FAKE_KMS_STATE", os.path.join(data_dir, "kms-state.json")
    )
    import sys as _sys
    import os as _os

    _sys.path.insert(
        0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    )
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    provider_mod.reset_for_tests()
    from keymgr.provider import ProviderUnavailable

    with pytest.raises(ProviderUnavailable):
        store.crypto_material(aes.key_id, "t")


# ---------------------------------------------------------------- CLI
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cli_env(data_dir):
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        os.path.dirname(os.path.abspath(__file__)) + os.pathsep + REPO_ROOT
    )
    env.pop("KEYMGR_PROVIDER", None)
    env["KEYMGR_DATA_DIR"] = data_dir
    return env


def run_cli(data_dir, *args):
    import subprocess
    import sys

    cmd = [sys.executable, "-m", "keymgr", "--data-dir", data_dir] + [
        str(a) for a in args
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True,
        env=_cli_env(data_dir), timeout=60,
    )


def _json(proc):
    for text in (proc.stdout.strip(), proc.stderr.strip()):
        if text.startswith("{"):
            return json.loads(text)
    raise AssertionError(proc.stdout + proc.stderr)


def test_cli_encrypt_decrypt_roundtrip_and_exit_codes(tmp_path):
    data_dir = str(tmp_path / "data")
    proc = run_cli(
        data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert proc.returncode == 0
    kid = _json(proc)["key_id"]

    proc = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", b64(b"cli-payload"), "--aad", b64(b"a"),
        "--operator", "alice",
    )
    assert proc.returncode == 0
    token = _json(proc)["envelope"]

    proc = run_cli(
        data_dir, "decrypt", "--tenant-id", "t", "--key-id", kid,
        "--envelope", token, "--aad", b64(b"a"), "--operator", "alice",
    )
    assert proc.returncode == 0
    assert base64.b64decode(_json(proc)["plaintext"]) == b"cli-payload"

    # AAD mismatch -> exit 2 (HTTP 400), naming aad.
    proc = run_cli(
        data_dir, "decrypt", "--tenant-id", "t", "--key-id", kid,
        "--envelope", token, "--operator", "alice",
    )
    assert proc.returncode == 2 and "aad" in _json(proc)["error"]

    # Cross-tenant -> exit 4 (HTTP 404).
    proc = run_cli(
        data_dir, "encrypt", "--tenant-id", "other", "--key-id", kid,
        "--plaintext", b64(b"x"), "--operator", "bob",
    )
    assert proc.returncode == 4

    # Revoked -> exit 3 (HTTP 409).
    run_cli(
        data_dir, "revoke", "--tenant-id", "t", "--key-id", kid,
        "--reason", "r", "--operator", "alice",
    )
    proc = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", b64(b"x"), "--operator", "alice",
    )
    assert proc.returncode == 3

