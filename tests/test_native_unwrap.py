"""KMS/HSM-native DEK unwrap for POST /v1/keys/{key_id}/decrypt.

Covers the optional ``unwrap_key`` provider operation: the provider contract
(handle/bytes/nonce validation, ProviderUnavailable vs
ProviderInvalidMaterial, the 32-byte success), the native decrypt path (no
``export_material``, no KEK private key in the service process), the legacy
export-based path for non-declaring providers, the 400 naming ``envelope``
on authentication failure, the fixed unaudited 503 on a malformed result or
backend failure, the contract failure of a declared-but-not-callable method,
and the fixed export/backup version object key order.
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
from keymgr.policy import PolicyStore
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _build_server(tmp_path, monkeypatch, faults=None):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
    monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
    if faults:
        with open(faults_path, "w") as fh:
            json.dump(faults, fh)
    provider_mod.reset_for_tests()
    import fake_kms

    fake_kms.reset()
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
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


@pytest.fixture()
def native_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, {"declare_unwrap": True})


@pytest.fixture()
def legacy_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _set_faults(stack, faults):
    with open(stack.faults_path, "w") as fh:
        json.dump(faults, fh)


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


_counter = [0]


def _encrypt(client, kid, plaintext=b"x", **extra):
    _counter[0] += 1
    body = {"tenant_id": "t", "plaintext": b64(plaintext)}
    body.update(extra)
    status, out = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": "unwrap-test-%d" % _counter[0]},
    )
    assert status == 200, out
    return out["envelope"]


def _decrypt(client, kid, token, **extra):
    body = {"tenant_id": "t", "envelope": token}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/decrypt" % kid, body)


def _decrypt_events(stack):
    return [
        e for e in stack.audit.query("t", limit=1000).events
        if e.action == "decrypt"
    ]


# -- native path --------------------------------------------------------------
@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_native_unwrap_roundtrip_without_export(native_stack, algorithm):
    import fake_kms

    key_id = _make_key(native_stack.client, algorithm)
    token = _encrypt(native_stack.client, key_id, b"native-payload")
    fake_kms.reset()
    status, body = _decrypt(native_stack.client, key_id, token)
    assert status == 200, body
    assert base64.b64decode(body["plaintext"]) == b"native-payload"
    # The DEK was unwrapped inside the KMS: no export, no KEK in-process.
    assert fake_kms.call_count("unwrap_key") == 1
    assert fake_kms.call_count("export_material") == 0


def test_legacy_path_exports_material(legacy_stack):
    import fake_kms

    key_id = _make_key(legacy_stack.client)
    token = _encrypt(legacy_stack.client, key_id, b"legacy-payload")
    fake_kms.reset()
    status, body = _decrypt(legacy_stack.client, key_id, token)
    assert status == 200, body
    assert base64.b64decode(body["plaintext"]) == b"legacy-payload"
    assert fake_kms.call_count("unwrap_key") == 0
    assert fake_kms.call_count("export_material") == 1


def test_native_unwrap_authentication_failure_is_400_envelope(native_stack):
    key_id = _make_key(native_stack.client)
    token = _encrypt(native_stack.client, key_id, b"secret")
    obj = json.loads(base64.b64decode(token))
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, body = _decrypt(native_stack.client, key_id, tampered)
    assert status == 400
    assert "envelope" in body["error"]


def test_native_unwrap_backend_failure_is_503_and_not_audited(native_stack):
    key_id = _make_key(native_stack.client)
    token = _encrypt(native_stack.client, key_id, b"x")
    _set_faults(
        native_stack, {"declare_unwrap": True, "fail": {"unwrap_key": True}}
    )
    before = len(_decrypt_events(native_stack))
    status, body = _decrypt(native_stack.client, key_id, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert len(_decrypt_events(native_stack)) == before


def test_native_unwrap_malformed_result_is_503_and_not_audited(native_stack):
    key_id = _make_key(native_stack.client)
    token = _encrypt(native_stack.client, key_id, b"x")
    _set_faults(
        native_stack, {"declare_unwrap": True, "unwrap_short": True}
    )
    before = len(_decrypt_events(native_stack))
    status, body = _decrypt(native_stack.client, key_id, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert len(_decrypt_events(native_stack)) == before


def test_native_unwrap_failure_never_falls_back_to_export(native_stack):
    import fake_kms

    key_id = _make_key(native_stack.client)
    token = _encrypt(native_stack.client, key_id, b"x")
    _set_faults(
        native_stack, {"declare_unwrap": True, "fail": {"unwrap_key": True}}
    )
    fake_kms.reset()
    status, _body = _decrypt(native_stack.client, key_id, token)
    assert status == 503
    assert fake_kms.call_count("export_material") == 0


def test_declared_unwrap_without_callable_method_breaks_contract(
    tmp_path, monkeypatch,
):
    stack_gen = _build_server(
        tmp_path, monkeypatch,
        {"declare_unwrap": True, "unwrap_not_callable": True},
    )
    stack = next(stack_gen)
    try:
        status, body = stack.client.call(
            "POST", "/v1/keys",
            {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
        )
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
    finally:
        list(stack_gen)


def test_invalid_key_id_under_valid_tenant_is_400_without_conflict(
    native_stack,
):
    key_id = _make_key(native_stack.client)
    token = _encrypt(native_stack.client, key_id, b"x")
    with open(os.path.join(native_stack.data_dir, "audit.log"), "rb") as fh:
        before = fh.read()
    status, body = native_stack.client.call(
        "POST", "/v1/keys/not-a-uuid/decrypt",
        {"tenant_id": "t", "envelope": token},
    )
    assert status == 400
    assert "key_id" in body["error"]
    with open(os.path.join(native_stack.data_dir, "audit.log"), "rb") as fh:
        after = fh.read()
    # No audit event at all: neither a decrypt attempt nor a tenant_conflict.
    assert before == after


# -- local provider contract --------------------------------------------------
def test_local_provider_unwrap_key_contract(tmp_path):
    import os as _os

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    provider = provider_mod.LocalProvider()
    provider.configure(str(tmp_path / "pdata"))
    aes_triple = provider.generate("AES256")
    rsa_triple = provider.generate("RSA2048")
    dek = _os.urandom(32)
    # Wrap a DEK under each KEK through the provider's exported material.
    aes_raw = base64.b64decode(
        provider.export_material(aes_triple.handle).encrypted_material
    )
    nonce = _os.urandom(12)
    aes_wrapped = AESGCM(aes_raw).encrypt(nonce, dek, None)
    rsa_priv = serialization.load_pem_private_key(
        provider.export_material(rsa_triple.handle).encrypted_material.encode(),
        password=None,
    )
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    rsa_wrapped = rsa_priv.public_key().encrypt(dek, oaep)
    # A handle that is not a non-empty string is a ValueError.
    with pytest.raises(ValueError):
        provider.unwrap_key("", aes_wrapped, nonce)
    with pytest.raises(ValueError):
        provider.unwrap_key(123, aes_wrapped, nonce)
    # Non-bytes wrapped_key / non-null non-bytes wrap_nonce is a TypeError.
    with pytest.raises(TypeError):
        provider.unwrap_key(aes_triple.handle, "x", nonce)
    with pytest.raises(TypeError):
        provider.unwrap_key(aes_triple.handle, aes_wrapped, "x")
    # An empty wrapped_key is a ValueError.
    with pytest.raises(ValueError):
        provider.unwrap_key(aes_triple.handle, b"", nonce)
    # AES256 nonce must be exactly 12 bytes; RSA2048 nonce must be null.
    with pytest.raises(ValueError):
        provider.unwrap_key(aes_triple.handle, aes_wrapped, b"short")
    with pytest.raises(ValueError):
        provider.unwrap_key(aes_triple.handle, aes_wrapped, None)
    with pytest.raises(ValueError):
        provider.unwrap_key(rsa_triple.handle, rsa_wrapped, nonce)
    # An unknown handle is ProviderUnavailable.
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider.unwrap_key("no-such-handle", aes_wrapped, nonce)
    # Authentication failures are ProviderInvalidMaterial.
    with pytest.raises(provider_mod.ProviderInvalidMaterial):
        provider.unwrap_key(aes_triple.handle, aes_wrapped, _os.urandom(12))
    with pytest.raises(provider_mod.ProviderInvalidMaterial):
        provider.unwrap_key(rsa_triple.handle, _os.urandom(256))
    # Success is the 32-byte data key.
    assert provider.unwrap_key(aes_triple.handle, aes_wrapped, nonce) == dek
    assert provider.unwrap_key(rsa_triple.handle, rsa_wrapped) == dek
    assert provider.unwrap_key(rsa_triple.handle, rsa_wrapped, None) == dek


def test_local_provider_declares_unwrap_key():
    provider = provider_mod.LocalProvider()
    assert provider_mod.declares_unwrap_key(provider)
    assert "unwrap_key" in provider.capabilities["operations"]


# -- export/backup version object key order -----------------------------------
def test_export_version_object_fixed_key_order(tmp_path):
    store = KeyStore(str(tmp_path / "d"), AuditLog(str(tmp_path / "d")))
    record = store.create("t", "AES256", "k")
    payload = store.export_payload(record)
    assert list(payload["versions"][0].keys()) == [
        "version", "created_at", "algorithm", "public_key",
        "private_material", "provider", "status", "reason", "operator",
        "revoked_at",
    ]


def test_validated_bundle_version_fixed_key_order(tmp_path):
    from keymgr import keybundle

    store = KeyStore(str(tmp_path / "d"), AuditLog(str(tmp_path / "d")))
    record = store.create("t", "AES256", "k")
    bundle = store.export_bundle(record.key_id, "t", "pw")
    decoded = keybundle.decode_bundle(bundle, "pw")
    assert list(decoded["versions"][0].keys()) == [
        "version", "created_at", "algorithm", "public_key",
        "private_material", "provider", "status", "reason", "operator",
        "revoked_at",
    ]
