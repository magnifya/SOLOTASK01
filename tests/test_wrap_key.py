"""KMS/HSM-native DEK wrap (optional ``wrap_key`` provider operation).

Covers:

* the LocalProvider ``wrap_key`` argument/result contract
  (ValueError/TypeError/ProviderUnavailable, AES256 48-byte/12-byte and
  RSA2048 256-byte/null result shapes, unwrap round trips);
* the encrypt path of a provider that declares ``wrap_key``: the bound
  provider's ``wrap_key`` is called, ``export_material`` is never called and
  no KEK private material enters the service process, for both algorithms,
  and the produced envelope decrypts normally;
* a backend fault or a malformed provider result is the fixed 503 with body
  keys ``error,operation_id``, writes no audit event and leaves the
  operation pending, so a retry with the same Idempotency-Key reuses the
  operation_id and seals exactly once;
* a provider that does NOT declare the operation keeps the export path;
* declaring the operation without a callable method breaks the provider
  contract (503).
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
from keymgr.store import KeyStore, NativeWrap


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------- LocalProvider
@pytest.fixture()
def local_provider(tmp_path):
    provider = provider_mod.LocalProvider()
    provider.configure(str(tmp_path / "pdata"))
    return provider


def test_local_wrap_declared_and_roundtrips(local_provider):
    assert provider_mod.declares_wrap_key(local_provider)
    dek = os.urandom(32)
    aes = local_provider.generate("AES256")
    wrapped, nonce = local_provider.wrap_key(aes.handle, dek)
    assert isinstance(wrapped, bytes) and len(wrapped) == 48
    assert isinstance(nonce, bytes) and len(nonce) == 12
    assert local_provider.unwrap_key(aes.handle, wrapped, nonce) == dek
    rsa = local_provider.generate("RSA2048")
    wrapped, nonce = local_provider.wrap_key(rsa.handle, dek)
    assert isinstance(wrapped, bytes) and len(wrapped) == 256
    assert nonce is None
    assert local_provider.unwrap_key(rsa.handle, wrapped, None) == dek


def test_local_wrap_argument_contract(local_provider):
    aes = local_provider.generate("AES256")
    dek = os.urandom(32)

    def expect(exc, fn):
        with pytest.raises(exc):
            fn()

    # Handle must be a non-empty string.
    expect(ValueError, lambda: local_provider.wrap_key("", dek))
    expect(ValueError, lambda: local_provider.wrap_key(None, dek))
    expect(ValueError, lambda: local_provider.wrap_key(7, dek))
    # data_key must be bytes of exactly 32 bytes.
    expect(TypeError, lambda: local_provider.wrap_key(aes.handle, "x" * 32))
    expect(TypeError, lambda: local_provider.wrap_key(aes.handle, None))
    expect(ValueError, lambda: local_provider.wrap_key(aes.handle, b""))
    expect(ValueError, lambda: local_provider.wrap_key(aes.handle, b"x" * 31))
    expect(ValueError, lambda: local_provider.wrap_key(aes.handle, b"x" * 33))
    # Unknown handle -> ProviderUnavailable.
    expect(
        provider_mod.ProviderUnavailable,
        lambda: local_provider.wrap_key("no-such-handle", dek),
    )


# ------------------------------------------------------------- external KMS
def _build_server(tmp_path, monkeypatch, faults):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    with open(faults_path, "w") as fh:
        json.dump(faults, fh)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
    monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
    import fake_kms

    fake_kms.reset()
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
        data_dir=data_dir, store=store, audit=audit_log, client=client,
        faults_path=faults_path,
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
    yield from _build_server(
        tmp_path, monkeypatch, {"declare_wrap_key": True}
    )


@pytest.fixture()
def plain_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, {})


@pytest.fixture()
def broken_stack(tmp_path, monkeypatch):
    yield from _build_server(
        tmp_path, monkeypatch,
        {"declare_wrap_key": True, "wrap_not_callable": True},
    )


_idem = [0]


def _idem_key():
    _idem[0] += 1
    return "enc-wk-%d" % _idem[0]


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _encrypt(client, kid, plaintext, tenant="t", idem=None, **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": idem or _idem_key()},
    )


def _decrypt(client, kid, token, tenant="t", **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/decrypt" % kid, body)


def _audit(stack, tenant="t"):
    return stack.audit.query(tenant, limit=1000).events


@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_native_wrap_encrypt_roundtrip_without_export(
    native_stack, algorithm,
):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client, algorithm=algorithm)
    fake_kms.reset()
    status, sealed = _encrypt(client, kid, b"native payload")
    assert status == 200, sealed
    assert list(sealed) == ["format", "envelope", "operation_id"]
    assert fake_kms.call_count("wrap_key") == 1
    assert fake_kms.call_count("export_material") == 0
    # The envelope is an ordinary keymgr-envelope-v1 token and decrypts.
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 200, body
    assert base64.b64decode(body["plaintext"]) == b"native payload"
    # One encrypt success event and nothing rejected.
    events = _audit(native_stack)
    enc = [e for e in events if e.action == "encrypt"]
    assert len(enc) == 1 and enc[0].outcome == "success"


def test_native_wrap_aad_roundtrip(native_stack):
    client = native_stack.client
    kid = _make_key(client)
    status, sealed = _encrypt(client, kid, b"x", aad=b64(b"ctx"))
    assert status == 200
    status, body = _decrypt(client, kid, sealed["envelope"], aad=b64(b"ctx"))
    assert status == 200
    assert base64.b64decode(body["plaintext"]) == b"x"


def test_native_wrap_idempotent_replay_does_not_rewrap(native_stack):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client)
    fake_kms.reset()
    idem = _idem_key()
    status, first = _encrypt(client, kid, b"x", idem=idem)
    assert status == 200
    status, replay = _encrypt(client, kid, b"x", idem=idem)
    assert status == 200
    assert replay == first
    assert fake_kms.call_count("wrap_key") == 1


def test_native_wrap_backend_failure_is_pending_503_then_recovers(
    native_stack,
):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client)
    with open(native_stack.faults_path, "w") as fh:
        json.dump(
            {"declare_wrap_key": True, "fail": {"wrap_key": True}}, fh
        )
    fake_kms.reset()
    idem = _idem_key()
    status, body = _encrypt(client, kid, b"x", idem=idem)
    assert status == 503
    assert list(body) == ["error", "operation_id"]
    assert body["error"] == "key management provider is unavailable"
    op_id = body["operation_id"]
    assert fake_kms.call_count("wrap_key") == 1
    assert fake_kms.call_count("export_material") == 0
    # No audit event of any kind for the failed attempt.
    assert [e for e in _audit(native_stack) if e.action == "encrypt"] == []
    # The backend recovers: the same Idempotency-Key continues under the
    # SAME operation_id and seals exactly once.
    with open(native_stack.faults_path, "w") as fh:
        json.dump({"declare_wrap_key": True}, fh)
    status, sealed = _encrypt(client, kid, b"x", idem=idem)
    assert status == 200, sealed
    assert sealed["operation_id"] == op_id
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 200
    assert base64.b64decode(body["plaintext"]) == b"x"
    events = [e for e in _audit(native_stack) if e.action == "encrypt"]
    assert len(events) == 1 and events[0].outcome == "success"


def test_native_wrap_malformed_result_is_pending_503_and_not_audited(
    native_stack,
):
    client = native_stack.client
    kid = _make_key(client)
    with open(native_stack.faults_path, "w") as fh:
        json.dump({"declare_wrap_key": True, "wrap_short": True}, fh)
    status, body = _encrypt(client, kid, b"x")
    assert status == 503
    assert list(body) == ["error", "operation_id"]
    assert body["error"] == "key management provider is unavailable"
    assert [e for e in _audit(native_stack) if e.action == "encrypt"] == []


def test_non_declaring_provider_keeps_export_path(plain_stack):
    import fake_kms

    client = plain_stack.client
    kid = _make_key(client)
    fake_kms.reset()
    status, sealed = _encrypt(client, kid, b"x")
    assert status == 200, sealed
    assert fake_kms.call_count("wrap_key") == 0
    assert fake_kms.call_count("export_material") == 1
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 200
    assert base64.b64decode(body["plaintext"]) == b"x"


def test_declared_wrap_without_callable_method_breaks_contract(
    broken_stack,
):
    # Declaring "wrap_key" in capabilities without a callable method is a
    # provider-contract failure: every provider call is the fixed 503.
    status, body = broken_stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}


def test_crypto_material_native_wrap_resolves_pair(plain_stack):
    # Store-level resolution: a declaring provider yields a NativeWrap pair,
    # a non-declaring one yields exportable material.
    store = plain_stack.store
    import fake_kms

    kid = _make_key(plain_stack.client, algorithm="AES256")
    status, _r, ver, material = store.crypto_material(
        kid, "t", native_wrap=True
    )
    assert status == KeyStore.CRYPTO_OK
    assert not isinstance(material, NativeWrap)
    # Flip the faults file to declare wrap_key: a freshly built provider
    # (reconnect) then resolves natively.
    with open(plain_stack.faults_path, "w") as fh:
        json.dump({"declare_wrap_key": True}, fh)
    provider_mod.reconnect()
    fake_kms.reset()
    try:
        status, _r, ver, material = store.crypto_material(
            kid, "t", native_wrap=True
        )
        assert status == KeyStore.CRYPTO_OK
        assert isinstance(material, NativeWrap)
        assert material.handle == ver.handle
        assert fake_kms.call_count("export_material") == 0
        # Default (decrypt/rewrap path) still exports material.
        status, _r, _v, kek = store.crypto_material(kid, "t")
        assert status == KeyStore.CRYPTO_OK and len(kek) == 32
    finally:
        provider_mod.reconnect()
