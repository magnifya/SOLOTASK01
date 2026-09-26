"""KMS/HSM-native DEK unwrap (optional ``unwrap_key`` provider operation).

Covers:

* the LocalProvider ``unwrap_key`` argument/result contract
  (ValueError/TypeError/ProviderUnavailable/ProviderInvalidMaterial,
  32-byte result, AES256/RSA2048 round trips);
* the decrypt path of a provider that declares ``unwrap_key``: the bound
  provider's ``unwrap_key`` is called, ``export_material`` is never called and
  no KEK private material enters the service process, for both algorithms;
* a tampered wrapped key is a 400 naming the envelope (ProviderInvalidMaterial
  mapping), while a backend fault or a malformed provider result is the fixed
  503 and writes no audit event;
* a provider that does NOT declare the operation keeps the export path;
* declaring the operation without a callable method breaks the provider
  contract (503);
* a malformed key_id on the decrypt endpoint is a plain, unaudited 400 even
  for a valid tenant (no tenant_conflict event).
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

from keymgr import envelope as env_mod
from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.server import make_handler
from keymgr.store import KeyStore, NativeUnwrap


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------- LocalProvider
@pytest.fixture()
def local_provider(tmp_path):
    provider = provider_mod.LocalProvider()
    provider.configure(str(tmp_path / "pdata"))
    return provider


def _seal_wrapped_dek(provider, triple, algorithm):
    """Produce (wrapped_key, wrap_nonce, dek) the way envelope does."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dek = os.urandom(32)
    raw = provider.export_material(triple.handle).encrypted_material
    if algorithm == "AES256":
        kek = base64.b64decode(raw, validate=True)
        nonce = os.urandom(12)
        return AESGCM(kek).encrypt(nonce, dek, None), nonce, dek
    private_key = serialization.load_pem_private_key(
        raw.encode("utf-8"), password=None
    )
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    return private_key.public_key().encrypt(dek, oaep), None, dek


def test_local_unwrap_declared_and_roundtrips(local_provider):
    assert provider_mod.declares_unwrap_key(local_provider)
    for algorithm in ("AES256", "RSA2048"):
        triple = local_provider.generate(algorithm)
        wrapped, nonce, dek = _seal_wrapped_dek(
            local_provider, triple, algorithm
        )
        out = local_provider.unwrap_key(triple.handle, wrapped, nonce)
        assert isinstance(out, bytes) and out == dek and len(out) == 32


def test_local_unwrap_argument_contract(local_provider):
    aes = local_provider.generate("AES256")
    rsa = local_provider.generate("RSA2048")
    wk, nonce, _dek = _seal_wrapped_dek(local_provider, aes, "AES256")
    wk2, _n, _d = _seal_wrapped_dek(local_provider, rsa, "RSA2048")

    def expect(exc, fn):
        with pytest.raises(exc):
            fn()

    # Handle must be a non-empty string.
    expect(ValueError, lambda: local_provider.unwrap_key("", wk, nonce))
    expect(ValueError, lambda: local_provider.unwrap_key(None, wk, nonce))
    expect(ValueError, lambda: local_provider.unwrap_key(7, wk, nonce))
    # wrapped_key must be bytes; a non-null wrap_nonce must be bytes.
    expect(TypeError, lambda: local_provider.unwrap_key(aes.handle, "x", nonce))
    expect(TypeError, lambda: local_provider.unwrap_key(aes.handle, wk, "n"))
    # Empty wrapped_key and nonce-shape errors are ValueError.
    expect(
        ValueError, lambda: local_provider.unwrap_key(aes.handle, b"", nonce)
    )
    expect(ValueError, lambda: local_provider.unwrap_key(aes.handle, wk, None))
    expect(
        ValueError, lambda: local_provider.unwrap_key(aes.handle, wk, b"x")
    )
    expect(
        ValueError, lambda: local_provider.unwrap_key(rsa.handle, wk2, nonce)
    )
    # An AES256 handle called RSA-style (null nonce) is likewise a
    # nonce-shape ValueError.
    expect(ValueError, lambda: local_provider.unwrap_key(aes.handle, wk))
    # Unknown handle -> ProviderUnavailable.
    expect(
        provider_mod.ProviderUnavailable,
        lambda: local_provider.unwrap_key("no-such-handle", wk, nonce),
    )


def test_local_unwrap_authentication_failure_is_invalid_material(
    local_provider,
):
    aes = local_provider.generate("AES256")
    rsa = local_provider.generate("RSA2048")
    wk, nonce, _dek = _seal_wrapped_dek(local_provider, aes, "AES256")
    wk2, _n, _d = _seal_wrapped_dek(local_provider, rsa, "RSA2048")
    tampered = wk[:-1] + bytes([wk[-1] ^ 0x01])
    with pytest.raises(provider_mod.ProviderInvalidMaterial):
        local_provider.unwrap_key(aes.handle, tampered, nonce)
    tampered_rsa = wk2[:-1] + bytes([wk2[-1] ^ 0x01])
    with pytest.raises(provider_mod.ProviderInvalidMaterial):
        local_provider.unwrap_key(rsa.handle, tampered_rsa)


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
        tmp_path, monkeypatch, {"declare_unwrap_key": True}
    )


@pytest.fixture()
def plain_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, {})


@pytest.fixture()
def broken_stack(tmp_path, monkeypatch):
    yield from _build_server(
        tmp_path, monkeypatch,
        {"declare_unwrap_key": True, "unwrap_not_callable": True},
    )


_idem = [0]


def _idem_key():
    _idem[0] += 1
    return "enc-uk-%d" % _idem[0]


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _encrypt(client, kid, plaintext, tenant="t", **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": _idem_key()},
    )


def _decrypt(client, kid, token, tenant="t", **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/decrypt" % kid, body)


def _audit(stack, tenant="t"):
    return stack.audit.query(tenant, limit=1000).events


@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_native_unwrap_decrypt_roundtrip_without_export(
    native_stack, algorithm,
):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client, algorithm=algorithm)
    status, sealed = _encrypt(client, kid, b"native payload")
    assert status == 200, sealed
    # Encrypt used the export/wrap path as always; reset counters so the
    # decrypt accounting is unambiguous.
    fake_kms.reset()
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 200, body
    assert base64.b64decode(body["plaintext"]) == b"native payload"
    assert fake_kms.call_count("unwrap_key") == 1
    assert fake_kms.call_count("export_material") == 0
    # One decrypt success event and nothing rejected.
    events = _audit(native_stack)
    dec = [e for e in events if e.action == "decrypt"]
    assert len(dec) == 1 and dec[0].outcome == "success"


def test_native_unwrap_aad_roundtrip(native_stack):
    client = native_stack.client
    kid = _make_key(client)
    status, sealed = _encrypt(client, kid, b"x", aad=b64(b"ctx"))
    assert status == 200
    status, body = _decrypt(client, kid, sealed["envelope"], aad=b64(b"ctx"))
    assert status == 200
    assert base64.b64decode(body["plaintext"]) == b"x"


def test_native_unwrap_tampered_wrapped_key_is_400_and_names_envelope(
    native_stack,
):
    client = native_stack.client
    kid = _make_key(client)
    _, sealed = _encrypt(client, kid, b"x")
    obj = json.loads(base64.b64decode(sealed["envelope"]))
    wk = base64.b64decode(obj["wrapped_key"])
    obj["wrapped_key"] = b64(wk[:-1] + bytes([wk[-1] ^ 0x01]))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, body = _decrypt(client, kid, tampered)
    assert status == 400
    assert "envelope" in body["error"]
    # The authentication failure is a rejected business attempt, like every
    # other decrypt authentication failure.
    rejected = [
        e for e in _audit(native_stack)
        if e.action == "decrypt" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid


def test_native_unwrap_backend_failure_is_fixed_503_and_not_audited(
    native_stack,
):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client)
    _, sealed = _encrypt(client, kid, b"x")
    with open(native_stack.faults_path, "w") as fh:
        json.dump(
            {"declare_unwrap_key": True, "fail": {"unwrap_key": True}}, fh
        )
    fake_kms.reset()
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert fake_kms.call_count("export_material") == 0
    assert [
        e for e in _audit(native_stack) if e.action == "decrypt"
    ] == []


def test_native_unwrap_malformed_result_is_fixed_503_and_not_audited(
    native_stack,
):
    client = native_stack.client
    kid = _make_key(client)
    _, sealed = _encrypt(client, kid, b"x")
    with open(native_stack.faults_path, "w") as fh:
        json.dump({"declare_unwrap_key": True, "unwrap_short": True}, fh)
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert [
        e for e in _audit(native_stack) if e.action == "decrypt"
    ] == []


def test_non_declaring_provider_keeps_export_path(plain_stack):
    import fake_kms

    client = plain_stack.client
    kid = _make_key(client)
    _, sealed = _encrypt(client, kid, b"x")
    fake_kms.reset()
    status, body = _decrypt(client, kid, sealed["envelope"])
    assert status == 200, body
    assert fake_kms.call_count("unwrap_key") == 0
    assert fake_kms.call_count("export_material") == 1


def test_declared_unwrap_without_callable_method_breaks_contract(
    broken_stack,
):
    # Declaring "unwrap_key" in capabilities without a callable method is a
    # provider-contract failure: every provider call is the fixed 503.
    status, body = broken_stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}


def test_crypto_material_native_unwrap_resolves_pair(plain_stack):
    # Store-level resolution: a declaring provider yields a NativeUnwrap pair,
    # a non-declaring one yields exportable material.
    store = plain_stack.store
    import fake_kms

    kid = _make_key(plain_stack.client, algorithm="AES256")
    status, _r, ver, material = store.crypto_material(
        kid, "t", native_unwrap=True
    )
    assert status == KeyStore.CRYPTO_OK
    assert not isinstance(material, NativeUnwrap)
    # Flip the faults file to declare unwrap_key: a freshly built provider
    # (reconnect) then resolves natively.
    with open(plain_stack.faults_path, "w") as fh:
        json.dump({"declare_unwrap_key": True}, fh)
    provider_mod.reconnect()
    fake_kms.reset()
    try:
        status, _r, ver, material = store.crypto_material(
            kid, "t", native_unwrap=True
        )
        assert status == KeyStore.CRYPTO_OK
        assert isinstance(material, NativeUnwrap)
        assert material.handle == ver.handle
        assert fake_kms.call_count("export_material") == 0
        # Default (encrypt/rewrap path) still exports material.
        status, _r, _v, kek = store.crypto_material(kid, "t")
        assert status == KeyStore.CRYPTO_OK and len(kek) == 32
    finally:
        provider_mod.reconnect()


def _raw_ledger(stack):
    path = os.path.join(stack.data_dir, "audit.log")
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def test_decrypt_bad_key_id_is_400_and_no_tenant_conflict(plain_stack):
    # A valid tenant with a malformed key_id gets a plain 400 and NO audit
    # event of any kind (no tenant_conflict either).
    client = plain_stack.client
    status, body = client.call(
        "POST", "/v1/keys/not-a-uuid/decrypt",
        {"tenant_id": "t", "envelope": b64(b"{}")},
    )
    assert status == 400
    assert "key_id" in body["error"]
    assert _audit(plain_stack) == []
    assert b"tenant_conflict" not in _raw_ledger(plain_stack)


def test_decrypt_bad_key_id_with_bad_tenant_still_conflicts(plain_stack):
    # A missing/invalid tenant source keeps the invisible tenant_conflict
    # rule regardless of the key_id shape (the event carries a null tenant
    # and is invisible to per-tenant queries, so read the raw ledger).
    client = plain_stack.client
    status, body = client.call(
        "POST", "/v1/keys/not-a-uuid/decrypt",
        {"envelope": b64(b"{}")},
    )
    assert status == 400
    assert _raw_ledger(plain_stack).count(b"tenant_conflict") == 1
