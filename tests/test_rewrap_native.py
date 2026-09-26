"""KMS/HSM-native envelope rewrap (the optional ``rewrap_key`` operation).

Covers the provider contract itself (argument ``ValueError``/``TypeError``
rules, structural envelope validation, in-provider authentication, the exact
AES256/RSA2048 result shapes, unknown/algorithm-mismatched handles and
backend faults), the service-side native path of
``POST /v1/keys/{key_id}/rewrap`` (chosen only when BOTH versions share one
provider_id that declares ``rewrap_key``; five-second gate; no
``export_material``; DEK/KEK/plaintext never in the service process), the
fixed-text 503 with no audit on provider faults or malformed results, the
400 naming the envelope on authentication failure, and the fallback to the
export-based path when the operation is not declared.
"""

import base64
import itertools
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
from keymgr.provider import (
    LocalProvider,
    ProviderInvalidMaterial,
    ProviderUnavailable,
)
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


# -- local provider contract -------------------------------------------------
@pytest.fixture()
def local(tmp_path):
    provider = LocalProvider()
    provider.configure(str(tmp_path / "data"))
    return provider


def _seal(provider, handle, algorithm, plaintext=b"native", aad=b"ctx"):
    """Seal an envelope natively under ``handle``; return (token, opened)."""
    token = env_mod.seal_envelope_native(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1,
        algorithm=algorithm,
        provider=provider,
        handle=handle,
        plaintext=plaintext,
        aad=aad,
    )
    return token, env_mod.decode_envelope(token)


def test_local_provider_declares_rewrap_key():
    assert "rewrap_key" in LocalProvider.capabilities["operations"]
    assert provider_mod.declares_rewrap_key(LocalProvider())
    assert provider_mod.declares_rewrap_key(provider_mod.get_local_provider())


def test_local_rewrap_key_argument_contract(local):
    triple = local.generate("AES256")
    token, opened = _seal(local, triple.handle, "AES256")
    raw = env_mod.raw_token_bytes(token)
    # src/dst must be non-empty strings.
    for bad in (None, "", 7, b"x"):
        with pytest.raises(ValueError):
            local.rewrap_key(bad, triple.handle, raw)
        with pytest.raises(ValueError):
            local.rewrap_key(triple.handle, bad, raw)
    # envelope must be bytes, and non-empty/structurally valid.
    with pytest.raises(TypeError):
        local.rewrap_key(triple.handle, triple.handle, "not bytes")
    with pytest.raises(ValueError):
        local.rewrap_key(triple.handle, triple.handle, b"")
    with pytest.raises(ValueError):
        local.rewrap_key(triple.handle, triple.handle, b"not json")
    with pytest.raises(ValueError):
        local.rewrap_key(triple.handle, triple.handle, b"[1, 2]")
    obj = json.loads(raw.decode("utf-8"))
    obj["algorithm"] = "AES128"
    with pytest.raises(ValueError):
        local.rewrap_key(
            triple.handle, triple.handle,
            json.dumps(obj).encode("utf-8"),
        )
    obj = json.loads(raw.decode("utf-8"))
    obj["nonce"] = b64(b"short")
    with pytest.raises(ValueError):
        local.rewrap_key(
            triple.handle, triple.handle,
            json.dumps(obj).encode("utf-8"),
        )
    # Unknown handles are ProviderUnavailable.
    with pytest.raises(ProviderUnavailable):
        local.rewrap_key("no-such-handle", triple.handle, raw)
    with pytest.raises(ProviderUnavailable):
        local.rewrap_key(triple.handle, "no-such-handle", raw)


def test_local_rewrap_key_same_dek_and_shapes(local):
    aes1 = local.generate("AES256")
    aes2 = local.generate("AES256")
    rsa1 = local.generate("RSA2048")
    rsa2 = local.generate("RSA2048")
    cases = [
        (aes1, aes2, "AES256", 48, 12),
        (aes1, rsa1, "RSA2048", 256, None),
        (rsa1, aes1, "AES256", 48, 12),
        (rsa1, rsa2, "RSA2048", 256, None),
    ]
    for src, dst, dst_algorithm, wk_len, nonce_len in cases:
        token, opened = _seal(
            local, src.handle, src_algorithm_of(local, src.handle)
        )
        raw = env_mod.raw_token_bytes(token)
        wrapped, wrap_nonce = local.rewrap_key(src.handle, dst.handle, raw)
        assert isinstance(wrapped, bytes) and len(wrapped) == wk_len
        if nonce_len is None:
            assert wrap_nonce is None
        else:
            assert isinstance(wrap_nonce, bytes)
            assert len(wrap_nonce) == nonce_len
        # The SAME data key came back out: unwrap both wraps and compare.
        src_dek = local.unwrap_key(
            src.handle, opened.wrapped_key, opened.wrap_nonce
        )
        dst_dek = local.unwrap_key(dst.handle, wrapped, wrap_nonce)
        assert src_dek == dst_dek
        assert len(dst_dek) == 32


def src_algorithm_of(provider, handle):
    return provider._registry[handle]["algorithm"]


def test_local_rewrap_key_authentication_failures(local):
    src = local.generate("AES256")
    dst = local.generate("AES256")
    token, opened = _seal(local, src.handle, "AES256")
    raw = env_mod.raw_token_bytes(token)
    obj = json.loads(raw.decode("utf-8"))
    # Tampered wrapped_key: the wrap tag fails.
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    with pytest.raises(ProviderInvalidMaterial):
        local.rewrap_key(
            src.handle, dst.handle, json.dumps(obj).encode("utf-8")
        )
    # Tampered ciphertext: the content GCM tag fails.
    obj = json.loads(raw.decode("utf-8"))
    ct = bytearray(base64.b64decode(obj["ciphertext"]))
    ct[0] ^= 0x01
    obj["ciphertext"] = b64(bytes(ct))
    with pytest.raises(ProviderInvalidMaterial):
        local.rewrap_key(
            src.handle, dst.handle, json.dumps(obj).encode("utf-8")
        )
    # An RSA envelope presented with an AES src handle: algorithm mismatch.
    rsa_src = local.generate("RSA2048")
    rsa_token, _ = _seal(local, rsa_src.handle, "RSA2048")
    with pytest.raises(ProviderUnavailable):
        local.rewrap_key(
            src.handle, dst.handle, env_mod.raw_token_bytes(rsa_token)
        )


def test_local_rewrap_key_plaintext_never_returned(local):
    src = local.generate("AES256")
    dst = local.generate("RSA2048")
    secret = b"provider-boundary-secret"
    token, _ = _seal(local, src.handle, "AES256", plaintext=secret)
    wrapped, wrap_nonce = local.rewrap_key(
        src.handle, dst.handle, env_mod.raw_token_bytes(token)
    )
    assert secret not in wrapped
    assert wrap_nonce is None


# -- envelope.rewrap_envelope_native -----------------------------------------
class _StubProvider:
    """Minimal stand-in driving rewrap_envelope_native's result checks."""

    def __init__(self, result=None, exc=None):
        self.result = result
        self.exc = exc
        self.calls = []

    def rewrap_key(self, src, dst, envelope):
        self.calls.append((src, dst, envelope))
        if self.exc is not None:
            raise self.exc
        return self.result


def _opened_aes():
    kek = os.urandom(32)
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", kek=kek,
        plaintext=b"payload", aad=b"ctx",
    )
    return token, env_mod.decode_envelope(token)


def test_native_envelope_carries_bytes_and_reseals():
    token, opened = _opened_aes()
    wrapped, nonce = os.urandom(48), os.urandom(12)
    stub = _StubProvider(result=(wrapped, nonce))
    out = env_mod.rewrap_envelope_native(
        opened, stub,
        src="src-handle", dst="dst-handle",
        target_version=2, target_algorithm="AES256",
        envelope_bytes=env_mod.raw_token_bytes(token),
    )
    # The provider received the raw base64-decoded envelope bytes.
    assert stub.calls == [
        ("src-handle", "dst-handle", base64.b64decode(token.encode("ascii")))
    ]
    after = env_mod.decode_envelope(out)
    assert after.version == 2 and after.algorithm == "AES256"
    assert (after.nonce, after.tag, after.ciphertext, after.aad) == (
        opened.nonce, opened.tag, opened.ciphertext, opened.aad,
    )
    assert after.key_id == opened.key_id
    assert after.wrapped_key == wrapped and after.wrap_nonce == nonce


def test_native_envelope_rsa_target_shapes():
    token, opened = _opened_aes()
    wrapped = os.urandom(256)
    stub = _StubProvider(result=(wrapped, None))
    out = env_mod.rewrap_envelope_native(
        opened, stub,
        src="s", dst="d",
        target_version=3, target_algorithm="RSA2048",
        envelope_bytes=env_mod.raw_token_bytes(token),
    )
    after = env_mod.decode_envelope(out)
    assert after.algorithm == "RSA2048"
    assert after.wrap == env_mod.WRAP_RSA_OAEP_SHA256
    assert after.wrap_nonce is None
    assert after.wrapped_key == wrapped


def test_native_envelope_malformed_results_are_unavailable():
    token, opened = _opened_aes()
    raw = env_mod.raw_token_bytes(token)
    bad_results = [
        b"not-a-tuple",
        (b"x",),
        (b"x", None, None),
        (b"short", os.urandom(12)),          # AES wrapped_key must be 48
        (os.urandom(48), b"short"),          # AES wrap_nonce must be 12
        (os.urandom(48), "not-bytes"),
        ("not-bytes", os.urandom(12)),
    ]
    for result in bad_results:
        with pytest.raises(ProviderUnavailable):
            env_mod.rewrap_envelope_native(
                opened, _StubProvider(result=result),
                src="s", dst="d",
                target_version=2, target_algorithm="AES256",
                envelope_bytes=raw,
            )
    # RSA targets: wrong blob length or a non-null nonce.
    for result in [(os.urandom(48), None), (os.urandom(256), os.urandom(12))]:
        with pytest.raises(ProviderUnavailable):
            env_mod.rewrap_envelope_native(
                opened, _StubProvider(result=result),
                src="s", dst="d",
                target_version=2, target_algorithm="RSA2048",
                envelope_bytes=raw,
            )


def test_native_envelope_error_mapping():
    token, opened = _opened_aes()
    raw = env_mod.raw_token_bytes(token)
    # Authentication failure -> EnvelopeError (the 400 naming the envelope).
    with pytest.raises(env_mod.EnvelopeError) as excinfo:
        env_mod.rewrap_envelope_native(
            opened,
            _StubProvider(exc=ProviderInvalidMaterial("cannot authenticate")),
            src="s", dst="d",
            target_version=2, target_algorithm="AES256",
            envelope_bytes=raw,
        )
    assert "field envelope" in str(excinfo.value)
    # Backend faults and contract violations -> ProviderUnavailable (503).
    for exc in (
        ProviderUnavailable("backend down"),
        ValueError("should not happen for a valid envelope"),
        TypeError("should not happen for a valid envelope"),
        RuntimeError("backend exploded"),
    ):
        with pytest.raises(ProviderUnavailable):
            env_mod.rewrap_envelope_native(
                opened, _StubProvider(exc=exc),
                src="s", dst="d",
                target_version=2, target_algorithm="AES256",
                envelope_bytes=raw,
            )


# -- HTTP endpoint over the fake KMS -----------------------------------------
def _build_server(tmp_path, monkeypatch, faults):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    with open(faults_path, "w") as fh:
        json.dump(faults, fh)
    sys.path.insert(0, os.path.dirname(__file__))
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
        data_dir=data_dir, store=store, policies=policies,
        audit=audit_log, client=client, faults_path=faults_path,
        fake_kms=fake_kms,
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
        tmp_path, monkeypatch, {"declare_rewrap_key": True}
    )


@pytest.fixture()
def plain_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, {})


@pytest.fixture()
def broken_native_stack(tmp_path, monkeypatch):
    # The factory is built lazily on first use; with the fault present from
    # the start, declaring "rewrap_key" without a callable method fails the
    # contract and every provider call is the fixed 503.
    yield from _build_server(
        tmp_path, monkeypatch,
        {"declare_rewrap_key": True, "rewrap_not_callable": True},
    )


_idem_counter = itertools.count(1)


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(client, key_id, algorithm, key, tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": key},
    )
    assert status == 201, body
    return body


def _encrypt(client, key_id, plaintext, tenant="t", **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    status, reply = client.call(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        headers={"Idempotency-Key": "enc-%d" % next(_idem_counter)},
    )
    assert status == 200, reply
    return reply["envelope"]


def _rewrap(client, key_id, token, tenant="t", **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/rewrap" % key_id, body)


def _decrypt(client, key_id, token, tenant="t", **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/decrypt" % key_id, body)


def _inner(token):
    return json.loads(base64.b64decode(token))


def _rewrap_events(st):
    return [
        e for e in st.audit.query("t", limit=1000).events
        if e.action == "rewrap"
    ]


def _set_faults(st, faults):
    with open(st.faults_path, "w") as fh:
        json.dump(faults, fh)


def test_endpoint_uses_native_path_without_export(native_stack):
    client = native_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"native payload", version=1, aad=b64(b"c"))
    _rotate(client, kid, "AES256", "rot-native-1")
    native_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token, aad=b64(b"c"))
    assert status == 200, body
    assert list(body.keys()) == ["format", "envelope"]
    # The native path called rewrap_key exactly once and never exported.
    assert native_stack.fake_kms.call_count("rewrap_key") == 1
    assert native_stack.fake_kms.call_count("export_material") == 0
    before, after = _inner(token), _inner(body["envelope"])
    assert before["version"] == 1 and after["version"] == 2
    for field in ("key_id", "nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field
    assert after["wrapped_key"] != before["wrapped_key"]
    status, reply = _decrypt(client, kid, body["envelope"], aad=b64(b"c"))
    assert status == 200
    assert base64.b64decode(reply["plaintext"]) == b"native payload"
    events = _rewrap_events(native_stack)
    assert len(events) == 1 and events[0].outcome == "success"


def test_endpoint_native_cross_algorithm(native_stack):
    client = native_stack.client
    kid = _make_key(client, algorithm="AES256")
    token = _encrypt(client, kid, b"cross", version=1)
    _rotate(client, kid, "RSA2048", "rot-native-rsa")
    native_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token)
    assert status == 200, body
    assert native_stack.fake_kms.call_count("rewrap_key") == 1
    assert native_stack.fake_kms.call_count("export_material") == 0
    out = _inner(body["envelope"])
    assert out["version"] == 2 and out["algorithm"] == "RSA2048"
    assert out["wrap"] == env_mod.WRAP_RSA_OAEP_SHA256
    assert "wrap_nonce" not in out
    assert len(base64.b64decode(out["wrapped_key"])) == 256
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"cross"


def test_endpoint_native_provider_fault_is_503_not_audited(native_stack):
    client = native_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-native-503")
    _set_faults(
        native_stack,
        {"declare_rewrap_key": True, "rewrap_fail": True},
    )
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(native_stack) == []


def test_endpoint_native_malformed_result_is_503_not_audited(native_stack):
    client = native_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-native-short")
    _set_faults(
        native_stack,
        {"declare_rewrap_key": True, "rewrap_short": True},
    )
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(native_stack) == []


def test_endpoint_native_not_callable_breaks_contract(broken_native_stack):
    # Declaring "rewrap_key" in capabilities without a callable method is a
    # provider-contract failure: every provider call is the fixed 503.
    status, body = broken_native_stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}


def test_endpoint_native_authentication_failure_is_400(native_stack):
    client = native_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"auth", version=1)
    _rotate(client, kid, "AES256", "rot-native-auth")
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    native_stack.fake_kms.reset()
    status, err = _rewrap(client, kid, tampered)
    assert status == 400, err
    assert "field envelope" in err["error"]
    # The provider was asked natively and its authentication failure surfaced
    # as the 400; nothing was audited.
    assert native_stack.fake_kms.call_count("rewrap_key") == 1
    assert native_stack.fake_kms.call_count("export_material") == 0
    assert _rewrap_events(native_stack) == []


def test_endpoint_falls_back_when_not_declared(plain_stack):
    client = plain_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"legacy", version=1)
    _rotate(client, kid, "AES256", "rot-legacy-1")
    plain_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token)
    assert status == 200, body
    # Undeclared: the export-based path runs, rewrap_key is never called.
    assert plain_stack.fake_kms.call_count("rewrap_key") == 0
    assert plain_stack.fake_kms.call_count("export_material") == 2
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"legacy"
