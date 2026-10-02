"""Split-native envelope rewrap: per-side ``unwrap_key``/``wrap_key``.

When both versions of a ``POST /v1/keys/{key_id}/rewrap`` are owned by the
same provider_id that does NOT declare ``rewrap_key``, each side
independently keeps its DEK native when it declares the matching operation:
a source ``unwrap_key`` declaration means no source KEK export, a target
``wrap_key`` declaration means no target KEK export; only the undeclared
side falls back to ``export_material``. Both declared means neither KEK is
exported and the rewrap still succeeds. A native failure (backend fault,
malformed result, non-callable method) is the fixed-text, non-audited 503
and never falls back to export; an authentication failure of the source
wrapping key or content tag is a 400 naming the envelope (not audited).
All AES256/RSA2048 source/target combinations stay keymgr-envelope-v1 and
the result opens with the ordinary decrypt path.
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
from keymgr.server import make_handler
from keymgr.store import KeyStore, NativeRewrapSplit


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


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
def both_stack(tmp_path, monkeypatch):
    yield from _build_server(
        tmp_path, monkeypatch,
        {"declare_unwrap_key": True, "declare_wrap_key": True},
    )


@pytest.fixture()
def unwrap_only_stack(tmp_path, monkeypatch):
    yield from _build_server(
        tmp_path, monkeypatch, {"declare_unwrap_key": True}
    )


@pytest.fixture()
def wrap_only_stack(tmp_path, monkeypatch):
    yield from _build_server(
        tmp_path, monkeypatch, {"declare_wrap_key": True}
    )


@pytest.fixture()
def chain_stack(tmp_path, monkeypatch):
    # The single-entry chain makes every ordinary provider call probe the
    # active instance, so a slow health probe can exhaust the five-second
    # gate budget.
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", "fake_kms:make_provider")
    yield from _build_server(
        tmp_path, monkeypatch,
        {"declare_unwrap_key": True, "declare_wrap_key": True},
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


def _rewrap_events(st, tenant="t"):
    return [
        e for e in st.audit.query(tenant, limit=1000).events
        if e.action == "rewrap"
    ]


def _set_faults(st, faults):
    with open(st.faults_path, "w") as fh:
        json.dump(faults, fh)


# -- all AES256/RSA2048 source/target combinations, both sides native ------
@pytest.mark.parametrize(
    "src_algorithm,dst_algorithm",
    [("AES256", "AES256"), ("AES256", "RSA2048"),
     ("RSA2048", "AES256"), ("RSA2048", "RSA2048")],
)
def test_split_both_native_all_algorithm_pairs(
    both_stack, src_algorithm, dst_algorithm
):
    client = both_stack.client
    kid = _make_key(client, algorithm=src_algorithm)
    token = _encrypt(client, kid, b"split payload", version=1, aad=b64(b"a"))
    _rotate(client, kid, dst_algorithm, "rot-split-%s-%s" % (
        src_algorithm[0], dst_algorithm[0]))
    both_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token, aad=b64(b"a"))
    assert status == 200, body
    # Neither KEK is exported; one native unwrap and one native wrap run.
    counts = both_stack.fake_kms.call_count
    assert counts("unwrap_key") == 1
    assert counts("wrap_key") == 1
    assert counts("export_material") == 0
    assert counts("rewrap_key") == 0
    before, after = _inner(token), _inner(body["envelope"])
    assert after["version"] == 2 and after["algorithm"] == dst_algorithm
    for field in ("key_id", "nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field
    assert after["wrapped_key"] != before["wrapped_key"]
    if dst_algorithm == "AES256":
        assert after["wrap"] == env_mod.WRAP_AES_GCM
        assert len(base64.b64decode(after["wrapped_key"])) == 48
        assert len(base64.b64decode(after["wrap_nonce"])) == 12
    else:
        assert after["wrap"] == env_mod.WRAP_RSA_OAEP_SHA256
        assert "wrap_nonce" not in after
        assert len(base64.b64decode(after["wrapped_key"])) == 256
    status, reply = _decrypt(client, kid, body["envelope"], aad=b64(b"a"))
    assert status == 200
    assert base64.b64decode(reply["plaintext"]) == b"split payload"
    events = _rewrap_events(both_stack)
    assert len(events) == 1 and events[0].outcome == "success"
    assert events[0].key_id == kid


def test_split_target_version_defaults_to_current(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256", "rot-default")
    token = _encrypt(client, kid, b"v1", version=1)
    status, body = _rewrap(client, kid, token)
    assert status == 200, body
    assert _inner(body["envelope"])["version"] == 2


def test_split_explicit_target_version(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256", "rot-v2")
    _rotate(client, kid, "RSA2048", "rot-v3")
    token = _encrypt(client, kid, b"v1", version=1)
    status, body = _rewrap(client, kid, token, target_version=2)
    assert status == 200
    out = _inner(body["envelope"])
    assert out["version"] == 2 and out["algorithm"] == "AES256"
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"v1"


# -- one side native, the other export-based -------------------------------
def test_split_unwrap_native_wrap_exports_target(unwrap_only_stack):
    client = unwrap_only_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"half src", version=1)
    _rotate(client, kid, "AES256", "rot-half-src")
    unwrap_only_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token)
    assert status == 200, body
    counts = unwrap_only_stack.fake_kms.call_count
    assert counts("unwrap_key") == 1
    assert counts("wrap_key") == 0
    # Only the TARGET KEK is exported.
    assert counts("export_material") == 1
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"half src"
    events = _rewrap_events(unwrap_only_stack)
    assert len(events) == 1 and events[0].outcome == "success"


def test_split_wrap_native_unwrap_exports_source(wrap_only_stack):
    client = wrap_only_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"half dst", version=1)
    _rotate(client, kid, "AES256", "rot-half-dst")
    wrap_only_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token)
    assert status == 200, body
    counts = wrap_only_stack.fake_kms.call_count
    assert counts("wrap_key") == 1
    assert counts("unwrap_key") == 0
    # Only the SOURCE KEK is exported.
    assert counts("export_material") == 1
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"half dst"
    events = _rewrap_events(wrap_only_stack)
    assert len(events) == 1 and events[0].outcome == "success"


# -- store binding resolution ----------------------------------------------
def test_native_rewrap_binding_split_shapes(both_stack, unwrap_only_stack):
    import fake_kms

    client = both_stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256", "rot-bind")
    _set_faults(both_stack, {"declare_unwrap_key": True,
                             "declare_wrap_key": True})
    provider_mod.reconnect()
    try:
        status, binding = both_stack.store.native_rewrap_binding(
            kid, "t", 1, 2
        )
        assert status == KeyStore.REWRAP_OK
        assert isinstance(binding, NativeRewrapSplit)
        assert binding.native_unwrap and binding.native_wrap
    finally:
        provider_mod.reconnect()

    # A provider declaring neither returns None (fully export-based).
    _set_faults(unwrap_only_stack, {})
    provider_mod.reconnect()
    try:
        kid2 = _make_key(unwrap_only_stack.client)
        _rotate(unwrap_only_stack.client, kid2, "AES256", "rot-none")
        status, binding = unwrap_only_stack.store.native_rewrap_binding(
            kid2, "t", 1, 2
        )
        assert status == KeyStore.REWRAP_OK and binding is None
    finally:
        provider_mod.reconnect()


# -- authentication failures: 400 naming envelope, not audited -------------
def test_split_unwrap_authentication_failure_is_400(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"auth", version=1)
    _rotate(client, kid, "AES256", "rot-split-auth")
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    both_stack.fake_kms.reset()
    status, err = _rewrap(client, kid, tampered)
    assert status == 400, err
    assert "field envelope" in err["error"]
    assert both_stack.fake_kms.call_count("unwrap_key") == 1
    # Authentication fails before the target side wraps.
    assert both_stack.fake_kms.call_count("wrap_key") == 0
    assert both_stack.fake_kms.call_count("export_material") == 0
    assert _rewrap_events(both_stack) == []


def test_split_content_tag_failure_is_400(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"auth2", version=1)
    _rotate(client, kid, "AES256", "rot-split-tag")
    obj = _inner(token)
    ct = bytearray(base64.b64decode(obj["ciphertext"]))
    ct[0] ^= 0x01
    obj["ciphertext"] = b64(bytes(ct))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, kid, tampered)
    assert status == 400, err
    assert "field envelope" in err["error"]
    assert _rewrap_events(both_stack) == []


def test_split_exported_source_auth_failure_is_400(wrap_only_stack):
    # The source side exports (no unwrap_key declaration): a tampered wrapped
    # DEK is authenticated in memory and is the same 400, never audited.
    client = wrap_only_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"auth3", version=1)
    _rotate(client, kid, "AES256", "rot-export-auth")
    wrap_only_stack.fake_kms.reset()
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, kid, tampered)
    assert status == 400, err
    assert "field envelope" in err["error"]
    # Authentication fails before the native target wrap runs.
    assert wrap_only_stack.fake_kms.call_count("wrap_key") == 0
    # The source side exported, but only the source KEK.
    assert wrap_only_stack.fake_kms.call_count("export_material") == 1
    assert _rewrap_events(wrap_only_stack) == []


# -- native failures: fixed 503, not audited, NO export fallback -----------
def test_split_unwrap_backend_fault_is_503_no_fallback(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-unwrap-503")
    _set_faults(both_stack, {
        "declare_unwrap_key": True,
        "declare_wrap_key": True,
        "fail": {"unwrap_key": True},
    })
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert both_stack.fake_kms.call_count("export_material") == 0
    assert _rewrap_events(both_stack) == []


def test_split_wrap_backend_fault_is_503_no_fallback(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-wrap-503")
    _set_faults(both_stack, {
        "declare_unwrap_key": True,
        "declare_wrap_key": True,
        "fail": {"wrap_key": True},
    })
    both_stack.fake_kms.reset()
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    # The source side authenticated natively; the target fault does not
    # downgrade into a target KEK export.
    assert both_stack.fake_kms.call_count("unwrap_key") == 1
    assert both_stack.fake_kms.call_count("export_material") == 0
    assert _rewrap_events(both_stack) == []


def test_split_unwrap_short_result_is_503(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-unwrap-short")
    _set_faults(both_stack, {
        "declare_unwrap_key": True,
        "declare_wrap_key": True,
        "unwrap_short": True,
    })
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(both_stack) == []


def test_split_wrap_short_result_is_503(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-wrap-short")
    _set_faults(both_stack, {
        "declare_unwrap_key": True,
        "declare_wrap_key": True,
        "wrap_short": True,
    })
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(both_stack) == []


def test_split_gate_timeout_is_503_not_audited(chain_stack):
    # A provider whose admission health probe runs past the one-second probe
    # cap fails the rewrap with the fixed 503 (the late healthy result is
    # void), with no audit event and no material exposure.
    client = chain_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-split-gate")
    _set_faults(chain_stack, {
        "declare_unwrap_key": True,
        "declare_wrap_key": True,
        "health_sleep": 6.0,
    })
    import time

    t0 = time.monotonic()
    status, body = _rewrap(client, kid, token)
    assert time.monotonic() - t0 < 5
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert chain_stack.fake_kms.call_count("unwrap_key") == 0
    assert chain_stack.fake_kms.call_count("export_material") == 0
    assert _rewrap_events(chain_stack) == []


def test_split_exported_target_fault_is_503_not_audited(unwrap_only_stack):
    # Source native, target exported: an export fault is the same fixed 503.
    client = unwrap_only_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-tgt-fault")
    _set_faults(unwrap_only_stack, {
        "declare_unwrap_key": True,
        "fail": {"export_material": True},
    })
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(unwrap_only_stack) == []


# -- same-version / revoked stay business rejections before native calls ---
def test_split_same_version_is_409_rejected(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256", "rot-same")
    current = _encrypt(client, kid, b"cur")
    both_stack.fake_kms.reset()
    status, err = _rewrap(client, kid, current)
    assert status == 409, err
    counts = both_stack.fake_kms.call_count
    assert counts("unwrap_key") == counts("wrap_key") == 0
    assert counts("export_material") == 0
    events = _rewrap_events(both_stack)
    assert len(events) == 1
    assert events[0].outcome == "rejected" and events[0].key_id == kid


def test_split_algorithm_mismatch_is_400_not_audited(both_stack):
    client = both_stack.client
    kid = _make_key(client, algorithm="AES256")
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "RSA2048", "rot-split-mismatch")
    obj = _inner(token)
    obj["version"] = 2
    forged = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, kid, forged, target_version=1)
    assert status == 400 and "algorithm" in err["error"]
    assert _rewrap_events(both_stack) == []


def test_split_success_audited_once_without_material(both_stack):
    client = both_stack.client
    kid = _make_key(client)
    secret = b"split-secret-payload"
    token = _encrypt(client, kid, secret, version=1, aad=b64(b"split-aad"))
    _rotate(client, kid, "AES256", "rot-audit")
    status, body = _rewrap(client, kid, token, aad=b64(b"split-aad"))
    assert status == 200
    events = _rewrap_events(both_stack)
    assert len(events) == 1
    assert events[0].outcome == "success" and events[0].key_id == kid
    raw = open(os.path.join(both_stack.data_dir, "audit.log"), "rb").read()
    assert b"split-secret-payload" not in raw
    assert b"split-aad" not in raw
    assert body["envelope"].encode() not in raw
    # No new wrap/unwrap audit event kinds.
    assert not any(
        e.action in ("wrap_key", "unwrap_key")
        for e in both_stack.audit.query("t", limit=1000).events
    )


# -- envelope.rewrap_envelope_split primitive ------------------------------
def test_primitive_split_all_native_local_provider(tmp_path):
    from keymgr.provider import LocalProvider, ProviderInvalidMaterial

    provider = LocalProvider()
    provider.configure(str(tmp_path / "pdata"))
    src = provider.generate("AES256")
    dst = provider.generate("RSA2048")
    token = env_mod.seal_envelope_native(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", provider=provider,
        handle=src.handle, plaintext=b"primitive split", aad=b"z",
    )
    opened = env_mod.decode_envelope(token)
    out_token = env_mod.rewrap_envelope_split(
        opened,
        (provider, src.handle),
        (provider, dst.handle),
        target_version=2, target_algorithm="RSA2048",
    )
    out = env_mod.decode_envelope(out_token)
    assert out.version == 2 and out.algorithm == "RSA2048"
    assert (out.nonce, out.tag, out.ciphertext, out.aad) == (
        opened.nonce, opened.tag, opened.ciphertext, opened.aad,
    )
    assert len(out.wrapped_key) == 256 and out.wrap_nonce is None

    # A native source authentication failure is the envelope-naming 400.
    bad = dict(_inner(token))
    wk = bytearray(base64.b64decode(bad["wrapped_key"]))
    wk[0] ^= 0x01
    bad["wrapped_key"] = b64(bytes(wk))
    bad_token = b64(json.dumps(bad, sort_keys=True).encode())
    with pytest.raises(env_mod.EnvelopeError) as excinfo:
        env_mod.rewrap_envelope_split(
            env_mod.decode_envelope(bad_token),
            (provider, src.handle),
            (provider, dst.handle),
            target_version=2, target_algorithm="RSA2048",
        )
    assert "field envelope" in str(excinfo.value)


def test_primitive_split_mixed_export_and_native(tmp_path):
    import base64 as _b64

    from keymgr.provider import LocalProvider

    provider = LocalProvider()
    provider.configure(str(tmp_path / "pdata2"))
    src = provider.generate("AES256")
    dst = provider.generate("AES256")
    src_kek = _b64.b64decode(
        provider.export_material(src.handle).encrypted_material,
        validate=True,
    )
    token = env_mod.encode_envelope(
        key_id="22222222-2222-4222-8222-222222222222",
        version=1, algorithm="AES256", kek=src_kek,
        plaintext=b"mixed", aad=b"",
    )
    opened = env_mod.decode_envelope(token)
    # Source exported in memory, target wrapped natively.
    out_token = env_mod.rewrap_envelope_split(
        opened, src_kek, (provider, dst.handle),
        target_version=3, target_algorithm="AES256",
    )
    out = env_mod.decode_envelope(out_token)
    assert out.version == 3
    dst_kek = _b64.b64decode(
        provider.export_material(dst.handle).encrypted_material,
        validate=True,
    )
    assert env_mod.open_envelope(out, dst_kek) == b"mixed"
