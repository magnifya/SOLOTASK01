"""Ad-hoc verification of cross-key rewrap (not part of the suite)."""

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
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"X-Operator-Id": operator, "Content-Type": "application/json"}
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
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
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
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield types.SimpleNamespace(
        client=Client("http://127.0.0.1:%d" % httpd.server_address[1]),
        store=store, policies=policies, audit=audit_log, data_dir=data_dir,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


_counter = itertools.count(1)


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _encrypt(client, key_id, plaintext, tenant="t", **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    status, reply = client.call(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        headers={"Idempotency-Key": "enc-%d" % next(_counter)},
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
    return [e for e in st.audit.query("t", limit=1000).events
            if e.action == "rewrap"]


def test_cross_key_happy(stack):
    client = stack.client
    src = _make_key(client, "AES256")
    dst = _make_key(client, "RSA2048")
    token = _encrypt(client, src, b"cross-key", aad=b64(b"ctx"))
    status, body = _rewrap(client, src, token, target_key_id=dst,
                           aad=b64(b"ctx"))
    assert status == 200, body
    assert list(body.keys()) == ["format", "envelope"]
    assert body["format"] == env_mod.FORMAT
    before, after = _inner(token), _inner(body["envelope"])
    assert after["key_id"] == dst and after["version"] == 1
    assert after["algorithm"] == "RSA2048"
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field
    # decrypts under the target key; original still decrypts under source
    status, reply = _decrypt(client, dst, body["envelope"], aad=b64(b"ctx"))
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"cross-key"
    status, reply = _decrypt(client, src, token, aad=b64(b"ctx"))
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"cross-key"
    events = _rewrap_events(stack)
    assert len(events) == 1 and events[0].outcome == "success"
    assert events[0].key_id == src


def test_cross_key_explicit_version_and_same_numbers(stack):
    client = stack.client
    src = _make_key(client, "AES256")
    dst = _make_key(client, "AES256")
    token = _encrypt(client, src, b"v", version=1)
    # same version number 1 on both keys: not a conflict
    status, body = _rewrap(client, src, token, target_key_id=dst,
                           target_version=1)
    assert status == 200, body
    assert _inner(body["envelope"])["key_id"] == dst


def test_target_key_id_validation(stack):
    client = stack.client
    src = _make_key(client)
    token = _encrypt(client, src, b"x")
    for bad in (None, "", 123, "not-a-uuid",
                "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", True):
        status, err = _rewrap(client, src, token, target_key_id=bad)
        assert status == 400, (bad, err)
        assert "target_key_id" in err["error"], (bad, err)
    assert _rewrap_events(stack) == []
    # equal to path key: same-key behavior (same version -> 409)
    status, err = _rewrap(client, src, token, target_key_id=src)
    assert status == 409, err


def test_cross_key_policy(stack):
    client = stack.client
    src = _make_key(client)
    dst = _make_key(client)
    token = _encrypt(client, src, b"x")
    # deny scoped to the TARGET key only
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["rewrap"], effect="deny",
                   key_ids=frozenset({dst}))]
    )
    status, _ = _rewrap(client, src, token, target_key_id=dst)
    assert status == 403
    events = _rewrap_events(stack)
    assert len(events) == 1 and events[0].outcome == "rejected"
    assert events[0].key_id == src
    # deny scoped to the SOURCE key only
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["rewrap"], effect="deny",
                   key_ids=frozenset({src}))]
    )
    status, _ = _rewrap(client, src, token, target_key_id=dst)
    assert status == 403
    assert len(_rewrap_events(stack)) == 2


def test_cross_key_404_409(stack):
    client = stack.client
    src = _make_key(client)
    dst = _make_key(client)
    token = _encrypt(client, src, b"x")
    unknown = "00000000-0000-4000-8000-000000000000"
    assert _rewrap(client, src, token, target_key_id=unknown)[0] == 404
    # cross-tenant target
    foreign = _make_key(client, tenant="other")
    assert _rewrap(client, src, token, target_key_id=foreign)[0] == 404
    # unknown target version
    assert _rewrap(client, src, token, target_key_id=dst,
                   target_version=9)[0] == 404
    # revoked target key
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % dst,
        {"tenant_id": "t", "reason": "done", "operator": "alice"},
    )
    assert status == 200
    assert _rewrap(client, src, token, target_key_id=dst)[0] == 409
    events = _rewrap_events(stack)
    assert len(events) == 4
    assert all(e.outcome == "rejected" and e.key_id == src for e in events)


def test_cross_key_algorithm_mismatch_not_audited(stack):
    client = stack.client
    src = _make_key(client, "AES256")
    dst = _make_key(client, "AES256")
    token = _encrypt(client, src, b"x", version=1)
    # rotate source to RSA, forge envelope claiming version 2
    status, _ = client.call(
        "POST", "/v1/keys/%s/rotate" % src,
        {"tenant_id": "t", "algorithm": "RSA2048"},
        headers={"Idempotency-Key": "rot-x1"},
    )
    assert status == 201
    obj = _inner(token)
    obj["version"] = 2
    forged = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, src, forged, target_key_id=dst)
    assert status == 400 and "algorithm" in err["error"]
    assert _rewrap_events(stack) == []


def test_cross_key_404_precedes_409(stack):
    client = stack.client
    src = _make_key(client)
    token = _encrypt(client, src, b"x")
    unknown = "00000000-0000-4000-8000-000000000000"
    # Revoke the SOURCE key: an unknown target is still a uniform 404
    # (existence on both sides is settled before any revocation answer).
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % src,
        {"tenant_id": "t", "reason": "done", "operator": "alice"},
    )
    assert status == 200
    assert _rewrap(client, src, token, target_key_id=unknown)[0] == 404
    # Both existing and revoked: 409.
    dst = _make_key(client)
    assert _rewrap(client, src, token, target_key_id=dst)[0] == 409


def test_cross_key_revoked_version_409(stack):
    client = stack.client
    src = _make_key(client)
    dst = _make_key(client)
    # Rotate the target and revoke its old version 1.
    status, _ = client.call(
        "POST", "/v1/keys/%s/rotate" % dst,
        {"tenant_id": "t", "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-cross-v"},
    )
    assert status == 201
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % dst,
        {"tenant_id": "t", "reason": "old", "operator": "alice"},
    )
    assert status == 200
    token = _encrypt(client, src, b"x")
    # Explicit target_version=1 (revoked) -> 409; default (current v2) -> 200.
    assert _rewrap(client, src, token, target_key_id=dst,
                   target_version=1)[0] == 409
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 200, body
    assert _inner(body["envelope"])["version"] == 2


def test_cross_key_auth_failure_not_audited(stack):
    client = stack.client
    src = _make_key(client)
    dst = _make_key(client)
    token = _encrypt(client, src, b"x")
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, src, tampered, target_key_id=dst)
    assert status == 400 and "field envelope" in err["error"]
    assert _rewrap_events(stack) == []


# -- external provider -------------------------------------------------------
@pytest.fixture()
def ext_stack(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
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
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield types.SimpleNamespace(
        client=Client("http://127.0.0.1:%d" % httpd.server_address[1]),
        store=store, policies=policies, audit=audit_log, data_dir=data_dir,
        faults_path=faults_path,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _set_faults(st, faults):
    with open(st.faults_path, "w") as fh:
        json.dump(faults, fh)


def test_cross_key_native_rewrap_key(ext_stack):
    import fake_kms

    _set_faults(ext_stack, {"declare_rewrap_key": True})
    client = ext_stack.client
    src = _make_key(client, "AES256")
    dst = _make_key(client, "RSA2048")
    token = _encrypt(client, src, b"native-cross")
    before = fake_kms.call_count("export_material")
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 200, body
    assert fake_kms.call_count("rewrap_key") == 1
    assert fake_kms.call_count("export_material") == before
    assert _inner(body["envelope"])["key_id"] == dst
    status, reply = _decrypt(client, dst, body["envelope"])
    assert status == 200
    assert base64.b64decode(reply["plaintext"]) == b"native-cross"


def test_cross_key_native_split(ext_stack):
    import fake_kms

    _set_faults(ext_stack, {"declare_wrap_key": True})
    client = ext_stack.client
    src = _make_key(client)
    dst = _make_key(client)
    token = _encrypt(client, src, b"split-cross")
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 200, body
    # target side native (wrap_key), source side exported its KEK once
    assert fake_kms.call_count("wrap_key") >= 1
    status, reply = _decrypt(client, dst, body["envelope"])
    assert status == 200
    assert base64.b64decode(reply["plaintext"]) == b"split-cross"


def test_cross_key_provider_failure_503(ext_stack):
    client = ext_stack.client
    src = _make_key(client)
    dst = _make_key(client)
    token = _encrypt(client, src, b"x")
    _set_faults(ext_stack, {"fail": {"export_material": True}})
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(ext_stack) == []


def test_cross_key_different_providers_503(tmp_path, monkeypatch):
    # Key A owned by the local provider, key B by fakekms: 503, not audited.
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
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
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    try:
        src = _make_key(client)
        token = _encrypt(client, src, b"x")
        # Switch the active provider to fakekms and create the target there.
        faults_path = str(tmp_path / "kms-faults.json")
        sys.path.insert(0, os.path.dirname(__file__))
        monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
        monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
        monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
        provider_mod.reset_for_tests()
        dst = _make_key(client)
        status, body = _rewrap(client, src, token, target_key_id=dst)
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
        events = [e for e in audit_log.query("t", limit=1000).events
                  if e.action == "rewrap"]
        assert events == []
    finally:
        httpd.shutdown()
        provider_mod.reset_for_tests()


# -- cross-provider rewrap over a provider chain -----------------------------
CHAIN = "local,fake_kms:make_provider"


@pytest.fixture()
def chain_stack(tmp_path, monkeypatch):
    """A local/fakekms provider chain; local activates first (healthy)."""
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    state_path = str(tmp_path / "kms-state.json")
    sys.path.insert(0, os.path.dirname(__file__))
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    monkeypatch.setenv("FAKE_KMS_STATE", state_path)
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
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    # Touch the chain so local is the committed active (first healthy) entry.
    status, reply = client.call("GET", "/v1/provider/status")
    assert status == 200 and reply["provider_id"] == "local", reply
    yield types.SimpleNamespace(
        client=client, store=store, policies=policies, audit=audit_log,
        data_dir=data_dir, faults_path=faults_path,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _switchover(client, provider_id):
    return client.call(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id},
    )


def _provider_status(client):
    status, body = client.call("GET", "/v1/provider/status")
    assert status == 200, body
    return body["provider_id"]


def _key_on(client, provider_id, algorithm):
    """Make ``provider_id`` active, create one key, return its id."""
    assert _switchover(client, provider_id)[0] == 200
    return _make_key(client, algorithm=algorithm)


def _assert_key_provider(st, key_id, provider_id):
    path = os.path.join(st.data_dir, key_id + ".json")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert {v["provider_id"] for v in data["versions"]} == {provider_id}


@pytest.mark.parametrize(
    "src_algorithm,dst_algorithm",
    [
        ("AES256", "AES256"),
        ("AES256", "RSA2048"),
        ("RSA2048", "AES256"),
        ("RSA2048", "RSA2048"),
    ],
)
def test_cross_provider_four_algorithm_combinations(
    chain_stack, src_algorithm, dst_algorithm
):
    # Source key on the (then active) fakekms entry, target key on local:
    # at rewrap time local is active and fakekms is a healthy STANDBY that
    # participates without being activated. fakekms declares neither native
    # op here, so its source KEK is exported once; local stays fully native.
    import fake_kms

    client = chain_stack.client
    message = ("combo-%s-%s" % (src_algorithm, dst_algorithm)).encode()
    src = _key_on(client, "fakekms", src_algorithm)
    # The same-key encrypt endpoint needs the source provider active.
    token = _encrypt(client, src, message, aad=b64(b"z"))
    dst = _key_on(client, "local", dst_algorithm)  # local now active
    exports_before = fake_kms.call_count("export_material")
    status, body = _rewrap(client, src, token, target_key_id=dst,
                           aad=b64(b"z"))
    assert status == 200, body
    assert fake_kms.call_count("export_material") == exports_before + 1
    before, after = _inner(token), _inner(body["envelope"])
    assert after["key_id"] == dst and after["version"] == 1
    assert after["algorithm"] == dst_algorithm
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field
    # The new envelope decrypts under the target (active) key ...
    status, reply = _decrypt(client, dst, body["envelope"], aad=b64(b"z"))
    assert status == 200, reply
    assert base64.b64decode(reply["plaintext"]) == message
    # ... and the original envelope still decrypts under the source key once
    # its provider is active again.
    assert _switchover(client, "fakekms")[0] == 200
    status, reply = _decrypt(client, src, token, aad=b64(b"z"))
    assert status == 200, reply
    assert base64.b64decode(reply["plaintext"]) == message
    # Exactly one source-key success event; the rewrap neither activated the
    # standby nor migrated either key.
    assert _switchover(client, "local")[0] == 200
    events = _rewrap_events(chain_stack)
    assert len(events) == 1 and events[0].outcome == "success"
    assert events[0].key_id == src
    assert _provider_status(client) == "local"
    _assert_key_provider(chain_stack, src, "fakekms")
    _assert_key_provider(chain_stack, dst, "local")


def test_cross_provider_inactive_target_participates(chain_stack):
    # local active; the target lives on the fakekms standby, which is
    # resolved/probed for the rewrap but never activated.
    client = chain_stack.client
    src = _key_on(client, "local", "AES256")
    token = _encrypt(client, src, b"to-standby")
    dst = _key_on(client, "fakekms", "RSA2048")
    assert _switchover(client, "local")[0] == 200
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 200, body
    assert _inner(body["envelope"])["key_id"] == dst
    assert _provider_status(client) == "local"
    events = _rewrap_events(chain_stack)
    assert len(events) == 1 and events[0].key_id == src
    _assert_key_provider(chain_stack, src, "local")
    _assert_key_provider(chain_stack, dst, "fakekms")


def test_cross_provider_both_sides_native(chain_stack):
    # Source fakekms declares unwrap_key; target local always declares
    # wrap_key: neither KEK is exported.
    import fake_kms

    _set_faults(chain_stack, {"declare_unwrap_key": True})
    client = chain_stack.client
    src = _key_on(client, "fakekms", "AES256")
    token = _encrypt(client, src, b"both-native")
    dst = _key_on(client, "local", "AES256")
    exports_before = fake_kms.call_count("export_material")
    unwraps_before = fake_kms.call_count("unwrap_key")
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 200, body
    assert fake_kms.call_count("unwrap_key") == unwraps_before + 1
    assert fake_kms.call_count("export_material") == exports_before
    status, reply = _decrypt(client, dst, body["envelope"])
    assert status == 200
    assert base64.b64decode(reply["plaintext"]) == b"both-native"


def test_cross_provider_target_native_wrap(chain_stack):
    # local source (native unwrap) -> fakekms standby target declaring
    # wrap_key: the target KEK is wrapped inside the standby, never exported.
    import fake_kms

    client = chain_stack.client
    src = _key_on(client, "local", "AES256")
    token = _encrypt(client, src, b"target-native")
    dst = _key_on(client, "fakekms", "RSA2048")
    assert _switchover(client, "local")[0] == 200
    _set_faults(chain_stack, {"declare_wrap_key": True})
    exports_before = fake_kms.call_count("export_material")
    wraps_before = fake_kms.call_count("wrap_key")
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 200, body
    assert fake_kms.call_count("wrap_key") == wraps_before + 1
    assert fake_kms.call_count("export_material") == exports_before
    assert _switchover(client, "fakekms")[0] == 200
    status, reply = _decrypt(client, dst, body["envelope"])
    assert status == 200
    assert base64.b64decode(reply["plaintext"]) == b"target-native"


def test_cross_provider_target_wrap_failure_503_no_fallback(chain_stack):
    # A declared wrap_key faulting on the standby target is the fixed 503;
    # it never falls back to exporting the target KEK.
    import fake_kms

    client = chain_stack.client
    src = _key_on(client, "local", "AES256")
    token = _encrypt(client, src, b"x")
    dst = _key_on(client, "fakekms", "AES256")
    assert _switchover(client, "local")[0] == 200
    _set_faults(chain_stack, {"declare_wrap_key": True, "wrap_fail": True})
    exports_before = fake_kms.call_count("export_material")
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 503, body
    assert body == {"error": "key management provider is unavailable"}
    assert fake_kms.call_count("export_material") == exports_before
    assert _rewrap_events(chain_stack) == []
    assert _provider_status(client) == "local"


def test_cross_provider_source_unwrap_failure_503_no_fallback(chain_stack):
    # A declared unwrap_key faulting on the standby source is the fixed 503;
    # it never falls back to exporting the source KEK.
    import fake_kms

    client = chain_stack.client
    src = _key_on(client, "fakekms", "AES256")
    token = _encrypt(client, src, b"x")
    dst = _key_on(client, "local", "AES256")
    _set_faults(chain_stack, {"declare_unwrap_key": True,
                              "unwrap_fail": True})
    exports_before = fake_kms.call_count("export_material")
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 503, body
    assert body == {"error": "key management provider is unavailable"}
    assert fake_kms.call_count("export_material") == exports_before
    assert _rewrap_events(chain_stack) == []


def test_cross_provider_standby_unhealthy_503(chain_stack):
    # The standby owning the target fails its (one-second, shared-budget)
    # health probe: fixed 503, not audited, no failover, no activation.
    client = chain_stack.client
    src = _key_on(client, "local", "AES256")
    token = _encrypt(client, src, b"x")
    dst = _key_on(client, "fakekms", "AES256")
    assert _switchover(client, "local")[0] == 200
    _set_faults(chain_stack, {"health": False})
    status, body = _rewrap(client, src, token, target_key_id=dst)
    assert status == 503, body
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(chain_stack) == []
    assert _provider_status(client) == "local"


def test_cross_provider_auth_failure_400_not_audited(chain_stack):
    client = chain_stack.client
    src = _key_on(client, "fakekms", "AES256")
    token = _encrypt(client, src, b"x")
    dst = _key_on(client, "local", "AES256")
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, src, tampered, target_key_id=dst)
    assert status == 400 and "field envelope" in err["error"], err
    assert _rewrap_events(chain_stack) == []


def test_cross_provider_same_version_number_ok(chain_stack):
    # Equal version NUMBERS on two keys on two providers are not a conflict.
    client = chain_stack.client
    src = _key_on(client, "fakekms", "AES256")
    token = _encrypt(client, src, b"v", version=1)
    dst = _key_on(client, "local", "AES256")
    status, body = _rewrap(client, src, token, target_key_id=dst,
                           target_version=1)
    assert status == 200, body
    after = _inner(body["envelope"])
    assert after["key_id"] == dst and after["version"] == 1


def test_cross_provider_authorization_403(chain_stack):
    client = chain_stack.client
    src = _key_on(client, "fakekms", "AES256")
    token = _encrypt(client, src, b"x")
    dst = _key_on(client, "local", "AES256")
    chain_stack.policies.put(
        "t", [Rule(subject="alice", actions=["rewrap"], effect="deny",
                   key_ids=frozenset({dst}))]
    )
    status, _ = _rewrap(client, src, token, target_key_id=dst)
    assert status == 403
    events = _rewrap_events(chain_stack)
    assert len(events) == 1 and events[0].outcome == "rejected"
    assert events[0].key_id == src


def test_cross_provider_revoked_target_409(chain_stack):
    client = chain_stack.client
    src = _key_on(client, "fakekms", "AES256")
    token = _encrypt(client, src, b"x")
    dst = _key_on(client, "local", "AES256")
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % dst,
        {"tenant_id": "t", "reason": "done", "operator": "alice"},
    )
    assert status == 200
    status, _ = _rewrap(client, src, token, target_key_id=dst)
    assert status == 409
    events = _rewrap_events(chain_stack)
    assert len(events) == 1 and events[0].outcome == "rejected"
    assert events[0].key_id == src
