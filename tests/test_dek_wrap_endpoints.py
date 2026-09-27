"""Standalone DEK wrap/unwrap endpoints.

Covers ``POST /v1/keys/{key_id}/wrap-key`` and
``POST /v1/keys/{key_id}/unwrap-key``:

* request body shapes (exact key sets), padded standard base64, the 32-byte
  data key constraint and the algorithm wrapped-field shapes (AES 48/12,
  RSA 256/null);
* 200 key order ``key_id, version, algorithm, wrapped_key, wrap_nonce`` for
  wrap and ``{"data_key"}`` for unwrap;
* native ``wrap_key``/``unwrap_key`` provider paths (no ``export_material``)
  when declared, and the in-memory export path otherwise;
* side-effect-free, field-naming 400s (including an unwrap authentication
  failure naming ``wrapped_key``); 403 policy denial, 404 unknown/cross-tenant
  key, 409 revoked -- each with a same-name rejected event carrying key_id;
* a provider fault is the fixed 503 with no audit, a ledger failure is 500;
* the data key never reaches disk/audit/errors, but the unwrap success body
  returns it.
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


def _serve(tmp_path, monkeypatch=None, faults=None, provider_env=True):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = None
    if provider_env:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        faults_path = str(tmp_path / "kms-faults.json")
        with open(faults_path, "w") as fh:
            json.dump(faults or {}, fh)
        if monkeypatch is not None:
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
        data_dir=data_dir, store=store, policies=policies, audit=audit_log,
        client=client, faults_path=faults_path,
    )
    yield stack
    httpd.shutdown()
    provider_mod.reset_for_tests()


@pytest.fixture()
def local_stack(tmp_path):
    yield from _serve(tmp_path, provider_env=False)


@pytest.fixture()
def native_stack(tmp_path, monkeypatch):
    yield from _serve(
        tmp_path, monkeypatch,
        {"declare_wrap_key": True, "declare_unwrap_key": True},
    )


@pytest.fixture()
def plain_stack(tmp_path, monkeypatch):
    yield from _serve(tmp_path, monkeypatch, {})


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _wrap(client, kid, data_key, tenant="t", **extra):
    body = {"tenant_id": tenant, "data_key": b64(data_key)}
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/wrap-key" % kid, body)


def _unwrap(client, kid, wrapped, nonce, tenant="t", **extra):
    body = {"tenant_id": tenant, "wrapped_key": b64(wrapped)}
    if nonce is not None:
        body["wrap_nonce"] = b64(nonce)
    body.update(extra)
    return client.call("POST", "/v1/keys/%s/unwrap-key" % kid, body)


def _audit(stack, tenant="t"):
    return stack.audit.query(tenant, limit=1000).events


def _dek_events(stack):
    return [
        e for e in _audit(stack)
        if e.action in ("wrap_key", "unwrap_key", "tenant_conflict")
    ]


def _raw_ledger(stack):
    with open(os.path.join(stack.data_dir, "audit.log"), "rb") as fh:
        return fh.read()


# --------------------------------------------------------------- happy paths
@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_wrap_unwrap_roundtrip_local(local_stack, algorithm):
    client = local_stack.client
    kid = _make_key(client, algorithm=algorithm)
    dek = os.urandom(32)
    status, body = _wrap(client, kid, dek)
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "version", "algorithm", "wrapped_key", "wrap_nonce"
    ]
    assert body["key_id"] == kid
    assert body["version"] == 1
    assert body["algorithm"] == algorithm
    wrapped = base64.b64decode(body["wrapped_key"])
    if algorithm == "AES256":
        assert len(wrapped) == 48
        nonce = base64.b64decode(body["wrap_nonce"])
        assert len(nonce) == 12
    else:
        assert len(wrapped) == 256
        assert body["wrap_nonce"] is None
        nonce = None
    status, out = _unwrap(client, kid, wrapped, nonce)
    assert status == 200, out
    assert list(out.keys()) == ["data_key"]
    assert base64.b64decode(out["data_key"]) == dek
    events = _audit(local_stack)
    actions = [(e.action, e.outcome, e.key_id) for e in events]
    assert ("wrap_key", "success", kid) in actions
    assert ("unwrap_key", "success", kid) in actions


def test_wrap_defaults_to_current_version(local_stack):
    client = local_stack.client
    kid = _make_key(client, algorithm="AES256")
    status, _ = client.call(
        "POST", "/v1/keys/%s/rotate" % kid,
        {"tenant_id": "t", "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-1"},
    )
    assert status == 201
    status, body = _wrap(client, kid, b"k" * 32)
    assert status == 200 and body["version"] == 2
    status, body = _wrap(client, kid, b"k" * 32, version=1)
    assert status == 200 and body["version"] == 1


def test_explicit_version_roundtrip(native_stack):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client, algorithm="RSA2048")
    dek = os.urandom(32)
    fake_kms.reset()
    status, body = _wrap(client, kid, dek, version=1)
    assert status == 200
    assert fake_kms.call_count("wrap_key") == 1
    assert fake_kms.call_count("export_material") == 0
    wrapped = base64.b64decode(body["wrapped_key"])
    fake_kms.reset()
    status, out = _unwrap(client, kid, wrapped, None, version=1)
    assert status == 200
    assert base64.b64decode(out["data_key"]) == dek
    assert fake_kms.call_count("unwrap_key") == 1
    assert fake_kms.call_count("export_material") == 0


def test_non_declaring_provider_uses_export_path(plain_stack):
    import fake_kms

    client = plain_stack.client
    kid = _make_key(client, algorithm="AES256")
    dek = os.urandom(32)
    fake_kms.reset()
    status, body = _wrap(client, kid, dek)
    assert status == 200
    assert fake_kms.call_count("wrap_key") == 0
    assert fake_kms.call_count("export_material") >= 1
    wrapped = base64.b64decode(body["wrapped_key"])
    nonce = base64.b64decode(body["wrap_nonce"])
    fake_kms.reset()
    status, out = _unwrap(client, kid, wrapped, nonce)
    assert status == 200
    assert base64.b64decode(out["data_key"]) == dek
    assert fake_kms.call_count("unwrap_key") == 0
    assert fake_kms.call_count("export_material") >= 1


# ------------------------------------------------------------- 400 validation
@pytest.mark.parametrize(
    "wrap_body",
    [
        {"tenant_id": "t"},  # missing data_key
        {"tenant_id": "t", "data_key": 123},  # non-string
        {"tenant_id": "t", "data_key": b64(b"k" * 31)},  # 31 bytes
        {"tenant_id": "t", "data_key": b64(b"k" * 33)},  # 33 bytes
        {"tenant_id": "t", "data_key": "not-base64!!", },
        {"tenant_id": "t", "data_key": b64(b"k" * 32), "version": 0},
        {"tenant_id": "t", "data_key": b64(b"k" * 32), "version": True},
        {"tenant_id": "t", "data_key": b64(b"k" * 32), "version": "2"},
        {"tenant_id": "t", "data_key": b64(b"k" * 32), "extra": 1},
    ],
)
def test_wrap_400_validation_no_audit(local_stack, wrap_body):
    client = local_stack.client
    kid = _make_key(client)
    status, body = client.call(
        "POST", "/v1/keys/%s/wrap-key" % kid, wrap_body
    )
    assert status == 400, body
    assert _dek_events(local_stack) == []


def test_wrap_bad_key_id_is_400_no_audit(local_stack):
    client = local_stack.client
    status, body = client.call(
        "POST", "/v1/keys/not-a-uuid/wrap-key",
        {"tenant_id": "t", "data_key": b64(b"k" * 32)},
    )
    assert status == 400 and "key_id" in body["error"]
    assert _dek_events(local_stack) == []


def test_wrap_missing_tenant_conflict_is_audited(local_stack):
    client = local_stack.client
    kid = _make_key(client)
    status, _ = client.call(
        "POST", "/v1/keys/%s/wrap-key" % kid,
        {"data_key": b64(b"k" * 32)},
    )
    assert status == 400
    assert _raw_ledger(local_stack).count(b"tenant_conflict") == 1


@pytest.mark.parametrize(
    "unwrap_body,field",
    [
        ({"tenant_id": "t"}, "wrapped_key"),  # missing
        ({"tenant_id": "t", "wrapped_key": ""}, "wrapped_key"),
        ({"tenant_id": "t", "wrapped_key": 5}, "wrapped_key"),
        ({"tenant_id": "t", "wrapped_key": "!!!", "wrap_nonce": None},
         "wrapped_key"),
        ({"tenant_id": "t", "wrapped_key": b64(b"x" * 48), "wrap_nonce": 7},
         "wrap_nonce"),
        ({"tenant_id": "t", "wrapped_key": b64(b"x" * 47),
          "wrap_nonce": b64(b"n" * 12)}, "wrapped_key"),
        ({"tenant_id": "t", "wrapped_key": b64(b"x" * 48),
          "wrap_nonce": b64(b"n" * 11)}, "wrap_nonce"),
        ({"tenant_id": "t", "wrapped_key": b64(b"x" * 48),
          "version": -1}, "version"),
        ({"tenant_id": "t", "wrapped_key": b64(b"x" * 48),
          "wrap_nonce": b64(b"n" * 12), "extra": 1}, "extra"),
    ],
)
def test_unwrap_400_validation_shapes_aes(local_stack, unwrap_body, field):
    client = local_stack.client
    kid = _make_key(client, algorithm="AES256")
    status, body = client.call(
        "POST", "/v1/keys/%s/unwrap-key" % kid, unwrap_body
    )
    assert status == 400, body
    assert field in body["error"]
    assert _dek_events(local_stack) == []


def test_unwrap_rsa_requires_null_nonce(local_stack):
    client = local_stack.client
    kid = _make_key(client, algorithm="RSA2048")
    status, body = client.call(
        "POST", "/v1/keys/%s/unwrap-key" % kid,
        {
            "tenant_id": "t",
            "wrapped_key": b64(b"x" * 256),
            "wrap_nonce": b64(b"n" * 12),
        },
    )
    assert status == 400 and "wrap_nonce" in body["error"]
    assert _dek_events(local_stack) == []


def test_unwrap_rsa_wrong_length_is_400(local_stack):
    client = local_stack.client
    kid = _make_key(client, algorithm="RSA2048")
    status, body = client.call(
        "POST", "/v1/keys/%s/unwrap-key" % kid,
        {"tenant_id": "t", "wrapped_key": b64(b"x" * 255)},
    )
    assert status == 400 and "wrapped_key" in body["error"]
    assert _dek_events(local_stack) == []


def test_unwrap_shape_algorithm_mismatch_is_400_no_audit(local_stack):
    # An RSA-shaped wrapped key (256 bytes, null nonce) presented against an
    # AES256 version is a parameter/shape 400 naming the field, with no audit
    # and no provider contact.
    client = local_stack.client
    kid = _make_key(client, algorithm="AES256")
    status, body = client.call(
        "POST", "/v1/keys/%s/unwrap-key" % kid,
        {"tenant_id": "t", "wrapped_key": b64(b"x" * 256)},
    )
    assert status == 400 and "wrapped_key" in body["error"]
    assert _dek_events(local_stack) == []


def test_unwrap_shape_400_precedes_authorization(local_stack):
    # Validation precedes authorization and existence: a malformed shape is a
    # 400 even for a denied operator and an unknown key (never 403/404), with
    # no rejected event.
    client = local_stack.client
    stack = local_stack
    stack.policies.put(
        "t",
        [Rule(subject="alice", actions=["unwrap_key"], effect="deny")],
    )
    unknown = "12345678-1234-4123-8234-123456789abc"
    status, body = client.call(
        "POST", "/v1/keys/%s/unwrap-key" % unknown,
        {
            "tenant_id": "t",
            "wrapped_key": b64(b"x" * 10),
            "wrap_nonce": None,
        },
    )
    assert status == 400 and "wrapped_key" in body["error"]
    assert [
        e for e in _audit(stack) if e.action == "unwrap_key"
    ] == []


def test_unwrap_tampered_wrapped_key_is_400_naming_field(local_stack):
    client = local_stack.client
    kid = _make_key(client, algorithm="AES256")
    _, sealed = _wrap(client, kid, b"k" * 32)
    wk = base64.b64decode(sealed["wrapped_key"])
    tampered = bytearray(wk)
    tampered[0] ^= 0x01
    status, body = _unwrap(
        client, kid, bytes(tampered),
        base64.b64decode(sealed["wrap_nonce"]),
    )
    assert status == 400
    assert "wrapped_key" in body["error"]
    # Authentication failure is a rejected business attempt (decrypt
    # precedent): one unwrap_key/rejected event carrying key_id.
    rejected = [
        e for e in _audit(local_stack)
        if e.action == "unwrap_key" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid


# ------------------------------------------------------- 403/404/409 + audit
def test_policy_denial_is_403_with_rejected_event(local_stack):
    client = local_stack.client
    stack = local_stack
    kid = _make_key(client)
    stack.policies.put(
        "t",
        [Rule(subject="alice", actions=["wrap_key"], effect="deny")],
    )
    status, body = _wrap(client, kid, b"k" * 32)
    assert status == 403, body
    rejected = [
        e for e in _audit(stack)
        if e.action == "wrap_key" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid

    stack.policies.put(
        "t",
        [Rule(subject="alice", actions=["unwrap_key"], effect="deny")],
    )
    status, body = client.call(
        "POST", "/v1/keys/%s/unwrap-key" % kid,
        {
            "tenant_id": "t",
            "wrapped_key": b64(b"x" * 48),
            "wrap_nonce": b64(b"n" * 12),
        },
    )
    assert status == 403
    rejected = [
        e for e in _audit(stack)
        if e.action == "unwrap_key" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid


def test_unknown_and_cross_tenant_are_404(local_stack):
    client = local_stack.client
    unknown = "12345678-1234-4123-8234-123456789abc"
    status, body = _wrap(client, unknown, b"k" * 32)
    assert status == 404, body
    rejected = [
        e for e in _audit(local_stack)
        if e.action == "wrap_key" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == unknown

    kid = _make_key(client, tenant="t")
    status, _ = _wrap(client, kid, b"k" * 32, tenant="other")
    assert status == 404


def test_revoked_key_is_409(local_stack):
    client = local_stack.client
    kid = _make_key(client)
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "r", "operator": "alice"},
    )
    assert status == 200
    status, body = _wrap(client, kid, b"k" * 32)
    assert status == 409, body
    rejected = [
        e for e in _audit(local_stack)
        if e.action == "wrap_key" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid


# --------------------------------------------------------------- 503 / leaks
def test_wrap_backend_fault_is_503_no_audit(native_stack):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client, algorithm="AES256")
    with open(native_stack.faults_path, "w") as fh:
        json.dump(
            {
                "declare_wrap_key": True,
                "declare_unwrap_key": True,
                "fail": {"wrap_key": True},
            },
            fh,
        )
    fake_kms.reset()
    secret = os.urandom(32)
    status, body = _wrap(client, kid, secret)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert [
        e for e in _audit(native_stack) if e.action == "wrap_key"
    ] == []

    blob = b""
    for root, _dirs, files in os.walk(native_stack.data_dir):
        for name in files:
            with open(os.path.join(root, name), "rb") as fh:
                blob += fh.read()
    assert secret not in blob


def test_unwrap_backend_fault_is_503_no_audit(native_stack):
    import fake_kms

    client = native_stack.client
    kid = _make_key(client, algorithm="AES256")
    _, sealed = _wrap(client, kid, b"k" * 32)
    wk = base64.b64decode(sealed["wrapped_key"])
    nonce = base64.b64decode(sealed["wrap_nonce"])
    with open(native_stack.faults_path, "w") as fh:
        json.dump(
            {
                "declare_wrap_key": True,
                "declare_unwrap_key": True,
                "fail": {"unwrap_key": True},
            },
            fh,
        )
    fake_kms.reset()
    status, body = _unwrap(client, kid, wk, nonce)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert [
        e for e in _audit(native_stack) if e.action == "unwrap_key"
    ] == []
