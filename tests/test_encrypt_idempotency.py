"""Optional idempotent recovery for envelope encryption.

Without an Idempotency-Key the historical behavior is unchanged (every call
mints a fresh envelope). With a single valid key, POST .../encrypt and the CLI
``encrypt`` bind the normalized request once: identical HTTP/CLI retries, a
restart and GET /v1/operations/{operation_id} replay the SAME envelope and the
single audit event; a same key with a different normalized request is 409
naming the original operation_id. Pre-bind parameter/header failures are
side-effect-free 400; post-bind failures are durable terminals (403/404/409/
sticky 503). Plaintext, AAD, handles and key material never reach the
operation record, the ledger or an audit projection.
"""

import base64
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import audit as audit_mod
from keymgr import envelope as env_mod
from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import (
    OperationStore,
    normalize_body,
    request_digest,
)
from keymgr.policy import PolicyStore, Rule
from keymgr.server import _resolve_committed_operation, make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


# ------------------------------------------------------------------ fixtures
class Server:
    def __init__(self, data_dir, store, policies, ops, httpd, base):
        self.data_dir = data_dir
        self.store = store
        self.policies = policies
        self.ops = ops
        self.httpd = httpd
        self.base = base

    def shutdown(self):
        self.httpd.shutdown()


def _build_server(tmp_path, monkeypatch, provider_env=None):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    monkeypatch.delenv("FAKE_KMS_STATE", raising=False)
    monkeypatch.delenv("FAKE_KMS_FAULTS", raising=False)
    provider_mod.reset_for_tests()
    data_dir = str(tmp_path / "data")
    if provider_env:
        for key, value in provider_env.items():
            monkeypatch.setenv(key, value)
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    ops = OperationStore(data_dir, audit_log)
    artifacts = ArtifactStore(data_dir, store, audit_log)
    artifacts.settle_pending(ops)
    ops.recover_pending(
        lambda record, event: _resolve_committed_operation(
            store, policies, record, event
        ),
        is_parked=artifacts.is_parked,
    )
    handler = make_handler(store, policies, coordinator, ops, artifacts)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    return Server(data_dir, store, policies, ops, httpd, base)


@pytest.fixture()
def server(tmp_path, monkeypatch):
    srv = _build_server(tmp_path, monkeypatch)
    yield srv
    srv.shutdown()
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
            with urllib.request.urlopen(req, timeout=15) as resp:
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


def _encrypt_body(plaintext, **extra):
    body = {"tenant_id": "t", "plaintext": b64(plaintext)}
    body.update(extra)
    return body


# --------------------------------------------------------- basic idempotency
def test_idempotent_encrypt_replays_same_envelope(server):
    client = Client(server.base)
    kid = _make_key(client)
    body = _encrypt_body(b"secret", aad=b64(b"ctx"))
    path = "/v1/keys/%s/encrypt" % kid

    s1, b1 = client.call("POST", path, body, headers={"Idempotency-Key": "e1"})
    assert s1 == 200
    assert set(b1) == {"format", "envelope", "operation_id"}
    assert b1["format"] == env_mod.FORMAT
    op_id = b1["operation_id"]

    s2, b2 = client.call("POST", path, body, headers={"Idempotency-Key": "e1"})
    assert s2 == 200
    assert b2["envelope"] == b1["envelope"]
    assert b2["operation_id"] == op_id

    # Exactly one encrypt success event, named after the operation.
    events = [
        e for e in server.store.audit._read_all()
        if e.event_id == op_id
    ]
    assert len(events) == 1
    assert events[0].action == "encrypt"
    assert events[0].outcome == "success"
    assert events[0].key_id == kid


def test_idempotent_encrypt_rsa(server):
    client = Client(server.base)
    kid = _make_key(client, algorithm="RSA2048")
    body = _encrypt_body(b"rsa")
    s1, b1 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": "rsa1"},
    )
    assert s1 == 200
    s2, b2 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": "rsa1"},
    )
    assert b2["envelope"] == b1["envelope"]
    obj = json.loads(base64.b64decode(b1["envelope"]))
    assert obj["wrap"] == env_mod.WRAP_RSA_OAEP_SHA256


def test_without_key_preserves_legacy_behavior(server):
    client = Client(server.base)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = _encrypt_body(b"x")
    s1, b1 = client.call("POST", path, body)
    s2, b2 = client.call("POST", path, body)
    assert s1 == 200 and s2 == 200
    assert b1["envelope"] != b2["envelope"]
    assert "operation_id" not in b1 and "operation_id" not in b2


def test_same_key_different_body_conflicts(server):
    client = Client(server.base)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    s1, b1 = client.call(
        "POST", path, _encrypt_body(b"first"),
        headers={"Idempotency-Key": "shared"},
    )
    assert s1 == 200
    s2, b2 = client.call(
        "POST", path, _encrypt_body(b"second"),
        headers={"Idempotency-Key": "shared"},
    )
    assert s2 == 409
    assert b2["operation_id"] == b1["operation_id"]
    # A differing aad / version also binds differently.
    s3, b3 = client.call(
        "POST", path, _encrypt_body(b"first", aad=b64(b"z")),
        headers={"Idempotency-Key": "shared"},
    )
    assert s3 == 409 and b3["operation_id"] == b1["operation_id"]


def test_get_operation_replays_record(server):
    client = Client(server.base)
    kid = _make_key(client)
    _, b1 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, _encrypt_body(b"x"),
        headers={"Idempotency-Key": "g1"},
    )
    op_id = b1["operation_id"]
    s, body = client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id
    )
    assert s == 200
    assert body["status"] == "succeeded"
    assert body["http_status"] == 200
    assert body["response"]["envelope"] == b1["envelope"]
    # Another operator/tenant cannot see it (existence never leaks).
    s404, _ = client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id, operator="bob"
    )
    assert s404 == 404


# ------------------------------------------------- pre-bind 400 / zero side
def test_pre_bind_failures_are_400_with_zero_side_effects(server):
    client = Client(server.base)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid

    def op_names():
        return set(os.listdir(os.path.join(server.data_dir, "operations")))

    def tenant_events():
        return [
            e for e in server.store.audit._read_all()
            if e.tenant_id == "t"
        ]

    cases = [
        (_encrypt_body(b"x", version=0), "version"),
        (_encrypt_body(b"x", version="2"), "version"),
        (_encrypt_body(b"x", version=True), "version"),
        ({"tenant_id": "t"}, "plaintext"),
        ({"tenant_id": "t", "plaintext": 12}, "plaintext"),
        ({"tenant_id": "t", "plaintext": "!!!"}, "plaintext"),
        ({"tenant_id": "t", "plaintext": b64(b"x"), "aad": "!!!"}, "aad"),
        ({"tenant_id": "", "plaintext": b64(b"x")}, "tenant_id"),
    ]
    for body, field in cases:
        before_ops = op_names()
        before_events = len(tenant_events())
        status, out = client.call(
            "POST", path, body, headers={"Idempotency-Key": "k-%s" % field}
        )
        assert status == 400 and field in out["error"], (body, out)
        assert op_names() == before_ops
        assert len(tenant_events()) == before_events

    # Malformed path key_id.
    status, _ = client.call(
        "POST", "/v1/keys/not-a-uuid/encrypt",
        {"tenant_id": "t", "plaintext": b64(b"x")},
        headers={"Idempotency-Key": "kbadid"},
    )
    assert status == 400

    # Illegal / duplicated idempotency keys never read the body for binding.
    status, _ = client.call(
        "POST", path, _encrypt_body(b"x"),
        headers={"Idempotency-Key": "bad space"},
    )
    assert status == 400

    # A duplicated Idempotency-Key header is a side-effect-free 400.
    import http.client
    from urllib.parse import urlsplit

    parsed = urlsplit(client.base)
    data = json.dumps(_encrypt_body(b"x")).encode()
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port)
    conn.putrequest("POST", path)
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(data)))
    conn.putheader("Idempotency-Key", "a")
    conn.putheader("Idempotency-Key", "b")
    conn.endheaders(data)
    resp = conn.getresponse()
    assert resp.status == 400
    conn.close()


def test_pre_bind_400_does_not_consume_key(server):
    client = Client(server.base)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    # A bad request under a key leaves it free to bind to a later good request.
    status, _ = client.call(
        "POST", path, {"tenant_id": "t", "plaintext": "!!!"},
        headers={"Idempotency-Key": "reuse"},
    )
    assert status == 400
    status, body = client.call(
        "POST", path, _encrypt_body(b"ok"),
        headers={"Idempotency-Key": "reuse"},
    )
    assert status == 200 and body["operation_id"]


# ------------------------------------------------------- post-bind terminals
def test_policy_denial_is_terminal_403(server):
    client = Client(server.base)
    store = server.store
    kid = _make_key(client)
    store.audit  # noop
    server.policies.put(
        "t", [Rule("alice", ["create", "read", "decrypt"], "allow")]
    )
    path = "/v1/keys/%s/encrypt" % kid
    s1, b1 = client.call(
        "POST", path, _encrypt_body(b"x"), headers={"Idempotency-Key": "deny"}
    )
    assert s1 == 403 and b1["operation_id"]
    op_id = b1["operation_id"]
    s2, b2 = client.call(
        "POST", path, _encrypt_body(b"x"), headers={"Idempotency-Key": "deny"}
    )
    assert s2 == 403 and b2["operation_id"] == op_id
    events = [
        e for e in store.audit._read_all() if e.event_id == op_id
    ]
    assert len(events) == 1 and events[0].outcome == "rejected"
    assert events[0].action == "encrypt" and events[0].key_id == kid


def test_unknown_and_cross_tenant_are_terminal_404(server):
    client = Client(server.base)
    kid = _make_key(client, tenant="t")
    unknown = "33333333-3333-4333-8333-333333333333"
    s, b = client.call(
        "POST", "/v1/keys/%s/encrypt" % unknown,
        _encrypt_body(b"x"), headers={"Idempotency-Key": "u1"},
    )
    assert s == 404 and b["operation_id"]
    # Replays the same 404.
    s2, b2 = client.call(
        "POST", "/v1/keys/%s/encrypt" % unknown,
        _encrypt_body(b"x"), headers={"Idempotency-Key": "u1"},
    )
    assert s2 == 404 and b2["operation_id"] == b["operation_id"]
    # Cross-tenant is indistinguishable from missing.
    s3, b3 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid,
        {"tenant_id": "other", "plaintext": b64(b"x")},
        operator="bob", headers={"Idempotency-Key": "u2"},
    )
    assert s3 == 404 and b3["operation_id"]


def test_revoked_version_is_terminal_409(server):
    client = Client(server.base)
    store = server.store
    kid = _make_key(client)
    store.revoke(kid, "t", "compromise", "alice")
    s, b = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, _encrypt_body(b"x"),
        headers={"Idempotency-Key": "rev"},
    )
    assert s == 409 and b["operation_id"]
    s2, b2 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, _encrypt_body(b"x"),
        headers={"Idempotency-Key": "rev"},
    )
    assert s2 == 409 and b2["operation_id"] == b["operation_id"]


# --------------------------------------------------------- version pinning
def test_default_version_pins_current_at_first_attempt(server):
    client = Client(server.base)
    store = server.store
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = _encrypt_body(b"x")
    # Bind and resolve version 1 (current), then rotate before the retry.
    normalized = normalize_body(body)
    begin = server.ops.begin(
        "t", "alice", path, request_digest(normalized), "pin1",
        mirror_required=False,
    )
    record = begin.record
    server.ops.update_details(
        record,
        {
            "kind": "encrypt", "key_id": kid, "version_requested": None,
            "version": 1, "algorithm": "AES256", "provider_id": "local",
        },
    )
    store.rotate(kid, "t", "AES256")
    s, b = client.call("POST", path, body, headers={"Idempotency-Key": "pin1"})
    assert s == 200
    assert json.loads(base64.b64decode(b["envelope"]))["version"] == 1
    # A fresh (legacy) call uses the new current.
    s2, b2 = client.call("POST", path, body)
    assert json.loads(base64.b64decode(b2["envelope"]))["version"] == 2


def test_explicit_version_is_pinned(server):
    client = Client(server.base)
    store = server.store
    kid = _make_key(client)
    store.rotate(kid, "t", "AES256")
    body = _encrypt_body(b"x", version=1)
    s, b = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": "v1"},
    )
    assert s == 200
    assert json.loads(base64.b64decode(b["envelope"]))["version"] == 1


# ------------------------------------------------------------- no leakage
def test_no_material_in_record_or_ledger(server):
    client = Client(server.base)
    kid = _make_key(client)
    secret = b"plaintext-never-persisted"
    aad_secret = b"aad-never-persisted"
    body = _encrypt_body(secret, aad=b64(aad_secret))
    _, out = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": "leak"},
    )
    op_id = out["operation_id"]
    # The record file carries only the body digest, never the body/material.
    op_path = os.path.join(
        server.data_dir, "operations", op_id + ".json"
    )
    with open(op_path, "rb") as fh:
        raw = fh.read()
    assert secret not in raw and aad_secret not in raw
    record = json.loads(raw)
    assert record["request_body"] == request_digest(normalize_body(body))
    # The durable recovery facts carry no plaintext/AAD/envelope/handle.
    facts = {
        k: v for k, v in (record.get("details") or {}).items()
        if k not in ("result", "audit", "terminal")
    }
    facts_text = json.dumps(facts)
    for forbidden in ("plaintext", "aad", "envelope", "handle", "wrapped"):
        assert forbidden not in facts_text, (forbidden, facts_text)
    facts_details = record["details"]
    assert facts_details["version"] == 1
    assert facts_details["algorithm"] == "AES256"
    assert facts_details["provider_id"] == "local"
    # The provider HANDLE (which lives on the key file) must never be copied
    # into the operation record, response or audit.
    key_rec = server.store.get(kid, "t")
    handle = key_rec.current.handle
    assert handle and handle.encode() not in raw
    # The opaque envelope (a ciphertext token, not key material) is the
    # durable response replayed by retries/restart/GET.
    assert record["response"]["envelope"] == out["envelope"]
    assert record["response"]["operation_id"] == op_id
    # The audit ledger never carries the plaintext/AAD/envelope.
    with open(os.path.join(server.data_dir, "audit.log"), "rb") as fh:
        ledger = fh.read()
    assert secret not in ledger and aad_secret not in ledger
    assert out["envelope"].encode() not in ledger
    assert handle.encode() not in ledger


# ------------------------------------------------------------ crash windows
def _bind_pending(server, path, body, key, details):
    begin = server.ops.begin(
        "t", "alice", path, request_digest(normalize_body(body)), key,
        mirror_required=False,
    )
    merged = {"kind": "encrypt", "key_id": path.split("/")[3]}
    merged.update(details)
    server.ops.update_details(begin.record, merged)
    return begin.record


def test_crash_before_event_stays_pending_and_retry_completes(server):
    client = Client(server.base)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = _encrypt_body(b"x")
    record = _bind_pending(
        server, path, body, "crashA",
        {"version_requested": None, "version": 1, "algorithm": "AES256",
         "provider_id": "local"},
    )
    # Restart recovery leaves it pending and hides any result.
    reopened = OperationStore(server.data_dir, AuditLog(server.data_dir))
    reopened.recover_pending(None)
    rec = reopened._read_record(record.operation_id)
    assert rec.status == "pending"
    assert rec.to_status_response()["response"] is None
    # The identical HTTP request takes it over and finishes once.
    s, b = client.call("POST", path, body, headers={"Idempotency-Key": "crashA"})
    assert s == 200 and b["operation_id"] == record.operation_id
    s2, b2 = client.call("POST", path, body, headers={"Idempotency-Key": "crashA"})
    assert b2["envelope"] == b["envelope"]


def test_staged_response_without_event_is_only_reappended(server):
    client = Client(server.base)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = _encrypt_body(b"x")
    record = _bind_pending(
        server, path, body, "crashC",
        {"version": 1, "algorithm": "AES256", "provider_id": "local"},
    )
    staged = {
        "format": env_mod.FORMAT,
        "envelope": "STAGED-TOKEN",
        "operation_id": record.operation_id,
    }
    server.ops.stage_terminal(
        record, 200, staged,
        audit={"action": "encrypt", "outcome": "success",
               "tenant_id": "t", "key_id": kid},
    )
    # Restart keeps it pending (event never durable, envelope not rebuildable).
    reopened = OperationStore(server.data_dir, AuditLog(server.data_dir))
    reopened.recover_pending(None)
    assert reopened._read_record(record.operation_id).status == "pending"
    # Retry: the SAME staged envelope is replayed and the event appended once;
    # no fresh envelope is minted.
    s, b = client.call("POST", path, body, headers={"Idempotency-Key": "crashC"})
    assert s == 200 and b["envelope"] == "STAGED-TOKEN"
    events = [
        e for e in server.store.audit._read_all()
        if e.event_id == record.operation_id
    ]
    assert len(events) == 1 and events[0].outcome == "success"


def test_durable_event_finalizes_on_restart(server):
    kid = _make_key(Client(server.base))
    path = "/v1/keys/%s/encrypt" % kid
    body = _encrypt_body(b"x")
    record = _bind_pending(
        server, path, body, "crashD",
        {"version": 1, "algorithm": "AES256", "provider_id": "local"},
    )
    staged = {
        "format": env_mod.FORMAT,
        "envelope": "DURABLE-TOKEN",
        "operation_id": record.operation_id,
    }
    server.ops.stage_terminal(
        record, 200, staged,
        audit={"action": "encrypt", "outcome": "success",
               "tenant_id": "t", "key_id": kid},
    )
    server.store.audit_attempt(
        "t", kid, "encrypt", audit_mod.OUTCOME_SUCCESS,
        event_id=record.operation_id,
    )
    # finish() deliberately omitted -> crash right after the commit append.
    reopened = OperationStore(server.data_dir, AuditLog(server.data_dir))
    reopened.recover_pending(None)
    rec = reopened._read_record(record.operation_id)
    assert rec.status == "succeeded"
    assert rec.http_status == 200
    assert rec.response["envelope"] == "DURABLE-TOKEN"


# --------------------------------------------------------- provider outage
def test_provider_outage_is_sticky_503(tmp_path, monkeypatch):
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(tests_dir)
    sys.path.insert(0, tests_dir)
    sys.path.insert(0, repo_root)
    import fake_kms  # noqa: E402

    state = str(tmp_path / "kms-state.json")
    faults = str(tmp_path / "kms-faults.json")
    srv = _build_server(
        tmp_path, monkeypatch,
        {
            "KEYMGR_PROVIDER": "fake_kms:make_provider",
            "FAKE_KMS_STATE": state,
            "FAKE_KMS_FAULTS": faults,
        },
    )
    fake_kms.reset()
    try:
        client = Client(srv.base)
        kid = _make_key(client)
        path = "/v1/keys/%s/encrypt" % kid
        body = _encrypt_body(b"x")
        with open(faults, "w", encoding="utf-8") as fh:
            json.dump({"unreachable": True}, fh)
        s, b = client.call(
            "POST", path, body, headers={"Idempotency-Key": "down"}
        )
        assert s == 503
        assert b == {
            "error": "key management provider is unavailable",
            "operation_id": b["operation_id"],
        }
        op_id = b["operation_id"]
        events = [
            e for e in srv.store.audit._read_all() if e.event_id == op_id
        ]
        assert len(events) == 1 and events[0].outcome == "rejected"
        # Provider recovers, but the same key still replays the sticky 503
        # (the scene is reserved for the original owning provider).
        os.unlink(faults)
        fake_kms.reset()
        s2, b2 = client.call(
            "POST", path, body, headers={"Idempotency-Key": "down"}
        )
        assert s2 == 503 and b2["operation_id"] == op_id
        # GET reports the durable failed/503 terminal.
        s3, b3 = client.call(
            "GET", "/v1/operations/%s?tenant_id=t" % op_id
        )
        assert b3["status"] == "failed" and b3["http_status"] == 503
    finally:
        srv.shutdown()
        provider_mod.reset_for_tests()


def test_inactive_owning_provider_is_sticky_503(server, monkeypatch):
    # A local-owned key must never be handled after switching providers.
    client = Client(server.base)
    kid = _make_key(client)
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    monkeypatch.syspath_prepend(tests_dir)
    monkeypatch.setenv(
        "FAKE_KMS_STATE",
        os.path.join(server.data_dir, "kms-state.json"),
    )
    provider_mod.reset_for_tests()
    s, b = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, _encrypt_body(b"x"),
        headers={"Idempotency-Key": "switch"},
    )
    assert s == 503 and b["operation_id"]
    assert b["error"] == "key management provider is unavailable"


# ------------------------------------------------------------- concurrency
def test_concurrent_same_key_executes_once(tmp_path, monkeypatch):
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(tests_dir)
    sys.path.insert(0, tests_dir)
    sys.path.insert(0, repo_root)
    import fake_kms  # noqa: E402

    state = str(tmp_path / "kms-state.json")
    faults = str(tmp_path / "kms-faults.json")
    srv = _build_server(
        tmp_path, monkeypatch,
        {
            "KEYMGR_PROVIDER": "fake_kms:make_provider",
            "FAKE_KMS_STATE": state,
            "FAKE_KMS_FAULTS": faults,
        },
    )
    fake_kms.reset()
    try:
        client = Client(srv.base)
        kid = _make_key(client)
        path = "/v1/keys/%s/encrypt" % kid
        body = _encrypt_body(b"x")
        with open(faults, "w", encoding="utf-8") as fh:
            # Hold the provider briefly so both requests overlap.
            json.dump({"sleep": {"export_material": 0.5}}, fh)
        results = []

        def fire():
            results.append(
                client.call(
                    "POST", path, body,
                    headers={"Idempotency-Key": "race"},
                )
            )

        t1 = threading.Thread(target=fire)
        t2 = threading.Thread(target=fire)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert len(results) == 2
        assert {s for s, _ in results} == {200}
        envelopes = {b["envelope"] for _, b in results}
        op_ids = {b["operation_id"] for _, b in results}
        assert len(envelopes) == 1 and len(op_ids) == 1
        events = [
            e for e in srv.store.audit._read_all()
            if e.action == "encrypt" and e.tenant_id == "t"
        ]
        assert len(events) == 1
    finally:
        srv.shutdown()
        provider_mod.reset_for_tests()


# -------------------------------------------------------------------- CLI
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


def test_cli_idempotent_encrypt_replays_and_conflicts(tmp_path):
    data_dir = str(tmp_path / "data")
    proc = run_cli(
        data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert proc.returncode == 0
    kid = _json(proc)["key_id"]
    pt, aad = b64(b"cli-secret"), b64(b"c")
    p1 = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", pt, "--aad", aad, "--operator", "alice",
        "--idempotency-key", "c1",
    )
    assert p1.returncode == 0
    body = _json(p1)
    assert body["operation_id"]
    p2 = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", pt, "--aad", aad, "--operator", "alice",
        "--idempotency-key", "c1",
    )
    assert p2.returncode == 0
    assert _json(p2)["envelope"] == body["envelope"]
    # Different plaintext, same key -> exit 3 naming the original op.
    p3 = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", b64(b"other"), "--operator", "alice",
        "--idempotency-key", "c1",
    )
    assert p3.returncode == 3
    assert _json(p3)["operation_id"] == body["operation_id"]
    # Bad base64 -> exit 2 and the key is not consumed.
    p4 = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", "!!!", "--operator", "alice",
        "--idempotency-key", "c2",
    )
    assert p4.returncode == 2
    p5 = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", pt, "--operator", "alice",
        "--idempotency-key", "c2",
    )
    assert p5.returncode == 0 and _json(p5)["operation_id"]
    # GET operation replays the stored terminal.
    p6 = run_cli(
        data_dir, "operation", "--tenant-id", "t", "--operator", "alice",
        "--operation-id", body["operation_id"],
    )
    assert p6.returncode == 0
    status = _json(p6)
    assert status["status"] == "succeeded" and status["http_status"] == 200
    assert status["response"]["envelope"] == body["envelope"]


def test_cli_without_key_is_legacy(tmp_path):
    data_dir = str(tmp_path / "data")
    run_cli(
        data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    # Discover the key id via a fresh gen output.
    proc = run_cli(
        data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k2", "--operator", "alice",
    )
    kid = _json(proc)["key_id"]
    pt = b64(b"x")
    a = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", pt, "--operator", "alice",
    )
    b = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", pt, "--operator", "alice",
    )
    assert a.returncode == 0 and b.returncode == 0
    assert _json(a)["envelope"] != _json(b)["envelope"]
    assert "operation_id" not in _json(a)
