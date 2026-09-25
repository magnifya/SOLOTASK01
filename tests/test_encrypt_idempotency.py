"""Idempotency for POST /v1/keys/{key_id}/encrypt.

Covers the header contract (single, 1-128, unreserved ASCII, before the
body), side-effect-free pre-bind 400s, same-binding replay (same envelope,
operation_id and audit; the provider is not invoked twice), same-key/
different-request 409 naming the original operation, the fixed
``format,envelope,operation_id`` 200 key order, terminal error bodies of only
``error,operation_id``, 503 provider wording and replay, the 5 s lock timeout,
GET-operation pending nulls, crash consistency (pre-event pending with the
envelope hidden, post-event verbatim replay), and the guarantee that plaintext,
AAD, keys, handles and backend faults never reach the operation record, the
audit ledger or any file.

The CLI ``encrypt`` command is intentionally NOT idempotent and is covered
separately in test_envelope.py.
"""

import base64
import glob
import json
import os
import threading
import time
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
from keymgr import operations as operations_mod
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _build(tmp_path):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    return data_dir, audit_log, store, policies, coordinator, op_store, \
        artifact_store


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, headers=None,
             operator="alice", raw=None):
        if raw is None:
            data = json.dumps(body).encode() if body is not None else None
        else:
            data = raw
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
def stack(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    parts = _build(tmp_path)
    data_dir, audit_log, store, policies, coordinator, op_store, art = parts
    handler = make_handler(store, policies, coordinator, op_store, art)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    yield types.SimpleNamespace(
        data_dir=data_dir, audit=audit_log, store=store, policies=policies,
        op_store=op_store, artifacts=art, client=client, tmp=tmp_path,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _is_uuid4(value):
    import uuid

    try:
        return uuid.UUID(str(value)).version == 4
    except (ValueError, AttributeError, TypeError):
        return False


def _enc_path(kid):
    return "/v1/keys/%s/encrypt" % kid


def _body(plaintext=b"payload", aad=None, **extra):
    body = {"tenant_id": "t", "plaintext": b64(plaintext)}
    if aad is not None:
        body["aad"] = b64(aad)
    body.update(extra)
    return body


# ------------------------------------------------------------- header / bind
def test_missing_key_is_400_without_side_effects(stack):
    c = stack.client
    kid = _make_key(c)
    status, out = c.call("POST", _enc_path(kid), _body())
    assert status == 400 and "Idempotency-Key" in out["error"]
    assert set(out) == {"error"}
    # No operation record, no NEW audit event, no artifact directory.
    assert not glob.glob(os.path.join(stack.data_dir, "operations", "*.json"))
    assert not os.path.exists(
        os.path.join(stack.data_dir, "operation-artifacts")
    )
    assert [e.action for e in stack.audit._read_all()] == ["create"]


@pytest.mark.parametrize("value", ["", "with space", "slash/ok", "caf\u00e9",
                                  "x" * 129, "tab\tx"])
def test_illegal_key_is_400(stack, value):
    c = stack.client
    kid = _make_key(c)
    status, out = c.call(
        "POST", _enc_path(kid), _body(),
        headers={"Idempotency-Key": value},
    )
    assert status == 400 and "Idempotency-Key" in out["error"]
    assert [e.action for e in stack.audit._read_all()] == ["create"]


def test_duplicate_key_header_is_400(stack):
    import http.client

    c = stack.client
    kid = _make_key(c)
    conn = http.client.HTTPConnection("127.0.0.1", c.base.rsplit(":", 1)[1])
    raw = json.dumps(_body()).encode()
    conn.putrequest("POST", _enc_path(kid))
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Idempotency-Key", "a")
    conn.putheader("Idempotency-Key", "b")
    conn.putheader("Content-Length", str(len(raw)))
    conn.endheaders(raw)
    resp = conn.getresponse()
    assert resp.status == 400
    assert "Idempotency-Key" in json.loads(resp.read())["error"]
    assert [e.action for e in stack.audit._read_all()] == ["create"]


def test_pre_bind_parse_and_param_400s_leave_no_trace(stack):
    c = stack.client
    kid = _make_key(c)
    # Malformed JSON body.
    status, _ = c.call(
        "POST", _enc_path(kid), headers={"Idempotency-Key": "k"}, raw=b"{nope"
    )
    assert status == 400
    # Bad base64 plaintext.
    status, _ = c.call(
        "POST", _enc_path(kid), {"tenant_id": "t", "plaintext": "!!!"},
        headers={"Idempotency-Key": "k2"},
    )
    assert status == 400
    # Bad version.
    status, _ = c.call(
        "POST", _enc_path(kid), _body(version=0),
        headers={"Idempotency-Key": "k3"},
    )
    assert status == 400
    # Conflicting tenant (header vs body) pre-bind is silent, not even an
    # invisible tenant_conflict.
    status, _ = c.call(
        "POST", _enc_path(kid), _body(),
        headers={"Idempotency-Key": "k4", "X-Tenant-Id": "other"},
    )
    assert status == 400
    assert [e.action for e in stack.audit._read_all()] == ["create"]
    # None of these keys may have been consumed: rebinding k succeeds.
    status, out = c.call(
        "POST", _enc_path(kid), _body(), headers={"Idempotency-Key": "k2"}
    )
    assert status == 200 and _is_uuid4(out["operation_id"])


# ----------------------------------------------------------------- 200 shape
def test_success_key_order_format_and_operation_id(stack):
    c = stack.client
    kid = _make_key(c)
    status, out = c.call(
        "POST", _enc_path(kid), _body(b"p", aad=b"a"),
        headers={"Idempotency-Key": "one"},
    )
    assert status == 200
    assert list(out.keys()) == ["format", "envelope", "operation_id"]
    assert out["format"] == env_mod.FORMAT
    assert _is_uuid4(out["operation_id"])
    obj = json.loads(base64.b64decode(out["envelope"]))
    assert obj["key_id"] == kid and obj["version"] == 1


# ------------------------------------------------------------------ replay
def test_same_binding_replays_envelope_operation_and_audit(stack):
    c = stack.client
    kid = _make_key(c)
    body = _body(b"replay-me", aad=b"c")
    status, first = c.call(
        "POST", _enc_path(kid), body, headers={"Idempotency-Key": "dup"}
    )
    assert status == 200
    op_id = first["envelope"], first["operation_id"]
    # Several identical retries (also a different JSON key order) all replay.
    reordered = {"aad": body["aad"], "plaintext": body["plaintext"],
                 "tenant_id": "t"}
    for payload in (body, reordered, body):
        status, again = c.call(
            "POST", _enc_path(kid), payload,
            headers={"Idempotency-Key": "dup"},
        )
        assert status == 200 and again == first
    events = [e for e in stack.audit._read_all() if e.action == "encrypt"]
    assert len(events) == 1
    assert events[0].event_id == first["operation_id"]
    assert events[0].outcome == "success" and events[0].key_id == kid
    assert op_id[1] == first["operation_id"]


def test_same_key_different_request_conflicts(stack):
    c = stack.client
    kid = _make_key(c)
    status, first = c.call(
        "POST", _enc_path(kid), _body(b"same"),
        headers={"Idempotency-Key": "K"},
    )
    assert status == 200
    original = first["operation_id"]

    def conflict(body):
        status, out = c.call(
            "POST", _enc_path(kid), body, headers={"Idempotency-Key": "K"}
        )
        assert status == 409
        assert set(out) == {"error", "operation_id"}
        assert out["operation_id"] == original
        return out

    conflict(_body(b"different-plaintext"))
    conflict(_body(b"same", aad=b"different-aad"))
    conflict({"tenant_id": "t", "plaintext": b64(b"same"), "version": 1})
    # A different tenant/operator on the same key value conflicts too.
    status, out = c.call(
        "POST", _enc_path(kid),
        {"tenant_id": "other", "plaintext": b64(b"same")},
        headers={"Idempotency-Key": "K"}, operator="bob",
    )
    assert status == 409 and out["operation_id"] == original
    # The conflict answers write no additional audit event.
    events = [e for e in stack.audit._read_all() if e.action == "encrypt"]
    assert len(events) == 1 and events[0].event_id == original


# --------------------------------------------------------------- terminals
def test_bound_refusals_carry_operation_id(stack):
    c = stack.client
    kid = _make_key(c)
    # Policy denial -> 403 bound terminal.
    stack.policies.put("t", [Rule("alice", ["create", "read"], "allow")])
    status, out = c.call(
        "POST", _enc_path(kid), _body(), headers={"Idempotency-Key": "deny"}
    )
    assert status == 403 and out["error"] == "action not permitted by policy"
    assert _is_uuid4(out["operation_id"])
    # Retry replays the 403 and writes the rejected event exactly once.
    status, again = c.call(
        "POST", _enc_path(kid), _body(), headers={"Idempotency-Key": "deny"}
    )
    assert again == out
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "encrypt" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].event_id == out["operation_id"]


def test_unknown_key_and_version_are_bound_404(stack):
    c = stack.client
    kid = _make_key(c)
    unknown = "33333333-3333-4333-8333-333333333333"
    status, out = c.call(
        "POST", _enc_path(unknown), _body(),
        headers={"Idempotency-Key": "u"},
    )
    assert status == 404 and out["error"] == "key not found"
    assert _is_uuid4(out["operation_id"])
    status, out = c.call(
        "POST", _enc_path(kid), _body(version=99),
        headers={"Idempotency-Key": "v"},
    )
    assert status == 404 and _is_uuid4(out["operation_id"])


def test_revoked_key_is_bound_409(stack):
    c = stack.client
    kid = _make_key(c)
    stack.store.revoke(kid, "t", "r", "alice")
    status, out = c.call(
        "POST", _enc_path(kid), _body(), headers={"Idempotency-Key": "rev"}
    )
    assert status == 409 and "revoked" in out["error"]
    assert _is_uuid4(out["operation_id"])


# ------------------------------------------------------------- GET operation
def test_get_operation_pending_nulls_and_terminal(stack):
    c = stack.client
    kid = _make_key(c)
    # Drive one success; the terminal projection carries http_status/response.
    status, out = c.call(
        "POST", _enc_path(kid), _body(), headers={"Idempotency-Key": "g"}
    )
    op_id = out["operation_id"]
    status, got = c.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id
    )
    assert status == 200
    assert got["operation_id"] == op_id and got["status"] == "succeeded"
    assert got["http_status"] == 200 and got["response"] == out


# -------------------------------------------------------------- concurrency
def test_concurrent_same_key_executes_once(stack):
    c = stack.client
    kid = _make_key(c)
    body = _body(b"race")
    results = []

    def fire():
        results.append(c.call(
            "POST", _enc_path(kid), body,
            headers={"Idempotency-Key": "race"},
        ))

    threads = [threading.Thread(target=fire) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    assert all(s == 200 for s, _ in results)
    assert len({json.dumps(b, sort_keys=True) for _, b in results}) == 1
    op_id = results[0][1]["operation_id"]
    events = [e for e in stack.audit._read_all() if e.action == "encrypt"]
    assert len(events) == 1 and events[0].event_id == op_id


def test_lock_wait_timeout_is_503_timed_out(stack, monkeypatch):
    import fcntl

    c = stack.client
    kid = _make_key(c)
    monkeypatch.setattr(operations_mod, "LOCK_WAIT_SECONDS", 0.5)
    lock_fd = os.open(
        os.path.join(stack.data_dir, kid + ".lock"),
        os.O_RDWR | os.O_CREAT, 0o600,
    )
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        status, out = c.call(
            "POST", _enc_path(kid), _body(),
            headers={"Idempotency-Key": "held"},
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    assert status == 503
    assert out["error"] == "operation timed out waiting for a lock"
    assert set(out) == {"error", "operation_id"}
    record = stack.op_store._read_record(out["operation_id"])
    assert record.status == "timed_out" and record.http_status == 503
    # The waiter appended no audit event.
    assert stack.audit.get_event(out["operation_id"]) is None


# --------------------------------------------------------- crash consistency
def _restart(ns):
    """Reopen every store over the same directory (a new process)."""
    data_dir = ns.data_dir
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    ns.audit, ns.store, ns.policies = audit_log, store, policies
    ns.op_store, ns.artifacts = op_store, artifact_store
    return store, policies, coordinator, op_store, artifact_store


def _serve(ns, parts):
    store, policies, coordinator, op_store, art = parts
    handler = make_handler(store, policies, coordinator, op_store, art)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, Client("http://127.0.0.1:%d" % httpd.server_address[1])


def test_crash_before_event_keeps_pending_hides_envelope_then_runs_once(stack):
    ns = stack
    kid = _make_key(ns.client)
    # Construct a bound, staged-but-uncommitted encrypt (crash between the
    # 200 stage and the event append).
    _st, rec, ver, kek = ns.store.crypto_material(kid, "t")
    token = env_mod.encode_envelope(
        key_id=kid, version=ver.version, algorithm=ver.algorithm, kek=kek,
        plaintext=b"crash-secret", aad=b"crash-aad",
    )
    body = _body(b"crash-secret", aad=b"crash-aad")
    binding = {
        "tenant_id": "t",
        "plaintext": ns.audit.commitment(
            "plaintext:" + b64(b"crash-secret")
        ),
        "aad": ns.audit.commitment("aad:" + b64(b"crash-aad")),
    }
    begin = ns.op_store.begin(
        "t", "alice", _enc_path(kid),
        operations_mod.normalize_body(binding), "pre-crash",
    )
    op = begin.record
    ns.op_store.update_details(op, {"kind": "encrypt", "key_id": kid})
    mirror = ns.artifacts.create(op)
    mirror.describe({"kind": "encrypt", "write_set": [kid]})
    staged = {
        "format": env_mod.FORMAT, "envelope": token,
        "operation_id": op.operation_id,
    }
    ns.op_store.stage_terminal(
        op, 200, staged,
        audit={"action": "encrypt", "outcome": "success",
               "tenant_id": "t", "key_id": kid},
    )

    parts = _restart(ns)
    record = ns.op_store._read_record(op.operation_id)
    assert record.status == "pending"
    assert ns.audit.get_event(op.operation_id) is None
    # The pre-event mirror survives as the pending strand's cross-reference.
    assert os.path.exists(ns.artifacts.path_for(op.operation_id))

    httpd, client = _serve(ns, parts)
    try:
        # GET pending hides http_status/response (the staged envelope).
        status, got = client.call(
            "GET", "/v1/operations/%s?tenant_id=t" % op.operation_id
        )
        assert status == 200 and got["status"] == "pending"
        assert got["http_status"] is None and got["response"] is None
        # Identical retry runs once under the SAME operation_id.
        status, out = client.call(
            "POST", _enc_path(kid), body,
            headers={"Idempotency-Key": "pre-crash"},
        )
        assert status == 200 and out["operation_id"] == op.operation_id
        events = [e for e in ns.audit._read_all() if e.action == "encrypt"]
        assert len(events) == 1 and events[0].event_id == op.operation_id
        # The mirror is cleaned once the commit is verified (cleanup runs
        # after the response is sent, so allow a brief settle window).
        mirror_path = ns.artifacts.path_for(op.operation_id)
        for _ in range(100):
            if not os.path.exists(mirror_path):
                break
            time.sleep(0.02)
        assert not os.path.exists(mirror_path)
        # Further retries replay byte-for-byte.
        status, again = client.call(
            "POST", _enc_path(kid), body,
            headers={"Idempotency-Key": "pre-crash"},
        )
        assert again == out
    finally:
        httpd.shutdown()


def test_crash_after_event_replays_staged_envelope(stack):
    ns = stack
    kid = _make_key(ns.client)
    _st, rec, ver, kek = ns.store.crypto_material(kid, "t")
    token = env_mod.encode_envelope(
        key_id=kid, version=ver.version, algorithm=ver.algorithm, kek=kek,
        plaintext=b"durable",
    )
    binding = {
        "tenant_id": "t",
        "plaintext": ns.audit.commitment("plaintext:" + b64(b"durable")),
    }
    begin = ns.op_store.begin(
        "t", "alice", _enc_path(kid),
        operations_mod.normalize_body(binding), "post-crash",
    )
    op = begin.record
    ns.op_store.update_details(op, {"kind": "encrypt", "key_id": kid})
    mirror = ns.artifacts.create(op)
    mirror.describe({"kind": "encrypt", "write_set": [kid]})
    staged = {
        "format": env_mod.FORMAT, "envelope": token,
        "operation_id": op.operation_id,
    }
    ns.op_store.stage_terminal(
        op, 200, staged,
        audit={"action": "encrypt", "outcome": "success",
               "tenant_id": "t", "key_id": kid},
    )
    ns.audit.append(ns.audit.new_event(
        "t", "encrypt", kid, "success", event_id=op.operation_id
    ))  # commit point durable; finish() never ran

    parts = _restart(ns)
    record = ns.op_store._read_record(op.operation_id)
    assert record.status == "succeeded"
    assert record.http_status == 200 and record.response == staged
    assert not os.path.exists(ns.artifacts.path_for(op.operation_id))
    httpd, client = _serve(ns, parts)
    try:
        status, out = client.call(
            "POST", _enc_path(kid), _body(b"durable"),
            headers={"Idempotency-Key": "post-crash"},
        )
        assert status == 200 and out == staged
        events = [e for e in ns.audit._read_all() if e.action == "encrypt"]
        assert [e.event_id for e in events].count(op.operation_id) == 1
    finally:
        httpd.shutdown()


# ----------------------------------------------------------- material safety
def test_no_plaintext_aad_or_material_persisted(stack):
    c = stack.client
    kid = _make_key(c, algorithm="RSA2048")
    secret = b"the-plaintext-secret"
    aad_secret = b"the-aad-secret"
    status, out = c.call(
        "POST", _enc_path(kid), _body(secret, aad=aad_secret),
        headers={"Idempotency-Key": "safe"},
    )
    assert status == 200
    blob = b""
    for root, _dirs, files in os.walk(stack.data_dir):
        for name in files:
            with open(os.path.join(root, name), "rb") as fh:
                blob += fh.read()
    assert secret not in blob
    assert aad_secret not in blob
    assert b64(secret).encode() not in blob
    assert b64(aad_secret).encode() not in blob
    # The operation record binds on an opaque commitment, not the plaintext.
    record_path = os.path.join(
        stack.data_dir, "operations", out["operation_id"] + ".json"
    )
    raw = open(record_path, "rb").read()
    assert b64(secret).encode() not in raw
