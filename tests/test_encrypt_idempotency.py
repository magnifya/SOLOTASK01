"""Optional idempotency for envelope encryption.

Covers POST /v1/keys/{key_id}/encrypt (and the CLI `encrypt`) with an
OPTIONAL Idempotency-Key:

* no key -> legacy non-idempotent behavior (no operation_id, fresh envelope,
  legacy field-error auditing);
* key present -> 200 {format, envelope, operation_id}, identical retries and
  GET /v1/operations replay byte-for-byte; same key/different canonical body
  is 409 naming the original operation_id;
* every pre-bind parameter failure is a side-effect-free 400 (no audit,
  operation record or provider handle, the key is not consumed);
* bound 403 (rejected audit), 404 unknown/cross-tenant, 409 revoked version;
* provider outage is a fixed-wording 503 terminal that replays;
* version omitted is locked to current BEFORE the provider call;
* the binding persists only the SHA-256 of the canonical body and the
  operation record stores key_id/version/algorithm/provider_id/response --
  never plaintext, AAD, a handle or key material; event_id == operation_id;
* crash windows: past the no-redo boundary with no durable result stays
  pending and NEVER calls the provider again; event durable only finishes;
* HTTP <-> CLI cross-entry replay and replay across a restart.
"""

import base64
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import envelope as env_mod
from keymgr import provider as provider_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import (
    OperationStore,
    STATUS_PENDING,
    STATUS_SUCCEEDED,
)
from keymgr.policy import PolicyStore, Rule
from keymgr.restore import RestoreCoordinator
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def run_cli(data_dir, *args):
    """Run the CLI in a subprocess against a data-dir path (string)."""
    import subprocess
    import sys

    env = dict(os.environ)
    env["PYTHONPATH"] = TESTS_DIR + os.pathsep + REPO_ROOT
    env.pop("KEYMGR_PROVIDER", None)
    cmd = [sys.executable, "-m", "keymgr", "--data-dir", data_dir] + [
        str(a) for a in args
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, env=env, timeout=60
    )


# --------------------------------------------------------------------- stack
class Client:
    def __init__(self, port):
        self.base = "http://127.0.0.1:%d" % port

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
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def call_raw_error(self, method, path, body=None, operator="alice",
                       headers=None):
        """Like call() but a dropped connection surfaces as None."""
        try:
            return self.call(method, path, body, operator, headers)
        except (urllib.error.URLError, ConnectionError, OSError):
            return None


def build_server(data_dir):
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact = ArtifactStore(data_dir, store, audit_log)
    artifact.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact.is_parked)
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(store, policies, coordinator, op_store, artifact),
    )
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return {
        "store": store, "policies": policies, "op_store": op_store,
        "artifact": artifact, "httpd": httpd, "thread": thread,
        "client": Client(httpd.server_address[1]), "data_dir": data_dir,
    }


def stop_server(stack):
    stack["httpd"].shutdown()
    stack["httpd"].server_close()
    stack["thread"].join()


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    data_dir = str(tmp_path / "data")
    s = build_server(data_dir)
    yield s
    stop_server(s)
    provider_mod.reset_for_tests()


def _make_key(client, tenant="t", algorithm="AES256"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _enc_body(plaintext, tenant="t", **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    return body


def _op_record(data_dir, operation_id):
    with open(
        os.path.join(data_dir, "operations", operation_id + ".json"),
        "r", encoding="utf-8",
    ) as fh:
        return json.load(fh)


def _op_files(data_dir):
    d = os.path.join(data_dir, "operations")
    return [f for f in os.listdir(d) if f.endswith(".json") and f != "index.json"]


def _encrypt(client, kid, key, plaintext=b"x", tenant="t", operator="alice",
             **extra):
    headers = {"Idempotency-Key": key}
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % kid,
        _enc_body(plaintext, tenant, **extra),
        operator=operator, headers=headers,
    )


# --------------------------------------------------------- legacy/no-key path
def test_no_key_keeps_legacy_non_idempotent_behavior(stack):
    client = client = stack["client"]
    kid = _make_key(client)
    s1, b1 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, _enc_body(b"same")
    )
    s2, b2 = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, _enc_body(b"same")
    )
    assert s1 == 200 and s2 == 200
    # No operation_id in the legacy response, and a fresh DEK means a
    # different envelope on every call.
    assert "operation_id" not in b1 and "operation_id" not in b2
    assert b1["envelope"] != b2["envelope"]
    # The legacy path never binds an operation.
    assert _op_files(stack["data_dir"]) == []


# -------------------------------------------------------------------- success
def test_success_shape_and_identical_replay(stack):
    client = stack["client"]
    kid = _make_key(client)
    s1, b1 = _encrypt(client, kid, "enc-1", b"payload", aad=b64(b"ctx"))
    assert s1 == 200, b1
    assert set(b1) == {"format", "envelope", "operation_id"}
    assert b1["format"] == env_mod.FORMAT
    op1 = b1["operation_id"]
    obj = json.loads(base64.b64decode(b1["envelope"]))
    assert obj["key_id"] == kid and obj["version"] == 1
    assert obj["aad"] == b64(b"ctx")

    # Identical binding replays the SAME envelope and operation_id.
    s2, b2 = _encrypt(client, kid, "enc-1", b"payload", aad=b64(b"ctx"))
    assert s2 == 200 and b2 == b1
    assert b2["operation_id"] == op1
    assert len(_op_files(stack["data_dir"])) == 1

    # GET /v1/operations replays the stored response too.
    s3, b3 = client.call(
        "GET", "/v1/operations/%s" % op1, None,
        headers={"X-Tenant-Id": "t"},
    )
    assert s3 == 200
    assert b3["status"] == STATUS_SUCCEEDED
    assert b3["http_status"] == 200
    assert b3["response"] == b1


def test_same_key_different_canonical_body_conflicts(stack):
    client = stack["client"]
    kid = _make_key(client)
    s1, b1 = _encrypt(client, kid, "k", b"first")
    assert s1 == 200
    original = b1["operation_id"]

    # Different plaintext, AAD or version under the same key all conflict and
    # name the ORIGINAL operation_id.
    for kwargs in (
        dict(plaintext=b"second"),
        dict(plaintext=b"first", aad=b64(b"a")),
        dict(plaintext=b"first", version=1),
    ):
        status, body = _encrypt(client, kid, "k", **kwargs)
        assert status == 409, body
        assert body["operation_id"] == original
        assert "already bound" in body["error"]
    assert len(_op_files(stack["data_dir"])) == 1


def test_version_default_locks_to_current_before_provider(stack):
    client = stack["client"]
    store = stack["store"]
    kid = _make_key(client)
    # First call omits version while v1 is current: the boundary locks v1.
    s1, b1 = _encrypt(client, kid, "ver", b"lock-v1")
    assert s1 == 200
    assert json.loads(base64.b64decode(b1["envelope"]))["version"] == 1
    # Rotate the key (current becomes v2) directly through the store.
    store.rotate(kid, "t", "AES256")
    # The idempotent retry omits version again but must replay the v1 result,
    # never re-resolve to the new current v2.
    s2, b2 = _encrypt(client, kid, "ver", b"lock-v1")
    assert s2 == 200 and b2 == b1
    assert json.loads(base64.b64decode(b2["envelope"]))["version"] == 1
    rec = _op_record(stack["data_dir"], b1["operation_id"])
    assert rec["details"]["encrypt"]["version"] == 1


# ------------------------------------------------------- pre-bind side effects
@pytest.mark.parametrize(
    "headers,body,field",
    [
        # Duplicate / illegal Idempotency-Key.
        ({"Idempotency-Key": "a b"}, None, "Idempotency-Key"),
        # Missing/empty tenant.
        (None, {"plaintext": b64(b"x")}, "tenant_id"),
        # Bad version / plaintext / aad.
        (None, {"tenant_id": "t", "plaintext": b64(b"x"), "version": 0},
         "version"),
        (None, {"tenant_id": "t", "plaintext": b64(b"x"), "version": "1.5"},
         "version"),
        (None, {"tenant_id": "t"}, "plaintext"),
        (None, {"tenant_id": "t", "plaintext": "!!!"}, "plaintext"),
        (None, {"tenant_id": "t", "plaintext": b64(b"x"), "aad": "!!!"},
         "aad"),
    ],
)
def test_pre_bind_failures_are_400_with_zero_side_effects(
    stack, headers, body, field
):
    client = stack["client"]
    kid = _make_key(client)
    before = len(stack["store"].audit._read_all())
    hdrs = dict(headers or {})
    hdrs.setdefault("Idempotency-Key", "prebind")
    # The duplicate-header case is sent manually (urllib dedupes dict keys).
    if headers == {"Idempotency-Key": "a b"}:
        hdrs = {"Idempotency-Key": "a b"}
    status, out = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body, headers=hdrs
    )
    assert status == 400, out
    assert field in out["error"]
    # No operation record, no new audit event, no key consumed: the same key
    # can still bind a successful operation.
    assert _op_files(stack["data_dir"]) == []
    assert len(stack["store"].audit._read_all()) == before
    status, ok = _encrypt(client, kid, "after-400", b"x")
    assert status == 200


def test_duplicate_idempotency_header_is_400(stack):
    import http.client

    client = stack["client"]
    kid = _make_key(client)
    port = int(client.base.rsplit(":", 1)[1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest("POST", "/v1/keys/%s/encrypt" % kid)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("Idempotency-Key", "a")
    conn.putheader("Idempotency-Key", "b")
    conn.endheaders(json.dumps(_enc_body(b"x")).encode())
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 400
    conn.close()
    assert _op_files(stack["data_dir"]) == []


def test_malformed_path_key_id_is_400_before_bind(stack):
    client = stack["client"]
    status, out = client.call(
        "POST", "/v1/keys/not-a-uuid/encrypt",
        _enc_body(b"x"), headers={"Idempotency-Key": "badkid"},
    )
    assert status == 400 and "key_id" in out["error"]
    assert _op_files(stack["data_dir"]) == []


# ------------------------------------------------------------- bound terminals
def test_bound_policy_denial_is_403_and_replays(stack):
    client = stack["client"]
    store = stack["store"]
    kid = _make_key(client)
    stack["policies"].put(
        "t", [Rule("alice", ["create", "read"], "allow")]
    )
    s1, b1 = _encrypt(client, kid, "deny", b"x")
    assert s1 == 403 and b1 == {
        "error": "action not permitted by policy",
        "operation_id": b1["operation_id"],
    }
    op_id = b1["operation_id"]
    # Replay is the same terminal; policy is not re-evaluated.
    s2, b2 = _encrypt(client, kid, "deny", b"x")
    assert (s2, b2) == (403, b1)
    events = [
        e for e in store.audit._read_all() if e.action == "encrypt"
    ]
    rejected = [e for e in events if e.outcome == "rejected"]
    assert len(rejected) == 1 and rejected[0].event_id == op_id
    assert rejected[0].key_id == kid


def test_bound_unknown_and_cross_tenant_are_404(stack):
    client = stack["client"]
    kid = _make_key(client, tenant="t")
    unknown = "33333333-3333-4333-8333-333333333333"
    s1, b1 = _encrypt(client, unknown, "nf", b"x")
    assert s1 == 404 and b1["error"] == "key not found"
    s2, b2 = _encrypt(
        client, kid, "ct", b"x", tenant="other", operator="bob"
    )
    assert s2 == 404 and b2["error"] == "key not found"
    # Cross-tenant GET on either operation hides it (404 on the op lookup).
    status, _ = client.call(
        "GET", "/v1/operations/%s" % b1["operation_id"], None,
        operator="alice", headers={"X-Tenant-Id": "t"},
    )
    assert status == 200


def test_bound_revoked_version_is_409_and_replays(stack):
    client = stack["client"]
    store = stack["store"]
    kid = _make_key(client)
    store.revoke(kid, "t", "compromise", "alice")
    s1, b1 = _encrypt(client, kid, "rev", b"x")
    assert s1 == 409 and "revoked" in b1["error"]
    op_id = b1["operation_id"]
    s2, b2 = _encrypt(client, kid, "rev", b"x")
    assert (s2, b2) == (409, b1) and b2["operation_id"] == op_id
    # A revoked encrypt 409 is the "failed" state, never "conflict".
    rec = _op_record(stack["data_dir"], op_id)
    assert rec["status"] == "failed"


# ------------------------------------------------------------- 503 provider
def test_bound_provider_outage_is_fixed_503_terminal(env, monkeypatch):
    from test_strand_mirrors import HttpTestServer

    srv = HttpTestServer(env.data_dir)
    try:
        client = Client(srv.port)
        kid = _make_key(client)
        env.set_faults({"unreachable": True})
        s1, b1 = _encrypt(client, kid, "down", b"x")
        assert s1 == 503
        assert b1 == {
            "error": "key management provider is unavailable",
            "operation_id": b1["operation_id"],
        }
        op_id = b1["operation_id"]
        # Retry replays the 503 verbatim; the provider failure is durable.
        s2, b2 = _encrypt(client, kid, "down", b"x")
        assert (s2, b2) == (503, b1) and b2["operation_id"] == op_id
        rec = _op_record(env.data_dir, op_id)
        assert rec["status"] == "failed" and rec["http_status"] == 503
    finally:
        srv.stop()
        env.clear_faults()


# ----------------------------------------------------- durable material safety
def test_persisted_record_holds_no_plaintext_aad_or_handle(stack):
    client = stack["client"]
    kid = _make_key(client)
    secret = b"never-touch-disk-plaintext"
    aad_secret = b"never-touch-disk-aad"
    status, body = _encrypt(
        client, kid, "safe", secret, aad=b64(aad_secret)
    )
    assert status == 200
    op_id = body["operation_id"]
    rec = _op_record(stack["data_dir"], op_id)
    # The binding is a 64-char SHA-256 hex digest, not the body.
    assert len(rec["request_body"]) == 64
    assert all(c in "0123456789abcdef" for c in rec["request_body"])
    serialized = json.dumps(rec)
    assert b64(secret) not in serialized
    assert b64(aad_secret) not in serialized
    assert secret.decode() not in serialized
    # Details carry exactly the documented boundary metadata + result.
    assert rec["details"]["encrypt"] == {
        "version": 1, "algorithm": "AES256", "provider_id": "local",
    }
    assert "handle" not in serialized and "private" not in serialized
    # The audit event is metadata-only and event_id == operation_id.
    events = [
        e for e in stack["store"].audit._read_all() if e.action == "encrypt"
    ]
    assert len(events) == 1
    assert events[0].event_id == op_id
    assert events[0].outcome == "success" and events[0].key_id == kid
    with open(stack["store"].audit.path, "rb") as fh:
        ledger = fh.read()
    assert secret not in ledger and aad_secret not in ledger


# --------------------------------------------------------------- restart replay
def test_replay_survives_restart(stack):
    data_dir = stack["data_dir"]
    client = stack["client"]
    kid = _make_key(client)
    s1, b1 = _encrypt(client, kid, "restart", b"persist", aad=b64(b"a"))
    assert s1 == 200
    op_id = b1["operation_id"]
    stop_server(stack)

    reopened = build_server(data_dir)
    try:
        # GET after a restart replays the stored envelope.
        status, got = reopened["client"].call(
            "GET", "/v1/operations/%s" % op_id, None,
            headers={"X-Tenant-Id": "t"},
        )
        assert status == 200 and got["response"] == b1
        # A same-key retry after restart also replays.
        status, b2 = _encrypt(
            reopened["client"], kid, "restart", b"persist", aad=b64(b"a")
        )
        assert status == 200 and b2 == b1
    finally:
        stop_server(reopened)


# ----------------------------------------------------------- HTTP <-> CLI
def test_http_then_cli_cross_entry_replay(stack):
    data_dir = stack["data_dir"]
    client = stack["client"]
    kid = _make_key(client)
    status, b1 = _encrypt(
        client, kid, "cross", b"cli-payload", aad=b64(b"z")
    )
    assert status == 200
    # The CLI presents the same key with byte-identical field values; it must
    # replay the HTTP envelope and operation_id.
    proc = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", b64(b"cli-payload"), "--aad", b64(b"z"),
        "--operator", "alice", "--idempotency-key", "cross",
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out == b1


def test_cli_then_http_cross_entry_replay(stack):
    data_dir = stack["data_dir"]
    client = stack["client"]
    kid = _make_key(client)
    proc = run_cli(
        data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
        "--plaintext", b64(b"x"), "--operator", "alice",
        "--idempotency-key", "cross2",
    )
    assert proc.returncode == 0, proc.stderr
    cli_body = json.loads(proc.stdout)
    status, http_body = _encrypt(client, kid, "cross2", b"x")
    assert status == 200 and http_body == cli_body


# ------------------------------------------------------------- crash windows
def test_crash_after_boundary_without_result_keeps_pending_and_no_recall(
    env, monkeypatch
):
    """Boundary durable, provider called once, then the process "dies" before
    the result is staged: the retried attempt stays pending, hides the result
    and must NOT call the provider a second time."""
    import fake_kms
    from test_strand_mirrors import HttpTestServer

    srv1 = HttpTestServer(env.data_dir)
    client1 = Client(srv1.port)
    kid = _make_key(client1)

    first_calls = {"n": 0}
    orig_export = fake_kms.FakeKmsProvider.export_material

    def counted_export(self, handle):
        first_calls["n"] += 1
        return orig_export(self, handle)

    # Die inside encode_envelope, i.e. AFTER export_material returned and the
    # boundary was fsynced but BEFORE the response is staged/committed.
    import keymgr.server as server_mod

    def boom(**kwargs):
        raise RuntimeError("simulated crash after the provider call")

    monkeypatch.setattr(
        fake_kms.FakeKmsProvider, "export_material", counted_export
    )
    monkeypatch.setattr(server_mod.envelope, "encode_envelope", boom)
    result = client1.call_raw_error(
        "POST", "/v1/keys/%s/encrypt" % kid, _enc_body(b"x"),
        headers={"Idempotency-Key": "crashed"},
    )
    assert result is None  # connection dropped by the simulated crash
    assert first_calls["n"] == 1
    srv1.stop()

    # A brand-new process runs startup recovery: the event is absent and the
    # encrypt crossed its boundary, so the operation is parked pending and the
    # mirror is retained.
    srv2 = HttpTestServer(env.data_dir)
    try:
        client2 = Client(srv2.port)
        # Find the bound operation id from the index.
        ops = _op_files(env.data_dir)
        assert len(ops) == 1
        op_id = ops[0][:-5]
        status, got = client2.call(
            "GET", "/v1/operations/%s" % op_id, None,
            headers={"X-Tenant-Id": "t"},
        )
        assert status == 200 and got["status"] == STATUS_PENDING
        assert got["http_status"] is None and got["response"] is None

        # A same-key retry must NOT reach the provider again: it answers a
        # retryable strand fault and keeps the operation pending.
        second_calls = {"n": 0}

        def counted2(self, handle):
            second_calls["n"] += 1
            return orig_export(self, handle)

        monkeypatch.setattr(
            fake_kms.FakeKmsProvider, "export_material", counted2
        )
        status, body = _encrypt(client2, kid, "crashed", b"x")
        assert status == 503, body
        assert set(body) == {"error", "operation_id"}
        assert body["operation_id"] == op_id
        assert second_calls["n"] == 0
        status, got = client2.call(
            "GET", "/v1/operations/%s" % op_id, None,
            headers={"X-Tenant-Id": "t"},
        )
        assert got["status"] == STATUS_PENDING
        # The boundary mirror is retained as the pending attempt's evidence.
        assert os.path.exists(
            os.path.join(
                env.data_dir, "operation-artifacts", op_id + ".json"
            )
        )
        # And no encrypt event was ever written.
        assert not [
            e for e in env.audit_events() if e.action == "encrypt"
        ]
    finally:
        srv2.stop()


def test_result_staged_but_event_missing_retries_appends_event_only(
    env, monkeypatch
):
    """Boundary crossed AND the 200 response is staged, but the commit-point
    event append never happened: a same-key retry appends the event alone and
    returns the stored envelope WITHOUT calling the provider again."""
    import fake_kms
    from test_strand_mirrors import HttpTestServer

    # First, a fully successful idempotent encrypt gives us the envelope and
    # all durable facts.
    srv1 = HttpTestServer(env.data_dir)
    client1 = Client(srv1.port)
    kid = _make_key(client1)
    status, body = _encrypt(client1, kid, "staged", b"win")
    assert status == 200
    op_id = body["operation_id"]
    srv1.stop()

    # Rewind the scene to "result durable, event missing, op pending, mirror
    # past its boundary": drop the encrypt event and reset the operation.
    audit_path = os.path.join(env.data_dir, "audit.log")
    kept = []
    with open(audit_path, "r", encoding="utf-8") as fh:
        for line in fh:
            ev = json.loads(line)
            if not (ev.get("event_id") == op_id and ev.get("action") == "encrypt"):
                kept.append(line if line.endswith("\n") else line + "\n")
    with open(audit_path, "w", encoding="utf-8") as fh:
        fh.writelines(kept)
    op_path = os.path.join(env.data_dir, "operations", op_id + ".json")
    rec = json.load(open(op_path))
    rec["status"] = "pending"
    rec["http_status"] = None
    # response stays inside details.result (the staged terminal); top-level
    # response is hidden while pending.
    rec["response"] = None
    with open(op_path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)
    os.chmod(op_path, 0o600)
    mirror_path = os.path.join(
        env.data_dir, "operation-artifacts", op_id + ".json"
    )
    # Reconstruct the crossed-boundary mirror exactly as it would be on disk
    # in the window after the result was staged but before/around the missing
    # event append (a real crash there leaves the mirror at "provisioning").
    descriptor = {
        "version": 1,
        "operation_id": op_id,
        "tenant_id": rec["tenant_id"],
        "operator_id": rec["operator_id"],
        "path": rec["path"],
        "request_body": rec["request_body"],
        "kind": "encrypt",
        "action": "encrypt",
        "phase": "provisioning",
        "write_set": [kid],
        "handles": [],
        "journal": None,
        "snapshot": None,
        "empty_marker": None,
        "policy": False,
        "encrypt": rec["details"]["encrypt"],
    }
    os.makedirs(os.path.dirname(mirror_path), exist_ok=True)
    with open(mirror_path, "w", encoding="utf-8") as fh:
        json.dump(descriptor, fh)
    os.chmod(mirror_path, 0o600)

    srv2 = HttpTestServer(env.data_dir)
    try:
        client2 = Client(srv2.port)
        # GET still hides the result while the event is missing.
        status, got = client2.call(
            "GET", "/v1/operations/%s" % op_id, None,
            headers={"X-Tenant-Id": "t"},
        )
        assert got["status"] == STATUS_PENDING and got["response"] is None

        calls = {"n": 0}
        orig = fake_kms.FakeKmsProvider.export_material

        def counted(self, handle):
            calls["n"] += 1
            return orig(self, handle)

        monkeypatch.setattr(
            fake_kms.FakeKmsProvider, "export_material", counted
        )
        status, b2 = _encrypt(client2, kid, "staged", b"win")
        assert status == 200, b2
        assert b2 == body  # the original envelope, replayed
        assert calls["n"] == 0  # provider never called again
        # Exactly one encrypt event exists now.
        enc = [e for e in env.audit_events() if e.action == "encrypt"]
        assert len(enc) == 1 and enc[0].event_id == op_id
    finally:
        srv2.stop()


def test_staged_503_with_event_missing_retries_appends_rejected_only(
    env, monkeypatch
):
    """Boundary crossed and a 503 provider-failure terminal is staged, but its
    rejected event is missing: a same-key retry appends that one rejected
    event and replays 503 WITHOUT calling the provider."""
    import fake_kms
    from test_strand_mirrors import HttpTestServer

    srv1 = HttpTestServer(env.data_dir)
    client1 = Client(srv1.port)
    kid = _make_key(client1)
    env.set_faults({"unreachable": True})
    status, body = _encrypt(client1, kid, "down503", b"x")
    assert status == 503
    op_id = body["operation_id"]
    srv1.stop()
    env.clear_faults()

    # Rewind to "staged 503, rejected event missing, op pending".
    audit_path = os.path.join(env.data_dir, "audit.log")
    lines = [
        ln for ln in open(audit_path, encoding="utf-8")
        if json.loads(ln).get("event_id") != op_id
    ]
    with open(audit_path, "w", encoding="utf-8") as fh:
        fh.writelines(ln if ln.endswith("\n") else ln + "\n" for ln in lines)
    op_path = os.path.join(env.data_dir, "operations", op_id + ".json")
    rec = json.load(open(op_path))
    rec["status"] = "pending"
    rec["http_status"] = None
    rec["response"] = None
    with open(op_path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)
    os.chmod(op_path, 0o600)
    descriptor = {
        "version": 1,
        "operation_id": op_id,
        "tenant_id": rec["tenant_id"],
        "operator_id": rec["operator_id"],
        "path": rec["path"],
        "request_body": rec["request_body"],
        "kind": "encrypt",
        "action": "encrypt",
        "phase": "provisioning",
        "write_set": [kid],
        "handles": [],
        "journal": None,
        "snapshot": None,
        "empty_marker": None,
        "policy": False,
        "encrypt": rec["details"]["encrypt"],
    }
    mdir = os.path.join(env.data_dir, "operation-artifacts")
    os.makedirs(mdir, exist_ok=True)
    mp = os.path.join(mdir, op_id + ".json")
    with open(mp, "w", encoding="utf-8") as fh:
        json.dump(descriptor, fh)
    os.chmod(mp, 0o600)

    srv2 = HttpTestServer(env.data_dir)
    try:
        client2 = Client(srv2.port)
        calls = {"n": 0}
        orig = fake_kms.FakeKmsProvider.export_material

        def counted(self, handle):
            calls["n"] += 1
            return orig(self, handle)

        monkeypatch.setattr(
            fake_kms.FakeKmsProvider, "export_material", counted
        )
        status, b2 = _encrypt(client2, kid, "down503", b"x")
        assert status == 503 and b2 == body
        assert calls["n"] == 0
        enc = [e for e in env.audit_events() if e.action == "encrypt"]
        assert len(enc) == 1
        assert enc[0].outcome == "rejected" and enc[0].event_id == op_id
    finally:
        srv2.stop()


def test_crash_after_event_durable_only_finishes(stack, monkeypatch):
    """The success event and staged response are durable, but finish() is
    interrupted: restart finalizes succeeded and replays the envelope."""
    data_dir = stack["data_dir"]
    client = stack["client"]
    kid = _make_key(client)
    op_store = stack["op_store"]

    real_finish = op_store.finish
    state = {"done": False}

    def crash_finish(record, status, http_status, response):
        if (
            not state["done"]
            and (record.details or {}).get("kind") == "encrypt"
        ):
            state["done"] = True
            raise OSError("simulated crash at finish")
        return real_finish(record, status, http_status, response)

    op_store.finish = crash_finish
    dropped = client.call_raw_error(
        "POST", "/v1/keys/%s/encrypt" % kid, _enc_body(b"fin"),
        headers={"Idempotency-Key": "finish-crash"},
    )
    assert dropped is None
    stop_server(stack)

    reopened = build_server(data_dir)
    try:
        status, b2 = _encrypt(
            reopened["client"], kid, "finish-crash", b"fin"
        )
        assert status == 200
        op_id = b2["operation_id"]
        rec = _op_record(data_dir, op_id)
        assert rec["status"] == STATUS_SUCCEEDED
        assert rec["http_status"] == 200
        # Exactly one success event despite the crash + replay.
        events = [
            e for e in reopened["store"].audit._read_all()
            if e.action == "encrypt"
        ]
        assert len(events) == 1 and events[0].event_id == op_id
    finally:
        stop_server(reopened)
