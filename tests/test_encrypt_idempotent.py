"""Idempotent HTTP envelope-encrypt: binding, replay, conflict, recovery.

POST /v1/keys/{key_id}/encrypt requires a single Idempotency-Key header. A
missing/empty/duplicate/illegal key -- and every parse/parameter failure
before the key is bound -- is a side-effect-free 400 (no audit event,
operation record or provider handle). Once bound, the operation commits
exactly one ``encrypt`` audit event named after its operation_id; identical
retries replay the stored response byte-for-byte, a same-key different
request answers 409 naming the original operation. A crash before the
commit-point event leaves the operation pending (its staged envelope
hidden); once the event is durable, a restart or retry replays the staged
response verbatim without re-encrypting. The plaintext and AAD never touch
the disk: the persisted binding carries only their digests.
"""

import base64
import hashlib
import http.client
import itertools
import json
import os
import subprocess
import sys
import threading
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
from keymgr.server import _resolve_committed_operation, make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


class Stack:
    """One full wiring over a data dir, like one serve() process."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        audit_log = AuditLog(data_dir)
        self.store = KeyStore(data_dir, audit_log)
        self.policies = PolicyStore(data_dir, audit_log)
        self.coordinator = restore_mod.RestoreCoordinator(
            self.store, self.policies
        )
        self.op_store = OperationStore(data_dir, audit_log)
        self.artifact_store = ArtifactStore(data_dir, self.store, audit_log)
        self.artifact_store.settle_pending(self.op_store)
        self.op_store.recover_pending(
            lambda record, event: _resolve_committed_operation(
                self.store, self.policies, record, event
            ),
            is_parked=self.artifact_store.is_parked,
        )

    def serve(self):
        handler = make_handler(
            self.store, self.policies, self.coordinator, self.op_store,
            self.artifact_store,
        )
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        httpd.daemon_threads = True
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd, Client(
            "http://127.0.0.1:%d" % httpd.server_address[1]
        )


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    yield str(tmp_path / "data")
    provider_mod.reset_for_tests()


@pytest.fixture()
def servers():
    running = []

    def start(stack):
        httpd, client = stack.serve()
        running.append(httpd)
        return client

    yield start
    for httpd in running:
        httpd.shutdown()


class Client:
    def __init__(self, base):
        self.base = base
        self.port = int(base.rsplit(":", 1)[1])

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
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def raw_post_duplicate_key(self, path, body, keys):
        """POST with several Idempotency-Key headers (urllib cannot)."""
        payload = json.dumps(body).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.putrequest("POST", path)
        conn.putheader("X-Operator-Id", "alice")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(payload)))
        for key in keys:
            conn.putheader("Idempotency-Key", key)
        conn.endheaders(payload)
        resp = conn.getresponse()
        status = resp.status
        out = json.loads(resp.read())
        conn.close()
        return status, out


_counter = itertools.count(1)


def _key():
    return "enc-%d" % next(_counter)


def _encrypt(client, kid, tenant="t", plaintext=b"x", idem=None, **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % kid, body,
        headers={"Idempotency-Key": idem or _key()},
    )


def _make_key(client, tenant="t", algorithm="AES256"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _get_operation(client, operation_id, tenant="t", operator="alice"):
    return client.call(
        "GET", "/v1/operations/%s" % operation_id,
        operator=operator, headers={"X-Tenant-Id": tenant},
    )


def _events(stack, tenant="t", action=None):
    page = stack.store.audit.query(tenant, action=action, limit=1000)
    return page.events


def _redacted_normalized(kid_path_unused, body, raw_plaintext, raw_aad):
    """The exact redacted canonical body the server persists for a bind."""
    redacted = dict(body)
    redacted["plaintext"] = (
        "sha256:" + hashlib.sha256(raw_plaintext).hexdigest()
    )
    if raw_aad is not None:
        redacted["aad"] = "sha256:" + hashlib.sha256(raw_aad).hexdigest()
    return json.dumps(
        redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


# ------------------------------------------------------------- key header
def test_idempotency_key_header_validation_is_side_effect_free(
    data_dir, servers
):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    body = {"tenant_id": "t", "plaintext": b64(b"x")}

    # Missing header.
    status, out = client.call("POST", path, body)
    assert status == 400 and "Idempotency-Key" in out["error"]
    # Empty header.
    status, out = client.call(
        "POST", path, body, headers={"Idempotency-Key": ""}
    )
    assert status == 400 and "Idempotency-Key" in out["error"]
    # Illegal characters and overlong values.
    for bad in ("bad key!", "bad/key", "x" * 129, " clé"):
        status, out = client.call(
            "POST", path, body, headers={"Idempotency-Key": bad}
        )
        assert status == 400 and "Idempotency-Key" in out["error"], bad
    # Duplicated header.
    status, out = client.raw_post_duplicate_key(path, body, ["k1", "k2"])
    assert status == 400 and "Idempotency-Key" in out["error"]

    # None of the rejections left an operation, audit event or artifact.
    assert _events(stack, action="encrypt") == []
    assert os.listdir(stack.op_store.dir_path) == []
    artifacts = os.path.join(data_dir, "operation-artifacts")
    assert not os.path.isdir(artifacts) or os.listdir(artifacts) == []


def test_prebind_parameter_400_leaves_no_trace_and_key_stays_usable(
    data_dir, servers
):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    path = "/v1/keys/%s/encrypt" % kid
    idem = _key()

    bad_bodies = [
        {"tenant_id": "t"},  # missing plaintext
        {"tenant_id": "t", "plaintext": "!!!"},  # invalid base64
        {"tenant_id": "t", "plaintext": b64(b"x"), "aad": "!!!"},
        {"tenant_id": "t", "plaintext": b64(b"x"), "version": 0},
        {"tenant_id": "t", "plaintext": b64(b"x"), "version": "1.5"},
        {"plaintext": b64(b"x")},  # missing tenant_id
    ]
    for body in bad_bodies:
        status, out = client.call(
            "POST", path, body, headers={"Idempotency-Key": idem}
        )
        # Pre-binding failures are plain {"error": ...}: no operation_id.
        assert status == 400 and set(out) == {"error"}, (body, out)
    # A malformed key_id is a pre-binding 400 as well.
    status, out = client.call(
        "POST", "/v1/keys/not-a-uuid/encrypt",
        {"tenant_id": "t", "plaintext": b64(b"x")},
        headers={"Idempotency-Key": idem},
    )
    assert status == 400 and set(out) == {"error"}

    # Nothing was recorded: no operation, no audit event of any kind beyond
    # the key creation, no artifact mirror.
    assert os.listdir(stack.op_store.dir_path) == []
    assert [e.action for e in _events(stack)] == ["create"]

    # The same Idempotency-Key is still usable: it was never consumed.
    status, out = _encrypt(client, kid, plaintext=b"redeemed", idem=idem)
    assert status == 200 and out["format"] == env_mod.FORMAT


# ---------------------------------------------------------- success shape
def test_success_body_key_order_and_get_operation(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    status, body = _encrypt(
        client, kid, plaintext=b"shaped", aad=b64(b"ctx")
    )
    assert status == 200
    assert list(body) == ["format", "envelope", "operation_id"]
    assert body["format"] == "keymgr-envelope-v1"
    # The envelope is a base64 keymgr-envelope-v1 token.
    payload = json.loads(base64.b64decode(body["envelope"]))
    assert payload["format"] == env_mod.FORMAT
    assert payload["key_id"] == kid

    op_id = body["operation_id"]
    status, op = _get_operation(client, op_id)
    assert status == 200
    assert list(op) == [
        "operation_id", "tenant_id", "status", "http_status", "response",
    ]
    assert op["operation_id"] == op_id
    assert op["tenant_id"] == "t"
    assert op["status"] == "succeeded"
    assert op["http_status"] == 200
    assert op["response"] == body

    # Another operator or tenant cannot see the operation.
    status, _ = _get_operation(client, op_id, operator="bob")
    assert status == 404
    status, _ = _get_operation(client, op_id, tenant="other")
    assert status == 404


def test_replay_same_key_same_request(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    status, first = _encrypt(
        client, kid, plaintext=b"replay-me", aad=b64(b"a"), idem=idem
    )
    assert status == 200
    # An identical retry replays the stored response byte-for-byte: the
    # same envelope (no re-encryption) and the same operation_id.
    status, second = _encrypt(
        client, kid, plaintext=b"replay-me", aad=b64(b"a"), idem=idem
    )
    assert status == 200
    assert second == first

    # Exactly one encrypt audit event, named after the operation_id.
    events = _events(stack, action="encrypt")
    assert len(events) == 1
    assert events[0].event_id == first["operation_id"]
    assert events[0].outcome == "success"
    assert events[0].key_id == kid

    # Key order in the body does not matter for the binding.
    status, third = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid,
        {"aad": b64(b"a"), "plaintext": b64(b"replay-me"), "tenant_id": "t"},
        headers={"Idempotency-Key": idem},
    )
    assert status == 200 and third == first
    assert len(_events(stack, action="encrypt")) == 1


def test_same_key_different_request_conflicts(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    status, first = _encrypt(client, kid, plaintext=b"original", idem=idem)
    assert status == 200
    op_id = first["operation_id"]

    # Different plaintext, different aad, different explicit version and a
    # different tenant/operator all bind differently -> 409 naming the
    # original operation_id.
    for extra in (
        {"plaintext": b64(b"changed")},
        {"plaintext": b64(b"original"), "aad": b64(b"other")},
        {"plaintext": b64(b"original"), "version": 1},
    ):
        body = {"tenant_id": "t"}
        body.update(extra)
        status, out = client.call(
            "POST", "/v1/keys/%s/encrypt" % kid, body,
            headers={"Idempotency-Key": idem},
        )
        assert status == 409
        assert set(out) == {"error", "operation_id"}
        assert out["operation_id"] == op_id
    status, out = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid,
        {"tenant_id": "other", "plaintext": b64(b"original")},
        headers={"Idempotency-Key": idem}, operator="bob",
    )
    assert status == 409 and out["operation_id"] == op_id

    # The conflict wrote no additional audit event.
    assert len(_events(stack, action="encrypt")) == 1


# ------------------------------------------------------- terminal replays
def test_policy_denial_is_a_replaying_terminal(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    stack.policies.put("t", [Rule("alice", ["create", "read"], "allow")])

    idem = _key()
    status, out = _encrypt(client, kid, idem=idem)
    assert status == 403
    assert set(out) == {"error", "operation_id"}
    assert out["error"] == "action not permitted by policy"

    # The rejection is durable and replays verbatim, even after the policy
    # is opened up again: a terminal is never re-evaluated.
    stack.policies.delete("t")
    status, replay = _encrypt(client, kid, idem=idem)
    assert status == 403 and replay == out

    events = _events(stack, action="encrypt")
    assert len(events) == 1
    assert events[0].event_id == out["operation_id"]
    assert events[0].outcome == "rejected"
    assert events[0].key_id == kid


def test_revoked_key_409_terminal_replays(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    stack.store.revoke(kid, "t", "compromise", "alice")
    idem = _key()
    status, out = _encrypt(client, kid, idem=idem)
    assert status == 409
    assert set(out) == {"error", "operation_id"}
    assert "revoked" in out["error"]
    status, replay = _encrypt(client, kid, idem=idem)
    assert status == 409 and replay == out
    events = _events(stack, action="encrypt")
    assert len(events) == 1
    assert events[0].event_id == out["operation_id"]
    assert events[0].outcome == "rejected"


def test_provider_unavailable_503_terminal_replays(env, servers):
    stack = Stack(env.data_dir)
    client = servers(stack)
    kid = _make_key(client)
    env.set_faults({"unreachable": True})
    idem = _key()
    status, out = _encrypt(client, kid, idem=idem)
    assert status == 503
    assert out["error"] == "key management provider is unavailable"
    assert set(out) == {"error", "operation_id"}

    # The backend recovers: the bound terminal still replays verbatim
    # instead of re-attempting the provider call.
    env.clear_faults()
    status, replay = _encrypt(client, kid, idem=idem)
    assert status == 503 and replay == out
    events = [
        e for e in AuditLog(env.data_dir)._read_all()
        if e.action == "encrypt"
    ]
    assert len(events) == 1
    assert events[0].event_id == out["operation_id"]
    assert events[0].outcome == "rejected"


def test_lock_wait_timeout_503_writes_nothing(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    path = "/v1/keys/%s/encrypt" % kid
    normalized = _redacted_normalized(
        path, {"tenant_id": "t", "plaintext": b64(b"x")}, b"x", None
    )
    begin = stack.op_store.begin("t", "alice", path, normalized, idem)
    assert begin.kind == "new"
    op_id = begin.record.operation_id

    # A live owner holds the attempt claim: the concurrent same-key request
    # waits, times out after 5 s and answers 503 timed_out without writing.
    with stack.artifact_store._claim(op_id, True):
        status, out = _encrypt(client, kid, idem=idem)
        assert status == 503
        assert out == {
            "error": "operation timed out waiting for a lock",
            "operation_id": op_id,
        }
    record = stack.op_store._read_record(op_id)
    assert record.status == "pending"
    assert _events(stack, action="encrypt") == []


# --------------------------------------------------------- crash recovery
def _craft_pending_encrypt(stack, kid, idem, plaintext=b"x", aad=None,
                           stage=None, append_event=False):
    """Bind an encrypt operation and drive it to a chosen crash point."""
    path = "/v1/keys/%s/encrypt" % kid
    body = {"tenant_id": "t", "plaintext": b64(plaintext)}
    if aad is not None:
        body["aad"] = b64(aad)
    normalized = _redacted_normalized(path, body, plaintext, aad)
    begin = stack.op_store.begin("t", "alice", path, normalized, idem)
    assert begin.kind == "new"
    operation = begin.record
    stack.op_store.update_details(
        operation, {"kind": "encrypt", "key_id": kid}
    )
    if stage is not None:
        stack.op_store.stage_terminal(operation, 200, stage)
    if append_event:
        stack.store.audit_attempt(
            "t", kid, "encrypt", "success",
            event_id=operation.operation_id,
        )
    return operation


def test_crash_before_event_stays_pending_and_hides_envelope(
    data_dir, servers
):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    staged = {
        "format": env_mod.FORMAT,
        "envelope": b64(b"never-committed-envelope"),
        "operation_id": None,  # filled below
    }
    operation = _craft_pending_encrypt(
        stack, kid, idem, plaintext=b"crash-secret", stage=None,
    )
    staged["operation_id"] = operation.operation_id
    stack.op_store.stage_terminal(operation, 200, staged)
    # Crash: no audit event, no finish. A brand-new process opens the dir.
    reopened = Stack(data_dir)
    client2 = servers(reopened)

    # The operation stays pending and the staged envelope stays hidden.
    status, op = _get_operation(client2, operation.operation_id)
    assert status == 200
    assert op["status"] == "pending"
    assert op["http_status"] is None
    assert op["response"] is None
    assert _events(reopened, action="encrypt") == []

    # A same-key retry re-drives the attempt under the same operation_id.
    status, out = _encrypt(
        client2, kid, plaintext=b"crash-secret", idem=idem
    )
    assert status == 200
    assert out["operation_id"] == operation.operation_id
    assert out["envelope"] != staged["envelope"]
    events = _events(reopened, action="encrypt")
    assert len(events) == 1
    assert events[0].event_id == operation.operation_id


def test_crash_with_surviving_mirror_is_taken_over(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    operation = _craft_pending_encrypt(stack, kid, idem, plaintext=b"mirrored")
    # A real mid-request crash leaves the attempt's mirror behind at the
    # bound phase (described, never provisioned, no event).
    mirror = stack.artifact_store.create(operation)
    mirror.describe({"kind": "encrypt", "write_set": [kid]})

    reopened = Stack(data_dir)
    client2 = servers(reopened)
    # The operation stays pending across the restart...
    status, op = _get_operation(client2, operation.operation_id)
    assert status == 200 and op["status"] == "pending"
    assert op["http_status"] is None and op["response"] is None
    # ...and a same-key retry takes the clean strand over under the same
    # operation_id and runs exactly once.
    status, out = _encrypt(client2, kid, plaintext=b"mirrored", idem=idem)
    assert status == 200
    assert out["operation_id"] == operation.operation_id
    events = _events(reopened, action="encrypt")
    assert len(events) == 1
    assert events[0].event_id == operation.operation_id


def test_crash_after_event_replays_verbatim_without_reencrypt(
    data_dir, servers
):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    operation = _craft_pending_encrypt(stack, kid, idem, plaintext=b"durable")
    staged = {
        "format": env_mod.FORMAT,
        "envelope": b64(b"committed-envelope-bytes"),
        "operation_id": operation.operation_id,
    }
    stack.op_store.stage_terminal(operation, 200, staged)
    stack.store.audit_attempt(
        "t", kid, "encrypt", "success", event_id=operation.operation_id
    )
    # Crash after the commit-point event but before finish. Restart.
    reopened = Stack(data_dir)
    client2 = servers(reopened)

    # Recovery finalized the operation from the staged response alone.
    status, op = _get_operation(client2, operation.operation_id)
    assert status == 200
    assert op["status"] == "succeeded"
    assert op["http_status"] == 200
    assert op["response"] == staged

    # A retry replays the staged body byte-for-byte: no re-encryption, no
    # second audit event.
    status, out = _encrypt(client2, kid, plaintext=b"durable", idem=idem)
    assert status == 200
    assert out == staged
    events = _events(reopened, action="encrypt")
    assert len(events) == 1
    assert events[0].event_id == operation.operation_id


def test_crash_after_rejected_event_replays_terminal(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    idem = _key()
    operation = _craft_pending_encrypt(stack, kid, idem, plaintext=b"deny")
    body = {
        "error": "action not permitted by policy",
        "operation_id": operation.operation_id,
    }
    stack.op_store.stage_terminal(
        operation, 403, body,
        audit={
            "action": "encrypt", "outcome": "rejected",
            "tenant_id": "t", "key_id": kid,
        },
    )
    stack.store.audit_attempt(
        "t", kid, "encrypt", "rejected", event_id=operation.operation_id
    )
    reopened = Stack(data_dir)
    client2 = servers(reopened)

    status, op = _get_operation(client2, operation.operation_id)
    assert status == 200
    assert op["status"] == "failed"
    assert op["http_status"] == 403
    assert op["response"] == body
    status, out = _encrypt(client2, kid, plaintext=b"deny", idem=idem)
    assert status == 403 and out == body
    assert len(_events(reopened, action="encrypt")) == 1


# ------------------------------------------------------------- secrecy
def test_plaintext_and_aad_never_touch_the_disk(data_dir, servers):
    stack = Stack(data_dir)
    client = servers(stack)
    kid = _make_key(client)
    plaintext = b"plaintext-must-never-be-persisted"
    aad = b"aad-must-never-be-persisted"
    status, body = _encrypt(
        client, kid, plaintext=plaintext, aad=b64(aad)
    )
    assert status == 200

    secrets = [
        plaintext,
        aad,
        b64(plaintext).encode("ascii"),
        b64(aad).encode("ascii"),
    ]
    for root, _dirs, files in os.walk(data_dir):
        for name in files:
            with open(os.path.join(root, name), "rb") as fh:
                content = fh.read()
            for secret in secrets:
                assert secret not in content, (name, secret)

    # The persisted binding carries only the digests.
    with open(
        stack.op_store._path_for(body["operation_id"]), "r",
        encoding="utf-8",
    ) as fh:
        record = json.load(fh)
    assert '"plaintext":"sha256:%s"' % hashlib.sha256(
        plaintext
    ).hexdigest() in record["request_body"]
    assert '"aad":"sha256:%s"' % hashlib.sha256(
        aad
    ).hexdigest() in record["request_body"]
    # The opaque envelope and its metadata are what gets persisted.
    assert record["response"]["envelope"] == body["envelope"]
    assert record["response"]["format"] == env_mod.FORMAT


# ------------------------------------------------------------------- CLI
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cli_env(data_dir):
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        os.path.dirname(os.path.abspath(__file__)) + os.pathsep + REPO_ROOT
    )
    env.pop("KEYMGR_PROVIDER", None)
    env["KEYMGR_DATA_DIR"] = data_dir
    return env


def _run_cli(data_dir, *args):
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


def test_cli_encrypt_behavior_unchanged(tmp_path):
    """The CLI encrypt needs no Idempotency-Key and stays non-idempotent."""
    data_dir = str(tmp_path / "data")
    proc = _run_cli(
        data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert proc.returncode == 0
    kid = _json(proc)["key_id"]

    envelopes = []
    for _ in range(2):
        proc = _run_cli(
            data_dir, "encrypt", "--tenant-id", "t", "--key-id", kid,
            "--plaintext", b64(b"cli"), "--operator", "alice",
        )
        assert proc.returncode == 0
        out = _json(proc)
        # No operation_id: the CLI does not bind idempotent operations.
        assert list(out) == ["format", "envelope"]
        envelopes.append(out["envelope"])
    # Every CLI call encrypts freshly and audits its own event.
    assert envelopes[0] != envelopes[1]
    events = [
        e for e in AuditLog(data_dir)._read_all() if e.action == "encrypt"
    ]
    assert len(events) == 2
    # And no operation records were created by the CLI encrypts.
    op_dir = os.path.join(data_dir, "operations")
    assert not os.path.isdir(op_dir) or os.listdir(op_dir) == []
