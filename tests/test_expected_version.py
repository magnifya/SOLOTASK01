"""Optional optimistic-concurrency precondition (expected_version) for rotation.

Covers the strict rotate body shape (only {tenant_id, algorithm,
expected_version?}; a positive non-bool integer precondition; illegal or
extra fields are side-effect-free 400s before the Idempotency-Key is bound),
the atomic precondition check on the committed current_version before any
provider call (single-key 409, whole-batch 409 on any mismatch, no handles
minted, no files changed), the bound conflict terminal (body keys
error,operation_id; operation status conflict; exactly one rotate or
batch_rotate/rejected audit event, batch key_id null), idempotent replay of
both conflict and success across a restart without re-judging the
precondition, single-winner concurrency, and the CLI --expected-version /
--items shapes.
"""

import json
import os
import subprocess
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
from keymgr.store import KeyStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _open_server(data_dir):
    """Build a running HTTP stack on an existing data dir (a 'restart')."""
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
    return types.SimpleNamespace(
        data_dir=data_dir, store=store, audit=audit_log, client=client,
        httpd=httpd,
    )


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    stack = _open_server(data_dir)
    yield stack
    stack.httpd.shutdown()
    provider_mod.reset_for_tests()


def _restart(stack):
    """Close the stack and reopen a fresh server on the same data dir."""
    stack.httpd.shutdown()
    provider_mod.reset_for_tests()
    return _open_server(stack.data_dir)


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


def _gen(stack, tenant="t", algorithm="AES256", label="k"):
    status, body = stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": label},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(stack, key_id, idem, body_extra=None, tenant="t",
            algorithm="AES256"):
    body = {"tenant_id": tenant, "algorithm": algorithm}
    if body_extra:
        body.update(body_extra)
    return stack.client.call(
        "POST", "/v1/keys/%s/rotate" % key_id, body,
        headers={"Idempotency-Key": idem},
    )


def _batch(stack, items, idem, tenant="t"):
    return stack.client.call(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": tenant, "items": items},
        headers={"Idempotency-Key": idem},
    )


def _events(stack, action=None):
    events = stack.audit._read_all()
    if action is not None:
        events = [e for e in events if e.action == action]
    return events


def _current_version(stack, key_id, tenant="t"):
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/current?tenant_id=%s" % (key_id, tenant)
    )
    assert status == 200, body
    return body["version"]


def _operation_count(stack):
    ops_dir = os.path.join(stack.data_dir, "operations")
    try:
        names = os.listdir(ops_dir)
    except OSError:
        return 0
    return len([n for n in names if n.endswith(".json") and n != "index.json"])


# -- single-key rotate -----------------------------------------------------

def test_rotate_expected_version_success(stack):
    key_id = _gen(stack)
    status, body = _rotate(stack, key_id, "r1", {"expected_version": 1})
    assert status == 201, body
    assert body["version"] == 2
    status, body = _rotate(stack, key_id, "r2", {"expected_version": 2})
    assert status == 201, body
    assert body["version"] == 3


def test_rotate_without_expected_version_keeps_old_semantics(stack):
    key_id = _gen(stack)
    status, body = _rotate(stack, key_id, "r1")
    assert status == 201, body
    assert body["version"] == 2


def test_rotate_expected_version_conflict_is_bound_409(stack):
    key_id = _gen(stack)
    status, body = _rotate(stack, key_id, "r1", {"expected_version": 5})
    assert status == 409, body
    # The bound conflict body is exactly error,operation_id in that order.
    assert list(body.keys()) == ["error", "operation_id"]
    # No version appended, exactly one rotate/rejected event carrying key_id.
    assert _current_version(stack, key_id) == 1
    events = _events(stack, "rotate")
    assert len(events) == 1
    event = events[-1]
    assert event.outcome == "rejected"
    assert event.key_id == key_id
    assert event.event_id == body["operation_id"]
    # The operation is a durable conflict terminal.
    status, op = stack.client.call(
        "GET",
        "/v1/operations/%s?tenant_id=t" % body["operation_id"],
    )
    assert status == 200
    assert op["status"] == "conflict"
    assert op["http_status"] == 409
    # An identical retry replays the same terminal; no second event.
    status, replay = _rotate(stack, key_id, "r1", {"expected_version": 5})
    assert status == 409
    assert replay == body
    assert len(_events(stack, "rotate")) == 1


def test_rotate_conflict_and_success_replay_after_restart(stack):
    key_id = _gen(stack)
    status, conflict = _rotate(stack, key_id, "r1", {"expected_version": 9})
    assert status == 409
    status, success = _rotate(stack, key_id, "r2", {"expected_version": 1})
    assert status == 201
    assert success["version"] == 2

    stack2 = _restart(stack)
    try:
        # The conflict replays verbatim without re-judging the precondition
        # (the committed current_version is now 2, not 9 or 1).
        status, body = _rotate(stack2, key_id, "r1", {"expected_version": 9})
        assert status == 409
        assert body == conflict
        # The success replays the original version even though the
        # precondition value no longer matches the committed version.
        status, body = _rotate(stack2, key_id, "r2", {"expected_version": 1})
        assert status == 201
        assert body == success
        assert _current_version(stack2, key_id) == 2
        rejected = [e for e in _events(stack2) if e.outcome == "rejected"]
        assert len(rejected) == 1
    finally:
        stack2.httpd.shutdown()


def test_rotate_expected_version_idempotency_binding(stack):
    key_id = _gen(stack)
    status, first = _rotate(stack, key_id, "r1", {"expected_version": 1})
    assert status == 201
    # The canonical request carries expected_version: the same key with a
    # different precondition is a different binding -> 409 naming the
    # original operation_id.
    status, body = _rotate(stack, key_id, "r1", {"expected_version": 2})
    assert status == 409
    assert body["operation_id"] == first["operation_id"]
    assert "already bound" in body["error"]
    # Same key without the precondition is also a different binding.
    status, body = _rotate(stack, key_id, "r1")
    assert status == 409
    assert body["operation_id"] == first["operation_id"]
    assert _current_version(stack, key_id) == 2


@pytest.mark.parametrize("bad", [0, -1, 1.5, "1", True, False, [], {}])
def test_rotate_expected_version_invalid_is_side_effect_free_400(stack, bad):
    key_id = _gen(stack)
    before = len(_events(stack))
    status, body = _rotate(stack, key_id, "r1", {"expected_version": bad})
    assert status == 400, body
    assert "expected_version" in body["error"]
    # Zero side effects: no audit event, no operation record, no version.
    assert len(_events(stack)) == before
    assert _operation_count(stack) == 0
    assert _current_version(stack, key_id) == 1
    # The Idempotency-Key was not consumed: a valid request binds it anew.
    status, body = _rotate(stack, key_id, "r1", {"expected_version": 1})
    assert status == 201, body


def test_rotate_extra_field_is_side_effect_free_400(stack):
    key_id = _gen(stack)
    before = len(_events(stack))
    status, body = _rotate(stack, key_id, "r1", {"label": "x"})
    assert status == 400, body
    assert "label" in body["error"]
    assert len(_events(stack)) == before
    assert _operation_count(stack) == 0
    assert _current_version(stack, key_id) == 1


def test_concurrent_rotations_single_winner(stack):
    key_id = _gen(stack)
    results = []

    def worker(index):
        results.append(
            _rotate(stack, key_id, "race-%d" % index,
                    {"expected_version": 1})[0]
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # Exactly one rotation passes the same version precondition.
    assert sorted(results) == [201, 409, 409, 409, 409, 409]
    assert _current_version(stack, key_id) == 2


# -- batch rotate ----------------------------------------------------------

def test_batch_rotate_expected_version_success(stack):
    key1 = _gen(stack, label="a")
    key2 = _gen(stack, label="b")
    status, body = _batch(stack, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 1},
    ], "b1")
    assert status == 201, body
    assert [item["version"] for item in body["items"]] == [2, 2]


def test_batch_rotate_one_mismatch_fails_whole_batch(stack):
    key1 = _gen(stack, label="a")
    key2 = _gen(stack, label="b")
    status, body = _batch(stack, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 7},
    ], "b1")
    assert status == 409, body
    assert list(body.keys()) == ["error", "operation_id"]
    # Zero changes on every key; one batch_rotate/rejected, key_id null.
    assert _current_version(stack, key1) == 1
    assert _current_version(stack, key2) == 1
    events = _events(stack, "batch_rotate")
    assert len(events) == 1
    event = events[-1]
    assert event.outcome == "rejected"
    assert event.key_id is None
    # A retry replays the conflict without a second event.
    status, replay = _batch(stack, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 7},
    ], "b1")
    assert status == 409
    assert replay == body
    assert len(_events(stack, "batch_rotate")) == 1


def test_batch_rotate_item_validation(stack):
    key_id = _gen(stack)
    before = len(_events(stack))
    # An unknown item field is a pre-binding 400 naming the field.
    status, body = _batch(stack, [
        {"key_id": key_id, "algorithm": "AES256", "label": "x"},
    ], "b1")
    assert status == 400
    assert "label" in body["error"]
    # A non-positive-integer precondition is a 400 naming expected_version.
    for bad in (0, -1, 1.5, "1", True):
        status, body = _batch(stack, [
            {"key_id": key_id, "algorithm": "AES256",
             "expected_version": bad},
        ], "b1")
        assert status == 400, (bad, body)
        assert "expected_version" in body["error"]
    assert len(_events(stack)) == before
    assert _operation_count(stack) == 0
    assert _current_version(stack, key_id) == 1
    # The key was never consumed.
    status, body = _batch(stack, [
        {"key_id": key_id, "algorithm": "AES256", "expected_version": 1},
    ], "b1")
    assert status == 201, body


# -- CLI -------------------------------------------------------------------

def _cli_env():
    env = dict(os.environ)
    env.pop("KEYMGR_PROVIDER", None)
    env["PYTHONPATH"] = TESTS_DIR + os.pathsep + REPO_ROOT
    return env


def run_cli(data_dir, *args, timeout=60):
    cmd = [sys.executable, "-m", "keymgr", "--data-dir", data_dir] + [
        str(a) for a in args
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, env=_cli_env(), timeout=timeout
    )


def _json_out(proc):
    for stream in (proc.stdout, proc.stderr):
        text = stream.strip()
        if text.startswith("{"):
            return json.loads(text)
    raise AssertionError(
        "no JSON body: rc=%d out=%r err=%r"
        % (proc.returncode, proc.stdout, proc.stderr)
    )


@pytest.fixture()
def cli_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    yield data_dir
    provider_mod.reset_for_tests()


def _cli_gen(data_dir, tenant="t"):
    proc = run_cli(
        data_dir, "gen", "--tenant-id", tenant, "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["key_id"]


def test_cli_rotate_expected_version(cli_dir):
    key_id = _cli_gen(cli_dir)
    proc = run_cli(
        cli_dir, "rotate", "--tenant-id", "t", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "r1", "--expected-version", "1",
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["version"] == 2
    # A stale precondition is a bound conflict: exit 3, error+operation_id.
    proc = run_cli(
        cli_dir, "rotate", "--tenant-id", "t", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "r2", "--expected-version", "1",
    )
    assert proc.returncode == 3
    conflict = _json_out(proc)
    assert list(conflict.keys()) == ["error", "operation_id"]
    # A same-key retry replays the conflict verbatim (no re-judgment).
    proc = run_cli(
        cli_dir, "rotate", "--tenant-id", "t", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "r2", "--expected-version", "1",
    )
    assert proc.returncode == 3
    assert _json_out(proc) == conflict
    # The operation is queryable as a conflict terminal.
    proc = run_cli(
        cli_dir, "operation", "--tenant-id", "t", "--operator", "alice",
        "--operation-id", conflict["operation_id"],
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["status"] == "conflict"


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5"])
def test_cli_rotate_expected_version_invalid_exit_2(cli_dir, bad):
    key_id = _cli_gen(cli_dir)
    proc = run_cli(
        cli_dir, "rotate", "--tenant-id", "t", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "r1", "--expected-version", bad,
    )
    assert proc.returncode == 2
    assert "expected_version" in _json_out(proc)["error"]
    # The invalid attempt consumed nothing: the key still binds.
    proc = run_cli(
        cli_dir, "rotate", "--tenant-id", "t", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "r1", "--expected-version", "1",
    )
    assert proc.returncode == 0, proc.stderr


def test_cli_batch_rotate_expected_version(cli_dir):
    key1 = _cli_gen(cli_dir)
    key2 = _cli_gen(cli_dir)
    items = json.dumps([
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 1},
    ])
    proc = run_cli(
        cli_dir, "batch-rotate", "--tenant-id", "t", "--operator", "alice",
        "--idempotency-key", "b1", "--items", items,
    )
    assert proc.returncode == 0, proc.stderr
    assert [i["version"] for i in json.loads(proc.stdout)["items"]] == [2, 2]
    # Any mismatch fails the whole batch with exit 3 and zero changes.
    items = json.dumps([
        {"key_id": key1, "algorithm": "AES256", "expected_version": 2},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 1},
    ])
    proc = run_cli(
        cli_dir, "batch-rotate", "--tenant-id", "t", "--operator", "alice",
        "--idempotency-key", "b2", "--items", items,
    )
    assert proc.returncode == 3
    assert list(_json_out(proc).keys()) == ["error", "operation_id"]
    # An invalid item precondition is an exit-2 parameter error.
    items = json.dumps([
        {"key_id": key1, "algorithm": "AES256", "expected_version": 0},
    ])
    proc = run_cli(
        cli_dir, "batch-rotate", "--tenant-id", "t", "--operator", "alice",
        "--idempotency-key", "b3", "--items", items,
    )
    assert proc.returncode == 2
    assert "expected_version" in _json_out(proc)["error"]
