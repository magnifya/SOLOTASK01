"""Regression tests for the directed-switchover idempotency defect.

After an operation is BOUND to an Idempotency-Key, a directed switchover (or
reconnect) that makes a different ``provider_id`` active must not terminalize
the operation when the provider it needs WAS active earlier in this data
directory (the built-in ``local`` provider included): the attempt answers the
fixed 503 but stays ``pending`` (http_status/response null, no audit event, no
backend call/handle/key/artifact change) and continues under the same
operation_id/event_id exactly once once a provider with the same id is active
again. A provider id that was NEVER active here still gets the terminal 503
with one rejected event, and a same-key/different-binding request answers 409
naming the original operation.

Covers HTTP rotate/batch-rotate/import/restore/encrypt and the CLI for the
first four.
"""

import json
import os
import threading
import uuid

import pytest

from keymgr import keybundle
from keymgr import provider as provider_mod
from keymgr import tenantbundle
from keymgr.audit import AuditLog

from test_provider_reconnect import OPERATOR, HttpServer, _create_key
from test_recovery_cli import run_cli

CHAIN = "local,fake_kms:make_provider"


@pytest.fixture()
def chain_env(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()


def _switchover(srv, provider_id):
    return srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id}, OPERATOR,
    )


def _activate_local(srv):
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200 and body == {"provider_id": "local", "status": "ready"}


def _rotate(srv, key_id, idem_key, tenant="t1", algorithm="AES256"):
    return srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        {"X-Operator-Id": "alice", "Idempotency-Key": idem_key},
    )


def _get_op(srv, op_id, tenant="t1"):
    return srv.request(
        "GET", "/v1/operations/%s?tenant_id=%s" % (op_id, tenant),
        headers=OPERATOR,
    )


def _events_for(env, op_id):
    return [
        (e.action, e.outcome)
        for e in AuditLog(env.data_dir)._read_all()
        if e.event_id == op_id
    ]


# -- HTTP rotate -------------------------------------------------------------
def test_rotate_local_displaced_stays_pending_then_continues(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = _rotate(srv, key_id, "rot-displace")
    assert status == 503
    assert list(body.keys()) == ["error", "operation_id"]
    assert body["error"] == "key management provider is unavailable"
    op_id = body["operation_id"]

    # Still pending: original operation_id, no terminal/envelope projection.
    status, body = _get_op(srv, op_id)
    assert status == 200
    assert body == {
        "operation_id": op_id,
        "tenant_id": "t1",
        "status": "pending",
        "http_status": None,
        "response": None,
    }
    # No backend work and no audit event while displaced.
    assert _events_for(env, op_id) == []

    # A retry while the foreign id stays active reuses the same operation.
    status, body = _rotate(srv, key_id, "rot-displace")
    assert status == 503 and body["operation_id"] == op_id
    assert _events_for(env, op_id) == []

    # Switch local back: the identical binding continues exactly once.
    assert _switchover(srv, "local")[0] == 200
    status, body = _rotate(srv, key_id, "rot-displace")
    assert status == 201, body
    assert body["operation_id"] == op_id and body["version"] == 2
    assert _events_for(env, op_id) == [("rotate", "success")]

    # A replay never executes or appends a second event.
    status, body = _rotate(srv, key_id, "rot-displace")
    assert status == 201 and body["operation_id"] == op_id
    assert _events_for(env, op_id) == [("rotate", "success")]


# -- HTTP encrypt ------------------------------------------------------------
def test_encrypt_local_displaced_stays_pending_then_seals_once(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    headers = {"X-Operator-Id": "alice", "Idempotency-Key": "enc-displace"}
    status, body = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": "QQ=="}, headers,
    )
    assert status == 503
    assert list(body.keys()) == ["error", "operation_id"]
    op_id = body["operation_id"]
    status, body = _get_op(srv, op_id)
    assert body["status"] == "pending"
    assert body["http_status"] is None and body["response"] is None
    assert _events_for(env, op_id) == []

    assert _switchover(srv, "local")[0] == 200
    status, body = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": "QQ=="}, headers,
    )
    assert status == 200
    assert list(body.keys()) == ["format", "envelope", "operation_id"]
    assert body["operation_id"] == op_id
    assert _events_for(env, op_id) == [("encrypt", "success")]


# -- HTTP batch-rotate -------------------------------------------------------
def test_batch_rotate_local_displaced_stays_pending(http):
    env, srv = http
    _activate_local(srv)
    key_ids = [_create_key(srv), _create_key(srv)]
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = srv.request(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1",
         "items": [{"key_id": key_ids[0], "algorithm": "AES256"},
                   {"key_id": key_ids[1], "algorithm": "RSA2048"}]},
        {"X-Operator-Id": "alice", "Idempotency-Key": "batch-displace"},
    )
    assert status == 503
    op_id = body["operation_id"]
    assert _get_op(srv, op_id)[1]["status"] == "pending"
    assert _events_for(env, op_id) == []
    # No version was appended.
    from keymgr.store import KeyStore

    store = KeyStore(env.data_dir, AuditLog(env.data_dir))
    for key_id in key_ids:
        assert store.get(key_id, "t1").current_version == 1

    assert _switchover(srv, "local")[0] == 200
    status, body = srv.request(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1",
         "items": [{"key_id": key_ids[0], "algorithm": "AES256"},
                   {"key_id": key_ids[1], "algorithm": "RSA2048"}]},
        {"X-Operator-Id": "alice", "Idempotency-Key": "batch-displace"},
    )
    assert status == 201 and body["operation_id"] == op_id
    assert [item["version"] for item in body["items"]] == [2, 2]
    assert _events_for(env, op_id) == [("batch_rotate", "success")]


# -- HTTP import (modern provenance block and legacy blockless bundle) -------
def _rekeyed_export(srv, key_id):
    status, exported = srv.request(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t1", "passphrase": "pw"}, OPERATOR,
    )
    assert status == 200
    payload = keybundle.decode_bundle(exported["bundle"], "pw")
    payload["key_id"] = str(uuid.uuid4())
    return payload


def test_import_local_provenance_displaced_stays_pending(http):
    env, srv = http
    _activate_local(srv)
    original = _create_key(srv)
    payload = _rekeyed_export(srv, original)
    bundle = keybundle.encode_bundle(payload, "pw")
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "import-displace"},
    )
    assert status == 503
    op_id = body["operation_id"]
    assert _get_op(srv, op_id)[1]["status"] == "pending"
    assert _events_for(env, op_id) == []

    assert _switchover(srv, "local")[0] == 200
    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "import-displace"},
    )
    assert status == 201 and body["operation_id"] == op_id
    assert _events_for(env, op_id) == [("import", "success")]


def test_import_legacy_blockless_bundle_displaced_stays_pending(http):
    env, srv = http
    _activate_local(srv)
    original = _create_key(srv)
    payload = _rekeyed_export(srv, original)
    for ver in payload["versions"]:
        ver.pop("provider", None)  # pre-provider keymgr-export-v1 shape
    bundle = keybundle.encode_bundle(payload, "pw")
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "legacy-displace"},
    )
    assert status == 503
    op_id = body["operation_id"]
    assert _get_op(srv, op_id)[1]["status"] == "pending"
    assert _events_for(env, op_id) == []

    assert _switchover(srv, "local")[0] == 200
    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "legacy-displace"},
    )
    assert status == 201 and body["operation_id"] == op_id
    assert _events_for(env, op_id) == [("import", "success")]


# -- HTTP restore ------------------------------------------------------------
def test_restore_local_provenance_displaced_stays_pending(http):
    env, srv = http
    _activate_local(srv)
    _create_key(srv)
    status, backup = srv.request(
        "POST", "/v1/backup", {"tenant_id": "t1", "passphrase": "pw"}, OPERATOR
    )
    assert status == 200
    payload = tenantbundle.decode_bundle(backup["bundle"], "pw")
    payload["tenant_id"] = "t2"
    for key in payload["keys"]:  # fresh ids: no foreign-owner conflict
        key["key_id"] = str(uuid.uuid4())
    bundle = tenantbundle.encode_bundle(payload, "pw")
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = srv.request(
        "POST", "/v1/restore",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "restore-displace"},
    )
    assert status == 503
    op_id = body["operation_id"]
    status, body = _get_op(srv, op_id, tenant="t2")
    assert body["status"] == "pending"
    assert _events_for(env, op_id) == []

    assert _switchover(srv, "local")[0] == 200
    status, body = srv.request(
        "POST", "/v1/restore",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "restore-displace"},
    )
    assert status == 201 and body["operation_id"] == op_id
    assert _events_for(env, op_id) == [("import", "success")]


# -- conflict while displaced ------------------------------------------------
def test_different_binding_while_displaced_is_409_naming_original(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = _rotate(srv, key_id, "shared-key")
    assert status == 503
    op_id = body["operation_id"]

    # Same Idempotency-Key, different normalized request: 409 names the
    # original pending operation and leaves it pending (no second op/event).
    status, body = _rotate(srv, key_id, "shared-key", algorithm="RSA2048")
    assert status == 409
    assert list(body.keys()) == ["error", "operation_id"]
    assert body["operation_id"] == op_id
    assert _get_op(srv, op_id)[1]["status"] == "pending"
    assert _events_for(env, op_id) == []


# -- never-active provider id stays a terminal 503 with a rejected event ------
def test_never_active_provider_id_is_terminal_503_with_rejected_event(http):
    env, srv = http
    _activate_local(srv)
    original = _create_key(srv)
    payload = _rekeyed_export(srv, original)
    for ver in payload["versions"]:
        ver["provider"]["provider_id"] = "never-active-here"
    bundle = keybundle.encode_bundle(payload, "pw")
    # Activate fakekms (a real, but different, provider is now active).
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "import-never"},
    )
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    op_id = body["operation_id"]
    status, body = _get_op(srv, op_id)
    assert body["status"] == "failed"
    assert body["http_status"] == 503
    assert body["response"] == {
        "error": "key management provider is unavailable",
        "operation_id": op_id,
    }
    assert _events_for(env, op_id) == [("import", "rejected")]

    # A retry replays the stored terminal; the rejected event is not doubled.
    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": "import-never"},
    )
    assert status == 503
    assert _events_for(env, op_id) == [("import", "rejected")]


# -- restart while displaced keeps the op pending ----------------------------
def test_restart_while_displaced_keeps_pending_then_continues(chain_env):
    env = chain_env
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        _activate_local(srv)
        key_id = _create_key(srv)
        assert _switchover(srv, "fakekms")[0] == 200
        status, body = _rotate(srv, key_id, "rot-restart")
        assert status == 503
        op_id = body["operation_id"]
    finally:
        srv.stop()

    # A brand-new process while the foreign id stays active: the operation
    # must not be crash-finalized into failed(500)/failed(503).
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        assert _get_op(srv2, op_id)[1]["status"] == "pending"
        assert _events_for(env, op_id) == []
        assert _switchover(srv2, "local")[0] == 200
        status, body = _rotate(srv2, key_id, "rot-restart")
        assert status == 201 and body["operation_id"] == op_id
        assert _events_for(env, op_id) == [("rotate", "success")]
    finally:
        srv2.stop()


# -- concurrent HTTP retries continue the op exactly once ---------------------
def test_concurrent_retries_after_switchback_rotate_once(chain_env):
    env = chain_env
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        _activate_local(srv)
        key_id = _create_key(srv)
        assert _switchover(srv, "fakekms")[0] == 200
        status, body = _rotate(srv, key_id, "rot-race")
        assert status == 503
        op_id = body["operation_id"]

        results = []
        lock = threading.Lock()

        def retry():
            for _ in range(10):
                status, body = _rotate(srv, key_id, "rot-race")
                with lock:
                    results.append((status, body.get("version")))
                if status == 201:
                    return
                import time

                time.sleep(0.02)

        def switch_back():
            import time

            time.sleep(0.05)
            _switchover(srv, "local")

        threads = [threading.Thread(target=retry) for _ in range(6)]
        threads.append(threading.Thread(target=switch_back))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)

        successes = [r for r in results if r[0] == 201]
        assert successes and {version for _, version in successes} == {2}
        from keymgr.store import KeyStore

        store = KeyStore(env.data_dir, AuditLog(env.data_dir))
        assert store.get(key_id, "t1").current_version == 2
        assert _events_for(env, op_id) == [("rotate", "success")]
    finally:
        srv.stop()


# -- CLI ----------------------------------------------------------------------
def test_cli_rotate_displaced_exit1_pending_then_continues(chain_env):
    env = chain_env
    result = run_cli(
        env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert result.returncode == 0
    result = run_cli(
        env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    key_id = json.loads(result.stdout)["key_id"]
    assert run_cli(
        env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    ).returncode == 0

    result = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-rot",
    )
    assert result.returncode == 1
    body = json.loads(result.stderr.strip())
    assert list(body.keys()) == ["error", "operation_id"]
    assert body["error"] == "key management provider is unavailable"
    op_id = body["operation_id"]

    result = run_cli(
        env, "operation", "--tenant-id", "t1", "--operator", "alice",
        "--operation-id", op_id,
    )
    body = json.loads(result.stdout)
    assert body["status"] == "pending"
    assert body["http_status"] is None and body["response"] is None

    assert run_cli(
        env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    ).returncode == 0
    result = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-rot",
    )
    assert result.returncode == 0
    body = json.loads(result.stdout)
    assert body["operation_id"] == op_id and body["version"] == 2
    assert _events_for(env, op_id) == [("rotate", "success")]
