"""Pending idempotent operations displaced by a directed provider switch.

Regression coverage for the defect where, after a KMS/HSM directed switchover
(or reconnect/failover), an idempotent operation bound to a key version or an
import/restore bundle whose ``provider_id`` is no longer active was wrongly
finalized as a *terminal* 503 (with a rejected audit event) whenever that
provider was the built-in ``local`` provider.

The contract now holds uniformly for every idempotent entry -- HTTP rotate,
batch-rotate, import, restore and encrypt, plus the rotate/batch-rotate/
import/restore CLIs:

* when the owning ``provider_id`` differs from the active one but that id WAS
  active in this data directory earlier (``local`` included), the bound
  operation stays ``pending`` and answers the fixed 503
  ``{"error","operation_id"}`` -- no backend call that mints anything, no
  handle/key/artifact change, no audit event;
* a retry (HTTP or CLI, concurrently) and a process restart reuse the SAME
  operation_id; once a provider with the same id is active again the identical
  Idempotency-Key executes exactly once (event_id == operation_id, exactly one
  audit event, no duplicate versions/imports/envelopes);
* the same key with a different binding is a 409 naming the original
  operation_id, even while the operation is displaced;
* a provider_id that was NEVER active in this data directory still gets the
  classic TERMINAL 503 with exactly one rejected event.
"""

import base64
import json
import os
import threading
import uuid

import pytest

from keymgr import keybundle, provider as provider_mod, tenantbundle

from test_provider_reconnect import OPERATOR, HttpServer
from test_recovery_cli import run_cli

CHAIN = "local,fake_kms:make_provider"
FIXED_ERROR = "key management provider is unavailable"
PROVIDER_UNAVAILABLE_BODY = ["error", "operation_id"]


@pytest.fixture()
def chain_env(env, monkeypatch):
    """A data dir wired to a two-entry primary(local)/standby(fakekms) chain."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()


# -- helpers ----------------------------------------------------------------
def _switchover(srv, provider_id):
    return srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id}, OPERATOR,
    )


def _activate_local(srv):
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200
    assert body == {"provider_id": "local", "status": "ready"}


def _create_key(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(srv, key_id, idem, tenant="t1", algorithm="AES256"):
    return srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        {"X-Operator-Id": "alice", "Idempotency-Key": idem},
    )


def _operation(srv, op_id, tenant="t1"):
    return srv.request(
        "GET", "/v1/operations/%s?tenant_id=%s" % (op_id, tenant),
        headers=OPERATOR,
    )


def _events(env, op_id):
    return [e for e in env.audit_events() if e.event_id == op_id]


def _assert_pending_503(env, status, body, op_id):
    assert status == 503
    assert list(body.keys()) == PROVIDER_UNAVAILABLE_BODY
    assert body["error"] == FIXED_ERROR
    assert body["operation_id"] == op_id
    # No audit event while displaced.
    assert _events(env, op_id) == []


# -- rotate -----------------------------------------------------------------
def test_rotate_displaced_local_stays_pending_then_runs_once(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    idem = "rotate-local-displace"
    status, body = _rotate(srv, key_id, idem)
    op_id = body["operation_id"]
    _assert_pending_503(env, status, body, op_id)

    # The pending operation hides http_status/response on GET.
    status, got = _operation(srv, op_id)
    assert status == 200
    assert got["status"] == "pending"
    assert got["http_status"] is None and got["response"] is None

    # A displaced retry keeps it pending under the same operation_id.
    status, body = _rotate(srv, key_id, idem)
    assert status == 503 and body["operation_id"] == op_id
    assert _events(env, op_id) == []
    # No version was appended.
    status, cur = srv.request(
        "GET", "/v1/keys/%s/current" % key_id,
        headers={**OPERATOR, "X-Tenant-Id": "t1"},
    )
    assert cur["version"] == 1

    # Switch local back: the identical key executes exactly once.
    assert _switchover(srv, "local")[0] == 200
    status, body = _rotate(srv, key_id, idem)
    assert status == 201, body
    assert body["operation_id"] == op_id and body["version"] == 2

    # A replay returns the first result, never a second version/event.
    status, body = _rotate(srv, key_id, idem)
    assert body["version"] == 2 and body["operation_id"] == op_id
    assert len(_events(env, op_id)) == 1
    assert _events(env, op_id)[0].outcome == "success"


def test_rotate_displaced_same_key_different_binding_is_409(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = _rotate(srv, key_id, "shared-key")
    op_id = body["operation_id"]
    assert status == 503

    # Same key, different algorithm -> conflict naming the original operation.
    status, body = _rotate(srv, key_id, "shared-key", algorithm="RSA2048")
    assert status == 409
    assert list(body.keys()) == PROVIDER_UNAVAILABLE_BODY
    assert body["operation_id"] == op_id
    assert _events(env, op_id) == []


def test_cli_rotate_displaced_exit_1_then_continues(chain_env):
    # Activate local and mint a local-owned key through the CLI first.
    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert r.returncode == 0, r.stderr
    key_id = json.loads(r.stdout.strip())["key_id"]

    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert r.returncode == 0, r.stderr

    r = run_cli(
        chain_env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-rotate-displace",
    )
    assert r.returncode == 1
    body = json.loads(r.stderr.strip())
    op_id = body["operation_id"]
    assert list(body.keys()) == PROVIDER_UNAVAILABLE_BODY
    assert body["error"] == FIXED_ERROR

    # GET operation (a fresh process) still reports pending with null fields.
    r = run_cli(
        chain_env, "operation", "--tenant-id", "t1", "--operator", "alice",
        "--operation-id", op_id,
    )
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout.strip())
    assert got["status"] == "pending"
    assert got["http_status"] is None and got["response"] is None

    # Back to local, the same CLI key runs the rotation exactly once.
    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-rotate-displace",
    )
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout.strip())
    assert body["operation_id"] == op_id and body["version"] == 2
    assert len(_events(chain_env, op_id)) == 1


# -- batch-rotate -----------------------------------------------------------
def test_batch_rotate_displaced_local_runs_once(http):
    env, srv = http
    _activate_local(srv)
    key_a = _create_key(srv)
    key_b = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    items = [
        {"key_id": key_a, "algorithm": "AES256"},
        {"key_id": key_b, "algorithm": "AES256"},
    ]
    idem = "batch-local-displace"

    def call():
        return srv.request(
            "POST", "/v1/keys/batch-rotate",
            {"tenant_id": "t1", "items": items},
            {"X-Operator-Id": "alice", "Idempotency-Key": idem},
        )

    status, body = call()
    op_id = body["operation_id"]
    _assert_pending_503(env, status, body, op_id)
    for key_id in (key_a, key_b):
        status, cur = srv.request(
            "GET", "/v1/keys/%s/current" % key_id,
            headers={**OPERATOR, "X-Tenant-Id": "t1"},
        )
        assert cur["version"] == 1

    assert _switchover(srv, "local")[0] == 200
    status, body = call()
    assert status == 201, body
    assert body["operation_id"] == op_id
    assert [item["version"] for item in body["items"]] == [2, 2]

    status, body = call()
    assert [item["version"] for item in body["items"]] == [2, 2]
    assert body["operation_id"] == op_id
    assert len(_events(env, op_id)) == 1


def test_cli_batch_rotate_displaced_exit_1_then_continues(chain_env):
    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert r.returncode == 0, r.stderr
    keys = []
    for _ in range(2):
        r = run_cli(
            chain_env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
            "--label", "k", "--operator", "alice",
        )
        assert r.returncode == 0, r.stderr
        keys.append(json.loads(r.stdout.strip())["key_id"])
    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert r.returncode == 0, r.stderr

    items = json.dumps(
        [{"key_id": key_id, "algorithm": "AES256"} for key_id in keys]
    )
    r = run_cli(
        chain_env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--idempotency-key", "cli-batch-displace", "--items", items,
    )
    assert r.returncode == 1
    body = json.loads(r.stderr.strip())
    op_id = body["operation_id"]
    assert body["error"] == FIXED_ERROR
    assert list(body.keys()) == PROVIDER_UNAVAILABLE_BODY

    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--idempotency-key", "cli-batch-displace", "--items", items,
    )
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout.strip())
    assert body["operation_id"] == op_id
    assert [item["version"] for item in body["items"]] == [2, 2]
    assert len(_events(chain_env, op_id)) == 1


# -- import -----------------------------------------------------------------
def _rekeyed_export_bundle(srv, tenant="t1", passphrase="pw"):
    """Export a local-owned key, then re-key it to a fresh key_id for import."""
    key_id = _create_key(srv, tenant=tenant)
    status, body = srv.request(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": tenant, "passphrase": passphrase}, OPERATOR,
    )
    assert status == 200, body
    payload = keybundle.decode_bundle(body["bundle"], passphrase)
    payload["key_id"] = str(uuid.uuid4())
    return keybundle.encode_bundle(payload, passphrase), payload["key_id"]


def test_import_displaced_local_runs_once(http):
    env, srv = http
    _activate_local(srv)
    bundle, new_key_id = _rekeyed_export_bundle(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    idem = "import-local-displace"

    def call():
        return srv.request(
            "POST", "/v1/keys/import",
            {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": idem},
        )

    status, body = call()
    op_id = body["operation_id"]
    _assert_pending_503(env, status, body, op_id)
    # The key must not exist while the import is displaced-pending.
    status, _ = srv.request(
        "GET", "/v1/keys/%s" % new_key_id,
        headers={**OPERATOR, "X-Tenant-Id": "t1"},
    )
    assert status == 404

    assert _switchover(srv, "local")[0] == 200
    status, body = call()
    assert status == 201, body
    assert body["operation_id"] == op_id and body["key_id"] == new_key_id

    status, body = call()
    assert body["operation_id"] == op_id and body["key_id"] == new_key_id
    assert len(_events(env, op_id)) == 1


def test_cli_import_displaced_exit_1_then_continues(chain_env):
    # Build the sealed bundle while local is active, using the HTTP harness
    # only for convenient bundle creation; the exercise itself is pure CLI.
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    try:
        _activate_local(server)
        bundle, new_key_id = _rekeyed_export_bundle(server)
    finally:
        server.stop()

    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "import", "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
        "--idempotency-key", "cli-import-displace",
    )
    assert r.returncode == 1
    body = json.loads(r.stderr.strip())
    op_id = body["operation_id"]
    assert body["error"] == FIXED_ERROR
    assert list(body.keys()) == PROVIDER_UNAVAILABLE_BODY

    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "import", "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
        "--idempotency-key", "cli-import-displace",
    )
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout.strip())
    assert body["operation_id"] == op_id and body["key_id"] == new_key_id
    assert len(_events(chain_env, op_id)) == 1


# -- restore ----------------------------------------------------------------
def _rekeyed_backup_bundle(srv, source_tenant, target_tenant, passphrase="pw"):
    """Back up ``source_tenant`` and re-seal it as a fresh ``target_tenant``.

    Every key is given a fresh key_id so the restore genuinely creates (the
    material is re-adopted through the owning provider regardless of key_id);
    the version provenance blocks still name ``local``, so a displaced local
    provider blocks the restore the same way an import is blocked.
    """
    status, body = srv.request(
        "POST", "/v1/backup",
        {"tenant_id": source_tenant, "passphrase": passphrase}, OPERATOR,
    )
    assert status == 200, body
    payload = tenantbundle.decode_bundle(body["bundle"], passphrase)
    payload["tenant_id"] = target_tenant
    for entry in payload["keys"]:
        entry["key_id"] = str(uuid.uuid4())
    return tenantbundle.encode_bundle(payload, passphrase)


def test_restore_displaced_local_runs_once(http):
    env, srv = http
    _activate_local(srv)
    _create_key(srv, tenant="t1")
    bundle = _rekeyed_backup_bundle(srv, "t1", "t2")
    assert _switchover(srv, "fakekms")[0] == 200

    idem = "restore-local-displace"

    def call():
        return srv.request(
            "POST", "/v1/restore",
            {"tenant_id": "t2", "passphrase": "pw", "bundle": bundle},
            {"X-Operator-Id": "alice", "Idempotency-Key": idem},
        )

    status, body = call()
    op_id = body["operation_id"]
    _assert_pending_503(env, status, body, op_id)

    assert _switchover(srv, "local")[0] == 200
    status, body = call()
    assert status == 201, body
    assert body["operation_id"] == op_id and body["tenant_id"] == "t2"
    assert len(body["key_ids"]) == 1

    status, body = call()
    assert body["operation_id"] == op_id
    assert len(_events(env, op_id)) == 1


def test_cli_restore_displaced_exit_1_then_continues(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    try:
        _activate_local(server)
        _create_key(server, tenant="t1")
        bundle = _rekeyed_backup_bundle(server, "t1", "t2")
    finally:
        server.stop()

    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "restore", "--tenant-id", "t2", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
        "--idempotency-key", "cli-restore-displace",
    )
    assert r.returncode == 1
    body = json.loads(r.stderr.strip())
    op_id = body["operation_id"]
    assert body["error"] == FIXED_ERROR
    assert list(body.keys()) == PROVIDER_UNAVAILABLE_BODY

    r = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "local",
    )
    assert r.returncode == 0, r.stderr
    r = run_cli(
        chain_env, "restore", "--tenant-id", "t2", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
        "--idempotency-key", "cli-restore-displace",
    )
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout.strip())
    assert body["operation_id"] == op_id and len(body["key_ids"]) == 1
    assert len(_events(chain_env, op_id)) == 1


# -- encrypt (HTTP only; the CLI encrypt entry is intentionally non-idempotent)
def test_encrypt_displaced_local_stays_pending_then_seals_once(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    plaintext = base64.b64encode(b"secret plaintext").decode("ascii")
    idem = "encrypt-local-displace"

    def call():
        return srv.request(
            "POST", "/v1/keys/%s/encrypt" % key_id,
            {"tenant_id": "t1", "plaintext": plaintext},
            {"X-Operator-Id": "alice", "Idempotency-Key": idem},
        )

    status, body = call()
    op_id = body["operation_id"]
    _assert_pending_503(env, status, body, op_id)
    status, got = _operation(srv, op_id)
    assert got["status"] == "pending"
    assert got["http_status"] is None and got["response"] is None

    assert _switchover(srv, "local")[0] == 200
    status, body = call()
    assert status == 200, body
    assert list(body.keys()) == ["format", "envelope", "operation_id"]
    assert body["operation_id"] == op_id
    envelope_token = body["envelope"]

    # The replay returns the SAME envelope and writes no second event.
    status, body = call()
    assert body["envelope"] == envelope_token
    assert body["operation_id"] == op_id
    assert len(_events(env, op_id)) == 1


# -- concurrency -------------------------------------------------------------
def test_concurrent_displaced_retries_share_pending_op(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    results = []
    barrier = threading.Barrier(6)

    def worker():
        barrier.wait()
        results.append(_rotate(srv, key_id, "concurrent-displaced"))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20.0)
        assert not t.is_alive()

    op_ids = {body["operation_id"] for _status, body in results}
    assert len(op_ids) == 1
    op_id = op_ids.pop()
    assert all(status == 503 for status, _ in results)
    assert _events(env, op_id) == []
    status, cur = srv.request(
        "GET", "/v1/keys/%s/current" % key_id,
        headers={**OPERATOR, "X-Tenant-Id": "t1"},
    )
    assert cur["version"] == 1


def test_concurrent_retries_after_switchback_execute_once(http):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _rotate(srv, key_id, "concurrent-continue")
    op_id = body["operation_id"]
    assert status == 503 and _events(env, op_id) == []

    # Make local active again, then storm the same idempotency key.
    assert _switchover(srv, "local")[0] == 200
    results = []
    barrier = threading.Barrier(6)

    def worker():
        barrier.wait()
        results.append(_rotate(srv, key_id, "concurrent-continue"))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20.0)
        assert not t.is_alive()

    assert all(status == 201 for status, _ in results), results
    # Every waiter replayed the winner's single committed version.
    assert {body["version"] for _status, body in results} == {2}
    assert {body["operation_id"] for _status, body in results} == {op_id}
    assert len(_events(env, op_id)) == 1
    status, cur = srv.request(
        "GET", "/v1/keys/%s/current" % key_id,
        headers={**OPERATOR, "X-Tenant-Id": "t1"},
    )
    assert cur["version"] == 2


# -- restart -----------------------------------------------------------------
def test_pending_displaced_op_survives_restart_and_continues(http, chain_env):
    env, srv = http
    _activate_local(srv)
    key_id = _create_key(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _rotate(srv, key_id, "restart-displace")
    op_id = body["operation_id"]
    assert status == 503 and _events(env, op_id) == []
    srv.stop()

    # A fresh process opens the data dir while local is still displaced: the
    # operation must be recovered as still-pending, never finalized.
    provider_mod.reset_for_tests()
    server = HttpServer(chain_env)
    try:
        status, got = _operation(server, op_id)
        assert status == 200
        assert got["status"] == "pending"
        assert got["http_status"] is None and got["response"] is None
        assert _events(env, op_id) == []

        # Switch local back in the new process, then continue under one id.
        assert _switchover(server, "local")[0] == 200
        status, body = _rotate(server, key_id, "restart-displace")
        assert status == 201
        assert body["operation_id"] == op_id and body["version"] == 2
        assert len(_events(env, op_id)) == 1
    finally:
        server.stop()


# -- never-active provider stays a terminal 503 ------------------------------
def _seed_foreign_record(data_dir, provider_id, tenant="t1"):
    key_id = str(uuid.uuid4())
    record = {
        "key_id": key_id,
        "tenant_id": tenant,
        "label": "k",
        "current_version": 1,
        "status": "active",
        "reason": None,
        "operator": None,
        "revoked_at": None,
        "pending_event": None,
        "versions": [
            {
                "version": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
                "algorithm": "AES256",
                "public_key": None,
                "provider_id": provider_id,
                "handle": "handle-owned-by-" + provider_id,
                "encrypted_material": "pev1.xx.yy",
            }
        ],
    }
    fd = os.open(
        os.path.join(data_dir, key_id + ".json"),
        os.O_WRONLY | os.O_CREAT,
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    return key_id


def test_never_active_provider_is_terminal_503_with_one_rejected_event(http):
    env, srv = http
    _activate_local(srv)
    # A record owned by a provider id that is neither chain entry and was
    # therefore never active in this data directory.
    ghost_id = "ghostkms"
    assert not provider_mod.provider_was_active(ghost_id)
    key_id = _seed_foreign_record(env.data_dir, ghost_id)
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = _rotate(srv, key_id, "never-active-ghost")
    op_id = body["operation_id"]
    assert status == 503
    assert body["error"] == FIXED_ERROR

    status, got = _operation(srv, op_id)
    assert got["status"] == "failed" and got["http_status"] == 503
    events = _events(env, op_id)
    assert len(events) == 1 and events[0].outcome == "rejected"

    # Replaying the terminal never appends a second event.
    status, body = _rotate(srv, key_id, "never-active-ghost")
    assert status == 503 and body["operation_id"] == op_id
    assert len(_events(env, op_id)) == 1


def test_never_active_local_with_single_external_provider_is_terminal(env):
    # With only the external provider configured (no chain), local is never
    # activated in this data directory: a local-owned record gets the classic
    # TERMINAL 503 (one rejected event), not the displaced-pending treatment.
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    try:
        status, _ = server.request(
            "GET", "/v1/provider/status", headers=OPERATOR
        )
        assert status == 200
        assert not provider_mod.provider_was_active("local")
        key_id = _seed_foreign_record(env.data_dir, "local")

        status, body = server.request(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t1", "algorithm": "AES256"},
            {"X-Operator-Id": "alice", "Idempotency-Key": "never-active-local"},
        )
        op_id = body["operation_id"]
        assert status == 503 and body["error"] == FIXED_ERROR
        status, got = server.request(
            "GET", "/v1/operations/%s?tenant_id=t1" % op_id, headers=OPERATOR
        )
        assert got["status"] == "failed" and got["http_status"] == 503
        events = _events(env, op_id)
        assert len(events) == 1 and events[0].outcome == "rejected"
    finally:
        server.stop()
