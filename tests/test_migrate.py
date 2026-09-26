"""Tests for the all-versions provider migration.

Covers ``POST /v1/keys/{key_id}/migrate`` and the CLI ``migrate`` command:

* a migration exports every version from its owning provider and imports it
  into the ready chain entry, preserving versions, algorithms, public keys,
  timestamps, the current pointer and the revocation state;
* the 200 key order is exactly ``key_id,provider_id,versions,operation_id``
  with ``provider_id`` the ready entry and ``versions`` ascending;
* a key already fully on the ready provider is a bound 409; unknown or
  cross-tenant keys are 404; a policy denial is 403; a missing/unhealthy
  source provider or mismatched material is the fixed 503 -- every bound
  error body is exactly ``error,operation_id``;
* body/UUID4/Idempotency-Key violations are side-effect-free 400s before
  binding;
* a pre-commit failure deletes the freshly minted handles and leaves the
  old record fully usable; a committed migration whose old-handle deletion
  fails still answers success and is cleaned up at the next open;
* retries replay the first result and never migrate or account twice.
"""

import json
import os
import uuid

import pytest

from keymgr import provider as provider_mod
from keymgr.store import KeyStore

from test_provider_reconnect import OPERATOR, HttpServer
from test_recovery_cli import (
    LedgerHold,
    _get_operation,
    _key_file_has_marker,
    _pending_operation_id,
    run_cli,
    start_cli,
    wait_for,
)

CHAIN = "local,fake_kms:make_provider"
TENANT = "t1"


@pytest.fixture()
def chain_env(env, monkeypatch):
    """A data dir wired to a two-entry primary/standby chain."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()


def _idem(key="migrate-0001"):
    return {"X-Operator-Id": "alice", "Idempotency-Key": key}


def _tenant_headers():
    return {"X-Operator-Id": "alice", "X-Tenant-Id": TENANT}


def _create(srv, algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": TENANT, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201
    return body["key_id"]


def _rotate(srv, key_id, algorithm="AES256", tag="r"):
    status, body = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": TENANT, "algorithm": algorithm},
        _idem("rotate-%s-%s" % (tag, key_id)),
    )
    assert status == 201
    return body


def _switch(srv, provider_id):
    status, body = srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id}, OPERATOR,
    )
    assert status == 200, body


def _migrate(srv, key_id, tenant=TENANT, key="migrate-0001"):
    return srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id,
        {"tenant_id": tenant}, _idem(key),
    )


def _local_handles(env):
    try:
        with open(os.path.join(env.data_dir, "local-registry.json")) as fh:
            return set(json.load(fh))
    except (OSError, ValueError):
        return set()


def _migrate_events(env):
    return [e for e in env.audit_events() if e.action == "migrate"]


# -- success path -------------------------------------------------------------
def test_migrate_moves_every_version_to_the_ready_provider(http):
    env, srv = http
    key_id = _create(srv)
    _rotate(srv, key_id, tag="a")
    _rotate(srv, key_id, tag="b")
    before = env.open_store().read_raw(key_id)
    old_handles = {ver.handle for ver in before.versions}
    assert {ver.provider_id for ver in before.versions} == {"local"}

    _switch(srv, "fakekms")
    status, body = _migrate(srv, key_id)
    assert status == 200
    assert list(body) == ["key_id", "provider_id", "versions", "operation_id"]
    assert body["key_id"] == key_id
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1, 2, 3]

    # Every version moved; metadata preserved exactly.
    record = env.open_store().read_raw(key_id)
    assert [ver.provider_id for ver in record.versions] == ["fakekms"] * 3
    assert record.current_version == before.current_version
    assert record.status == before.status
    for old, new in zip(before.versions, record.versions):
        assert new.version == old.version
        assert new.algorithm == old.algorithm
        assert new.public_key == old.public_key
        assert new.created_at == old.created_at
        assert new.handle not in old_handles

    # The replaced local handles are gone; the minted ones live in the KMS.
    assert _local_handles(env) == set()
    assert env.kms_handles() == {ver.handle for ver in record.versions}

    # Exactly one migrate event, named after the operation, projecting the key.
    events = _migrate_events(env)
    assert len(events) == 1
    assert events[0].event_id == body["operation_id"]
    assert events[0].key_id == key_id
    assert events[0].outcome == "success"

    # The operation is queryable and carries the same response.
    status, op = srv.request(
        "GET", "/v1/operations/%s" % body["operation_id"],
        headers=_tenant_headers(),
    )
    assert status == 200
    assert op["status"] == "succeeded"
    assert op["http_status"] == 200
    assert op["response"] == body

    # No durable attempt artifacts survive a settled migration (claim locks
    # are inert and may remain).
    for name in ("operation-artifacts", "provisions", "migration-cleanups"):
        directory = os.path.join(env.data_dir, name)
        leftovers = [
            entry
            for entry in (os.listdir(directory) if os.path.isdir(directory) else [])
            if not entry.endswith(".lock")
        ]
        assert leftovers == []


def test_migrate_preserves_revocation_and_rsa_public_key(http):
    env, srv = http
    key_id = _create(srv, algorithm="RSA2048")
    _rotate(srv, key_id, algorithm="RSA2048", tag="a")
    status, _ = srv.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": TENANT, "reason": "r", "operator": "alice"}, OPERATOR,
    )
    assert status == 200
    before = env.open_store().read_raw(key_id)

    _switch(srv, "fakekms")
    status, body = _migrate(srv, key_id)
    assert status == 200
    assert body["versions"] == [1, 2]

    record = env.open_store().read_raw(key_id)
    assert record.status == "revoked"
    assert record.reason == "r"
    assert record.revoked_at == before.revoked_at
    for old, new in zip(before.versions, record.versions):
        assert new.public_key == old.public_key
        assert new.public_key.startswith("-----BEGIN")


def test_migrated_key_still_encrypts_and_decrypts(http):
    env, srv = http
    key_id = _create(srv)
    _switch(srv, "fakekms")
    status, body = _migrate(srv, key_id)
    assert status == 200
    import base64

    status, sealed = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": TENANT, "plaintext": base64.b64encode(b"hi").decode()},
        _idem("enc-1"),
    )
    assert status == 200
    status, opened = srv.request(
        "POST", "/v1/keys/%s/decrypt" % key_id,
        {"tenant_id": TENANT, "envelope": sealed["envelope"]}, OPERATOR,
    )
    assert status == 200
    assert base64.b64decode(opened["plaintext"]) == b"hi"


# -- idempotent replay / conflict ----------------------------------------------
def test_migrate_replays_the_first_result(http):
    env, srv = http
    key_id = _create(srv)
    _switch(srv, "fakekms")
    status, first = _migrate(srv, key_id)
    assert status == 200
    handles_after_first = env.kms_handles()

    status, replay = _migrate(srv, key_id)
    assert status == 200
    assert replay == first
    # Nothing was migrated or accounted a second time.
    assert env.kms_handles() == handles_after_first
    assert len(_migrate_events(env)) == 1


def test_migrate_same_key_different_binding_conflicts(http):
    env, srv = http
    key_id = _create(srv)
    _switch(srv, "fakekms")
    status, first = _migrate(srv, key_id)
    assert status == 200
    # The same Idempotency-Key bound to a different tenant is a 409 naming
    # the original operation.
    status, body = srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id,
        {"tenant_id": "other"}, _idem("migrate-0001"),
    )
    assert status == 409
    assert body["operation_id"] == first["operation_id"]


# -- bound terminal refusals ----------------------------------------------------
def test_migrate_already_on_ready_provider_is_409(http):
    env, srv = http
    key_id = _create(srv)
    # The key is fully owned by the active (local) provider already.
    status, body = _migrate(srv, key_id)
    assert status == 409
    assert list(body) == ["error", "operation_id"]
    events = _migrate_events(env)
    assert len(events) == 1
    assert events[0].outcome == "rejected"
    assert events[0].key_id == key_id
    assert events[0].event_id == body["operation_id"]
    # The refusal is durable: a same-key retry replays it verbatim.
    status, replay = _migrate(srv, key_id)
    assert status == 409
    assert replay == body


def test_migrate_unknown_and_cross_tenant_are_404(http):
    env, srv = http
    key_id = _create(srv)
    _switch(srv, "fakekms")
    status, body = _migrate(srv, str(uuid.uuid4()), key="migrate-404")
    assert status == 404
    assert list(body) == ["error", "operation_id"]
    status, body = _migrate(srv, key_id, tenant="other", key="migrate-x")
    assert status == 404
    assert list(body) == ["error", "operation_id"]
    # Both rejections project no cross-tenant existence.
    events = _migrate_events(env)
    assert len(events) == 2
    assert all(e.outcome == "rejected" for e in events)


def test_migrate_policy_denial_is_403(http):
    env, srv = http
    key_id = _create(srv)
    _switch(srv, "fakekms")
    status, _ = srv.request(
        "PUT", "/v1/policy",
        {
            "tenant_id": TENANT,
            "rules": [
                {"subject": "alice", "actions": ["migrate"], "effect": "deny"}
            ],
        },
        OPERATOR,
    )
    assert status == 200
    status, body = _migrate(srv, key_id)
    assert status == 403
    assert list(body) == ["error", "operation_id"]
    events = _migrate_events(env)
    assert len(events) == 1
    assert events[0].outcome == "rejected"
    assert events[0].key_id == key_id
    # The key was never migrated.
    record = env.open_store().read_raw(key_id)
    assert {ver.provider_id for ver in record.versions} == {"local"}


# -- side-effect-free 400s -------------------------------------------------------
def test_migrate_validation_errors_happen_before_binding(http):
    env, srv = http
    key_id = _create(srv)
    baseline = len(env.audit_events())

    # Missing Idempotency-Key.
    status, _ = srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id,
        {"tenant_id": TENANT}, OPERATOR,
    )
    assert status == 400
    # Illegal Idempotency-Key.
    status, _ = srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id,
        {"tenant_id": TENANT},
        {"X-Operator-Id": "alice", "Idempotency-Key": "bad key!"},
    )
    assert status == 400
    # Malformed key_id.
    status, body = _migrate(srv, "not-a-uuid", key="migrate-b1")
    assert status == 400
    assert "key_id" in body["error"]
    # Missing tenant_id.
    status, body = srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id, {}, _idem("migrate-b2"),
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    # A body field other than tenant_id.
    status, body = srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id,
        {"tenant_id": TENANT, "algorithm": "AES256"}, _idem("migrate-b3"),
    )
    assert status == 400
    assert "algorithm" in body["error"]

    # No audit event, operation record, key change or handle was produced.
    assert len(env.audit_events()) == baseline
    operations = os.path.join(env.data_dir, "operations")
    assert not os.path.isdir(operations) or os.listdir(operations) == []


# -- provider failures ------------------------------------------------------------
def test_migrate_source_unhealthy_is_503(http):
    env, srv = http
    _switch(srv, "fakekms")
    key_id = _create(srv)
    _switch(srv, "local")
    env.set_faults({"health": False})
    status, body = _migrate(srv, key_id)
    assert status == 503
    assert list(body) == ["error", "operation_id"]
    assert body["error"] == "key management provider is unavailable"
    # The terminal is durable and replays verbatim.
    status, replay = _migrate(srv, key_id)
    assert status == 503
    assert replay == body
    # The key was never migrated.
    record = env.open_store().read_raw(key_id)
    assert {ver.provider_id for ver in record.versions} == {"fakekms"}


def test_migrate_source_provider_missing_is_503(http):
    env, srv = http
    key_id = _create(srv)
    _switch(srv, "fakekms")
    # Hand the record to a provider no configured entry builds.
    path = os.path.join(env.data_dir, key_id + ".json")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data["versions"][0]["provider_id"] = "ghost"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    status, body = _migrate(srv, key_id)
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    assert list(body) == ["error", "operation_id"]


def test_migrate_material_mismatch_is_503(http):
    env, srv = http
    _switch(srv, "fakekms")
    key_id = _create(srv)
    _switch(srv, "local")
    # Corrupt the KMS-stored material so the export yields garbage the ready
    # provider refuses.
    import fake_kms

    with open(env.state_path, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    for entry in state["handles"].values():
        entry["material"] = fake_kms._wrap("not-a-valid-key-material")
    with open(env.state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    status, body = _migrate(srv, key_id)
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    assert list(body) == ["error", "operation_id"]


def test_migrate_failure_deletes_new_handles_and_keeps_old_record(http):
    env, srv = http
    key_id = _create(srv)
    _rotate(srv, key_id, tag="a")
    _switch(srv, "fakekms")
    # The first import mints a handle, the second fails: the rollback must
    # delete the minted one and leave the old record fully usable.
    env.set_faults({"fail_after": {"import_material": 1}})
    status, body = _migrate(srv, key_id)
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    env.clear_faults()

    assert env.kms_handles() == set()
    assert _local_handles(env) != set()
    record = env.open_store().read_raw(key_id)
    assert {ver.provider_id for ver in record.versions} == {"local"}
    assert record.current_version == 2

    # A fresh attempt with a new Idempotency-Key now succeeds.
    status, body = _migrate(srv, key_id, key="migrate-retry")
    assert status == 200
    assert body["versions"] == [1, 2]


# -- crash / restart cleanup ------------------------------------------------------
def test_committed_migration_cleans_old_handles_at_restart(
    chain_env, monkeypatch
):
    env = chain_env
    store = env.open_store()
    record = store.create(TENANT, "AES256", "k")
    key_id = record.key_id
    old_handle = record.versions[0].handle
    provider_mod.switchover("fakekms")

    # The post-commit old-handle deletion fails: the request still commits
    # and the survivors stay in the durable cleanup file.
    monkeypatch.setattr(
        KeyStore, "_delete_migrated_handle", lambda self, pid, h: False
    )
    status, record = store.migrate(key_id, TENANT)
    assert status == KeyStore.MIGRATE_DONE
    cleanup_dir = os.path.join(env.data_dir, "migration-cleanups")
    assert len(os.listdir(cleanup_dir)) == 1
    assert old_handle in _local_handles(env)
    monkeypatch.undo()

    # The next open retries the cleanup: the orphan is deleted and the file
    # removed, while the migrated record stays intact.
    reopened = env.open_store()
    assert old_handle not in _local_handles(env)
    assert os.listdir(cleanup_dir) == []
    migrated = reopened.read_raw(key_id)
    assert [ver.provider_id for ver in migrated.versions] == ["fakekms"]
    events = _migrate_events(env)
    assert len(events) == 1
    assert events[0].action == "migrate"


def test_cleanup_file_of_uncommitted_migration_is_dropped(chain_env):
    env = chain_env
    store = env.open_store()
    record = store.create(TENANT, "AES256", "k")
    handle = record.versions[0].handle
    # A cleanup file whose migrate event never committed: the old handle is
    # still owned by the record, so the file is discarded WITHOUT deleting.
    store._write_migration_cleanup(str(uuid.uuid4()), [("local", handle)])
    cleanup_dir = os.path.join(env.data_dir, "migration-cleanups")
    assert len(os.listdir(cleanup_dir)) == 1

    env.open_store()
    assert os.listdir(cleanup_dir) == []
    assert handle in _local_handles(env)


# -- CLI ---------------------------------------------------------------------------
def test_migrate_cli(chain_env):
    env = chain_env
    created = run_cli(
        env, "gen", "--tenant-id", TENANT, "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert created.returncode == 0
    key_id = json.loads(created.stdout)["key_id"]
    rotated = run_cli(
        env, "rotate", "--tenant-id", TENANT, "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "rot-1",
    )
    assert rotated.returncode == 0
    switched = run_cli(
        env, "provider", "switchover", "--operator", "alice",
        "--provider-id", "fakekms",
    )
    assert switched.returncode == 0

    migrated = run_cli(
        env, "migrate", "--tenant-id", TENANT, "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "mig-1",
    )
    assert migrated.returncode == 0, migrated.stderr
    body = json.loads(migrated.stdout)
    assert list(body) == ["key_id", "provider_id", "versions", "operation_id"]
    assert body["key_id"] == key_id
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1, 2]

    # A same-key retry replays the first result exactly.
    replay = run_cli(
        env, "migrate", "--tenant-id", TENANT, "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "mig-1",
    )
    assert replay.returncode == 0
    assert json.loads(replay.stdout) == body
    assert len(_migrate_events(env)) == 1

    # A fresh key on an already-migrated record is the 409 conflict (exit 3).
    again = run_cli(
        env, "migrate", "--tenant-id", TENANT, "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "mig-2",
    )
    assert again.returncode == 3
    conflict = json.loads(again.stderr)
    assert list(conflict) == ["error", "operation_id"]

    # An unknown key is the 404 (exit 4).
    missing = run_cli(
        env, "migrate", "--tenant-id", TENANT, "--key-id",
        str(uuid.uuid4()), "--operator", "alice", "--idempotency-key", "mig-3",
    )
    assert missing.returncode == 4

    # A malformed key id is a parameter error (exit 2) with no side effects.
    bad = run_cli(
        env, "migrate", "--tenant-id", TENANT, "--key-id", "nope",
        "--operator", "alice", "--idempotency-key", "mig-4",
    )
    assert bad.returncode == 2


def test_migrate_cli_crash_at_commit_recovers_and_replays(chain_env):
    env = chain_env
    created = run_cli(
        env, "gen", "--tenant-id", TENANT, "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert created.returncode == 0
    key_id = json.loads(created.stdout)["key_id"]
    switched = run_cli(
        env, "provider", "switchover", "--operator", "alice",
        "--provider-id", "fakekms",
    )
    assert switched.returncode == 0
    assert _local_handles(env) != set()

    # Kill the CLI exactly at the commit-point ledger append: the migrated
    # file, marker, journal and cleanup file are already durable.
    with LedgerHold(env):
        proc = start_cli(
            env, "migrate", "--tenant-id", TENANT, "--key-id", key_id,
            "--operator", "alice", "--idempotency-key", "mig-crash",
        )
        assert wait_for(lambda: _key_file_has_marker(env, key_id))
        assert wait_for(lambda: _pending_operation_id(env) is not None)
        proc.kill()
        proc.wait()
    operation_id = _pending_operation_id(env)
    assert operation_id is not None
    cleanup_dir = os.path.join(env.data_dir, "migration-cleanups")
    assert os.path.isdir(cleanup_dir)
    assert len(os.listdir(cleanup_dir)) == 1

    # The next CLI process settles the scene: the event commits, the replaced
    # handles are deleted, the cleanup file is removed and the operation
    # finalizes as the staged 200.
    op = _get_operation(env, TENANT, operation_id)
    assert op.returncode == 0, op.stderr
    body = json.loads(op.stdout)
    assert body["status"] == "succeeded"
    assert body["http_status"] == 200
    assert body["response"] == {
        "key_id": key_id,
        "provider_id": "fakekms",
        "versions": [1],
        "operation_id": operation_id,
    }
    assert _local_handles(env) == set()
    assert os.listdir(cleanup_dir) == []

    # A same-key retry replays the first 200; nothing migrates or accounts
    # a second time.
    replay = run_cli(
        env, "migrate", "--tenant-id", TENANT, "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "mig-crash",
    )
    assert replay.returncode == 0
    assert json.loads(replay.stdout) == body["response"]
    assert len(_migrate_events(env)) == 1
