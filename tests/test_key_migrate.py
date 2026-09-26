"""Tests for whole-key provider migration (POST /v1/keys/{key_id}/migrate).

A migrate exports every version of a key from its bound provider(s) and
imports the material into the chain's ready entry, rebinding the key file in
place; version numbers, algorithm, public key, timestamps, current pointer and
revocation state are preserved. These tests cover:

* 200 body key order ``key_id,provider_id,versions,operation_id`` and an
  ascending positive-integer version list, with all versions (and no handle or
  material) rebound to the ready provider;
* idempotency: the same Idempotency-Key replays the first 200/operation_id,
  a second key after completion is a bound 409, and a restart never
  double-migrates or double-books;
* pre-binding 400s (body strictly ``{"tenant_id"}``, UUID4, idempotency key)
  with zero side effects; policy 403; unknown/cross-tenant 404;
* fixed-text 503 for a missing/unhealthy source provider, a failed target
  import and a timeout -- post-binding body order ``error,operation_id``;
* pre-commit failure rolls the new handles and old file back; post-commit
  old-handle delete failure still reports success and is finished on replay/
  restart, exactly once per audit ``migrate`` event (``event_id`` ==
  ``operation_id``, ``key_id`` == K);
* the CLI ``migrate`` subcommand and its exit-code mapping.
"""

import json
import os
import sys
import uuid

import pytest

from keymgr import provider as provider_mod
from keymgr.audit import AuditLog

from test_provider_reconnect import OPERATOR, HttpServer
from test_recovery_cli import run_cli

CHAIN = "local,fake_kms:make_provider"
CHAIN_REVERSED = "fake_kms:make_provider,local"


@pytest.fixture()
def chain_env(env, monkeypatch):
    """A data dir wired to a two-entry local/fakekms chain."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def reversed_chain_env(env, monkeypatch):
    """A data dir whose primary is fakekms and standby is local."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN_REVERSED)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()
    provider_mod.reset_for_tests()


def _switchover(srv, provider_id):
    return srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id}, OPERATOR,
    )


def _create(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(srv, key_id, tenant="t1", algorithm="AES256", key="rot"):
    return srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        {**OPERATOR, "Idempotency-Key": key},
    )


def _migrate(srv, key_id, tenant="t1", key="mig-1", headers=None,
             body=None, raw=None):
    hdrs = {**OPERATOR, "Idempotency-Key": key}
    hdrs.update(headers or {})
    if raw is not None:
        return srv.raw(
            "POST", "/v1/keys/%s/migrate" % key_id, raw, hdrs
        )
    return srv.request(
        "POST", "/v1/keys/%s/migrate" % key_id,
        body if body is not None else {"tenant_id": tenant}, hdrs,
    )


def _versions_on_disk(env, key_id):
    path = os.path.join(env.data_dir, key_id + ".json")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [
        (v["version"], v["provider_id"], v["handle"])
        for v in data["versions"]
    ], data


def _migrate_events(env, event_id=None):
    events = AuditLog(env.data_dir)._read_all()
    if event_id is not None:
        return [(e.action, e.outcome, e.key_id)
                for e in events if e.event_id == event_id]
    return [(e.action, e.outcome, e.key_id)
            for e in events if e.action == "migrate"]


# -- happy path --------------------------------------------------------------
def test_migrate_success_rebinds_all_versions(http):
    env, srv = http
    key_id = _create(srv, algorithm="RSA2048")
    status, rot = _rotate(srv, key_id, algorithm="RSA2048", key="rot-1")
    assert status == 201
    versions, data = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}
    assert data["current_version"] == 2

    status, body = _switchover(srv, "fakekms")
    assert status == 200, body

    status, body = _migrate(srv, key_id, key="mig-1")
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "provider_id", "versions", "operation_id"
    ]
    assert body["key_id"] == key_id
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1, 2]
    op_id = body["operation_id"]
    uuid.UUID(op_id).version == 4

    versions, data = _versions_on_disk(env, key_id)
    assert [number for number, _, _ in versions] == [1, 2]
    assert {pid for _, pid, _ in versions} == {"fakekms"}
    assert len({handle for _, _, handle in versions}) == 2
    # current pointer and revocation state are preserved.
    assert data["current_version"] == 2
    assert data["status"] == "active"
    assert data["pending_event"] is None
    # Old local handles are gone; exactly the two new fake handles survive.
    with open(os.path.join(env.data_dir, "local-registry.json")) as fh:
        assert json.load(fh) == {}
    assert len(env.kms_handles()) == 2
    # One migrate success event, event_id == operation_id, key_id == K.
    assert _migrate_events(env) == [("migrate", "success", key_id)]
    assert _migrate_events(env, op_id) == [("migrate", "success", key_id)]
    # No migration snapshot/journal/mirror remains.
    assert not os.path.exists(
        os.path.join(env.data_dir, "migrations", op_id + ".json")
    )
    assert not os.path.exists(
        os.path.join(env.data_dir, "provisions", op_id + ".json")
    )
    assert not os.path.exists(
        os.path.join(env.data_dir, "operation-artifacts", op_id + ".json")
    )


def test_migrate_preserves_revoked_and_public_key(http):
    env, srv = http
    key_id = _create(srv, algorithm="RSA2048")
    status, _ = _rotate(srv, key_id, algorithm="RSA2048", key="rot-1")
    assert status == 201
    status, _ = srv.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t1", "reason": "r", "operator": "alice"}, OPERATOR,
    )
    assert status == 200
    _, before = _versions_on_disk(env, key_id)
    public_keys = [v["public_key"] for v in before["versions"]]
    created = [v["created_at"] for v in before["versions"]]

    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id)
    assert status == 200, body
    _, after = _versions_on_disk(env, key_id)
    assert [v["public_key"] for v in after["versions"]] == public_keys
    assert [v["created_at"] for v in after["versions"]] == created
    assert after["status"] == "revoked"
    assert after["reason"] == "r"
    assert after["operator"] == "alice"
    assert after["revoked_at"] == before["revoked_at"]


def test_migrate_replay_same_key_is_verbatim_and_runs_once(http):
    env, srv = http
    key_id = _create(srv)
    assert _rotate(srv, key_id, key="rot-1")[0] == 201
    assert _switchover(srv, "fakekms")[0] == 200

    status, first = _migrate(srv, key_id, key="same-mig")
    assert status == 200
    first_handles = {
        handle for _, _, handle in _versions_on_disk(env, key_id)[0]
    }
    status, second = _migrate(srv, key_id, key="same-mig")
    assert status == 200
    assert second == first
    assert second["operation_id"] == first["operation_id"]
    # The backend was not touched a second time: no extra handles minted.
    assert len(env.kms_handles()) == 2
    assert {
        handle for _, _, handle in _versions_on_disk(env, key_id)[0]
    } == first_handles
    assert len(_migrate_events(env)) == 1


def test_migrate_second_key_when_already_on_ready_is_409(http):
    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id, key="mig-1")
    assert status == 200
    op_id = body["operation_id"]

    status, body = _migrate(srv, key_id, key="mig-2")
    assert status == 409, body
    assert list(body.keys()) == ["error", "operation_id"]
    uuid.UUID(body["operation_id"]).version == 4
    # The 409 is a terminal of the second operation; the first is untouched.
    assert _migrate_events(env, op_id) == [("migrate", "success", key_id)]
    second_events = [
        e for e in _migrate_events(env) if e[2] == key_id and e[1] == "rejected"
    ]
    assert len(second_events) == 1
    # Replaying the second key returns the same 409.
    status, replay = _migrate(srv, key_id, key="mig-2")
    assert status == 409
    assert replay == body


def test_migrate_409_when_ready_was_always_owner(http):
    # No switchover: the key is already owned by the ready (local) provider.
    _env, srv = http
    key_id = _create(srv)
    status, body = _migrate(srv, key_id)
    assert status == 409, body
    assert list(body.keys()) == ["error", "operation_id"]
    assert body["error"] == "key is already managed by the ready provider"


# -- pre-binding 400s: zero side effects -------------------------------------
@pytest.mark.parametrize(
    "raw,headers",
    [
        # Missing / malformed Idempotency-Key.
        (b'{"tenant_id":"t1"}', OPERATOR),
        (b'{"tenant_id":"t1"}', {**OPERATOR, "Idempotency-Key": ""}),
        (b'{"tenant_id":"t1"}', {**OPERATOR, "Idempotency-Key": "bad key!"}),
        # Bad JSON.
        (b'{not json', {**OPERATOR, "Idempotency-Key": "k"}),
        # Body must be an object with exactly tenant_id.
        (b'[]', {**OPERATOR, "Idempotency-Key": "k"}),
        (b'{}', {**OPERATOR, "Idempotency-Key": "k"}),
        (b'{"tenant_id":"t1","extra":1}',
         {**OPERATOR, "Idempotency-Key": "k"}),
        (b'{"tenant_id":""}', {**OPERATOR, "Idempotency-Key": "k"}),
        (b'{"tenant_id":5}', {**OPERATOR, "Idempotency-Key": "k"}),
        (b'{"tenant_id":"t1","provider_id":"local"}',
         {**OPERATOR, "Idempotency-Key": "k"}),
        # Tenant header/body conflict.
        (b'{"tenant_id":"other"}',
         {**OPERATOR, "Idempotency-Key": "k", "X-Tenant-Id": "t1"}),
    ],
)
def test_migrate_pre_binding_400(http, raw, headers):
    env, srv = http
    key_id = _create(srv)
    path = "/v1/keys/%s/migrate" % key_id
    status, text = srv.raw("POST", path, raw,
                           {**{"Content-Type": "application/json"}, **headers})
    assert status == 400, text
    body = json.loads(text)
    assert list(body.keys()) == ["error"]
    # Nothing bound, nothing audited.
    assert _migrate_events(env) == []


def test_migrate_bad_key_id_is_400(http):
    env, srv = http
    status, body = _migrate(srv, "not-a-uuid")
    assert status == 400, body
    assert _migrate_events(env) == []


def test_migrate_requires_operator(http):
    _env, srv = http
    status, _ = srv.request(
        "POST", "/v1/keys/%s/migrate" % str(uuid.uuid4()),
        {"tenant_id": "t1"}, {"Idempotency-Key": "k"},
    )
    assert status == 400


# -- authorization / existence -----------------------------------------------
def test_migrate_policy_denied_is_403(http):
    env, srv = http
    key_id = _create(srv)
    # Policy denying migrate while allowing the rest.
    rules = [
        {"subject": "alice", "actions": ["create", "rotate"],
         "effect": "allow"},
        {"subject": "alice", "actions": ["migrate"], "effect": "deny"},
    ]
    status, _ = srv.request(
        "PUT", "/v1/policy",
        {"tenant_id": "t1", "rules": rules}, OPERATOR,
    )
    assert status == 200
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id)
    assert status == 403, body
    assert list(body.keys()) == ["error", "operation_id"]
    assert _migrate_events(env) == [("migrate", "rejected", key_id)]
    # The key file never changed provider.
    versions, _ = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}


def test_migrate_unknown_key_is_404(http):
    env, srv = http
    assert _switchover(srv, "fakekms")[0] == 200
    missing = str(uuid.uuid4())
    status, body = _migrate(srv, missing)
    assert status == 404, body
    assert list(body.keys()) == ["error", "operation_id"]
    assert _migrate_events(env) == [("migrate", "rejected", missing)]


def test_migrate_cross_tenant_is_404(http):
    env, srv = http
    key_id = _create(srv, tenant="t1")
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id, tenant="t2")
    assert status == 404, body
    assert list(body.keys()) == ["error", "operation_id"]
    # The 404 is audited under the REQUESTING tenant (t2), like every other
    # bound rejection; the owning tenant t1 sees nothing, and existence never
    # leaks in the response.
    events = AuditLog(env.data_dir)._read_all()
    migrate_events = [e for e in events if e.action == "migrate"]
    assert len(migrate_events) == 1
    assert migrate_events[0].tenant_id == "t2"
    assert migrate_events[0].key_id == key_id
    assert not any(
        e.tenant_id == "t1" and e.action == "migrate" for e in events
    )


def test_migrate_same_key_different_binding_is_conflict(http):
    _env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    status, first = _migrate(srv, key_id, tenant="t1", key="bound")
    assert status == 200
    status, body = _migrate(srv, key_id, tenant="t2", key="bound")
    assert status == 409
    assert body["operation_id"] == first["operation_id"]
    assert body["error"] == (
        "Idempotency-Key is already bound to a different request"
    )


# -- provider failures -------------------------------------------------------
def test_migrate_unhealthy_source_is_503(reversed_chain_env):
    env = reversed_chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        # Primary fakekms activates; create + rotate there.
        status, _ = srv.request(
            "GET", "/v1/provider/status", headers=OPERATOR
        )
        assert status == 200
        key_id = _create(srv, algorithm="AES256")
        assert _rotate(srv, key_id, key="rot-1")[0] == 201
        assert len(env.kms_handles()) == 2
        # Move the ready provider to the healthy local standby.
        assert _switchover(srv, "local")[0] == 200
        # The source (fakekms) is now unhealthy.
        env.set_faults({"health": False})
        status, body = _migrate(srv, key_id)
        assert status == 503, body
        assert body == {
            "error": "key management provider is unavailable",
            "operation_id": body.get("operation_id"),
        }
        assert list(body.keys()) == ["error", "operation_id"]
        assert _migrate_events(env, body["operation_id"]) == [
            ("migrate", "rejected", key_id)
        ]
        # Nothing changed, no new handles.
        versions, data = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"fakekms"}
        assert len(env.kms_handles()) == 2
    finally:
        srv.stop()
        env.clear_faults()
        provider_mod.reset_for_tests()


def test_migrate_target_import_failure_is_503_and_rolls_back(http):
    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    # The ready provider refuses to mint (target import fails).
    env.set_faults({"fail": {"import_material": True}})
    status, body = _migrate(srv, key_id)
    assert status == 503, body
    assert body["error"] == "key management provider is unavailable"
    op_id = body["operation_id"]
    # Rollback: file back on local, no orphan fake handle, snapshot/journal
    # cleaned, one rejected event.
    versions, data = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}
    assert env.kms_handles() == set()
    assert not os.path.exists(
        os.path.join(env.data_dir, "migrations", op_id + ".json")
    )
    assert not os.path.exists(
        os.path.join(env.data_dir, "provisions", op_id + ".json")
    )
    assert _migrate_events(env, op_id) == [("migrate", "rejected", key_id)]


def test_migrate_503_replays_verbatim_and_does_not_retry(http):
    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    env.set_faults({"fail": {"import_material": True}})
    status, first = _migrate(srv, key_id, key="fail-mig")
    assert status == 503
    # Same key replays the stored terminal; the fault clearing changes
    # nothing -- the terminal is authoritative.
    env.clear_faults()
    status, second = _migrate(srv, key_id, key="fail-mig")
    assert status == 503
    assert second == first
    assert len(_migrate_events(env)) == 1
    versions, _ = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}


# -- mixed-provider versions --------------------------------------------------
def test_migrate_moves_only_versions_not_on_ready(reversed_chain_env):
    """Versions already bound to the ready entry stay untouched; only the
    other versions are exported/imported, and exactly the moved versions' old
    handles are reaped post-commit."""
    env = reversed_chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)  # v1 on fakekms (chain primary)
        fake_handle_v1 = _versions_on_disk(env, key_id)[0][0][2]
        # Hand-craft v2 as already owned by local (as if an earlier migration
        # moved only the newer version).
        store = srv.store
        path = store._path_for(key_id)
        record = store._read_record(path)
        local = provider_mod.configure_local(env.data_dir)
        import base64

        triple = local.import_material(
            "AES256", None, base64.b64encode(b"k" * 32).decode("ascii")
        )
        from keymgr.store import VersionRecord

        record.append_version(
            VersionRecord(
                version=2,
                created_at=record.versions[0].created_at,
                algorithm="AES256",
                public_key=None,
                provider_id="local",
                handle=triple.handle,
                encrypted_material=triple.encrypted_material,
            )
        )
        store._write_atomic(path, record.to_json())
        assert _switchover(srv, "local")[0] == 200
        local_handles_before = set(
            json.load(open(
                os.path.join(env.data_dir, "local-registry.json")
            )).keys()
        )
        assert triple.handle in local_handles_before

        status, body = _migrate(srv, key_id, key="mixed-mig")
        assert status == 200, body
        assert body["provider_id"] == "local"
        assert body["versions"] == [1, 2]
        versions, data = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        # The moved v1's old fake handle is gone; v2's local handle survives.
        assert fake_handle_v1 not in env.kms_handles()
        local_registry = json.load(
            open(os.path.join(env.data_dir, "local-registry.json"))
        )
        assert triple.handle in local_registry
        handles = {h for _, _, h in versions}
        assert triple.handle in handles
        assert len(_migrate_events(env)) == 1
    finally:
        srv.stop()
        provider_mod.reset_for_tests()


# -- lock contention ----------------------------------------------------------
def test_migrate_lock_wait_fixed_503_then_retry_succeeds(http):
    from keymgr import operations as operations_mod

    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    # Hold the per-key in-process lock from another thread; a migrate then
    # exhausts its (shrunk) wait budget.
    import threading

    held = threading.Event()
    release = threading.Event()

    def hold():
        lock = srv.store._key_lock(key_id)
        lock.acquire()
        held.set()
        release.wait(10)
        lock.release()

    thread = threading.Thread(target=hold)
    thread.start()
    assert held.wait(5)
    original_wait = operations_mod.LOCK_WAIT_SECONDS
    operations_mod.LOCK_WAIT_SECONDS = 0.1
    try:
        status, body = _migrate(srv, key_id, key="blocked-mig")
        assert status == 503, body
        assert list(body.keys()) == ["error", "operation_id"]
        assert body["error"] == "key management provider is unavailable"
        op_id = body["operation_id"]
        # No audit terminal: the op stays pending (http_status hidden).
        assert _migrate_events(env, op_id) == []
        status, opbody = srv.request(
            "GET", "/v1/operations/%s" % op_id,
            headers={**OPERATOR, "X-Tenant-Id": "t1"},
        )
        assert status == 200
        assert opbody["status"] == "pending"
        assert opbody["http_status"] is None
        assert opbody["response"] is None
    finally:
        operations_mod.LOCK_WAIT_SECONDS = original_wait
        release.set()
        thread.join()

    # The same key now executes exactly once under the same operation_id.
    status, body = _migrate(srv, key_id, key="blocked-mig")
    assert status == 200, body
    assert body["operation_id"] == op_id
    assert _migrate_events(env, op_id) == [("migrate", "success", key_id)]


# -- post-commit old-handle cleanup ------------------------------------------
def test_migrate_old_handle_delete_failure_succeeds_and_cleans_on_restart(
    reversed_chain_env,
):
    env = reversed_chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        assert _rotate(srv, key_id, key="rot-1")[0] == 201
        old_handles = set(env.kms_handles())
        assert len(old_handles) == 2
        assert _switchover(srv, "local")[0] == 200
        # The commit lands; deleting the OLD fakekms handles then fails.
        env.set_faults({"fail": {"delete": True}})
        status, body = _migrate(srv, key_id, key="mig-1")
        assert status == 200, body
        op_id = body["operation_id"]
        assert old_handles <= env.kms_handles()  # old objects survive
        snapshot = os.path.join(env.data_dir, "migrations", op_id + ".json")
        assert os.path.exists(snapshot)
        # The same key replays the committed success (no second migration).
        status, replay = _migrate(srv, key_id, key="mig-1")
        assert status == 200 and replay == body
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert len(_migrate_events(env)) == 1
    finally:
        srv.stop()
        env.clear_faults()
        provider_mod.reset_for_tests()

    # A fresh process (faults cleared) reaps the old handles at startup and
    # drops the snapshot; the operation still replays the same 200.
    env.clear_faults()
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        assert env.kms_handles() == set()
        assert not os.path.exists(
            os.path.join(env.data_dir, "migrations", op_id + ".json")
        )
        status, replay = _migrate(srv2, key_id, key="mig-1")
        assert status == 200
        assert replay["operation_id"] == op_id
        assert replay["provider_id"] == "local"
        assert len(_migrate_events(env)) == 1
    finally:
        srv2.stop()
        provider_mod.reset_for_tests()


# -- crash recovery ----------------------------------------------------------
def test_migrate_crash_after_commit_finishes_cleanup_on_restart(
    reversed_chain_env,
):
    env = reversed_chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        old_handles = set(env.kms_handles())
        assert _switchover(srv, "local")[0] == 200
        # Bind the idempotent operation the normal way, then craft the crash
        # scene under ITS operation_id (no mirror file in this crafted scene).
        operation = srv.op_store.begin(
            "t1", "alice", "/v1/keys/%s/migrate" % key_id,
            '{"tenant_id":"t1"}', "crash-after-commit",
            mirror_required=False,
        ).record
        op_id = operation.operation_id
        from keymgr.audit import AuditEvent
        audit = AuditLog(env.data_dir)
        store = srv.store
        path = store._path_for(key_id)
        previous_bytes = store._read_file_bytes(path)
        record = store._read_record(path)
        local = provider_mod.get_local_provider()
        journal_id, journal_path = store._new_provision_journal(
            op_id, "t1", "migrate"
        )
        for ver in record.versions:
            # Re-import the raw material into local through the live fake peer.
            import fake_kms
            entry = json.loads(
                open(env.state_path).read()
            )["handles"][ver.handle]
            material = fake_kms._unwrap(entry["material"])
            triple = local.import_material(
                ver.algorithm, ver.public_key, material
            )
            store._append_provision(journal_path, "local", triple.handle)
            ver.provider_id = "local"
            ver.handle = triple.handle
            ver.encrypted_material = triple.encrypted_material
        event = audit.new_event(
            "t1", "migrate", key_id, "success", event_id=op_id
        )
        store._write_migration_snapshot(
            event, previous_bytes,
            [{"provider_id": "fakekms", "handle": h} for h in old_handles],
        )
        marker = dict(event.to_json())
        marker["journal"] = op_id
        record.pending_event = marker
        store._write_atomic(path, record.to_json())
        # Stage the exact success response, as the real pre_commit hook does.
        srv.op_store.stage_terminal(
            operation, 200,
            {
                "key_id": key_id,
                "provider_id": "local",
                "versions": [1],
                "operation_id": op_id,
            },
        )
        audit.append(event)
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    # New process: outbox clears the marker/journal; migration sweep reaps the
    # old fake handles and drops the snapshot.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        assert env.kms_handles() == set()
        assert not os.path.exists(
            os.path.join(env.data_dir, "migrations", op_id + ".json")
        )
        versions, data = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert data["pending_event"] is None
        # The committed operation replays its 200 migrate body.
        status, body = srv2.request(
            "GET", "/v1/operations/%s" % op_id,
            headers={**OPERATOR, "X-Tenant-Id": "t1"},
        )
        assert status == 200, body
        assert body["status"] == "succeeded"
        assert body["http_status"] == 200
        assert list(body["response"].keys()) == [
            "key_id", "provider_id", "versions", "operation_id"
        ]
        assert body["response"]["provider_id"] == "local"
        assert body["response"]["versions"] == [1]
        assert len(_migrate_events(env)) == 1
    finally:
        srv2.stop()
        provider_mod.reset_for_tests()


def test_migrate_journal_only_crash_restores_old_file_and_deletes_handles(
    http,
):
    """Crash after the target minted new handles but before the key file
    marker landed: only the provision journal + migration snapshot survive.
    Startup recovery must delete the NEW handles, leave the old file exactly
    as it was and drop both artifacts, with no event ever booked."""
    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    op_id = str(uuid.uuid4())
    store = srv.store
    path = store._path_for(key_id)
    previous_bytes = store._read_file_bytes(path)
    old_record = store._read_record(path)
    old_handle = old_record.versions[0].handle
    # Mint a target (fakekms) handle exactly as a migrate mid-flight would,
    # journal it, and write the migration snapshot -- but never touch the key
    # file and never append an event (crash before the outbox marker).
    import base64 as _b64
    ready = provider_mod.get_provider()
    _jid, journal_path = store._new_provision_journal(op_id, "t1", "migrate")
    triple = ready.import_material(
        "AES256", None, _b64.b64encode(b"k" * 32).decode("ascii")
    )
    store._append_provision(journal_path, "fakekms", triple.handle)
    event = AuditLog(env.data_dir).new_event(
        "t1", "migrate", key_id, "success", event_id=op_id
    )
    store._write_migration_snapshot(
        event, previous_bytes,
        [{"provider_id": "local", "handle": old_handle}],
    )
    assert triple.handle in env.kms_handles()
    srv.stop()
    provider_mod.reset_for_tests()

    # New process: journal sweep deletes the new handle; migration sweep then
    # sees the file still at its old triples and drops the snapshot.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    fresh = env.open_store()
    assert triple.handle not in env.kms_handles()
    assert not os.path.exists(
        os.path.join(env.data_dir, "migrations", op_id + ".json")
    )
    assert not os.path.exists(
        os.path.join(env.data_dir, "provisions", op_id + ".json")
    )
    versions, data = _versions_on_disk(env, key_id)
    assert versions == [(1, "local", old_handle)]
    assert data["pending_event"] is None
    assert _migrate_events(env) == []


# -- envelope crypto still works after migration ------------------------------
def test_decrypt_works_after_migration(http):
    env, srv = http
    key_id = _create(srv, algorithm="RSA2048")
    plaintext = "aGVsbG8="  # base64("hello")
    status, enc = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": plaintext},
        {**OPERATOR, "Idempotency-Key": "enc-1"},
    )
    assert status == 200, enc
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id)
    assert status == 200, body
    status, dec = srv.request(
        "POST", "/v1/keys/%s/decrypt" % key_id,
        {"tenant_id": "t1", "envelope": enc["envelope"]}, OPERATOR,
    )
    assert status == 200, dec
    assert dec["plaintext"] == plaintext


# -- audit query accepts the new action --------------------------------------
def test_audit_filter_by_migrate_action(http):
    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    assert _migrate(srv, key_id)[0] == 200
    status, body = srv.request(
        "GET", "/v1/audit?action=migrate",
        headers={**OPERATOR, "X-Tenant-Id": "t1"},
    )
    assert status == 200, body
    assert len(body["events"]) == 1
    assert body["events"][0]["action"] == "migrate"
    assert body["events"][0]["key_id"] == key_id


# -- CLI ---------------------------------------------------------------------
def test_cli_migrate_success_and_exit_codes(chain_env, monkeypatch):
    env = chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        assert _switchover(srv, "fakekms")[0] == 200
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    # Success: exit 0, ordered one-line JSON.
    result = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "cli-mig-1",
    )
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout.strip())
    assert list(body.keys()) == [
        "key_id", "provider_id", "versions", "operation_id"
    ]
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1]
    op_id = body["operation_id"]

    # Replay exits 0 with the same body.
    replay = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "cli-mig-1",
    )
    assert replay.returncode == 0
    assert json.loads(replay.stdout.strip()) == body

    # A second key -> 409 -> exit 3.
    conflict = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "cli-mig-2",
    )
    assert conflict.returncode == 3
    err = json.loads(conflict.stderr.strip())
    assert list(err.keys()) == ["error", "operation_id"]

    # Unknown key -> 404 -> exit 4.
    missing = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", str(uuid.uuid4()),
        "--operator", "alice", "--idempotency-key", "cli-mig-3",
    )
    assert missing.returncode == 4

    # Bad key id -> 400 -> exit 2.
    bad = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", "nope",
        "--operator", "alice", "--idempotency-key", "cli-mig-4",
    )
    assert bad.returncode == 2

    # Bad idempotency key -> 400 -> exit 2.
    badkey = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "bad key!",
    )
    assert badkey.returncode == 2
    assert op_id  # one migration committed


def test_cli_migrate_503_exit_1(reversed_chain_env, monkeypatch):
    env = reversed_chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        assert _switchover(srv, "local")[0] == 200
    finally:
        srv.stop()
        provider_mod.reset_for_tests()
    env.set_faults({"health": False})
    try:
        result = run_cli(
            env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
            "--operator", "alice", "--idempotency-key", "cli-mig-down",
        )
        assert result.returncode == 1
        err = json.loads(result.stderr.strip())
        assert list(err.keys()) == ["error", "operation_id"]
        assert err["error"] == "key management provider is unavailable"
    finally:
        env.clear_faults()
        provider_mod.reset_for_tests()
