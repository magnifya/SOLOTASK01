"""Operation artifact mirrors for rotate/import/restore/batch-rotate.

The mirror (``operation-artifacts/<operation_id>.json``, 0600/fsync) is
created after the Idempotency-Key is bound and before the provider is called;
it ties the operation record, the provision journal and (for a batch) the
snapshot / (for a restore) the marker together. Recovery retains the whole
evidence group whenever committed-vs-rolled-back cannot be proven and discards
the mirror only once the event is durable and every marker is gone, or the
rollback fully verified. These tests exercise that contract directly and
through the HTTP surface.
"""

import json
import os
import stat

import pytest

from keymgr import audit as audit_mod
from keymgr.artifacts import ArtifactConflict, ArtifactStore
from keymgr.audit import AuditEvent, AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.provider import ProviderUnavailable
from keymgr.restore import RestoreCoordinator
from keymgr.store import KeyStore

from test_recovery_batch import _craft_batch_scene, _make_keys
from test_recovery_misc import HttpServer, _create_key_http  # noqa: F401
from test_recovery_restore import _craft_restore_scene
from test_recovery_rotate import (
    _craft_journal_only_scene,
    _craft_rotate_marker_scene,
    _make_key,
)


def _artifact_path(env, operation_id):
    return os.path.join(
        env.data_dir, "operation-artifacts", operation_id + ".json"
    )


def _stage_mirror(env, operation_id, action="rotate", kind="rotate",
                  write_set=None, tenant="t1", operator="alice",
                  path="/v1/keys/x/rotate", body='{"tenant_id":"t1"}'):
    store = ArtifactStore(env.data_dir, AuditLog(env.data_dir))
    return store.stage(
        operation_id, tenant, operator, path, body, action, kind,
        write_set=write_set or [],
    )


# -- file shape, permissions and confidentiality -----------------------------
def test_mirror_is_0600_fsynced_and_records_full_context(env):
    store = env.open_store()
    operation_id = "00000000-0000-4000-8000-0000000000aa"
    artifact = _stage_mirror(
        env, operation_id, write_set=["k1"], path="/v1/keys/x/rotate"
    )
    path = _artifact_path(env, operation_id)
    artifact.link_provision_journal(operation_id)
    artifact.register_handle("fakekms", "handle-abc")
    # The first minted handle advances staged -> provisioned.
    with open(path, "r", encoding="utf-8") as fh:
        assert json.load(fh)["phase"] == "provisioned"
    artifact.set_phase("files_written")

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["operation_id"] == operation_id
    assert doc["tenant_id"] == "t1"
    assert doc["operator_id"] == "alice"
    assert doc["path"] == "/v1/keys/x/rotate"
    assert doc["request_body"] == '{"tenant_id":"t1"}'
    assert doc["action"] == "rotate"
    assert doc["kind"] == "rotate"
    assert doc["phase"] == "files_written"
    assert doc["write_set"] == ["k1"]
    assert doc["provision_journal"] == operation_id
    assert doc["handles"] == [
        {"provider_id": "fakekms", "handle": "handle-abc"}
    ]
    # Repeated handle registration is de-duplicated and keeps the phase.
    artifact.register_handle("fakekms", "handle-abc")
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert len(doc["handles"]) == 1
    assert doc["phase"] == "files_written"


def test_stage_is_idempotent_but_rejects_a_mismatched_binding(env):
    operation_id = "00000000-0000-4000-8000-0000000000bb"
    store = ArtifactStore(env.data_dir, AuditLog(env.data_dir))
    first = store.stage(
        operation_id, "t1", "alice", "/p", "{}", "rotate", "rotate", []
    )
    # Same binding returns the same durable mirror.
    again = store.stage(
        operation_id, "t1", "alice", "/p", "{}", "rotate", "rotate", []
    )
    assert again.operation_id == first.operation_id
    # A surviving mirror for a different tenant/action/path is never adopted.
    with pytest.raises(ArtifactConflict):
        store.stage(
            operation_id, "t2", "alice", "/p", "{}", "rotate", "rotate", []
        )


def test_corrupt_mirror_is_retained_not_guessed(env):
    operation_id = "00000000-0000-4000-8000-0000000000cc"
    _stage_mirror(env, operation_id)
    path = _artifact_path(env, operation_id)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    # Unreadable evidence is preserved verbatim for operator handling.
    assert os.path.exists(path)


# -- the mirror is durable strictly BEFORE the provider is called ------------
def test_mirror_is_durable_before_the_provider_call(env):
    key_id = _make_key(env)
    store = env.open_store()
    operation_id = "00000000-0000-4000-8000-0000000000dd"
    artifact_store = ArtifactStore(env.data_dir, store.audit)
    artifact = artifact_store.stage(
        operation_id, "t1", "alice",
        "/v1/keys/%s/rotate" % key_id,
        '{"algorithm":"AES256","tenant_id":"t1"}',
        audit_mod.ACTION_ROTATE, "rotate", [key_id],
    )
    provider = store._provider()
    observed = {}
    real_rotate = provider.rotate

    def observe(algorithm):
        # Inside the provider call the mirror is already durable and the
        # journal is already linked; no handle is registered yet.
        path = _artifact_path(env, operation_id)
        observed["exists"] = os.path.exists(path)
        observed["mode"] = stat.S_IMODE(os.stat(path).st_mode)
        with open(path, "r", encoding="utf-8") as fh:
            observed["doc"] = json.load(fh)
        return real_rotate(algorithm)

    provider.rotate = observe
    try:
        store.rotate(
            key_id, "t1", "AES256",
            event_id=operation_id, artifact=artifact,
        )
    finally:
        provider.rotate = real_rotate

    assert observed["exists"] is True
    assert observed["mode"] == 0o600
    doc = observed["doc"]
    assert doc["tenant_id"] == "t1"
    assert doc["operator_id"] == "alice"
    assert doc["path"] == "/v1/keys/%s/rotate" % key_id
    # Canonical request body: key-sorted, compact.
    assert doc["request_body"] == '{"algorithm":"AES256","tenant_id":"t1"}'
    assert doc["action"] == "rotate"
    assert doc["write_set"] == [key_id]
    assert doc["provision_journal"] == operation_id
    assert doc["handles"] == []  # no handle minted at the pre-call point
    # After commit and settle the mirror is gone; no material leaked.
    artifact_store.settle(operation_id)
    assert not os.path.exists(_artifact_path(env, operation_id))


# -- single-key rotate crash scenes ------------------------------------------
def _mirror_for_scene(env, event_id, action="rotate", kind="rotate",
                      write_set=None):
    return _stage_mirror(
        env, event_id, action=action, kind=kind, write_set=write_set or []
    )


def test_rotate_committed_scene_discards_mirror_and_keeps_version(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    _mirror_for_scene(env, event_id, write_set=[key_id])
    # The commit-point event is durable: append the exact marker event.
    ledger = AuditLog(env.data_dir)
    with open(os.path.join(env.data_dir, key_id + ".json")) as fh:
        marker = json.load(fh)["pending_event"]
    ledger.append(AuditEvent.from_json(marker))

    env.open_store()  # outbox recovery commits forward and clears markers
    ArtifactStore(env.data_dir, ledger).recover()

    assert not os.path.exists(_artifact_path(env, event_id))
    # The new version (and its handle) stays as the committed state.
    assert env.open_store().get(key_id, "t1").current_version == 2
    assert handle in env.kms_handles()


def test_rotate_uncommitted_scene_discards_mirror_after_rollback(env):
    key_id = _make_key(env)
    # Crash after the provider minted the handle, before any key-file write:
    # no durable event, so startup reaps the handle and drops the journal.
    event_id, handle, journal_id = _craft_journal_only_scene(env, key_id)
    _mirror_for_scene(env, event_id, write_set=[key_id])

    env.open_store()  # no durable event -> handle reaped, journal dropped
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()

    assert not os.path.exists(_artifact_path(env, event_id))
    assert handle not in env.kms_handles()
    assert env.open_store().get(key_id, "t1").current_version == 1


def test_rotate_provider_down_keeps_mirror_with_the_journal(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_journal_only_scene(env, key_id)
    mirror = _mirror_for_scene(env, event_id, write_set=[key_id])
    mirror.link_provision_journal(journal_id)

    env.set_faults({"unreachable": True})
    env.open_store()  # cannot delete the handle: journal retained
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    # The whole evidence group, mirror included, waits for the next open.
    assert os.path.exists(_artifact_path(env, event_id))
    assert os.path.exists(
        os.path.join(env.data_dir, "provisions", journal_id + ".json")
    )

    env.clear_faults()
    env.open_store()  # the later process reaps the handle
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    assert not os.path.exists(_artifact_path(env, event_id))
    assert handle not in env.kms_handles()


def test_rotate_foreign_event_parks_the_mirror(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    _mirror_for_scene(env, event_id, write_set=[key_id])
    # A durable same-id event of another tenant: the commit is unprovable.
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "other", audit_mod.ACTION_ROTATE, key_id,
            audit_mod.OUTCOME_SUCCESS, event_id=event_id,
        )
    )
    env.open_store()
    ArtifactStore(env.data_dir, ledger).recover()
    assert os.path.exists(_artifact_path(env, event_id))
    assert handle in env.kms_handles()


def test_rotate_unreadable_ledger_retains_the_mirror(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    _mirror_for_scene(env, event_id, write_set=[key_id])
    log_path = os.path.join(env.data_dir, "audit.log")
    with open(log_path, "rb") as fh:
        saved = fh.read()
    os.unlink(log_path)
    os.mkdir(log_path)
    try:
        env.open_store()
        ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
        assert os.path.exists(_artifact_path(env, event_id))
    finally:
        os.rmdir(log_path)
        with open(log_path, "wb") as fh:
            fh.write(saved)
    # Once the ledger is readable the uncommitted scene settles and the
    # mirror is discarded.
    env.open_store()
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    assert not os.path.exists(_artifact_path(env, event_id))


# -- batch rotation ------------------------------------------------------------
def test_batch_uncommitted_rollback_discards_mirror(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    mirror = _stage_mirror(
        env, scene.event_id, action=audit_mod.ACTION_BATCH_ROTATE,
        kind="batch_rotate", write_set=keys,
        path="/v1/keys/batch-rotate",
    )
    mirror.link_provision_journal(scene.journal_id)
    mirror.link_snapshot(scene.event_id)

    env.open_store()  # whole group rolled back, journal/snapshot removed
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()

    assert not os.path.exists(_artifact_path(env, scene.event_id))


def test_batch_corrupt_snapshot_parks_the_mirror(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    mirror = _stage_mirror(
        env, scene.event_id, action=audit_mod.ACTION_BATCH_ROTATE,
        kind="batch_rotate", write_set=keys,
        path="/v1/keys/batch-rotate",
    )
    mirror.link_provision_journal(scene.journal_id)
    mirror.link_snapshot(scene.event_id)
    with open(
        os.path.join(env.data_dir, "batch-rotations", scene.event_id + ".json"),
        "w", encoding="utf-8",
    ) as fh:
        fh.write("{not json")

    env.open_store()  # parks the whole group
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    assert os.path.exists(_artifact_path(env, scene.event_id))


# -- restore -------------------------------------------------------------------
def test_restore_uncommitted_rollback_discards_mirror(env):
    scene = _craft_restore_scene(env, with_policy=True)
    mirror = _stage_mirror(
        env, scene.event_id, action=audit_mod.ACTION_IMPORT,
        kind="restore", write_set=scene.key_ids, path="/v1/restore",
    )
    mirror.link_provision_journal(scene.journal_id)

    store = env.open_store()
    RestoreCoordinator(store, PolicyStore(env.data_dir, store.audit))
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()

    assert not os.path.exists(_artifact_path(env, scene.event_id))


def test_restore_provider_down_keeps_mirror_with_the_group(env):
    scene = _craft_restore_scene(env, with_policy=True)
    mirror = _stage_mirror(
        env, scene.event_id, action=audit_mod.ACTION_IMPORT,
        kind="restore", write_set=scene.key_ids, path="/v1/restore",
    )
    mirror.link_provision_journal(scene.journal_id)

    env.set_faults({"unreachable": True})
    store = env.open_store()
    RestoreCoordinator(store, PolicyStore(env.data_dir, store.audit))
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    assert os.path.exists(_artifact_path(env, scene.event_id))

    env.clear_faults()
    store = env.open_store()
    RestoreCoordinator(store, PolicyStore(env.data_dir, store.audit))
    ArtifactStore(env.data_dir, AuditLog(env.data_dir)).recover()
    assert not os.path.exists(_artifact_path(env, scene.event_id))


# -- HTTP surface: mirrors back the request but never survive a settled op ----
@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield server
    server.stop()


def test_http_success_leaves_no_mirror_and_hides_nothing_new(http, env):
    key_id = _create_key_http(http)
    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-rot-1"},
    )
    assert status == 201, body
    operation_id = body["operation_id"]
    # A settled success removes its artifact mirror.
    assert not os.path.exists(_artifact_path(env, operation_id))
    # Replay still serves the exact first terminal state.
    status, retry = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-rot-1"},
    )
    assert status == 201 and retry == body


def test_http_provider_down_503_leaves_no_orphan_mirror(http, env):
    key_id = _create_key_http(http)
    env.set_faults({"unreachable": True})
    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-rot-down"},
    )
    assert status == 503
    operation_id = body["operation_id"]
    env.clear_faults()
    # The clean provider fault deleted every minted handle and dropped the
    # journal before the terminal was recorded, so the mirror is gone too.
    assert not os.path.exists(_artifact_path(env, operation_id))
    # GET operation never serves the mirror, the request body or any handle.
    status, op = http.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        {"X-Operator-Id": "alice", "X-Tenant-Id": "t1"},
    )
    assert status == 200
    assert "request_body" not in json.dumps(op)
    assert "handle" not in json.dumps(op)


def test_http_batch_success_clears_its_mirror(http, env):
    key_id = _create_key_http(http)
    status, body = http.request(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t1",
         "items": [{"key_id": key_id, "algorithm": "AES256"}]},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-batch-1"},
    )
    assert status == 201, body
    assert not os.path.exists(_artifact_path(env, body["operation_id"]))
    # No batch snapshot or provision journal survives a committed batch.
    snap_dir = os.path.join(env.data_dir, "batch-rotations")
    assert not os.path.isdir(snap_dir) or not os.listdir(snap_dir)
    prov_dir = os.path.join(env.data_dir, "provisions")
    assert not os.path.isdir(prov_dir) or not os.listdir(prov_dir)


def test_http_param_error_before_binding_creates_no_mirror(http, env):
    key_id = _create_key_http(http)
    # A malformed algorithm is a 400 before the key is bound: no mirror.
    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "DES"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-bad"},
    )
    assert status == 400
    assert "operation_id" not in body
    assert not os.path.isdir(
        os.path.join(env.data_dir, "operation-artifacts")
    ) or not os.listdir(os.path.join(env.data_dir, "operation-artifacts"))


def test_http_policy_rejection_403_clears_its_mirror(http, env):
    key_id = _create_key_http(http)
    # A rules:[] policy denies rotate (policy_* and create happened while no
    # policy existed, which allows all).
    status, put = http.request(
        "PUT", "/v1/policy",
        {"tenant_id": "t1", "rules": []},
        {"X-Operator-Id": "admin"},
    )
    assert status == 200, put
    status, body = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-deny"},
    )
    assert status == 403
    operation_id = body["operation_id"]
    # The bound rejection staged no journal/handle/file, so the mirror is
    # removed once the terminal is durable.
    assert not os.path.exists(_artifact_path(env, operation_id))
    # Replay serves the identical 403 with the same operation_id.
    status, retry = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-deny"},
    )
    assert status == 403
    assert retry["operation_id"] == operation_id


# -- empty restore keeps its finalized marker but drops the mirror -----------def test_http_empty_restore_finalizes_marker_but_clears_mirror(http, env):
    # Back up an empty tenant, then restore that empty bundle into it.
    status, backup = http.request(
        "POST", "/v1/backup",
        {"tenant_id": "empty", "passphrase": "pw"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 200, backup
    status, body = http.request(
        "POST", "/v1/restore",
        {"tenant_id": "empty", "passphrase": "pw", "bundle": backup["bundle"]},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-rest-empty"},
    )
    assert status == 201, body
    operation_id = body["operation_id"]
    assert body["key_ids"] == []
    assert body["policy_restored"] is False
    # The committed empty-restore marker survives (idempotency record)...
    markers = [
        n for n in os.listdir(env.data_dir)
        if n.startswith("restore-empty-") and n.endswith(".json")
    ]
    assert len(markers) == 1
    with open(os.path.join(env.data_dir, markers[0])) as fh:
        assert json.load(fh)["event"] is None  # finalized
    # ...but the operation artifact mirror is discarded.
    assert not os.path.exists(_artifact_path(env, operation_id))

    # A same-key retry replays the first terminal outcome verbatim (201).
    status, retry = http.request(
        "POST", "/v1/restore",
        {"tenant_id": "empty", "passphrase": "pw", "bundle": backup["bundle"]},
        {"X-Operator-Id": "alice", "Idempotency-Key": "m-rest-empty"},
    )
    assert status == 201
    assert retry["operation_id"] == operation_id
    assert not os.path.exists(_artifact_path(env, operation_id))


# -- CLI cross-process: mirrors settle across processes too -------------------
def test_cli_success_and_retry_leave_no_mirror(env):
    from test_recovery_cli import run_cli

    key_id = json.loads(
        run_cli(
            env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
            "--label", "k", "--operator", "alice",
        ).stdout
    )["key_id"]
    rotate = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-mirror-1",
    )
    assert rotate.returncode == 0, rotate.stderr
    operation_id = json.loads(rotate.stdout)["operation_id"]
    assert not os.path.exists(_artifact_path(env, operation_id))
    # A same-key retry replays and still leaves no mirror behind.
    retry = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-mirror-1",
    )
    assert retry.returncode == 0, retry.stderr
    assert json.loads(retry.stdout)["operation_id"] == operation_id
    assert not os.path.exists(_artifact_path(env, operation_id))


def test_cli_crash_before_commit_settles_mirror_on_next_process(env):
    from test_recovery_cli import (
        LedgerHold, _gen, run_cli, start_cli, wait_for,
    )

    key_id = _gen(env, "t1", "k")
    with LedgerHold(env):
        proc = start_cli(
            env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
            "--algorithm", "AES256", "--operator", "alice",
            "--idempotency-key", "cli-crash-mirror",
        )
        assert wait_for(lambda: os.path.isdir(
            os.path.join(env.data_dir, "operation-artifacts")
        ) and os.listdir(os.path.join(env.data_dir, "operation-artifacts")))
        proc.kill()
        proc.wait()
    mirror_dir = os.path.join(env.data_dir, "operation-artifacts")
    assert len([f for f in os.listdir(mirror_dir) if f.endswith(".json")]) == 1

    # The next process commits forward (marker + durable event) and the
    # artifact recovery then discards the mirror by operation_id.
    assert run_cli(
        env, "current", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice",
    ).returncode == 0
    assert [f for f in os.listdir(mirror_dir) if f.endswith(".json")] == []
