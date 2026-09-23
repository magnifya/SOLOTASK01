"""Artifact mirror lifecycle and crash settlement.

These tests cover the durable ``operation-artifacts/<operation_id>.json``
mirror introduced for rotate/import/restore/batch-rotate: its 0600/fsync
shape and binding facts, the new-handle/phase progression, and the startup
rules -- clean on a confirmed commit, clean after a fully verified rollback,
and ENTIRE evidence retained (operation kept pending) when the commit is
uncertain, a reference is missing/inconsistent, or the provider cannot
confirm a handle deletion.
"""

import json
import os
import stat

from keymgr import audit as audit_mod
from keymgr.artifacts import (
    ArtifactStore,
    PHASE_BOUND,
    PHASE_COMMITTED,
    PHASE_PROVISIONING,
    PHASE_STAGED,
)
from keymgr.audit import AuditLog
from keymgr.operations import (
    OperationRecord,
    OperationStore,
    STATUS_PENDING,
    STATUS_SUCCEEDED,
    STATUS_FAILED,
)
from keymgr.store import KeyStore

from test_recovery_rotate import (
    _craft_journal_only_scene,
    _craft_rotate_marker_scene,
    _make_key,
)


def _open_world(env):
    """Fresh store/operation/artifact handles over one data dir."""
    audit = AuditLog(env.data_dir)
    store = env.open_store()
    op_store = OperationStore(env.data_dir, audit)
    art = ArtifactStore(env.data_dir, store, audit)
    return store, op_store, art


def _setup_no_recovery(env):
    """Operation/artifact handles WITHOUT opening a KeyStore.

    Crafting a crash scene leaves residual markers/journals on disk; opening
    a KeyStore would run the outbox recovery immediately. The arrangement
    phase (pending operation + surviving mirror) therefore uses a keyless
    ArtifactStore (the request-path mutators it exercises never need the
    store); only the simulated "next process" opens a KeyStore.
    """
    audit = AuditLog(env.data_dir)
    op_store = OperationStore(env.data_dir, audit)
    art = ArtifactStore(env.data_dir, None, audit)
    return audit, op_store, art


def _pending_operation(op_store, operation_id, key_id, tenant="t1",
                       operator="alice"):
    """Write a pending operation record with a chosen operation_id."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    path = "/v1/keys/%s/rotate" % key_id
    body = json.dumps(
        {"tenant_id": tenant, "algorithm": "AES256"},
        sort_keys=True, separators=(",", ":"),
    )
    record = OperationRecord(
        operation_id=operation_id,
        tenant_id=tenant,
        operator_id=operator,
        path=path,
        request_body=body,
        idempotency_key="mirror-key-" + operation_id[:8],
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details={"kind": "rotate", "key_id": key_id, "algorithm": "AES256"},
    )
    op_store._write_record(record)
    return record


# -- descriptor shape ---------------------------------------------------------
def test_mirror_is_0600_and_carries_binding_facts(env):
    import uuid

    _make_key(env)
    _, op_store, art = _open_world(env)
    some_key = str(uuid.uuid4())
    begin = op_store.begin(
        "t1", "alice", "/v1/keys/%s/rotate" % some_key,
        json.dumps({"tenant_id": "t1", "algorithm": "AES256"},
                   sort_keys=True, separators=(",", ":")),
        "mirror-1",
    )
    mirror = art.create(begin.record)
    path = mirror.path()
    assert os.path.exists(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path, "r", encoding="utf-8") as fh:
        desc = json.load(fh)
    assert desc["operation_id"] == begin.record.operation_id
    assert desc["tenant_id"] == "t1"
    assert desc["operator_id"] == "alice"
    assert desc["path"] == "/v1/keys/%s/rotate" % some_key
    assert desc["phase"] == PHASE_BOUND
    assert desc["write_set"] == []
    assert desc["handles"] == []

    mirror.describe({"kind": "rotate", "write_set": [some_key]})
    mirror.provision(begin.record.operation_id)
    assert mirror.descriptor["phase"] == PHASE_PROVISIONING
    mirror.add_handle("fakekms", "handle-abc")
    with open(path, "r", encoding="utf-8") as fh:
        desc = json.load(fh)
    assert desc["action"] == audit_mod.ACTION_ROTATE
    assert desc["write_set"] == [some_key]
    assert desc["journal"] == begin.record.operation_id
    assert desc["handles"] == [
        {"provider_id": "fakekms", "handle": "handle-abc"}
    ]


def test_mirror_directory_is_lazy(env):
    # Constructing the store must not create the directory before a mutation
    # binds a key.
    ArtifactStore(env.data_dir, env.open_store(), AuditLog(env.data_dir))
    assert not os.path.isdir(
        os.path.join(env.data_dir, "operation-artifacts")
    )


# -- request-path cleanup -----------------------------------------------------
def test_successful_rotate_clears_its_mirror(env):
    key_id = _make_key(env)
    store, op_store, art = _open_world(env)
    begin = op_store.begin(
        "t1", "alice", "/v1/keys/%s/rotate" % key_id,
        json.dumps({"tenant_id": "t1", "algorithm": "AES256"},
                   sort_keys=True, separators=(",", ":")),
        "mirror-ok",
    )
    mirror = art.create(begin.record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    record = store.rotate(
        key_id, "t1", "AES256",
        event_id=begin.record.operation_id, mirror=mirror,
    )
    assert record.current_version == 2
    assert mirror.descriptor["phase"] == PHASE_COMMITTED
    art.after_terminal(mirror)
    assert not os.path.exists(mirror.path())


# -- startup: confirmed commit ------------------------------------------------
def test_committed_marker_scene_clears_mirror_and_succeeds(env):
    key_id = _make_key(env)
    event_id, handle, _journal = _craft_rotate_marker_scene(env, key_id)
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, event_id, key_id)
    mirror = art.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror.provision(event_id)
    mirror.add_handle("fakekms", handle)
    mirror.phase(PHASE_STAGED)
    assert os.path.exists(mirror.path())

    # New process: outbox recovery commits the marker forward, then the
    # mirror settles and the operation finalizes succeeded(201).
    audit = AuditLog(env.data_dir)
    store2 = env.open_store()
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    assert not art2.is_parked(event_id)
    op2.recover_pending(is_parked=art2.is_parked)

    final = op2.get(event_id, "t1", "alice")
    assert final.status == STATUS_SUCCEEDED
    assert final.http_status == 201
    assert not os.path.exists(mirror.path())
    assert handle in env.kms_handles()  # committed handle is kept


# -- startup: journal-only rollback -------------------------------------------
def test_journal_only_scene_clears_mirror_and_fails_op(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_journal_only_scene(env, key_id)
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, event_id, key_id)
    mirror = art.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror.provision(journal_id)
    mirror.add_handle("fakekms", handle)
    mirror.phase(PHASE_PROVISIONING)

    # New process: no commit event -> the orphan journal/handle is reaped and
    # the mirror is dropped; the interrupted operation finalizes failed(500).
    audit = AuditLog(env.data_dir)
    store2 = env.open_store()
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    assert not art2.is_parked(event_id)
    op2.recover_pending(is_parked=art2.is_parked)

    assert handle not in env.kms_handles()
    assert not os.path.exists(store2._provision_path(journal_id))
    assert not os.path.exists(mirror.path())
    final = op2.get(event_id, "t1", "alice")
    assert final.status == STATUS_FAILED
    assert final.http_status == 500


def test_provider_down_keeps_entire_evidence_and_parks_op(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_journal_only_scene(env, key_id)
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, event_id, key_id)
    mirror = art.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror.provision(journal_id)
    mirror.add_handle("fakekms", handle)
    mirror.phase(PHASE_PROVISIONING)

    env.set_faults({"unreachable": True})
    audit = AuditLog(env.data_dir)
    store2 = env.open_store()  # cannot reap the journal this open
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    # The whole evidence set survives and the operation stays pending.
    assert art2.is_parked(event_id)
    op2.recover_pending(is_parked=art2.is_parked)
    assert op2.get(event_id, "t1", "alice").status == STATUS_PENDING
    assert os.path.exists(store2._provision_path(journal_id))
    assert os.path.exists(mirror.path())
    assert handle in env.kms_handles()

    # A later, healthy process settles it: rollback, then failed(500).
    env.clear_faults()
    audit = AuditLog(env.data_dir)
    store3 = env.open_store()
    art3 = ArtifactStore(env.data_dir, store3, audit)
    op3 = OperationStore(env.data_dir, audit)
    art3.settle_pending(op3)
    op3.recover_pending(is_parked=art3.is_parked)
    assert handle not in env.kms_handles()
    assert not os.path.exists(mirror.path())
    final = op3.get(event_id, "t1", "alice")
    assert final.status == STATUS_FAILED
    assert final.http_status == 500


# -- startup: inconsistent references -----------------------------------------
def test_foreign_action_event_parks_mirror_and_op(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    # A durable SUCCESS event with the SAME id but a different action.
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "t1", audit_mod.ACTION_CREATE, key_id,
            audit_mod.OUTCOME_SUCCESS, event_id=event_id,
        )
    )
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, event_id, key_id)
    mirror = art.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror.provision(journal_id)
    mirror.add_handle("fakekms", handle)
    mirror.phase(PHASE_STAGED)

    audit = AuditLog(env.data_dir)
    store2 = env.open_store()  # parks the foreign-event marker scene
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    assert art2.is_parked(event_id)
    op2.recover_pending(is_parked=art2.is_parked)
    # Nothing is guessed: operation pending, mirror + handle retained, the
    # uncommitted current stays hidden.
    assert op2.get(event_id, "t1", "alice").status == STATUS_PENDING
    assert os.path.exists(mirror.path())
    assert handle in env.kms_handles()
    assert store2.get(key_id, "t1").current_version == 1


def test_binding_mismatch_between_mirror_and_operation_parks(env):
    key_id = _make_key(env)
    event_id, _handle, _j = _craft_journal_only_scene(env, key_id)
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, event_id, key_id)
    mirror = art.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    # Tamper the mirror so its tenant no longer matches the operation record.
    desc = dict(mirror.descriptor)
    desc["tenant_id"] = "other-tenant"
    art.write_descriptor(desc)

    audit = AuditLog(env.data_dir)
    store2 = env.open_store()
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    assert art2.is_parked(event_id)
    op2.recover_pending(is_parked=art2.is_parked)
    assert op2.get(event_id, "t1", "alice").status == STATUS_PENDING
    assert os.path.exists(mirror.path())


def test_corrupt_mirror_file_parks_op(env):
    key_id = _make_key(env)
    event_id, _handle, _j = _craft_journal_only_scene(env, key_id)
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, event_id, key_id)
    mirror = art.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    with open(mirror.path(), "w", encoding="utf-8") as fh:
        fh.write("{not json")

    audit = AuditLog(env.data_dir)
    store2 = env.open_store()
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    assert art2.is_parked(event_id)
    op2.recover_pending(is_parked=art2.is_parked)
    assert op2.get(event_id, "t1", "alice").status == STATUS_PENDING


# -- batch / import / restore lifecycle ---------------------------------------
def test_successful_batch_rotate_clears_mirror(env):
    from test_recovery_batch import _make_keys

    keys = _make_keys(env, n=2)
    store, op_store, art = _open_world(env)
    begin = op_store.begin(
        "t1", "alice", "/v1/keys/batch-rotate",
        json.dumps({"tenant_id": "t1"}, sort_keys=True,
                   separators=(",", ":")),
        "mirror-batch",
    )
    mirror = art.create(begin.record).describe(
        {"kind": "batch_rotate", "write_set": keys}
    )
    status, result = store.batch_rotate(
        "t1", [(k, "AES256") for k in keys],
        event_id=begin.record.operation_id, mirror=mirror,
    )
    assert status == store.BATCH_ROTATED
    assert mirror.descriptor["phase"] == PHASE_COMMITTED
    assert mirror.descriptor["snapshot"] == begin.record.operation_id
    assert len(mirror.descriptor["handles"]) == 2
    art.after_terminal(mirror)
    assert not os.path.exists(mirror.path())
    for key_id, record in result:
        assert record.current_version == 2


def test_successful_import_clears_mirror(env):
    from keymgr import keybundle

    # Export from one data dir and import into a fresh dir that shares the
    # same (fake) KMS backend, so the key_id is free there.
    src = env.open_store()
    rec = src.create("t1", "AES256", "imp-src")
    bundle = src.export_bundle(rec.key_id, "t1", "pw")
    decoded = keybundle.decode_bundle(bundle, "pw")

    dst_dir = env.data_dir + "-imp"
    os.makedirs(dst_dir, exist_ok=True)
    audit = AuditLog(dst_dir)
    dst = KeyStore(dst_dir, audit)
    op_store = OperationStore(dst_dir, audit)
    art = ArtifactStore(dst_dir, dst, audit)

    begin = op_store.begin(
        "t1", "alice", "/v1/keys/import",
        json.dumps({"tenant_id": "t1"}, sort_keys=True,
                   separators=(",", ":")),
        "mirror-import",
    )
    mirror = art.create(begin.record).describe(
        {"kind": "import", "write_set": [decoded["key_id"]]}
    )
    status, _new_rec = dst.import_bundle(
        "t1", decoded, event_id=begin.record.operation_id, mirror=mirror,
    )
    assert status == "created"
    assert mirror.descriptor["phase"] == PHASE_COMMITTED
    art.after_terminal(mirror)
    assert not os.path.exists(mirror.path())


def test_successful_restore_clears_mirror(env):
    from keymgr import tenantbundle
    from keymgr.policy import PolicyStore
    from keymgr.restore import RestoreCoordinator

    # Back a tenant up from one data dir and restore into a fresh dir sharing
    # the same KMS backend, so the write set is free there.
    src = env.open_store()
    src_policies = PolicyStore(env.data_dir, src.audit)
    src_coordinator = RestoreCoordinator(src, src_policies)
    src.create("t9", "AES256", "r")
    bundle = src_coordinator.backup_bundle("t9", "pw")
    decoded = tenantbundle.decode_bundle(bundle, "pw")

    dst_dir = env.data_dir + "-rest"
    os.makedirs(dst_dir, exist_ok=True)
    audit = AuditLog(dst_dir)
    dst = KeyStore(dst_dir, audit)
    policies = PolicyStore(dst_dir, audit)
    coordinator = RestoreCoordinator(dst, policies)
    op_store = OperationStore(dst_dir, audit)
    art = ArtifactStore(dst_dir, dst, audit)

    begin = op_store.begin(
        "t9", "alice", "/v1/restore",
        json.dumps({"tenant_id": "t9"}, sort_keys=True,
                   separators=(",", ":")),
        "mirror-restore",
    )
    key_ids = sorted(k["key_id"] for k in decoded["keys"])
    mirror = art.create(begin.record).describe(
        {"kind": "restore", "write_set": key_ids,
         "policy": decoded["policy"] is not None}
    )
    result = coordinator.restore(
        "t9", decoded,
        event_id=begin.record.operation_id, mirror=mirror,
    )
    assert result.status == "created"
    assert mirror.descriptor["phase"] == PHASE_COMMITTED
    assert len(mirror.descriptor["handles"]) == 1
    art.after_terminal(mirror)
    assert not os.path.exists(mirror.path())


def test_batch_uncommitted_with_provider_down_parks_then_settles(env):
    from test_recovery_batch import _craft_batch_scene, _make_keys

    keys = _make_keys(env, n=2)
    scene = _craft_batch_scene(env, keys)
    _, op_store, art = _setup_no_recovery(env)
    record = _pending_operation(op_store, scene.event_id, keys[0])
    # Re-point the pending op at the batch endpoint, with the same batch kind
    # and item set a real batch executor persists before describing the mirror.
    record.path = "/v1/keys/batch-rotate"
    record.details = {
        "kind": "batch_rotate",
        "items": [
            {"key_id": key_id, "algorithm": "AES256"} for key_id in keys
        ],
    }
    op_store._write_record(record)
    mirror = art.create(record).describe(
        {"kind": "batch_rotate", "write_set": keys}
    )
    mirror.provision(scene.journal_id, snapshot=scene.event_id)
    for handle in scene.handles:
        mirror.add_handle("fakekms", handle)
    mirror.phase(PHASE_STAGED)

    env.set_faults({"fail": {"delete": True}})
    audit = AuditLog(env.data_dir)
    store2 = env.open_store()  # batch recovery cannot confirm deletes
    art2 = ArtifactStore(env.data_dir, store2, audit)
    op2 = OperationStore(env.data_dir, audit)
    art2.settle_pending(op2)
    assert art2.is_parked(scene.event_id)
    op2.recover_pending(is_parked=art2.is_parked)
    assert op2.get(scene.event_id, "t1", "alice").status == STATUS_PENDING
    assert os.path.exists(mirror.path())

    env.clear_faults()
    audit = AuditLog(env.data_dir)
    store3 = env.open_store()
    art3 = ArtifactStore(env.data_dir, store3, audit)
    op3 = OperationStore(env.data_dir, audit)
    art3.settle_pending(op3)
    op3.recover_pending(is_parked=art3.is_parked)
    assert not os.path.exists(mirror.path())
    final = op3.get(scene.event_id, "t1", "alice")
    assert final.status == STATUS_FAILED
    assert final.http_status == 500
