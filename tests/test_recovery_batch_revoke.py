"""Crash-recovery coordination for atomic batch revocation."""

import os
from types import SimpleNamespace

import pytest

from keymgr import audit as audit_mod
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.provider import ProviderUnavailable


def _make_keys(env, tenant="t1", n=2):
    store = env.open_store()
    return sorted(
        store.create(tenant, "AES256", "k%d" % i).key_id for i in range(n)
    )


def _craft_batch_revoke_scene(
    env,
    keys,
    tenant="t1",
    reason="r",
    operator="o",
    mark=True,
    snapshot=True,
    partial_restore=False,
    commit=False,
    event_id=None,
):
    """Build the durable crash scene of an interrupted batch revocation."""
    store = env.open_store()
    previous_bytes = {
        k: store._read_file_bytes(store._path_for(k)) for k in keys
    }
    event = store.audit.new_event(
        tenant, audit_mod.ACTION_BATCH_REVOKE, None,
        audit_mod.OUTCOME_SUCCESS, event_id=event_id,
    )
    records = {}
    for key_id in keys:
        record = store._read_record(store._path_for(key_id))
        if record.status != "revoked":
            record.status = "revoked"
            record.reason = reason
            record.operator = operator
            record.revoked_at = event.timestamp
        records[key_id] = record
    if snapshot:
        store._write_batch_revoke_snapshot(
            event.event_id, tenant, sorted(keys), previous_bytes
        )
    marker = {
        "_batch_revoke": True,
        "event": event.to_json(),
        "tenant_id": tenant,
        "key_ids": sorted(keys),
        "snapshot": event.event_id,
    }
    if mark:
        for key_id, record in records.items():
            record.pending_event = marker
            store._write_atomic(store._path_for(key_id), record.to_json())
    if partial_restore:
        # One file was already rolled back to its pre-batch bytes (no
        # marker) when the process died.
        victim = sorted(keys)[0]
        store._write_bytes_atomic(
            store._path_for(victim), previous_bytes[victim]
        )
    if commit:
        store.audit.append(event)
    return SimpleNamespace(
        event_id=event.event_id,
        previous_bytes=previous_bytes,
        marker=marker,
        event=event,
    )


def test_uncommitted_scene_rolls_back(env):
    keys = _make_keys(env)
    scene = _craft_batch_revoke_scene(env, keys)

    store = env.open_store()  # recovery

    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "active"
        assert record.reason is None
        assert record.pending_event is None
        # Byte-for-byte restoration of the pre-batch file.
        assert (
            store._read_file_bytes(store._path_for(key_id))
            == scene.previous_bytes[key_id]
        )
    assert not os.path.exists(
        store._batch_revoke_snapshot_path(scene.event_id)
    )
    assert not any(e.event_id == scene.event_id for e in env.audit_events())


def test_committed_scene_finishes(env):
    keys = _make_keys(env)
    scene = _craft_batch_revoke_scene(env, keys, commit=True)

    store = env.open_store()  # recovery

    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "revoked"
        assert record.reason == "r"
        assert record.operator == "o"
        assert record.revoked_at == scene.event.timestamp
        assert record.pending_event is None
    # The snapshot is discarded as post-commit housekeeping.
    assert not os.path.exists(
        store._batch_revoke_snapshot_path(scene.event_id)
    )
    # The durable event is the single batch_revoke success.
    events = [
        e for e in env.audit_events()
        if e.action == audit_mod.ACTION_BATCH_REVOKE
    ]
    assert len(events) == 1
    assert events[0].event_id == scene.event_id
    assert events[0].key_id is None


def test_partial_marker_scene_rolls_back_whole_group(env):
    keys = _make_keys(env, n=3)
    scene = _craft_batch_revoke_scene(env, keys, partial_restore=True)

    store = env.open_store()  # recovery

    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "active"
        assert record.pending_event is None
        assert (
            store._read_file_bytes(store._path_for(key_id))
            == scene.previous_bytes[key_id]
        )
    assert not os.path.exists(
        store._batch_revoke_snapshot_path(scene.event_id)
    )


def test_uncommitted_scene_hides_revocation_until_recovery(env):
    """A read during the uncommitted window projects the pre-batch state."""
    store = env.open_store()
    key_id = store.create("t1", "AES256", "k").key_id
    previous = store._read_file_bytes(store._path_for(key_id))
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_BATCH_REVOKE, None,
        audit_mod.OUTCOME_SUCCESS,
    )
    store._write_batch_revoke_snapshot(
        event.event_id, "t1", [key_id], {key_id: previous}
    )
    record = store._read_record(store._path_for(key_id))
    record.status = "revoked"
    record.reason = "r"
    record.operator = "o"
    record.revoked_at = event.timestamp
    record.pending_event = {
        "_batch_revoke": True,
        "event": event.to_json(),
        "tenant_id": "t1",
        "key_ids": [key_id],
        "snapshot": event.event_id,
    }
    store._write_atomic(store._path_for(key_id), record.to_json())
    # The committed view projects the pre-batch (active) state, never the
    # uncommitted revocation.
    marked = store._read_record(store._path_for(key_id))
    view = store._committed_record(marked)
    assert view is not None
    assert view.status == "active"
    assert view.reason is None
    assert view.revoked_at is None
    # get() agrees: the key reads as active, not revoked.
    assert store.get(key_id, "t1").status == "active"


def test_corrupt_snapshot_parks_scene_and_hides_record(env):
    keys = _make_keys(env)
    scene = _craft_batch_revoke_scene(env, keys)
    # Corrupt the snapshot.
    with open(store_snapshot_path(env, scene.event_id), "w") as fh:
        fh.write("{corrupt")

    store = env.open_store()  # recovery: the scene is parked

    # The marked file is hidden (its committed state is unprovable).
    assert store.get(keys[0], "t1") is None
    # The snapshot and markers are retained for a later open.
    assert os.path.exists(
        store._batch_revoke_snapshot_path(scene.event_id)
    )
    record = store._read_record(store._path_for(keys[0]))
    assert record.pending_event is not None


def store_snapshot_path(env, event_id):
    return os.path.join(
        env.data_dir, "batch-revocations", event_id + ".json"
    )


def test_mutation_on_unsettled_key_is_refused(env):
    """A single-key mutation on a key with an unsettled batch scene is 503."""
    store = env.open_store()
    key_id = store.create("t2", "AES256", "k").key_id
    previous = store._read_file_bytes(store._path_for(key_id))
    event = store.audit.new_event(
        "t2", audit_mod.ACTION_BATCH_REVOKE, None,
        audit_mod.OUTCOME_SUCCESS,
    )
    store._write_batch_revoke_snapshot(
        event.event_id, "t2", [key_id], {key_id: previous}
    )
    record = store._read_record(store._path_for(key_id))
    record.status = "revoked"
    record.reason = "r"
    record.operator = "o"
    record.revoked_at = event.timestamp
    record.pending_event = {
        "_batch_revoke": True,
        "event": event.to_json(),
        "tenant_id": "t2",
        "key_ids": [key_id],
        "snapshot": event.event_id,
    }
    store._write_atomic(store._path_for(key_id), record.to_json())
    # A single-key revoke on the unsettled key raises ProviderUnavailable
    # (the file still owes crash recovery).
    with pytest.raises(ProviderUnavailable):
        store.revoke(key_id, "t2", "r", "o")


def test_recovery_is_idempotent(env):
    keys = _make_keys(env)
    scene = _craft_batch_revoke_scene(env, keys)
    store = env.open_store()  # first recovery
    store = env.open_store()  # second recovery: no-op
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "active"
        assert record.pending_event is None


def _pending_batch_revoke_op(env, keys, tenant="t1"):
    """Bind a pending batch_revoke operation record (mirror_required=False)."""
    import json as _json

    op_store = OperationStore(env.data_dir, AuditLog(env.data_dir))
    body = {
        "tenant_id": tenant,
        "key_ids": list(keys),
        "reason": "r",
        "operator": "o",
    }
    normalized = _json.dumps(body, sort_keys=True, separators=(",", ":"))
    begin = op_store.begin(
        tenant, "alice", "/v1/keys/batch-revoke", normalized, "idem-br",
        mirror_required=False,
    )
    record = begin.record
    op_store.update_details(
        record, {"kind": "batch_revoke", "key_ids": list(keys)}
    )
    return op_store, record


def test_committed_operation_replays_staged_result(env):
    keys = _make_keys(env)
    op_store, record = _pending_batch_revoke_op(env, keys)
    staged_items = [
        {
            "key_id": k, "status": "revoked", "reason": "r",
            "operator": "o", "revoked_at": "2026-01-01T00:00:00+00:00",
        }
        for k in keys
    ]
    staged = {
        "items": staged_items,
        "operation_id": record.operation_id,
    }
    op_store.stage_terminal(record, 200, staged)
    # The batch committed under the op's id (its event is durable) and the
    # scene carries the op's markers.
    scene = _craft_batch_revoke_scene(
        env, keys, commit=True, event_id=record.operation_id,
    )
    # Recovery: the store settles the batch scene, then the op is finalized
    # with the staged 200 replayed verbatim.
    env.open_store()
    op_store2 = OperationStore(env.data_dir, AuditLog(env.data_dir))
    op_store2.recover_pending()
    recovered = op_store2.get(record.operation_id, "t1", "alice")
    assert recovered.status == "succeeded"
    assert recovered.http_status == 200
    assert recovered.response == staged


def test_uncommitted_operation_finalizes_failed_500(env):
    keys = _make_keys(env)
    op_store, record = _pending_batch_revoke_op(env, keys)
    # The batch scene is uncommitted (no event); recovery rolls it back and
    # the operation is finalized as a 500 interruption.
    scene = _craft_batch_revoke_scene(env, keys)
    env.open_store()  # rolls back the batch scene
    op_store2 = OperationStore(env.data_dir, AuditLog(env.data_dir))
    op_store2.recover_pending()
    recovered = op_store2.get(record.operation_id, "t1", "alice")
    assert recovered.status == "failed"
    assert recovered.http_status == 500
    assert recovered.response["operation_id"] == record.operation_id
    # The keys are back to active.
    store = env.open_store()
    for key_id in keys:
        assert store.get(key_id, "t1").status == "active"


def test_lock_timeout_raises_before_any_write(env):
    """A batch that cannot take the key locks in time writes nothing."""
    from keymgr.store import LockTimeout

    store = env.open_store()
    key_id = store.create("t1", "AES256", "k").key_id
    # Hold the key lock so the batch times out acquiring it.
    with store.key_locks(key_id):
        with pytest.raises(LockTimeout):
            store.batch_revoke(
                "t1", [key_id], "r", "o", lock_timeout=0.1,
            )
    # No snapshot, marker, event or state change.
    assert store.get(key_id, "t1").status == "active"
    assert store._list_batch_revoke_snapshot_ids() == []
    assert not any(
        e.action == audit_mod.ACTION_BATCH_REVOKE
        for e in env.audit_events()
    )
