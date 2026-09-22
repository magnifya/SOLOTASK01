"""Crash-recovery coordination for atomic batch rotation."""

import os
from types import SimpleNamespace

import pytest

from keymgr import audit as audit_mod
from keymgr.provider import ProviderUnavailable
from keymgr.store import VersionRecord


def _make_keys(env, tenant="t1", n=2):
    store = env.open_store()
    return sorted(
        store.create(tenant, "AES256", "k%d" % i).key_id for i in range(n)
    )


def _craft_batch_scene(
    env,
    keys,
    tenant="t1",
    mark=True,
    snapshot=True,
    journal=True,
    partial_restore=False,
):
    """Build the durable crash scene of an interrupted batch rotation."""
    store = env.open_store()
    provider = store._provider()
    previous_bytes = {
        k: store._read_file_bytes(store._path_for(k)) for k in keys
    }
    event = store.audit.new_event(
        tenant, audit_mod.ACTION_BATCH_ROTATE, None, audit_mod.OUTCOME_SUCCESS
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    handles = []
    records = {}
    for key_id in keys:
        record = store._read_record(store._path_for(key_id))
        triple = provider.rotate("AES256")
        handles.append(triple.handle)
        if journal:
            store._append_provision(
                journal_path, provider.provider_id, triple.handle
            )
        record.append_version(
            VersionRecord(
                version=record.current_version + 1,
                created_at=event.timestamp,
                algorithm="AES256",
                public_key=triple.public_key,
                provider_id=provider.provider_id,
                handle=triple.handle,
                encrypted_material=triple.encrypted_material,
            )
        )
        records[key_id] = record
    if snapshot:
        store._write_batch_snapshot(
            event.event_id, tenant, keys, previous_bytes
        )
    marker = {
        "_batch_rotate": True,
        "event": event.to_json(),
        "tenant_id": tenant,
        "key_ids": keys,
        "journal": journal_id,
        "snapshot": event.event_id,
    }
    if mark:
        for key_id, record in records.items():
            record.pending_event = marker
            store._write_atomic(store._path_for(key_id), record.to_json())
    if partial_restore:
        # One file was already rolled back to its pre-batch bytes (no
        # marker) when the process died.
        victim = keys[0]
        store._write_bytes_atomic(
            store._path_for(victim), previous_bytes[victim]
        )
    if not journal:
        store._discard_provision_journal(journal_path)
    return SimpleNamespace(
        event_id=event.event_id,
        handles=handles,
        journal_id=journal_id,
        previous_bytes=previous_bytes,
        marker=marker,
    )


def test_batch_uncommitted_full_scene_rolls_back(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)

    store = env.open_store()  # recovery

    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.current_version == 1
        assert record.pending_event is None
        # Byte-for-byte restoration of the pre-batch file.
        assert (
            store._read_file_bytes(store._path_for(key_id))
            == scene.previous_bytes[key_id]
        )
    assert not os.path.exists(store._provision_path(scene.journal_id))
    assert not os.path.exists(store._batch_snapshot_path(scene.event_id))
    assert not any(e.event_id == scene.event_id for e in env.audit_events())


def test_batch_partial_marker_scene_rolls_back_whole_group(env):
    keys = _make_keys(env, n=3)
    scene = _craft_batch_scene(env, keys, partial_restore=True)

    store = env.open_store()

    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.current_version == 1
        assert (
            store._read_file_bytes(store._path_for(key_id))
            == scene.previous_bytes[key_id]
        )
    assert not os.path.exists(store._provision_path(scene.journal_id))
    assert not os.path.exists(store._batch_snapshot_path(scene.event_id))


def test_batch_journal_and_snapshot_only_no_markers(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys, mark=False)

    store = env.open_store()

    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 1
    assert not os.path.exists(store._provision_path(scene.journal_id))
    assert not os.path.exists(store._batch_snapshot_path(scene.event_id))


def test_batch_committed_scene_only_clears_artifacts(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    # The commit-point event IS durable (crash after the append). Append it
    # WITHOUT opening a KeyStore, which would run recovery first.
    from keymgr.audit import AuditEvent, AuditLog

    AuditLog(env.data_dir).append(AuditEvent.from_json(scene.marker["event"]))

    store = env.open_store()  # recovery

    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.current_version == 2
        assert record.pending_event is None
    # Handles are record-owned now: never deleted.
    for handle in scene.handles:
        assert handle in env.kms_handles()
    assert not os.path.exists(store._provision_path(scene.journal_id))
    assert not os.path.exists(store._batch_snapshot_path(scene.event_id))
    # Exactly one audit event for the batch.
    events = [e for e in env.audit_events() if e.event_id == scene.event_id]
    assert len(events) == 1


def test_batch_committed_event_mismatch_parks_scene(env):
    """A durable same-id event with another action must not finalize."""
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    # A durable same-id event with a DIFFERENT action (id collision), again
    # appended without opening a KeyStore (which would run recovery first).
    from keymgr.audit import AuditLog

    ledger = AuditLog(env.data_dir)
    foreign = ledger.new_event(
        "t1", audit_mod.ACTION_ROTATE, keys[0], audit_mod.OUTCOME_SUCCESS,
        event_id=scene.event_id,
    )
    ledger.append(foreign)

    store = env.open_store()  # recovery must NOT treat this as committed

    # The scene is preserved: markers, journal, snapshot and handles.
    assert os.path.exists(store._provision_path(scene.journal_id))
    assert os.path.exists(store._batch_snapshot_path(scene.event_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()
    # Reads hide the uncommitted current.
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.current_version == 1


def test_batch_delete_failure_preserves_scene_then_recovers(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)

    env.set_faults({"fail": {"delete": True}})
    store = env.open_store()  # recovery cannot confirm the deletes

    # Everything is retained: markers, journal, snapshot, handles.
    assert os.path.exists(store._provision_path(scene.journal_id))
    assert os.path.exists(store._batch_snapshot_path(scene.event_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()
    raw = store._read_record(store._path_for(keys[0]))
    assert raw.pending_event is not None
    # Reads hide the uncommitted current.
    assert store.get(keys[0], "t1").current_version == 1

    env.clear_faults()
    store = env.open_store()  # a later process retries
    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 1
    assert not os.path.exists(store._provision_path(scene.journal_id))
    assert not os.path.exists(store._batch_snapshot_path(scene.event_id))


def test_batch_missing_snapshot_parks_scene(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys, snapshot=False)

    store = env.open_store()

    # No snapshot to restore from: the whole scene is preserved, nothing
    # is deleted or rewritten, and reads hide the uncommitted current.
    assert os.path.exists(store._provision_path(scene.journal_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()
    raw = store._read_record(store._path_for(keys[0]))
    assert raw.pending_event is not None
    # The pre-image cannot be proven without the snapshot, so the record is
    # hidden entirely rather than exposing an uncommitted current.
    assert store.get(keys[0], "t1") is None


def test_batch_provider_down_during_recovery_preserves_scene(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)

    env.set_faults({"unreachable": True})
    store = env.open_store()
    assert os.path.exists(store._provision_path(scene.journal_id))
    assert os.path.exists(store._batch_snapshot_path(scene.event_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()
    assert store.get(keys[0], "t1").current_version == 1

    env.clear_faults()
    store = env.open_store()
    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 1


def test_batch_in_request_provider_failure_rolls_back(env):
    keys = _make_keys(env)
    env.set_faults({"fail": {"rotate": True}})
    store = env.open_store()
    before = env.kms_handles()
    with pytest.raises(ProviderUnavailable):
        store.batch_rotate(
            "t1", [(k, "AES256") for k in keys], lock_timeout=1.0
        )
    assert env.kms_handles() == before
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 1
    # No journal, snapshot or event survives a clean in-request rollback.
    assert not any(
        e.action == audit_mod.ACTION_BATCH_ROTATE for e in env.audit_events()
    )


def test_single_rotate_on_parked_batch_key_is_refused(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys, snapshot=False)  # parked scene
    store = env.open_store()
    with pytest.raises(ProviderUnavailable):
        store.rotate(keys[0], "t1", "AES256", lock_timeout=1.0)


def test_batch_recovery_with_unreadable_ledger_preserves_scene(env):
    keys = _make_keys(env)
    scene = _craft_batch_scene(env, keys)
    # Make the ledger unreadable (open() raises OSError).
    log_path = os.path.join(env.data_dir, "audit.log")
    with open(log_path, "rb") as fh:
        saved = fh.read()
    os.unlink(log_path)
    os.mkdir(log_path)
    try:
        store = env.open_store()
        # Nothing can be decided: the whole scene is retained.
        assert os.path.exists(store._provision_path(scene.journal_id))
        assert os.path.exists(store._batch_snapshot_path(scene.event_id))
        for handle in scene.handles:
            assert handle in env.kms_handles()
        raw = store._read_record(store._path_for(keys[0]))
        assert raw.pending_event is not None
        # An unreadable ledger is "unsettled and unprovable": the record is
        # hidden entirely rather than projecting either view.
        assert store.get(keys[0], "t1") is None
    finally:
        os.rmdir(log_path)
        with open(log_path, "wb") as fh:
            fh.write(saved)
    # Ledger readable again: recovery rolls the group back.
    store = env.open_store()
    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 1


def test_batch_in_request_ledger_outage_parks_scene(env, monkeypatch):
    keys = _make_keys(env)
    store = env.open_store()
    from keymgr.audit import LedgerError

    def boom_append(event):
        raise LedgerError("ledger down")

    def boom_get(event_id):
        raise LedgerError("ledger down")

    monkeypatch.setattr(store.audit, "append", boom_append)
    monkeypatch.setattr(store.audit, "get_event", boom_get)
    with pytest.raises(ProviderUnavailable):
        store.batch_rotate(
            "t1", [(k, "AES256") for k in keys], lock_timeout=1.0
        )
    # Neither commit nor rollback is provable: the ENTIRE scene (markers,
    # journal, snapshot, minted handles) is retained for startup recovery.
    provisions = os.path.join(env.data_dir, "provisions")
    assert len(os.listdir(provisions)) == 1
    snapshots = os.path.join(env.data_dir, "batch-rotations")
    assert len(os.listdir(snapshots)) == 1
    raw = store._read_record(store._path_for(keys[0]))
    assert raw.pending_event is not None

    # A later process with a healthy ledger settles the scene.
    store = env.open_store()
    for key_id in keys:
        assert store.get(key_id, "t1").current_version == 1
    assert not os.listdir(provisions)
    assert not os.listdir(snapshots)
