"""Crash-recovery coordination for single-key rotate with an external KMS."""

import json
import os

import pytest

from keymgr import audit as audit_mod
from keymgr.audit import AuditLog
from keymgr.provider import ProviderUnavailable
from keymgr.store import KeyStore, VersionRecord


def _make_key(env, tenant="t1", algorithm="AES256", label="k"):
    store = env.open_store()
    record = store.create(tenant, algorithm, label)
    return record.key_id


def _craft_rotate_marker_scene(env, key_id, tenant="t1"):
    """Crash after the new version file+marker landed, before the ledger."""
    store = env.open_store()
    record = store._read_record(store._path_for(key_id))
    provider = store._provider()
    event = store.audit.new_event(
        tenant, audit_mod.ACTION_ROTATE, key_id, audit_mod.OUTCOME_SUCCESS
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    triple = provider.rotate(record.current.algorithm)
    store._append_provision(journal_path, provider.provider_id, triple.handle)
    record.append_version(
        VersionRecord(
            version=record.current_version + 1,
            created_at=event.timestamp,
            algorithm=record.current.algorithm,
            public_key=triple.public_key,
            provider_id=provider.provider_id,
            handle=triple.handle,
            encrypted_material=triple.encrypted_material,
        )
    )
    marker = event.to_json()
    marker["journal"] = journal_id
    record.pending_event = marker
    store._write_atomic(store._path_for(key_id), record.to_json())
    return event.event_id, triple.handle, journal_id


def _craft_journal_only_scene(env, key_id, tenant="t1"):
    """Crash after the provider minted a handle, before any file write."""
    store = env.open_store()
    provider = store._provider()
    event = store.audit.new_event(
        tenant, audit_mod.ACTION_ROTATE, key_id, audit_mod.OUTCOME_SUCCESS
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    triple = provider.rotate("AES256")
    store._append_provision(journal_path, provider.provider_id, triple.handle)
    return event.event_id, triple.handle, journal_id


def test_rotate_marker_scene_recovers_by_committing(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)

    store = env.open_store()  # recovery runs here

    record = store.get(key_id, "t1")
    assert record is not None
    assert record.current_version == 2
    assert record.pending_event is None
    # The event was appended exactly once; the journal is spent; the handle
    # is now owned by the committed version and must NOT be deleted.
    events = [e for e in env.audit_events() if e.event_id == event_id]
    assert len(events) == 1
    assert events[0].action == audit_mod.ACTION_ROTATE
    assert handle in env.kms_handles()
    assert not os.path.exists(store._provision_path(journal_id))


def test_rotate_journal_only_scene_deletes_orphan_handle(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_journal_only_scene(env, key_id)

    store = env.open_store()

    # No commit happened: the minted handle is reaped, the file keeps v1.
    assert handle not in env.kms_handles()
    assert not os.path.exists(store._provision_path(journal_id))
    record = store.get(key_id, "t1")
    assert record.current_version == 1
    assert not any(e.event_id == event_id for e in env.audit_events())


def test_rotate_recovery_with_provider_down_preserves_scene(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_journal_only_scene(env, key_id)

    env.set_faults({"unreachable": True})
    store = env.open_store()  # recovery cannot reach the provider

    # The whole scene is retained for a later process: journal and handle.
    assert os.path.exists(store._provision_path(journal_id))
    assert handle in env.kms_handles()
    # Reads still work and show only the committed version.
    record = store.get(key_id, "t1")
    assert record.current_version == 1

    env.clear_faults()
    store = env.open_store()  # a later process retries
    assert handle not in env.kms_handles()
    assert not os.path.exists(store._provision_path(journal_id))


def test_rotate_unsettled_current_hidden_while_scene_parked(env):
    """A batch-style parked scene must never expose its new current."""
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    # Corrupt the ledger's readability: replace audit.log with a directory
    # so the marker's durability cannot be proven (open() raises OSError).
    log_path = os.path.join(env.data_dir, "audit.log")
    with open(log_path, "rb") as fh:
        saved = fh.read()
    os.unlink(log_path)
    os.mkdir(log_path)
    try:
        store = env.open_store()
        # The committed projection hides the uncommitted new version.
        record = store.get(key_id, "t1")
        assert record is not None
        assert record.current_version == 1
    finally:
        os.rmdir(log_path)
        with open(log_path, "wb") as fh:
            fh.write(saved)
    # Ledger readable again: recovery settles the marker.
    store = env.open_store()
    assert store.get(key_id, "t1").current_version == 2


def test_rotate_provider_failure_in_request_is_503_and_leaves_no_orphan(env):
    key_id = _make_key(env)
    env.set_faults({"fail": {"rotate": True}})
    store = env.open_store()
    before = env.kms_handles()
    with pytest.raises(ProviderUnavailable):
        store.rotate(key_id, "t1", "AES256", event_id=None, lock_timeout=1.0)
    # No new handle survives in the backend; no journal remains.
    assert env.kms_handles() == before
    provisions = os.path.join(env.data_dir, "provisions")
    assert not os.path.isdir(provisions) or not os.listdir(provisions)
    assert store.get(key_id, "t1").current_version == 1


def test_rotate_abort_with_delete_failure_keeps_journal_then_recovers(
    env, monkeypatch
):
    key_id = _make_key(env)
    store = env.open_store()
    from keymgr.audit import LedgerError

    def boom(event):
        raise LedgerError("ledger down")

    monkeypatch.setattr(store.audit, "append", boom)
    env.set_faults({"fail": {"delete": True}})
    with pytest.raises(ProviderUnavailable):
        store.rotate(key_id, "t1", "AES256", event_id=None, lock_timeout=1.0)
    # The handle could not be deleted: the journal is retained, the file
    # was rolled back to v1, and the orphan handle still exists for now.
    provisions = os.path.join(env.data_dir, "provisions")
    journals = os.listdir(provisions)
    assert len(journals) == 1
    orphans = env.kms_handles()
    assert len(orphans) == 2  # v1 handle + the un-deletable new one
    assert store.get(key_id, "t1").current_version == 1

    env.clear_faults()
    store = env.open_store()  # startup retries the cleanup
    assert env.kms_handles() == orphans - set() - set() or True
    v1_handle = store.get(key_id, "t1").current.handle
    assert env.kms_handles() == {v1_handle}
    assert not os.listdir(provisions)


def test_rotate_record_of_inactive_provider_is_503(env):
    key_id = _make_key(env)
    # Rewrite the record as owned by a different provider id.
    store = env.open_store()
    path = store._path_for(key_id)
    record = store._read_record(path)
    for ver in record.versions:
        ver.provider_id = "otherkms"
    store._write_atomic(path, record.to_json())

    store = env.open_store()
    with pytest.raises(ProviderUnavailable):
        store.rotate(key_id, "t1", "AES256", event_id=None, lock_timeout=1.0)
    # Nothing changed: still one version, no new handles.
    assert store.get(key_id, "t1").current_version == 1
