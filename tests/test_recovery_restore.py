"""Crash-recovery coordination for tenant restore and single-key import."""

import os
import uuid
from types import SimpleNamespace

import pytest

from keymgr import audit as audit_mod
from keymgr.policy import PolicyStore, Rule
from keymgr.provider import ProviderUnavailable
from keymgr.restore import RestoreCoordinator
from keymgr.store import KeyRecord, VersionRecord


def _rules():
    return [Rule(subject="alice", actions=["read"], effect="allow")]


def _craft_restore_scene(
    env, tenant="t1", n=2, with_policy=False, journal=True
):
    """Build the durable scene of a restore interrupted before its commit."""
    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    provider = store._provider()
    event = store.audit.new_event(
        tenant, audit_mod.ACTION_IMPORT, None, audit_mod.OUTCOME_SUCCESS
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    handles = []
    records = []
    for i in range(n):
        triple = provider.generate("AES256")
        handles.append(triple.handle)
        if journal:
            store._append_provision(
                journal_path, provider.provider_id, triple.handle
            )
        records.append(
            KeyRecord(
                key_id=str(uuid.uuid4()),
                tenant_id=tenant,
                label="r%d" % i,
                versions=[
                    VersionRecord(
                        version=1,
                        created_at=event.timestamp,
                        algorithm="AES256",
                        public_key=None,
                        provider_id=provider.provider_id,
                        handle=triple.handle,
                        encrypted_material=triple.encrypted_material,
                    )
                ],
                current_version=1,
            )
        )
    key_ids = sorted(r.key_id for r in records)
    marker = {
        "_restore": True,
        "event": event.to_json(),
        "tenant_id": tenant,
        "key_ids": key_ids,
        "policy": with_policy,
    }
    if journal:
        # Modern groups tie the marker to the attempt's handle journal;
        # legacy (pre-journal) groups have no such reference at all.
        marker["journal"] = journal_id
    for record in records:
        record.pending_event = marker
        store._write_atomic(store._path_for(record.key_id), record.to_json())
    if with_policy:
        policies.write_restore_pending(tenant, _rules(), marker)
    if not journal:
        store._discard_provision_journal(journal_path)
    return SimpleNamespace(
        event_id=event.event_id,
        handles=handles,
        journal_id=journal_id,
        key_ids=key_ids,
        marker=marker,
    )


def _recover(env):
    """Open a fresh coordinator (runs restore recovery), like a new process."""
    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    coordinator = RestoreCoordinator(store, policies)
    return store, policies, coordinator


def test_restore_uncommitted_scene_rolls_back(env):
    scene = _craft_restore_scene(env, with_policy=True)
    store, policies, _ = _recover(env)

    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in scene.key_ids:
        assert not os.path.exists(store._path_for(key_id))
    assert policies.get("t1") is None
    assert not os.path.exists(store._provision_path(scene.journal_id))
    assert not any(e.event_id == scene.event_id for e in env.audit_events())


def test_restore_committed_scene_only_clears_markers(env):
    scene = _craft_restore_scene(env, with_policy=True)
    from keymgr.audit import AuditEvent, AuditLog

    AuditLog(env.data_dir).append(AuditEvent.from_json(scene.marker["event"]))

    store, policies, _ = _recover(env)

    for key_id in scene.key_ids:
        record = store.get(key_id, "t1")
        assert record is not None
        assert record.pending_event is None
    assert policies.get("t1") is not None
    # Handles are record-owned: never deleted; exactly one audit event.
    for handle in scene.handles:
        assert handle in env.kms_handles()
    assert not os.path.exists(store._provision_path(scene.journal_id))
    events = [e for e in env.audit_events() if e.event_id == scene.event_id]
    assert len(events) == 1


def test_restore_uncommitted_hidden_from_reads(env):
    scene = _craft_restore_scene(env)
    # Before recovery settles it, an uncommitted restore file is invisible.
    store = env.open_store()
    for key_id in scene.key_ids:
        assert store.get(key_id, "t1") is None


def test_restore_legacy_group_without_journal_rolls_back(env):
    scene = _craft_restore_scene(env, journal=False)
    store, policies, _ = _recover(env)

    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in scene.key_ids:
        assert not os.path.exists(store._path_for(key_id))


def test_restore_provider_down_preserves_whole_group(env):
    scene = _craft_restore_scene(env, with_policy=True)
    env.set_faults({"unreachable": True})

    store, policies, _ = _recover(env)
    # Nothing is removed while the provider cannot confirm the deletes.
    for key_id in scene.key_ids:
        assert os.path.exists(store._path_for(key_id))
    assert os.path.exists(store._provision_path(scene.journal_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()
    # And the unsettled files stay invisible.
    for key_id in scene.key_ids:
        assert store.get(key_id, "t1") is None

    env.clear_faults()
    store, policies, _ = _recover(env)
    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in scene.key_ids:
        assert not os.path.exists(store._path_for(key_id))
    assert not os.path.exists(store._provision_path(scene.journal_id))


def test_restore_delete_failure_preserves_group_then_recovers(env):
    scene = _craft_restore_scene(env)
    env.set_faults({"fail": {"delete": True}})

    store, _, _ = _recover(env)
    for key_id in scene.key_ids:
        assert os.path.exists(store._path_for(key_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()

    env.clear_faults()
    store, _, _ = _recover(env)
    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in scene.key_ids:
        assert not os.path.exists(store._path_for(key_id))


def test_restore_orphan_journal_without_markers_is_reaped(env):
    """Crash after provider adoption but before the first file landed."""
    store = env.open_store()
    provider = store._provider()
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_IMPORT, None, audit_mod.OUTCOME_SUCCESS
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    triple = provider.generate("AES256")
    store._append_provision(journal_path, provider.provider_id, triple.handle)

    store, _, _ = _recover(env)
    assert triple.handle not in env.kms_handles()
    assert not os.path.exists(store._provision_path(journal_id))


def test_restore_partial_marker_group_rolls_back(env):
    """Crash mid-rollback: one file already removed, markers survive on two."""
    scene = _craft_restore_scene(env, n=3)
    store = env.open_store()
    removed = scene.key_ids[0]
    store.remove_file(removed)  # crash after removing one file of the group

    store, policies, _ = _recover(env)
    # All three minted handles are deleted (idempotently) and the surviving
    # files of the group are removed.
    for handle in scene.handles:
        assert handle not in env.kms_handles()
    for key_id in scene.key_ids[1:]:
        assert not os.path.exists(store._path_for(key_id))
    assert not os.path.exists(store._provision_path(scene.journal_id))


def test_import_uncommitted_marker_commits_forward(env):
    """A single-key import file with a marker is finished by recovery."""
    store = env.open_store()
    provider = store._provider()
    key_id = str(uuid.uuid4())
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_IMPORT, key_id, audit_mod.OUTCOME_SUCCESS
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    triple = provider.generate("AES256")
    store._append_provision(journal_path, provider.provider_id, triple.handle)
    record = KeyRecord(
        key_id=key_id,
        tenant_id="t1",
        label="imp",
        versions=[
            VersionRecord(
                version=1,
                created_at=event.timestamp,
                algorithm="AES256",
                public_key=None,
                provider_id=provider.provider_id,
                handle=triple.handle,
                encrypted_material=triple.encrypted_material,
            )
        ],
        current_version=1,
    )
    marker = event.to_json()
    marker["journal"] = journal_id
    record.pending_event = marker
    store._write_atomic(store._path_for(key_id), record.to_json())

    store = env.open_store()  # recovery commits the import forward

    record = store.get(key_id, "t1")
    assert record is not None
    assert record.pending_event is None
    assert triple.handle in env.kms_handles()
    assert not os.path.exists(store._provision_path(journal_id))
    events = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(events) == 1


def test_restore_in_request_delete_failure_keeps_journal(env, monkeypatch):
    """A restore aborted by a ledger failure whose handle deletes also fail
    surfaces 503 and retains the journal for startup cleanup."""
    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    coordinator = RestoreCoordinator(store, policies)
    key_id = str(uuid.uuid4())
    payload = {
        "keys": [
            {
                "key_id": key_id,
                "label": "r",
                "current_version": 1,
                "status": "active",
                "reason": None,
                "operator": None,
                "revoked_at": None,
                "versions": [
                    {
                        "version": 1,
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "algorithm": "AES256",
                        "public_key": None,
                        "private_material": "AAAA",
                        "provider": {
                            "provider_id": "fakekms",
                            "handle": "h",
                            "encrypted_material": "x",
                        },
                    }
                ],
            }
        ],
        "policy": None,
    }
    from keymgr.audit import LedgerError

    def boom(event):
        raise LedgerError("ledger down")

    monkeypatch.setattr(store.audit, "append", boom)
    env.set_faults({"fail": {"delete": True}})
    before = env.kms_handles()
    with pytest.raises(ProviderUnavailable):
        coordinator.restore("t1", payload, lock_timeout=1.0)
    # The minted handle could not be deleted: it survives with the journal.
    assert len(env.kms_handles()) == len(before) + 1
    provisions = os.path.join(env.data_dir, "provisions")
    assert len(os.listdir(provisions)) == 1
    assert not os.path.exists(store._path_for(key_id))

    env.clear_faults()
    store = env.open_store()  # startup retries the cleanup
    assert env.kms_handles() == before
    assert not os.listdir(provisions)


def test_import_in_request_provider_failure_cleans_handles(env):
    """An import aborted by a provider fault deletes every minted handle."""
    store = env.open_store()
    payload = {
        "key_id": str(uuid.uuid4()),
        "label": "imp",
        "current_version": 1,
        "status": "active",
        "reason": None,
        "operator": None,
        "revoked_at": None,
        "versions": [
            {
                "version": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
                "algorithm": "AES256",
                "public_key": None,
                "private_material": "AAAA",
                "provider": {
                    "provider_id": "fakekms",
                    "handle": "h",
                    "encrypted_material": "x",
                },
            },
            {
                "version": 2,
                "created_at": "2026-01-02T00:00:00+00:00",
                "algorithm": "AES256",
                "public_key": None,
                "private_material": "BBBB",
                "provider": {
                    "provider_id": "fakekms",
                    "handle": "h2",
                    "encrypted_material": "x",
                },
            },
        ],
    }
    # The first import_material succeeds, the second fails -> the attempt
    # aborts and must delete the first handle.
    env.set_faults({"fail_after": {"import_material": 1}})
    before = env.kms_handles()
    with pytest.raises(ProviderUnavailable):
        store.import_bundle("t1", payload, lock_timeout=1.0)
    assert env.kms_handles() == before
