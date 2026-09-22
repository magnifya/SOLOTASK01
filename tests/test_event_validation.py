"""Committed-event validation: event_id + action + tenant_id must all match.

A durable event whose id collides with an operation's but whose action or
tenant disagrees must NEVER be treated as that operation's commit point:
the scene is parked (artifacts preserved, uncommitted current hidden), never
finalized, rolled back blindly or exposed.
"""

import os

from keymgr import audit as audit_mod
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.restore import RestoreCoordinator

from test_recovery_batch import _craft_batch_scene, _make_keys  # noqa: F401
from test_recovery_misc import _empty_marker
from test_recovery_restore import _craft_restore_scene
from test_recovery_rotate import (
    _craft_rotate_marker_scene,
    _make_key,
)


def _append_foreign_event(env, event_id, action, tenant):
    ledger = AuditLog(env.data_dir)
    foreign = ledger.new_event(
        tenant, action, None, audit_mod.OUTCOME_SUCCESS, event_id=event_id
    )
    ledger.append(foreign)
    return foreign


def test_single_key_marker_with_foreign_action_event_parks(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    # A durable SUCCESS event with the same id but a different action.
    _append_foreign_event(env, event_id, audit_mod.ACTION_CREATE, "t1")

    store = env.open_store()

    # The scene is parked: marker, journal and handle all survive.
    raw = store._read_record(store._path_for(key_id))
    assert raw.pending_event is not None
    assert os.path.exists(store._provision_path(journal_id))
    assert handle in env.kms_handles()
    # Reads hide the uncommitted new version.
    assert store.get(key_id, "t1").current_version == 1


def test_single_key_marker_with_foreign_tenant_event_parks(env):
    key_id = _make_key(env)
    event_id, handle, journal_id = _craft_rotate_marker_scene(env, key_id)
    _append_foreign_event(env, event_id, audit_mod.ACTION_ROTATE, "other")

    store = env.open_store()

    raw = store._read_record(store._path_for(key_id))
    assert raw.pending_event is not None
    assert os.path.exists(store._provision_path(journal_id))
    assert handle in env.kms_handles()
    assert store.get(key_id, "t1").current_version == 1


def test_restore_group_with_foreign_event_parks(env):
    scene = _craft_restore_scene(env)
    _append_foreign_event(env, scene.event_id, audit_mod.ACTION_ROTATE, "t1")

    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    RestoreCoordinator(store, policies)

    # The mismatched event must not finalize the group: files, markers,
    # journal and handles are all preserved.
    for key_id in scene.key_ids:
        raw = store._read_record(store._path_for(key_id))
        assert raw is not None
        assert raw.pending_event is not None
    assert os.path.exists(store._provision_path(scene.journal_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()
    # And the unsettled files stay invisible.
    for key_id in scene.key_ids:
        assert store.get(key_id, "t1") is None


def test_restore_group_with_foreign_tenant_event_parks(env):
    scene = _craft_restore_scene(env)
    _append_foreign_event(env, scene.event_id, audit_mod.ACTION_IMPORT, "other")

    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    RestoreCoordinator(store, policies)

    for key_id in scene.key_ids:
        raw = store._read_record(store._path_for(key_id))
        assert raw is not None
        assert raw.pending_event is not None
    assert os.path.exists(store._provision_path(scene.journal_id))
    for handle in scene.handles:
        assert handle in env.kms_handles()


def test_empty_restore_marker_with_foreign_event_parks(env):
    path, marker = _empty_marker(env)
    _append_foreign_event(
        env, marker["event"]["event_id"], audit_mod.ACTION_ROTATE, "t1"
    )

    store = env.open_store()
    policies = PolicyStore(env.data_dir, store.audit)
    RestoreCoordinator(store, policies)

    # Neither finalized nor removed: the marker survives with its pending
    # event intact for operator/startup resolution.
    assert os.path.exists(path)
    import json

    with open(path, "r", encoding="utf-8") as fh:
        surviving = json.load(fh)
    assert surviving["event"] is not None


def test_operation_recovery_with_foreign_event_parks(env):
    key_id = _make_key(env)
    # A pending operation record whose event id collides with a durable
    # event of another tenant must not be finalized as committed.
    store = env.open_store()
    op_store = OperationStore(env.data_dir, store.audit)
    begin = op_store.begin("t1", "alice", "/v1/keys/%s/rotate" % key_id,
                           "{}", "op-key-1")
    operation_id = begin.record.operation_id
    _append_foreign_event(env, operation_id, audit_mod.ACTION_ROTATE, "other")

    op_store.recover_pending()

    record = op_store.get(operation_id, "t1", "alice")
    assert record is not None
    assert record.status == "pending"


def test_operation_recovery_with_matching_event_finalizes(env):
    key_id = _make_key(env)
    store = env.open_store()
    op_store = OperationStore(env.data_dir, store.audit)
    begin = op_store.begin("t1", "alice", "/v1/keys/%s/rotate" % key_id,
                           "{}", "op-key-2")
    operation_id = begin.record.operation_id
    # The operation's own success event (same id, action and tenant).
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "t1", audit_mod.ACTION_ROTATE, key_id,
            audit_mod.OUTCOME_SUCCESS, event_id=operation_id,
        )
    )

    op_store.recover_pending()

    record = op_store.get(operation_id, "t1", "alice")
    assert record.status == "succeeded"
    assert record.http_status == 201


# -- provision journal operation header --------------------------------------
import json
import stat


def _craft_orphan_journal(env, tenant="t1", action=audit_mod.ACTION_ROTATE,
                          header=True):
    """A journal with one minted handle and no marker (crash before files)."""
    store = env.open_store()
    provider = store._provider()
    event = store.audit.new_event(
        tenant, action, None, audit_mod.OUTCOME_SUCCESS
    )
    if header:
        journal_id, journal_path = store._new_provision_journal(
            event.event_id, tenant, action
        )
    else:
        # Legacy shape: no header line, handle entries only.
        journal_id, journal_path = store._new_provision_journal(event.event_id)
        with open(journal_path, "w", encoding="utf-8") as fh:
            fh.write("")
    triple = provider.rotate("AES256")
    store._append_provision(journal_path, provider.provider_id, triple.handle)
    return event.event_id, triple.handle, journal_id, journal_path


def test_journal_records_operation_header_with_0600(env):
    event_id, handle, journal_id, journal_path = _craft_orphan_journal(env)
    mode = stat.S_IMODE(os.stat(journal_path).st_mode)
    assert mode == 0o600
    with open(journal_path, "r", encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    header = lines[0]
    assert header["operation_id"] == event_id
    assert header["tenant_id"] == "t1"
    assert header["action"] == audit_mod.ACTION_ROTATE
    # The handle entry follows the header and names its provider.
    assert lines[1]["provider_id"] == "fakekms"
    assert lines[1]["handle"] == handle


def test_orphan_journal_with_matching_success_event_is_adopted(env):
    event_id, handle, journal_id, journal_path = _craft_orphan_journal(env)
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "t1", audit_mod.ACTION_ROTATE, None,
            audit_mod.OUTCOME_SUCCESS, event_id=event_id,
        )
    )

    store = env.open_store()
    assert not os.path.exists(journal_path)
    assert handle in env.kms_handles()


def test_orphan_journal_with_foreign_success_event_parks(env):
    event_id, handle, journal_id, journal_path = _craft_orphan_journal(env)
    # Same id, but the durable event's action/tenant disagree with the
    # journal's operation header.
    _append_foreign_event(env, event_id, audit_mod.ACTION_IMPORT, "t1")

    store = env.open_store()
    assert os.path.exists(journal_path)
    assert handle in env.kms_handles()


def test_orphan_journal_with_foreign_tenant_event_parks(env):
    event_id, handle, journal_id, journal_path = _craft_orphan_journal(env)
    _append_foreign_event(env, event_id, audit_mod.ACTION_ROTATE, "other")

    store = env.open_store()
    assert os.path.exists(journal_path)
    assert handle in env.kms_handles()


def test_legacy_headerless_journal_resolves_by_id_only(env):
    event_id, handle, journal_id, journal_path = _craft_orphan_journal(
        env, header=False
    )
    _append_foreign_event(env, event_id, audit_mod.ACTION_IMPORT, "t1")

    store = env.open_store()
    # Legacy journals keep the historical id-only resolution.
    assert not os.path.exists(journal_path)
    assert handle in env.kms_handles()
