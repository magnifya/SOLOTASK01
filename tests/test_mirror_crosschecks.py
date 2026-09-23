"""Cross-validation of the operation artifact mirror against its artifacts.

Every durable artifact of one mirrored idempotent attempt must agree exactly
with the ``operation-artifacts/<id>.json`` mirror and the bound operation:

* the mirror's tenant/operator/path/request/kind/action/write_set equal the
  operation record; kind/action correspond to the key_id/items/policy facts;
* the provision journal header (operation_id/tenant/action) and its exact
  provider_id/handle set match the mirror -- missing/corrupt/duplicate/extra
  entries fail the cross-check;
* a batch snapshot's filename/event_id/tenant/key set match, and every
  previous_b64 strictly decodes into a tenant-matching, version-contiguous,
  pending-free KeyRecord;
* restore/batch/empty markers agree on event/tenant/action/import/policy and
  the write set;
* a durable success/rejected event matches the operation id, action, tenant,
  outcome and (for rejections) the staged response.

Anything less provable parks the ENTIRE evidence set: the operation stays
pending, nothing uncommitted is exposed, and the mirror is retained.
"""

import json
import os
import uuid

from keymgr import audit as audit_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import (
    OperationRecord,
    OperationStore,
    STATUS_PENDING,
)

from test_recovery_batch import _craft_batch_scene, _make_keys
from test_recovery_rotate import _craft_journal_only_scene, _make_key


def _fresh_art(env):
    """Store + artifact handles over a pristine dir (harmless recovery)."""
    audit = AuditLog(env.data_dir)
    store = env.open_store()
    art = ArtifactStore(env.data_dir, store, audit)
    return store, art


def _descriptor(operation_id=None, kind="rotate", tenant="t1",
                action=None, write_set=None, handles=None, journal=None,
                snapshot=None, operator="alice",
                path="/v1/keys/x/rotate", request_body="{}"):
    return {
        "operation_id": operation_id or str(uuid.uuid4()),
        "tenant_id": tenant,
        "operator_id": operator,
        "path": path,
        "request_body": request_body,
        "kind": kind,
        "action": action or {
            "rotate": audit_mod.ACTION_ROTATE,
            "batch_rotate": audit_mod.ACTION_BATCH_ROTATE,
            "import": audit_mod.ACTION_IMPORT,
            "restore": audit_mod.ACTION_IMPORT,
        }[kind],
        "write_set": write_set if write_set is not None else [],
        "handles": handles or [],
        "journal": journal,
        "snapshot": snapshot,
        "policy": False,
        "empty_marker": None,
    }


# -- provision journal cross-check -------------------------------------------
def _write_journal(store, journal_id, tenant, action, handles,
                   provider="fakekms", header=True):
    if header:
        _jid, path = store._new_provision_journal(journal_id, tenant, action)
    else:
        _jid, path = store._new_provision_journal(journal_id)
    for handle in handles:
        store._append_provision(path, provider, handle)
    return path


def test_journal_exact_handle_set_matches_mirror(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _write_journal(store, oid, "t1", audit_mod.ACTION_ROTATE, ["h1"])
    desc = _descriptor(oid, handles=[{"provider_id": "fakekms", "handle": "h1"}])
    assert art._journal_consistent(desc) is True


def test_journal_extra_handle_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _write_journal(store, oid, "t1", audit_mod.ACTION_ROTATE, ["h1", "h2"])
    desc = _descriptor(oid, handles=[{"provider_id": "fakekms", "handle": "h1"}])
    assert art._journal_consistent(desc) is False


def test_journal_missing_handle_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _write_journal(store, oid, "t1", audit_mod.ACTION_ROTATE, ["h1"])
    desc = _descriptor(
        oid,
        handles=[
            {"provider_id": "fakekms", "handle": "h1"},
            {"provider_id": "fakekms", "handle": "h2"},
        ],
    )
    assert art._journal_consistent(desc) is False


def test_journal_duplicate_handle_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _write_journal(store, oid, "t1", audit_mod.ACTION_ROTATE, ["h1", "h1"])
    desc = _descriptor(oid, handles=[{"provider_id": "fakekms", "handle": "h1"}])
    assert art._journal_consistent(desc) is False


def test_journal_header_tenant_mismatch_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _write_journal(store, oid, "other", audit_mod.ACTION_ROTATE, ["h1"])
    desc = _descriptor(oid, handles=[{"provider_id": "fakekms", "handle": "h1"}])
    assert art._journal_consistent(desc) is False


def test_journal_header_action_mismatch_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _write_journal(store, oid, "t1", audit_mod.ACTION_IMPORT, ["h1"])
    desc = _descriptor(
        oid, kind="rotate", action=audit_mod.ACTION_ROTATE,
        handles=[{"provider_id": "fakekms", "handle": "h1"}],
    )
    assert art._journal_consistent(desc) is False


def test_journal_header_operation_id_mismatch_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    _jid, path = store._new_provision_journal(oid, "t1", audit_mod.ACTION_ROTATE)
    # Rewrite the header so it names a different operation.
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "operation_id": str(uuid.uuid4()),
            "tenant_id": "t1",
            "action": audit_mod.ACTION_ROTATE,
        }) + "\n")
    desc = _descriptor(oid, handles=[])
    assert art._journal_consistent(desc) is False


def test_corrupt_journal_is_inconsistent(env):
    store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    path = store._provision_path(oid)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{torn")
    desc = _descriptor(oid, handles=[])
    assert art._journal_consistent(desc) is False


def test_absent_journal_is_not_a_failure(env):
    store, art = _fresh_art(env)
    desc = _descriptor()
    assert art._journal_consistent(desc) is None


# -- batch snapshot cross-check ----------------------------------------------
def _valid_snapshot_scene(env, n=2):
    keys = _make_keys(env, n=n)
    store = env.open_store()
    previous = {
        k: store._read_file_bytes(store._path_for(k)) for k in keys
    }
    return store, keys, previous


def test_snapshot_matches_mirror_write_set(env):
    store, keys, previous = _valid_snapshot_scene(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    oid = str(uuid.uuid4())
    store._write_batch_snapshot(oid, "t1", keys, previous)
    desc = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys)
    assert art._snapshot_consistent(desc) is True


def test_snapshot_corrupt_file_is_inconsistent(env):
    store, keys, previous = _valid_snapshot_scene(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    oid = str(uuid.uuid4())
    store._write_batch_snapshot(oid, "t1", keys, previous)
    with open(store._batch_snapshot_path(oid), "w", encoding="utf-8") as fh:
        fh.write("{corrupt")
    desc = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys)
    assert art._snapshot_consistent(desc) is False


def test_snapshot_tenant_mismatch_is_inconsistent(env):
    store, keys, previous = _valid_snapshot_scene(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    oid = str(uuid.uuid4())
    store._write_batch_snapshot(oid, "t1", keys, previous)
    payload = json.loads(
        store._read_file_bytes(store._batch_snapshot_path(oid)).decode("utf-8")
    )
    payload["tenant_id"] = "other"
    store._write_atomic(store._batch_snapshot_path(oid), payload)
    desc = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys)
    assert art._snapshot_consistent(desc) is False


def test_snapshot_key_set_mismatch_is_inconsistent(env):
    store, keys, previous = _valid_snapshot_scene(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    oid = str(uuid.uuid4())
    # Snapshot only carries the first key, mirror names both.
    store._write_batch_snapshot(oid, "t1", [keys[0]], previous)
    desc = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys)
    assert art._snapshot_consistent(desc) is False


def test_snapshot_event_id_filename_mismatch_is_inconsistent(env):
    store, keys, previous = _valid_snapshot_scene(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    oid = str(uuid.uuid4())
    store._write_batch_snapshot(oid, "t1", keys, previous)
    payload = json.loads(
        store._read_file_bytes(store._batch_snapshot_path(oid)).decode("utf-8")
    )
    payload["event_id"] = str(uuid.uuid4())
    store._write_atomic(store._batch_snapshot_path(oid), payload)
    desc = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys)
    assert art._snapshot_consistent(desc) is False


# -- marker cross-check -------------------------------------------------------
def test_single_key_marker_must_own_mirror_key(env):
    _store, art = _fresh_art(env)
    key_id = str(uuid.uuid4())
    oid = str(uuid.uuid4())
    event = {
        "event_id": oid,
        "tenant_id": "t1",
        "action": audit_mod.ACTION_ROTATE,
        "key_id": key_id,
    }
    desc = _descriptor(oid, write_set=[key_id], journal=oid)
    assert art._one_marker_consistent(
        dict(event, journal=oid), desc, oid, "t1", oid, {key_id}
    ) is True
    # A marker projecting a different key than the mirror's write set fails.
    other = str(uuid.uuid4())
    assert art._one_marker_consistent(
        dict(event, key_id=other, journal=oid), desc, oid, "t1", oid,
        {key_id},
    ) is False


def test_batch_marker_references_and_key_set_must_match(env):
    _store, art = _fresh_art(env)
    keys = sorted(str(uuid.uuid4()) for _ in range(2))
    oid = str(uuid.uuid4())
    event = {
        "event_id": oid,
        "tenant_id": "t1",
        "action": audit_mod.ACTION_BATCH_ROTATE,
        "key_id": None,
    }
    marker = {
        "_batch_rotate": True,
        "event": event,
        "tenant_id": "t1",
        "key_ids": keys,
        "journal": oid,
        "snapshot": oid,
    }
    desc = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys,
                       journal=oid, snapshot=oid)
    assert art._one_marker_consistent(
        marker, desc, oid, "t1", oid, set(keys)
    ) is True
    # Wrong journal reference.
    bad = dict(marker, journal=str(uuid.uuid4()))
    assert art._one_marker_consistent(
        bad, desc, oid, "t1", oid, set(keys)
    ) is False
    # Wrong key set.
    bad = dict(marker, key_ids=[keys[0]])
    assert art._one_marker_consistent(
        bad, desc, oid, "t1", oid, set(keys)
    ) is False


def test_restore_marker_policy_flag_must_match(env):
    _store, art = _fresh_art(env)
    keys = sorted(str(uuid.uuid4()) for _ in range(2))
    oid = str(uuid.uuid4())
    event = {
        "event_id": oid,
        "tenant_id": "t1",
        "action": audit_mod.ACTION_IMPORT,
        "key_id": None,
    }
    marker = {
        "_restore": True,
        "event": event,
        "tenant_id": "t1",
        "key_ids": keys,
        "policy": True,
        "journal": oid,
    }
    desc = _descriptor(oid, kind="restore", action=audit_mod.ACTION_IMPORT,
                       write_set=keys, journal=oid)
    desc["policy"] = True
    assert art._one_marker_consistent(
        marker, desc, oid, "t1", oid, set(keys)
    ) is True
    # Mirror says no policy write, marker says one: inconsistent.
    desc["policy"] = False
    assert art._one_marker_consistent(
        marker, desc, oid, "t1", oid, set(keys)
    ) is False


def test_empty_restore_marker_must_match(env):
    _store, art = _fresh_art(env)
    oid = str(uuid.uuid4())
    good = {
        "_restore": True,
        "_empty": True,
        "event": {
            "event_id": oid,
            "tenant_id": "t7",
            "action": audit_mod.ACTION_IMPORT,
        },
        "tenant_id": "t7",
        "key_ids": [],
        "policy": False,
    }
    assert art._empty_marker_consistent(good, oid, "t7") is True
    bad = dict(good, tenant_id="other")
    assert art._empty_marker_consistent(bad, oid, "t7") is False
    bad = dict(good, key_ids=[str(uuid.uuid4())])
    assert art._empty_marker_consistent(bad, oid, "t7") is False


# -- binding (mirror vs operation record) -------------------------------------
def _operation(operation_id, details, tenant="t1", operator="alice",
               path="/v1/keys/x/rotate", body=None):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    return OperationRecord(
        operation_id=operation_id,
        tenant_id=tenant,
        operator_id=operator,
        path=path,
        request_body=body or "{}",
        idempotency_key="k",
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details=details,
    )


def test_binding_kind_write_set_must_match_operation_details(env):
    _store, art = _fresh_art(env)
    key_id = str(uuid.uuid4())
    oid = str(uuid.uuid4())
    record = _operation(
        oid, {"kind": "rotate", "key_id": key_id, "algorithm": "AES256"}
    )
    good = _descriptor(oid, write_set=[key_id])
    assert art._binding_matches(good, record) is True
    # Mirror write set names another key.
    bad = _descriptor(oid, write_set=[str(uuid.uuid4())])
    assert art._binding_matches(bad, record) is False
    # Mirror kind/action disagree.
    bad = _descriptor(oid, kind="import", action=audit_mod.ACTION_IMPORT,
                      write_set=[key_id])
    assert art._binding_matches(bad, record) is False


def test_binding_batch_items_must_match_mirror_write_set(env):
    _store, art = _fresh_art(env)
    keys = sorted(str(uuid.uuid4()) for _ in range(2))
    oid = str(uuid.uuid4())
    record = _operation(
        oid,
        {"kind": "batch_rotate",
         "items": [{"key_id": k, "algorithm": "AES256"} for k in keys]},
        path="/v1/keys/batch-rotate",
    )
    good = _descriptor(oid, kind="batch_rotate",
                       action=audit_mod.ACTION_BATCH_ROTATE, write_set=keys,
                       path="/v1/keys/batch-rotate")
    assert art._binding_matches(good, record) is True
    bad = _descriptor(oid, kind="batch_rotate",
                      action=audit_mod.ACTION_BATCH_ROTATE, write_set=[keys[0]],
                      path="/v1/keys/batch-rotate")
    assert art._binding_matches(bad, record) is False


def test_binding_restore_policy_flag_must_match(env):
    _store, art = _fresh_art(env)
    keys = sorted(str(uuid.uuid4()) for _ in range(1))
    oid = str(uuid.uuid4())
    record = _operation(
        oid,
        {"kind": "restore", "key_ids": keys, "policy_restored": True},
        path="/v1/restore",
    )
    good = _descriptor(oid, kind="restore", action=audit_mod.ACTION_IMPORT,
                       write_set=keys, path="/v1/restore")
    good["policy"] = True
    assert art._binding_matches(good, record) is True
    bad = _descriptor(oid, kind="restore", action=audit_mod.ACTION_IMPORT,
                      write_set=keys, path="/v1/restore")
    assert art._binding_matches(bad, record) is False


# -- rejected event cross-check (integration, no outbox artifact) -------------
def _pending_rejection_op(op_store, operation_id, key_id, action):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    record = OperationRecord(
        operation_id=operation_id,
        tenant_id="t1",
        operator_id="alice",
        path="/v1/keys/%s/rotate" % key_id,
        request_body=json.dumps(
            {"tenant_id": "t1", "algorithm": "AES256"},
            sort_keys=True, separators=(",", ":"),
        ),
        idempotency_key="rej-" + operation_id[:8],
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details={
            "kind": "rotate",
            "key_id": key_id,
            "algorithm": "AES256",
            "result": {
                "http_status": 403,
                "response": {"error": "denied", "operation_id": operation_id},
            },
            "terminal": 403,
            "audit": {
                "action": action,
                "outcome": audit_mod.OUTCOME_REJECTED,
                "tenant_id": "t1",
                "key_id": key_id,
            },
        },
    )
    op_store._write_record(record)
    return record


def _settle(env):
    audit = AuditLog(env.data_dir)
    store = env.open_store()
    art = ArtifactStore(env.data_dir, store, audit)
    op_store = OperationStore(env.data_dir, audit)
    art.settle_pending(op_store)
    return store, art, op_store


def test_foreign_action_rejected_event_parks_and_keeps_mirror(env):
    key_id = _make_key(env)
    audit = AuditLog(env.data_dir)
    op_store = OperationStore(env.data_dir, audit)
    art_keyless = ArtifactStore(env.data_dir, None, audit)
    oid = str(uuid.uuid4())
    record = _pending_rejection_op(
        op_store, oid, key_id, audit_mod.ACTION_ROTATE
    )
    # A bound, described mirror with no surviving provider artifacts.
    mirror = art_keyless.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror_path = mirror.path()
    # A durable REJECTED event with the same id but a DIFFERENT action.
    audit.append(
        audit.new_event(
            "t1", audit_mod.ACTION_IMPORT, key_id,
            audit_mod.OUTCOME_REJECTED, event_id=oid,
        )
    )

    _store2, art2, op2 = _settle(env)
    assert art2.is_parked(oid)
    op2.recover_pending(is_parked=art2.is_parked)
    assert op2.get(oid, "t1", "alice").status == STATUS_PENDING
    assert os.path.exists(mirror_path)


def test_matching_rejected_event_clears_mirror(env):
    key_id = _make_key(env)
    audit = AuditLog(env.data_dir)
    op_store = OperationStore(env.data_dir, audit)
    art_keyless = ArtifactStore(env.data_dir, None, audit)
    oid = str(uuid.uuid4())
    record = _pending_rejection_op(
        op_store, oid, key_id, audit_mod.ACTION_ROTATE
    )
    mirror = art_keyless.create(record).describe(
        {"kind": "rotate", "write_set": [key_id]}
    )
    mirror_path = mirror.path()
    audit.append(
        audit.new_event(
            "t1", audit_mod.ACTION_ROTATE, key_id,
            audit_mod.OUTCOME_REJECTED, event_id=oid,
        )
    )

    _store2, art2, op2 = _settle(env)
    assert not art2.is_parked(oid)
    op2.recover_pending(is_parked=art2.is_parked)
    final = op2.get(oid, "t1", "alice")
    assert final.status == "failed" and final.http_status == 403
    assert not os.path.exists(mirror_path)


# -- corrupt batch snapshot parks the pending operation (healthy provider) ----
def test_corrupt_batch_snapshot_parks_pending_operation(env):
    keys = _make_keys(env, n=2)
    scene = _craft_batch_scene(env, keys)
    audit = AuditLog(env.data_dir)
    op_store = OperationStore(env.data_dir, audit)
    art_keyless = ArtifactStore(env.data_dir, None, audit)

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    record = OperationRecord(
        operation_id=scene.event_id,
        tenant_id="t1",
        operator_id="alice",
        path="/v1/keys/batch-rotate",
        request_body="{}",
        idempotency_key="batch-snap-corrupt",
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details={
            "kind": "batch_rotate",
            "items": [
                {"key_id": k, "algorithm": "AES256"} for k in keys
            ],
        },
    )
    op_store._write_record(record)
    mirror = art_keyless.create(record).describe(
        {"kind": "batch_rotate", "write_set": keys}
    )
    mirror.provision(scene.journal_id, snapshot=scene.event_id)
    for handle in scene.handles:
        mirror.add_handle("fakekms", handle)
    mirror.phase("staged")
    mirror_path = mirror.path()

    # Corrupt the snapshot: even with a healthy provider the batch recovery
    # cannot roll back and the mirror cross-check must park the op.
    with open(
        env.open_store()._batch_snapshot_path(scene.event_id), "w",
        encoding="utf-8",
    ) as fh:
        fh.write("{not json")

    _store2, art2, op2 = _settle(env)
    assert art2.is_parked(scene.event_id)
    op2.recover_pending(is_parked=art2.is_parked)
    assert op2.get(scene.event_id, "t1", "alice").status == STATUS_PENDING
    assert os.path.exists(mirror_path)
