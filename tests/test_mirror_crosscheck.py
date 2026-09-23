"""Cross-validation of the operation artifact mirror against every durable
artifact of one mirrored attempt.

The mirror is the cross-index tying the operation record, the provision
journal, the batch snapshot / restore markers and the minted handles to one
attempt. These tests assert that a missing, corrupt, duplicated or extra
reference -- or a mirror whose kind/write set does not correspond to the
operation's durable details -- can never be cleaned or treated as committed:
the whole evidence set stays parked and the operation stays pending.
"""

import base64
import json
import os
import uuid
from types import SimpleNamespace

import pytest

from keymgr import audit as audit_mod
from keymgr.artifacts import (
    ArtifactInconsistent,
    ArtifactStore,
    PHASE_COMMITTED,
    PHASE_PROVISIONING,
    PHASE_STAGED,
)
from keymgr.audit import AuditLog
from keymgr.operations import (
    OperationRecord,
    OperationStore,
    STATUS_PENDING,
)

from test_recovery_batch import _craft_batch_scene, _make_keys
from test_recovery_restore import _craft_restore_scene
from test_recovery_rotate import (
    _craft_journal_only_scene,
    _craft_rotate_marker_scene,
    _make_key,
)
from test_recovery_misc import _empty_marker


_ACTIONS = {
    "rotate": audit_mod.ACTION_ROTATE,
    "batch_rotate": audit_mod.ACTION_BATCH_ROTATE,
    "import": audit_mod.ACTION_IMPORT,
    "restore": audit_mod.ACTION_IMPORT,
}


def _desc(operation_id, write_set, kind="rotate", handles=(), journal=None,
          snapshot=None, empty_marker=None, policy=False,
          phase=PHASE_COMMITTED):
    return {
        "version": 1,
        "operation_id": operation_id,
        "tenant_id": "t1",
        "operator_id": "alice",
        "path": "/v1/keys/x",
        "request_body": "{}",
        "kind": kind,
        "action": _ACTIONS[kind],
        "phase": phase,
        "write_set": sorted(write_set),
        "handles": [
            {"provider_id": provider_id, "handle": handle}
            for provider_id, handle in handles
        ],
        "journal": operation_id if journal is None else journal,
        "snapshot": snapshot,
        "empty_marker": empty_marker,
        "policy": policy,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }


def _pending_operation(op_store, operation_id, key_id, details=None):
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
        idempotency_key="xkey-" + operation_id[:8],
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details=details or {
            "kind": "rotate", "key_id": key_id, "algorithm": "AES256"
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
    return audit, store, art, op_store


# -- strict describe / provision shapes --------------------------------------
def test_describe_rejects_wrong_shape_and_foreign_reference(env):
    key_id = _make_key(env)
    op_store = OperationStore(env.data_dir, AuditLog(env.data_dir))
    art = ArtifactStore(env.data_dir, env.open_store(), AuditLog(env.data_dir))
    begin = op_store.begin(
        "t1", "alice", "/v1/keys/%s/rotate" % key_id, "{}", "shape-1"
    )
    mirror = art.create(begin.record)

    with pytest.raises(ArtifactInconsistent):
        mirror.describe({"kind": "rotate", "write_set": [key_id, str(uuid.uuid4())]})
    with pytest.raises(ArtifactInconsistent):
        mirror.describe({"kind": "batch_rotate", "write_set": []})
    with pytest.raises(ArtifactInconsistent):
        mirror.describe({"kind": "nope", "write_set": [key_id]})
    with pytest.raises(ArtifactInconsistent):
        mirror.describe(
            {"kind": "rotate", "action": audit_mod.ACTION_IMPORT,
             "write_set": [key_id]}
        )
    mirror.describe({"kind": "rotate", "write_set": [key_id]})
    with pytest.raises(ArtifactInconsistent):
        mirror.provision(str(uuid.uuid4()))


# -- committed write-set / handle ownership ----------------------------------
def _committed_rotate(env):
    key_id = _make_key(env)
    event_id, handle, _journal = _craft_rotate_marker_scene(env, key_id)
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "t1", audit_mod.ACTION_ROTATE, key_id,
            audit_mod.OUTCOME_SUCCESS, event_id=event_id,
        )
    )
    store = env.open_store()  # commits the marker forward, drops the journal
    return key_id, event_id, handle, store


def test_committed_verify_baseline_and_handle_ownership(env):
    key_id, eid, handle, store = _committed_rotate(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    good = _desc(eid, [key_id], handles=[("fakekms", handle)])
    assert art._committed_state_verified(good) is True
    # A handle the committed record does not own: extra evidence.
    bad = _desc(eid, [key_id], handles=[("fakekms", "handle-not-owned")])
    assert art._committed_state_verified(bad) is False
    # A write set naming a key that does not exist for the tenant.
    missing = _desc(eid, [str(uuid.uuid4())], handles=[])
    assert art._committed_state_verified(missing) is False


def test_committed_verify_fails_on_surviving_journal_handle_mismatch(env):
    key_id, eid, handle, store = _committed_rotate(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    journal_path = store._provision_path(eid)
    os.makedirs(os.path.dirname(journal_path), exist_ok=True)
    # A surviving journal naming an EXTRA handle the mirror does not know.
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(
            {"operation_id": eid, "tenant_id": "t1",
             "action": audit_mod.ACTION_ROTATE}) + "\n")
        fh.write(json.dumps(
            {"provider_id": "fakekms", "handle": "surviving-extra"}) + "\n")
    desc = _desc(eid, [key_id], handles=[("fakekms", handle)])
    assert art._committed_state_verified(desc) is False
    # Direct verdict raises on the set mismatch and on a duplicate line.
    with pytest.raises(ArtifactInconsistent):
        art._journal_verdict(desc)
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(
            {"operation_id": eid, "tenant_id": "t1",
             "action": audit_mod.ACTION_ROTATE}) + "\n")
        for _ in range(2):
            fh.write(json.dumps(
                {"provider_id": "fakekms", "handle": handle}) + "\n")
    with pytest.raises(ArtifactInconsistent):
        art._journal_verdict(desc)


def test_legacy_headerless_journal_must_still_match_handle_set(env):
    key_id, eid, handle, store = _committed_rotate(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    journal_path = store._provision_path(eid)
    os.makedirs(os.path.dirname(journal_path), exist_ok=True)
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"provider_id": "fakekms", "handle": handle}) + "\n")
    desc = _desc(eid, [key_id], handles=[("fakekms", handle)])
    art._journal_verdict(desc)  # equal sets: no raise


# -- mirror kind / write set must correspond to the operation ----------------
def test_settlement_parks_when_mirror_write_set_disagrees_with_operation(env):
    key_id, eid, handle, store = _committed_rotate(env)
    op_store = OperationStore(env.data_dir, AuditLog(env.data_dir))
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    # The operation record says rotate(key_id); the mirror claims a different
    # key in its write set. The two durable records disagree -> parked.
    record = _pending_operation(op_store, eid, key_id)
    mirror = art.create(record)
    mirror.descriptor = _desc(
        eid, [str(uuid.uuid4())], handles=[("fakekms", handle)]
    )
    art.write_descriptor(mirror.descriptor)
    art.settle_pending(op_store)
    assert art.is_parked(eid)
    assert os.path.exists(art.path_for(eid))


# -- batch snapshot cross-validation -----------------------------------------
def test_batch_snapshot_verdict_matches_then_detects_each_tamper(env):
    # Hold a store opened on the clean dir: its recovery runs before the
    # scene exists, so its helpers can read the crafted scene live without
    # rolling it back.
    store0 = env.open_store()
    keys = _make_keys(env, n=2)
    scene = _craft_batch_scene(env, keys)
    art = ArtifactStore(env.data_dir, store0, AuditLog(env.data_dir))
    desc = _desc(
        scene.event_id, keys, kind="batch_rotate",
        handles=[("fakekms", h) for h in scene.handles],
        snapshot=scene.event_id, phase=PHASE_STAGED,
    )
    art._snapshot_verdict(desc)  # intact: no raise

    snapshot_path = store0._batch_snapshot_path(scene.event_id)
    with open(snapshot_path, "r", encoding="utf-8") as fh:
        pristine = json.load(fh)

    def tamper(mutate):
        # Always start from the pristine snapshot so each tamper is isolated.
        raw = json.loads(json.dumps(pristine))
        mutate(raw)
        with open(snapshot_path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)

    # 1) mirror write set larger than the snapshot key set.
    wider = _desc(
        scene.event_id, keys + [str(uuid.uuid4())], kind="batch_rotate",
        handles=[("fakekms", h) for h in scene.handles],
        snapshot=scene.event_id, phase=PHASE_STAGED,
    )
    with pytest.raises(ArtifactInconsistent):
        art._snapshot_verdict(wider)

    # 2) a previous_b64 that does not decode into a valid KeyRecord.
    tamper(lambda raw: raw["keys"][0].__setitem__("previous_b64", "AAAA"))
    with pytest.raises(ArtifactInconsistent):
        art._snapshot_verdict(desc)

    # 3) previous_b64 of another tenant.
    def other_tenant(raw):
        data = json.loads(
            base64.b64decode(raw["keys"][0]["previous_b64"]).decode("utf-8")
        )
        data["tenant_id"] = "other"
        raw["keys"][0]["previous_b64"] = base64.b64encode(
            json.dumps(data).encode("utf-8")
        ).decode("ascii")

    tamper(other_tenant)
    with pytest.raises(ArtifactInconsistent):
        art._snapshot_verdict(desc)

    # 4) previous_b64 carrying a pending marker (never a valid snapshot image).
    def pending_image(raw):
        data = json.loads(
            base64.b64decode(raw["keys"][0]["previous_b64"]).decode("utf-8")
        )
        data["pending_event"] = {"event_id": str(uuid.uuid4())}
        raw["keys"][0]["previous_b64"] = base64.b64encode(
            json.dumps(data).encode("utf-8")
        ).decode("ascii")

    tamper(pending_image)
    with pytest.raises(ArtifactInconsistent):
        art._snapshot_verdict(desc)

    # 5) non-contiguous version sequence.
    def gap_versions(raw):
        data = json.loads(
            base64.b64decode(raw["keys"][0]["previous_b64"]).decode("utf-8")
        )
        data["versions"][0]["version"] = 7
        data["current_version"] = 7
        raw["keys"][0]["previous_b64"] = base64.b64encode(
            json.dumps(data).encode("utf-8")
        ).decode("ascii")

    tamper(gap_versions)
    with pytest.raises(ArtifactInconsistent):
        art._snapshot_verdict(desc)


# -- restore markers cross-validation ----------------------------------------
def test_restore_marker_write_set_and_policy_must_match_mirror(env):
    store0 = env.open_store()
    scene = _craft_restore_scene(env, with_policy=False)
    art = ArtifactStore(env.data_dir, store0, AuditLog(env.data_dir))
    desc = _desc(
        scene.event_id, scene.key_ids, kind="restore",
        handles=[("fakekms", h) for h in scene.handles],
        phase=PHASE_STAGED,
    )
    art._restore_artifacts_verdict(desc)  # intact: no raise

    # Rewrite one key file's marker with a foreign write set.
    victim = scene.key_ids[0]
    record = store0._read_record(store0._path_for(victim))
    record.pending_event["key_ids"] = [str(uuid.uuid4())]
    store0._write_atomic(store0._path_for(victim), record.to_json())
    with pytest.raises(ArtifactInconsistent):
        art._restore_artifacts_verdict(desc)


def test_empty_restore_marker_must_match_mirror(env):
    path, marker = _empty_marker(env, tenant="t1")
    store0 = env.open_store()
    art = ArtifactStore(env.data_dir, store0, AuditLog(env.data_dir))
    eid = marker["event"]["event_id"]
    desc = _desc(eid, [], kind="restore", empty_marker=path,
                 phase=PHASE_STAGED)
    art._restore_artifacts_verdict(desc)  # intact: no raise

    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    raw["tenant_id"] = "other"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)
    with pytest.raises(ArtifactInconsistent):
        art._restore_artifacts_verdict(desc)


# -- rejected events must match operation_id/action/tenant/outcome ------------
def _journal_only_with_mirror(env):
    key_id = _make_key(env)
    eid, handle, journal_id = _craft_journal_only_scene(env, key_id)
    op_store = OperationStore(env.data_dir, AuditLog(env.data_dir))
    art = ArtifactStore(env.data_dir, None, AuditLog(env.data_dir))
    record = _pending_operation(op_store, eid, key_id)
    mirror = art.create(record).describe({"kind": "rotate", "write_set": [key_id]})
    mirror.provision(journal_id)
    mirror.add_handle("fakekms", handle)
    mirror.phase(PHASE_PROVISIONING)
    return key_id, eid, handle, journal_id


def test_foreign_action_rejected_event_parks_mirror(env):
    key_id, eid, _handle, _jid = _journal_only_with_mirror(env)
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "t1", audit_mod.ACTION_IMPORT, key_id,
            audit_mod.OUTCOME_REJECTED, event_id=eid,
        )
    )
    _audit, store, art, op_store = _settle(env)
    assert art.is_parked(eid)
    assert os.path.exists(art.path_for(eid))
    op_store.recover_pending(is_parked=art.is_parked)
    assert op_store.get(eid, "t1", "alice").status == STATUS_PENDING


def test_matching_rejected_event_clears_spent_mirror(env):
    key_id, eid, _handle, _jid = _journal_only_with_mirror(env)
    ledger = AuditLog(env.data_dir)
    ledger.append(
        ledger.new_event(
            "t1", audit_mod.ACTION_ROTATE, key_id,
            audit_mod.OUTCOME_REJECTED, event_id=eid,
        )
    )
    _audit, store, art, op_store = _settle(env)
    assert not art.is_parked(eid)
    assert not os.path.exists(art.path_for(eid))


# -- staged success response must be backed by the committed state ------------
def test_staged_success_response_must_be_backed(env):
    key_id, eid, handle, store = _committed_rotate(env)
    art = ArtifactStore(env.data_dir, store, AuditLog(env.data_dir))
    desc = _desc(eid, [key_id], handles=[("fakekms", handle)])

    def record_with(response):
        return SimpleNamespace(details={"result": {"http_status": 201,
                                                   "response": response}})

    ok = record_with(
        {"key_id": key_id, "version": 2, "algorithm": "AES256",
         "public_key": None, "operation_id": eid}
    )
    assert art._staged_success_response_backed(desc, ok) is True
    ghost = record_with(
        {"key_id": key_id, "version": 99, "algorithm": "AES256",
         "public_key": None, "operation_id": eid}
    )
    assert art._staged_success_response_backed(desc, ghost) is False
    # A staged refusal response can never be backed by a committed write set.
    refusal = SimpleNamespace(
        details={"result": {"http_status": 409,
                            "response": {"error": "x", "operation_id": eid}}}
    )
    assert art._staged_success_response_backed(desc, refusal) is False
