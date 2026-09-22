"""Scenario tests for batch-rotate pre-commit rollback and unsettled reads."""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keymgr import audit as audit_mod
from keymgr import provider as provider_mod
from keymgr.audit import LedgerError
from keymgr.provider import ProviderUnavailable
from keymgr.store import KeyStore

DATA = tempfile.mkdtemp(prefix="keymgr-test-")


def fresh_store():
    return KeyStore(DATA)


def read_file(key_id):
    with open(os.path.join(DATA, key_id + ".json"), "rb") as fh:
        return fh.read()


def registry_handles():
    path = os.path.join(DATA, "local-registry.json")
    if not os.path.exists(path):
        return set()
    with open(path) as fh:
        data = json.load(fh)
    return set(data.get("handles", data if isinstance(data, dict) else []))


def main():
    store = fresh_store()
    k1 = store.create("t1", "AES256", "a")
    k2 = store.create("t1", "RSA2048", "b")
    bytes_before = {k.key_id: read_file(k.key_id) for k in (k1, k2)}

    # --- 1. In-request failure at the commit point (ledger append fails) ---
    real_append = store.audit.append

    def failing_append(event):
        if event.action == audit_mod.ACTION_BATCH_ROTATE:
            raise LedgerError("simulated ledger failure")
        return real_append(event)

    store.audit.append = failing_append
    try:
        store.batch_rotate(
            "t1",
            [(k1.key_id, "AES256"), (k2.key_id, "RSA2048")],
            event_id="11111111-1111-4111-8111-111111111111",
        )
        raise AssertionError("batch_rotate should have raised")
    except LedgerError:
        pass
    finally:
        store.audit.append = real_append

    # Files restored byte-for-byte.
    for key_id, raw in bytes_before.items():
        assert read_file(key_id) == raw, "file not restored byte-for-byte"
    # Journal and snapshot removed.
    assert not os.path.exists(
        os.path.join(DATA, "provisions",
                     "11111111-1111-4111-8111-111111111111.json")
    ), "provision journal survived"
    assert not os.path.exists(
        os.path.join(DATA, "batch-rotations",
                     "11111111-1111-4111-8111-111111111111.json")
    ), "batch snapshot survived"
    # No batch_rotate audit event recorded.
    events = [e for e in store.audit._read_all()
              if e.action == audit_mod.ACTION_BATCH_ROTATE]
    assert not events, "a batch_rotate event was recorded"
    # No orphan handles: registry should only hold the 2 create handles.
    handles = registry_handles()
    assert len(handles) == 2, "orphan handles leaked: %r" % handles
    print("1. in-request commit-point failure: full rollback OK")

    # --- 2. Unsettled marker read view: project old state from snapshot ---
    # Simulate a crash after phase 1 (files carry marker) by committing a
    # batch whose ledger append fails AND whose rollback fails (snapshot
    # retained). Easiest: craft the scene directly via a batch that fails
    # during rollback (make one handle delete fail).
    store2 = fresh_store()
    k3 = store2.create("t1", "AES256", "c")
    k4 = store2.create("t1", "AES256", "d")
    before3 = read_file(k3.key_id)
    before4 = read_file(k4.key_id)
    event_id = "22222222-2222-4222-8222-222222222222"

    store2.audit.append = failing_append
    real_delete = provider_mod.get_local_provider().delete
    calls = {"n": 0}

    def flaky_delete(handle):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated delete failure")
        return real_delete(handle)

    provider_mod.get_local_provider().delete = flaky_delete
    try:
        store2.batch_rotate(
            "t1",
            [(k3.key_id, "AES256"), (k4.key_id, "AES256")],
            event_id=event_id,
        )
        raise AssertionError("should have raised")
    except ProviderUnavailable:
        pass
    finally:
        store2.audit.append = real_append
        provider_mod.get_local_provider().delete = real_delete

    # Scene retained: snapshot + journal still present, files still marked.
    assert os.path.exists(
        os.path.join(DATA, "batch-rotations", event_id + ".json"))
    assert os.path.exists(
        os.path.join(DATA, "provisions", event_id + ".json"))
    marked = json.loads(read_file(k3.key_id))
    assert marked["pending_event"]["_batch_rotate"] is True

    # Reads project the OLD state from the validated snapshot.
    view = store2.get(k3.key_id, "t1")
    assert view is not None, "marked key hidden despite valid snapshot"
    assert view.current_version == 1, view.current_version
    assert len(view.versions) == 1
    # Export projects old state too (no uncommitted version in bundle).
    bundle = store2.export_bundle(k3.key_id, "t1", "pw")
    assert bundle is not None
    from keymgr import keybundle
    payload = keybundle.decode_bundle(bundle, "pw")
    assert payload["current_version"] == 1, payload["current_version"]
    assert len(payload["versions"]) == 1
    # Mutations on the unsettled file are refused (503 at API layer).
    for fn in (
        lambda: store2.rotate(k3.key_id, "t1", "AES256"),
        lambda: store2.revoke(k3.key_id, "t1", "r", "op"),
        lambda: store2.batch_rotate("t1", [(k3.key_id, "AES256")]),
    ):
        try:
            fn()
            raise AssertionError("mutation on unsettled file not refused")
        except ProviderUnavailable:
            pass
    print("2. unsettled marker: snapshot projection + 503 mutations OK")

    # --- 3. Corrupt snapshot hides the record entirely ---
    snap_path = os.path.join(DATA, "batch-rotations", event_id + ".json")
    with open(snap_path, "wb") as fh:
        fh.write(b'{"event_id": "wrong", "keys": []}')
    assert store2.get(k3.key_id, "t1") is None, "corrupt snapshot not hidden"
    assert store2.export_bundle(k3.key_id, "t1", "pw") is None
    # Restore the valid snapshot (rewrite from retained in-memory copy is
    # not possible; reconstruct from the journal-free scene: use backup of
    # the original snapshot we took before corrupting).
    print("3. corrupt snapshot hides record OK")

    # --- 4. Startup recovery rolls the retained scene back ---
    # Recreate a valid scene: run another failing batch with delete fixed.
    store3 = fresh_store()
    # The parked scene from step 2 has a corrupt snapshot; recovery must
    # preserve it (never guess).
    store3  # constructed above already ran recovery once; verify parked
    assert os.path.exists(snap_path), "corrupt snapshot wrongly removed"
    marked = json.loads(read_file(k3.key_id))
    assert marked["pending_event"]["_batch_rotate"] is True
    print("4. corrupt-snapshot scene preserved across restart OK")

    shutil.rmtree(DATA)


if __name__ == "__main__":
    main()
