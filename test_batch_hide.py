"""Hide conditions for unsettled _batch_rotate read views."""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keymgr import audit as audit_mod
from keymgr.audit import LedgerError
from keymgr.provider import ProviderUnavailable
from keymgr.store import KeyStore

DATA = tempfile.mkdtemp(prefix="keymgr-test3-")


def read_file(key_id):
    with open(os.path.join(DATA, key_id + ".json"), "rb") as fh:
        return fh.read()


def write_file(key_id, raw):
    with open(os.path.join(DATA, key_id + ".json"), "wb") as fh:
        fh.write(raw)


def make_scene(store, k1, k2, event_id):
    """Run a batch whose ledger append and rollback-delete both fail, so the
    marked files + snapshot + journal survive."""
    real_append = store.audit.append

    def failing_append(event):
        if event.action == audit_mod.ACTION_BATCH_ROTATE:
            raise LedgerError("simulated")
        return real_append(event)

    from keymgr import provider as provider_mod
    real_delete = provider_mod.get_local_provider().delete

    def flaky_delete(handle):
        raise RuntimeError("delete always fails")

    store.audit.append = failing_append
    provider_mod.get_local_provider().delete = flaky_delete
    try:
        store.batch_rotate(
            "t1", [(k1.key_id, "AES256"), (k2.key_id, "AES256")],
            event_id=event_id)
        raise AssertionError("should raise")
    except ProviderUnavailable:
        pass
    finally:
        store.audit.append = real_append
        provider_mod.get_local_provider().delete = real_delete


def main():
    store = KeyStore(DATA)
    k1 = store.create("t1", "AES256", "a")
    k2 = store.create("t1", "AES256", "b")
    event_id = "66666666-6666-4666-8666-666666666666"
    make_scene(store, k1, k2, event_id)

    # Baseline: valid scene projects old state.
    assert store.get(k1.key_id, "t1") is not None

    # 1. Ledger unreadable -> record hidden.
    real_read_all = store.audit._read_all

    def unreadable():
        raise LedgerError("simulated unreadable ledger")

    store.audit._read_all = unreadable
    try:
        assert store.get(k1.key_id, "t1") is None, "ledger outage not hidden"
    finally:
        store.audit._read_all = real_read_all
    print("1. unreadable ledger hides record OK")

    # 2. Marker tenant mismatch -> hidden.
    raw = json.loads(read_file(k1.key_id))
    good_marker = raw["pending_event"]
    bad = dict(good_marker)
    bad["tenant_id"] = "other-tenant"
    raw["pending_event"] = bad
    saved = read_file(k1.key_id)
    write_file(k1.key_id, json.dumps(raw).encode())
    assert store.get(k1.key_id, "t1") is None, "tenant mismatch not hidden"
    # 3. Marker action mismatch -> hidden.
    raw = json.loads(saved)
    bad = json.loads(json.dumps(good_marker))
    bad["event"]["action"] = "rotate"
    raw["pending_event"] = bad
    write_file(k1.key_id, json.dumps(raw).encode())
    assert store.get(k1.key_id, "t1") is None, "action mismatch not hidden"
    # 4. Marker journal/snapshot reference mismatch -> hidden.
    raw = json.loads(saved)
    bad = json.loads(json.dumps(good_marker))
    bad["snapshot"] = "99999999-9999-4999-8999-999999999999"
    raw["pending_event"] = bad
    write_file(k1.key_id, json.dumps(raw).encode())
    assert store.get(k1.key_id, "t1") is None, "snapshot ref mismatch shown"
    # 5. Snapshot file missing -> hidden.
    raw = json.loads(saved)
    raw["pending_event"] = good_marker
    write_file(k1.key_id, json.dumps(raw).encode())
    snap = os.path.join(DATA, "batch-rotations", event_id + ".json")
    snap_bytes = open(snap, "rb").read()
    os.unlink(snap)
    assert store.get(k1.key_id, "t1") is None, "missing snapshot not hidden"
    # 6. Snapshot previous_b64 tampered (strict decode fails) -> hidden.
    with open(snap, "wb") as fh:
        fh.write(snap_bytes)
    doc = json.loads(snap_bytes)
    doc["keys"][0]["previous_b64"] = "!!!not-base64!!!"
    with open(snap, "w") as fh:
        json.dump(doc, fh)
    assert store.get(k1.key_id, "t1") is None, "bad b64 not hidden"
    # 7. Snapshot image with broken version continuity -> hidden.
    doc = json.loads(snap_bytes)
    img = json.loads(__import__("base64").b64decode(
        doc["keys"][0]["previous_b64"]))
    img["versions"][0]["version"] = 7
    doc["keys"][0]["previous_b64"] = __import__("base64").b64encode(
        json.dumps(img).encode()).decode()
    with open(snap, "w") as fh:
        json.dump(doc, fh)
    assert store.get(k1.key_id, "t1") is None, "bad continuity not hidden"
    # Restore the valid scene; projection works again.
    with open(snap, "wb") as fh:
        fh.write(snap_bytes)
    write_file(k1.key_id, saved)
    assert store.get(k1.key_id, "t1") is not None
    print("2-7. marker/snapshot mismatch hide conditions OK")

    # 8. Restart with the valid scene rolls everything back.
    before1 = None
    store = KeyStore(DATA)
    view = store.get(k1.key_id, "t1")
    assert view is not None and view.current_version == 1
    assert not os.path.exists(snap)
    print("8. restart recovery of retained scene OK")

    shutil.rmtree(DATA)


if __name__ == "__main__":
    main()
