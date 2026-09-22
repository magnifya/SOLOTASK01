"""Startup recovery + committed-batch scenarios."""
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

DATA = tempfile.mkdtemp(prefix="keymgr-test2-")


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
    store = KeyStore(DATA)
    k1 = store.create("t1", "AES256", "a")
    k2 = store.create("t1", "RSA2048", "b")
    bytes_before = {k.key_id: read_file(k.key_id) for k in (k1, k2)}
    event_id = "33333333-3333-4333-8333-333333333333"

    # --- 5. Crash scene: files marked, snapshot+journal durable, event not.
    # Simulate by failing the ledger append AND failing the in-request
    # rollback's file restore (make _write_bytes_atomic fail once).
    real_append = store.audit.append

    def failing_append(event):
        if event.action == audit_mod.ACTION_BATCH_ROTATE:
            raise LedgerError("simulated")
        return real_append(event)

    real_write_bytes = store._write_bytes_atomic
    calls = {"n": 0}

    def flaky_write(path, raw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("simulated write failure")
        return real_write_bytes(path, raw)

    store.audit.append = failing_append
    store._write_bytes_atomic = flaky_write
    try:
        store.batch_rotate(
            "t1", [(k1.key_id, "AES256"), (k2.key_id, "RSA2048")],
            event_id=event_id,
        )
        raise AssertionError("should have raised")
    except ProviderUnavailable:
        pass
    finally:
        store.audit.append = real_append
        store._write_bytes_atomic = real_write_bytes

    # Scene retained: journal + snapshot survive (handles were already
    # confirmed deleted before the file restore failed; their re-delete at
    # startup is idempotent).
    assert os.path.exists(os.path.join(DATA, "batch-rotations",
                                       event_id + ".json"))
    assert os.path.exists(os.path.join(DATA, "provisions",
                                       event_id + ".json"))
    assert len(registry_handles()) == 2, registry_handles()
    # At least one file still carries the marker.
    assert any(
        (json.loads(read_file(k.key_id)).get("pending_event") or {})
        .get("_batch_rotate")
        for k in (k1, k2)
    )

    # Restart: recovery deletes new handles, restores bytes, drops artifacts.
    store = KeyStore(DATA)
    for key_id, raw in bytes_before.items():
        assert read_file(key_id) == raw, "recovery did not restore bytes"
    assert not os.path.exists(os.path.join(DATA, "batch-rotations",
                                           event_id + ".json"))
    assert not os.path.exists(os.path.join(DATA, "provisions",
                                           event_id + ".json"))
    assert len(registry_handles()) == 2, registry_handles()
    events = [e for e in store.audit._read_all()
              if e.action == audit_mod.ACTION_BATCH_ROTATE]
    assert not events
    print("5. startup recovery with valid snapshot: full rollback OK")

    # --- 6. Committed batch keeps new versions; marker cleared on restart ---
    result = store.batch_rotate(
        "t1", [(k1.key_id, "AES256"), (k2.key_id, "RSA2048")],
        event_id="44444444-4444-4444-8444-444444444444",
    )
    status, pairs = result
    assert status == store.BATCH_ROTATED
    assert dict((kid, r.current_version) for kid, r in pairs) == {
        k1.key_id: 2, k2.key_id: 2}
    # Artifacts cleaned on the happy path.
    assert not os.path.exists(os.path.join(
        DATA, "batch-rotations",
        "44444444-4444-4444-8444-444444444444.json"))
    assert not os.path.exists(os.path.join(
        DATA, "provisions",
        "44444444-4444-4444-8444-444444444444.json"))
    # Exactly one success event with key_id null.
    events = [e for e in store.audit._read_all()
              if e.action == audit_mod.ACTION_BATCH_ROTATE]
    assert len(events) == 1 and events[0].key_id is None
    assert events[0].outcome == audit_mod.OUTCOME_SUCCESS
    assert events[0].event_id == "44444444-4444-4444-8444-444444444444"
    # Reads show the committed new versions.
    assert store.get(k1.key_id, "t1").current_version == 2
    assert store.get(k2.key_id, "t1").current_version == 2
    print("6. committed batch: new versions kept, single event OK")

    # --- 7. Crash AFTER commit point (event durable, markers not cleared) ---
    event_id = "55555555-5555-4555-8555-555555555555"
    real_write_atomic = store._write_atomic
    state = {"phase": 0}

    def counting_write(path, payload):
        # Fail the first marker-clearing write (phase 3) after commit.
        if state["phase"] == 1:
            state["phase"] = 2
            raise OSError("simulated clear failure")
        return real_write_atomic(path, payload)

    # Hook: after the batch event append, arm the failing write.
    real_append2 = store.audit.append

    def arming_append(event):
        out = real_append2(event)
        if (event.action == audit_mod.ACTION_BATCH_ROTATE
                and event.event_id == event_id):
            state["phase"] = 1
        return out

    store.audit.append = arming_append
    store._write_atomic = counting_write
    try:
        store.batch_rotate(
            "t1", [(k1.key_id, "AES256"), (k2.key_id, "RSA2048")],
            event_id=event_id,
        )
    finally:
        store.audit.append = real_append2
        store._write_atomic = real_write_atomic
    # One file still carries the committed marker.
    marked = [json.loads(read_file(k.key_id)).get("pending_event")
              for k in (k1, k2)]
    assert any(m and m.get("_batch_rotate") for m in marked), marked
    # Reads still show the committed new versions (event durable).
    assert store.get(k1.key_id, "t1").current_version == 3
    assert store.get(k2.key_id, "t1").current_version == 3
    # Restart clears the leftover markers, keeps versions.
    store = KeyStore(DATA)
    assert store.get(k1.key_id, "t1").current_version == 3
    assert store.get(k2.key_id, "t1").current_version == 3
    for k in (k1, k2):
        assert json.loads(read_file(k.key_id)).get("pending_event") is None
    events = [e for e in store.audit._read_all()
              if e.action == audit_mod.ACTION_BATCH_ROTATE]
    assert len(events) == 2, "event duplicated by recovery"
    print("7. post-commit crash: markers cleared, versions kept, no dup OK")

    shutil.rmtree(DATA)


if __name__ == "__main__":
    main()
