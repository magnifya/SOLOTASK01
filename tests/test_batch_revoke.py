"""Atomic same-tenant batch whole-key revocation: POST /v1/keys/batch-revoke.

Covers the strict four-field body contract (exactly
``{tenant_id, key_ids, reason, operator}``; key_ids 1-100 unique lowercase
UUID4s; every pre-binding 400 is side-effect free and never consumes the
Idempotency-Key, only a bad tenant source records tenant_conflict), the
required Idempotency-Key (validated before the body), per-key ``revoke``
authorization (one denial rejects the whole batch as 403 and outranks a
missing key), the indistinct whole-batch 404 for unknown/cross-tenant keys,
the atomic 200 (request-order items with the full key-status fields, one
shared UTC revoked_at, first revocation wins, versions untouched), exactly
one ``batch_revoke`` event per operation (key_id null, event_id equal to
the operation_id, subject from the request header), idempotent replay and
409 binding conflicts, revocation without any provider access, and crash
recovery of the outbox commit (uncommitted groups roll back to active,
committed groups keep the revocation).
"""

import itertools
import json
import os
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import audit as audit_mod
from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.server import make_handler
from keymgr.store import KeyStore


def _build_server(tmp_path, monkeypatch, external=False):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    if external:
        sys.path.insert(0, os.path.dirname(__file__))
        monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
        monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
        monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
        import fake_kms

        fake_kms.reset()
    else:
        monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    handler = make_handler(
        store, policies, coordinator, op_store, artifact_store
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    stack = types.SimpleNamespace(
        data_dir=data_dir, store=store, policies=policies,
        audit=audit_log, client=client, faults_path=faults_path,
        op_store=op_store,
    )
    yield stack
    httpd.shutdown()
    provider_mod.reset_for_tests()


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None,
             raw=None):
        if raw is None:
            data = json.dumps(body).encode() if body is not None else None
        else:
            data = raw
        h = {"X-Operator-Id": operator}
        if data is not None:
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        req = urllib.request.Request(
            self.base + path, data=data, method=method, headers=h
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


@pytest.fixture()
def ext_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, external=True)


# -- helpers ---------------------------------------------------------------
def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


_idem_counter = itertools.count(1)


def _idem(prefix="op"):
    return "%s-%d" % (prefix, next(_idem_counter))


def _batch_revoke(client, key_ids, tenant="t", reason="retired",
                  operator="bob", idem=None, **extra):
    body = {
        "tenant_id": tenant, "key_ids": key_ids,
        "reason": reason, "operator": operator,
    }
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/batch-revoke", body,
        headers={"Idempotency-Key": idem or _idem("brev")},
    )


def _status(client, key_id, tenant="t"):
    return client.call("GET", "/v1/keys/%s/status?tenant_id=%s"
                       % (key_id, tenant))


def _audit_events(st, tenant="t"):
    return st.audit.query(tenant, limit=1000).events


def _events(st, action, tenant="t"):
    return [e for e in _audit_events(st, tenant) if e.action == action]


# -- happy path / response shape -------------------------------------------
def test_batch_revoke_happy_path(stack):
    client = stack.client
    kids = [_make_key(client) for _ in range(3)]
    status, body = _batch_revoke(client, kids, reason="compromised",
                                 operator="carol")
    assert status == 200, body
    assert set(body.keys()) == {"items", "operation_id"}
    assert [item["key_id"] for item in body["items"]] == kids
    assert isinstance(body["operation_id"], str) and body["operation_id"]
    revoked_ats = set()
    for item, kid in zip(body["items"], kids):
        assert list(item.keys()) == [
            "key_id", "status", "reason", "operator", "revoked_at",
        ]
        assert item["status"] == "revoked"
        assert item["reason"] == "compromised"
        assert item["operator"] == "carol"
        assert isinstance(item["revoked_at"], str) and item["revoked_at"]
        revoked_ats.add(item["revoked_at"])
        # The whole-key status read agrees with the batch item.
        assert _status(client, kid)[1] == item
    # Every key newly revoked by the batch shares one UTC timestamp.
    assert len(revoked_ats) == 1
    # Exactly one batch_revoke success event: key_id null, event_id equal to
    # the operation_id, subject from the request header.
    events = _events(stack, "batch_revoke")
    assert len(events) == 1
    event = events[0]
    assert event.outcome == "success"
    assert event.key_id is None
    assert event.event_id == body["operation_id"]
    assert event.operator_id == "alice"
    # And no per-key revoke events were written.
    assert _events(stack, "revoke") == []


def test_already_revoked_keys_keep_first_values(stack):
    client = stack.client
    first = _make_key(client)
    second = _make_key(client)
    # Revoke one key on its own first (different reason/operator/time).
    status, single = client.call(
        "POST", "/v1/keys/%s/revoke" % first,
        {"tenant_id": "t", "reason": "first", "operator": "dave"},
    )
    assert status == 200, single
    status, body = _batch_revoke(client, [first, second], reason="second",
                                 operator="carol")
    assert status == 200, body
    by_id = {item["key_id"]: item for item in body["items"]}
    # The already-revoked key keeps its first revocation's facts.
    assert by_id[first]["reason"] == "first"
    assert by_id[first]["operator"] == "dave"
    assert by_id[first]["revoked_at"] == single["revoked_at"]
    # The freshly revoked key carries the batch facts.
    assert by_id[second]["reason"] == "second"
    assert by_id[second]["operator"] == "carol"
    # An all-already-revoked batch still succeeds.
    status, again = _batch_revoke(client, [first, second], reason="third",
                                  operator="erin")
    assert status == 200, again
    assert {item["reason"] for item in again["items"]} == {"first", "second"}


def test_versions_and_current_pointer_untouched(stack):
    client = stack.client
    kid = _make_key(client)
    status, rotated = client.call(
        "POST", "/v1/keys/%s/rotate" % kid,
        {"tenant_id": "t", "algorithm": "AES256"},
        headers={"Idempotency-Key": _idem("rot")},
    )
    assert status == 201, rotated
    before = client.call(
        "GET", "/v1/keys/%s/versions?tenant_id=t" % kid
    )[1]
    status, _ = _batch_revoke(client, [kid])
    assert status == 200
    after = client.call("GET", "/v1/keys/%s/versions?tenant_id=t" % kid)[1]
    # Same versions, same current pointer; the history projects the
    # whole-key revocation on every item.
    assert [v["version"] for v in after["items"]] == [
        v["version"] for v in before["items"]
    ]
    assert [v["current"] for v in after["items"]] == [
        v["current"] for v in before["items"]
    ]
    assert all(v["status"] == "revoked" for v in after["items"])
    # The whole-key revocation restricts crypto on every version.
    status, enc = client.call(
        "POST", "/v1/keys/%s/encrypt" % kid,
        {"tenant_id": "t", "plaintext": "aGVsbG8="},
        headers={"Idempotency-Key": _idem("enc")},
    )
    assert status == 409 and enc["error"] == "key is revoked"


# -- pre-binding validation (side-effect-free 400s) -------------------------
def _assert_clean_400(stack, status, body, field):
    assert status == 400, body
    assert field in body["error"]
    # No batch_revoke audit event and no operation record was written.
    assert _events(stack, "batch_revoke") == []
    assert not _operation_records(stack)


def _operation_records(stack):
    return [
        name for name in os.listdir(stack.op_store.dir_path)
        if name.endswith(".json") and name != "index.json"
    ]


def test_bad_json_and_non_object_are_clean_400s(stack):
    client = stack.client
    status, body = client.call(
        "POST", "/v1/keys/batch-revoke", None, raw=b"{not json",
        headers={"Idempotency-Key": _idem("brev")},
    )
    _assert_clean_400(stack, status, body, "JSON")
    status, body = client.call(
        "POST", "/v1/keys/batch-revoke", None, raw=b"[1,2]",
        headers={"Idempotency-Key": _idem("brev")},
    )
    _assert_clean_400(stack, status, body, "object")


def test_missing_extra_and_mistyped_fields_are_clean_400s(stack):
    client = stack.client
    kid = _make_key(client)
    base = {
        "tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o",
    }
    cases = []
    for missing in ("key_ids", "reason", "operator"):
        body = {k: v for k, v in base.items() if k != missing}
        cases.append((body, missing))
    cases.append((dict(base, extra="x"), "extra"))
    cases.append((dict(base, key_ids="x"), "key_ids"))
    cases.append((dict(base, key_ids=[]), "key_ids"))
    cases.append((dict(base, key_ids=[kid] * 2), "duplicate"))
    cases.append((dict(base, key_ids=[kid.upper()]), "key_ids"))
    cases.append((dict(base, key_ids=[kid.replace("-", "")]), "key_ids"))
    cases.append((dict(base, key_ids=[123]), "key_ids"))
    cases.append((dict(base, key_ids=[None]), "key_ids"))
    cases.append((dict(base, reason=""), "reason"))
    cases.append((dict(base, reason=1), "reason"))
    cases.append((dict(base, operator=""), "operator"))
    cases.append((dict(base, operator=None), "operator"))
    for body, field in cases:
        status, resp = client.call(
            "POST", "/v1/keys/batch-revoke", body,
            headers={"Idempotency-Key": _idem("brev")},
        )
        _assert_clean_400(stack, status, resp, field)
    # Nothing was revoked.
    assert _status(client, kid)[1]["status"] == "active"


def test_key_ids_bounds_are_clean_400s(stack):
    client = stack.client
    too_many = [
        "00000000-0000-4000-8000-%012d" % i for i in range(101)
    ]
    status, body = _batch_revoke(client, too_many)
    _assert_clean_400(stack, status, body, "key_ids")


def test_failed_validation_does_not_consume_idempotency_key(stack):
    client = stack.client
    kid = _make_key(client)
    key = _idem("brev")
    status, body = client.call(
        "POST", "/v1/keys/batch-revoke",
        {"tenant_id": "t", "key_ids": [kid], "reason": "", "operator": "o"},
        headers={"Idempotency-Key": key},
    )
    assert status == 400, body
    # The same key binds the corrected request as a brand-new operation.
    status, resp = client.call(
        "POST", "/v1/keys/batch-revoke",
        {"tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o"},
        headers={"Idempotency-Key": key},
    )
    assert status == 200, resp
    assert _status(client, kid)[1]["status"] == "revoked"


def test_idempotency_header_validated_before_body(stack):
    client = stack.client
    for headers in ({}, {"Idempotency-Key": ""}, {"Idempotency-Key": "a b"}):
        status, body = client.call(
            "POST", "/v1/keys/batch-revoke", None, raw=b"{not json",
            headers=headers,
        )
        assert status == 400, body
        assert "Idempotency-Key" in body["error"]
    assert _events(stack, "batch_revoke") == []


def test_tenant_source_conflict_records_tenant_conflict(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = client.call(
        "POST", "/v1/keys/batch-revoke",
        {"tenant_id": "t", "key_ids": [kid], "reason": "r", "operator": "o"},
        headers={"Idempotency-Key": _idem("brev"), "X-Tenant-Id": "other"},
    )
    assert status == 400, body
    assert "tenant_id" in body["error"]
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1
    # The key was not revoked and no batch event exists.
    assert _status(client, kid)[1]["status"] == "active"
    assert _events(stack, "batch_revoke") == []


# -- authorization / existence ----------------------------------------------
def _put_policy(client, rules, tenant="t"):
    return client.call("PUT", "/v1/policy?tenant_id=%s" % tenant,
                       {"tenant_id": tenant, "rules": rules})


def test_policy_deny_rejects_whole_batch(stack):
    client = stack.client
    allowed = _make_key(client)
    denied = _make_key(client)
    status, _ = _put_policy(client, [
        {"subject": "alice", "actions": ["read"], "effect": "allow"},
        {"subject": "alice", "actions": ["revoke"], "effect": "allow",
         "key_ids": [allowed]},
    ])
    assert status == 200
    status, body = _batch_revoke(client, [allowed, denied])
    assert status == 403, body
    assert body["error"] == "action not permitted by policy"
    assert set(body.keys()) == {"error", "operation_id"}
    # No key changed, exactly one rejected batch_revoke event (key_id null).
    assert _status(client, allowed)[1]["status"] == "active"
    assert _status(client, denied)[1]["status"] == "active"
    events = _events(stack, "batch_revoke")
    assert len(events) == 1
    assert events[0].outcome == "rejected"
    assert events[0].key_id is None
    assert events[0].event_id == body["operation_id"]
    assert events[0].operator_id == "alice"


def test_deny_outranks_missing_key(stack):
    client = stack.client
    denied = _make_key(client)
    ghost = "00000000-0000-4000-8000-000000000099"
    status, _ = _put_policy(client, [
        {"subject": "alice", "actions": ["read"], "effect": "allow"},
        {"subject": "alice", "actions": ["revoke"], "effect": "deny",
         "key_ids": [denied]},
        {"subject": "alice", "actions": ["revoke"], "effect": "allow"},
    ])
    assert status == 200
    status, body = _batch_revoke(client, [ghost, denied])
    assert status == 403, body
    assert _status(client, denied)[1]["status"] == "active"


def test_unknown_or_cross_tenant_key_is_whole_batch_404(stack):
    client = stack.client
    mine = _make_key(client)
    foreign = _make_key(client, tenant="other")
    ghost = "00000000-0000-4000-8000-000000000099"
    for key_ids in ([mine, ghost], [mine, foreign]):
        status, body = _batch_revoke(client, key_ids)
        assert status == 404, body
        assert body["error"] == "key not found"
        assert set(body.keys()) == {"error", "operation_id"}
    # Nothing changed; one rejected event per operation, key_id null.
    assert _status(client, mine)[1]["status"] == "active"
    assert _status(client, foreign, tenant="other")[1]["status"] == "active"
    events = _events(stack, "batch_revoke")
    assert len(events) == 2
    assert all(e.outcome == "rejected" and e.key_id is None for e in events)


# -- idempotent replay / conflicts ------------------------------------------
def test_same_binding_replays_without_new_event(stack):
    client = stack.client
    kids = [_make_key(client) for _ in range(2)]
    key = _idem("brev")
    body = {
        "tenant_id": "t", "key_ids": kids, "reason": "r", "operator": "o",
    }
    status, first = client.call(
        "POST", "/v1/keys/batch-revoke", body,
        headers={"Idempotency-Key": key},
    )
    assert status == 200, first
    # JSON whitespace and field order do not affect the binding.
    raw = json.dumps(
        {
            "operator": "o", "reason": "r",
            "key_ids": kids, "tenant_id": "t",
        }, indent=2,
    ).encode()
    status, replay = client.call(
        "POST", "/v1/keys/batch-revoke", None, raw=raw,
        headers={"Idempotency-Key": key},
    )
    assert status == 200, replay
    assert replay == first
    assert len(_events(stack, "batch_revoke")) == 1


def test_array_order_is_part_of_the_binding(stack):
    client = stack.client
    kids = [_make_key(client) for _ in range(2)]
    key = _idem("brev")
    status, first = _batch_revoke(client, kids, idem=key)
    assert status == 200, first
    # The same set in a different order is a different binding: 409 naming
    # the original operation.
    status, conflict = _batch_revoke(
        client, list(reversed(kids)), idem=key
    )
    assert status == 409, conflict
    assert conflict["operation_id"] == first["operation_id"]
    assert len(_events(stack, "batch_revoke")) == 1


def test_different_binding_conflicts(stack):
    client = stack.client
    kid = _make_key(client)
    key = _idem("brev")
    status, first = _batch_revoke(client, [kid], idem=key, reason="one")
    assert status == 200, first
    status, conflict = client.call(
        "POST", "/v1/keys/batch-revoke",
        {"tenant_id": "t", "key_ids": [kid], "reason": "two",
         "operator": "o"},
        headers={"Idempotency-Key": key},
    )
    assert status == 409, conflict
    assert conflict["operation_id"] == first["operation_id"]


def test_concurrent_same_key_executes_once(stack):
    client = stack.client
    kids = [_make_key(client) for _ in range(2)]
    key = _idem("brev")
    body = {
        "tenant_id": "t", "key_ids": kids, "reason": "r", "operator": "o",
    }
    results = []

    def fire():
        results.append(client.call(
            "POST", "/v1/keys/batch-revoke", body,
            headers={"Idempotency-Key": key},
        ))

    threads = [threading.Thread(target=fire) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # Every request answered 200 with the same operation/result; exactly one
    # batch_revoke event exists.
    assert all(status == 200 for status, _ in results)
    bodies = [body for _, body in results]
    assert {b["operation_id"] for b in bodies} == {bodies[0]["operation_id"]}
    assert all(b["items"] == bodies[0]["items"] for b in bodies)
    assert len(_events(stack, "batch_revoke")) == 1


def test_operation_is_queryable(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = _batch_revoke(client, [kid])
    assert status == 200, body
    status, op = client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % body["operation_id"]
    )
    assert status == 200, op
    assert op["status"] == "succeeded"
    assert op["http_status"] == 200
    assert op["response"]["items"] == body["items"]


# -- audit query / verify ----------------------------------------------------
def test_audit_query_and_verify_support_the_action(stack):
    client = stack.client
    kid = _make_key(client)
    status, body = _batch_revoke(client, [kid])
    assert status == 200, body
    status, page = client.call(
        "GET", "/v1/audit?tenant_id=t&action=batch_revoke"
    )
    assert status == 200, page
    assert len(page["events"]) == 1
    item = page["events"][0]
    assert item["action"] == "batch_revoke"
    assert item["outcome"] == "success"
    assert item["key_id"] is None
    assert item["event_id"] == body["operation_id"]
    assert item["operator_id"] == "alice"
    # The operation_id filter locates the same single event.
    status, page = client.call(
        "GET", "/v1/audit?tenant_id=t&operation_id=%s"
        % body["operation_id"]
    )
    assert status == 200 and len(page["events"]) == 1
    status, verdict = client.call("GET", "/v1/audit/verify?tenant_id=t")
    assert status == 200 and verdict["valid"] is True


# -- provider independence ---------------------------------------------------
def test_revoke_works_while_external_kms_is_down(ext_stack):
    client = ext_stack.client
    kids = [_make_key(client) for _ in range(2)]
    # Break every provider operation; revocation must not notice.
    with open(ext_stack.faults_path, "w", encoding="utf-8") as fh:
        json.dump({"fail": ["generate", "rotate", "delete", "export",
                            "import", "health"]}, fh)
    status, body = _batch_revoke(client, kids)
    assert status == 200, body
    assert all(item["status"] == "revoked" for item in body["items"])


# -- crash recovery (store level) --------------------------------------------
def _craft_revoke_scene(env, keys, tenant="t1", commit=False):
    """Build the durable crash scene of an interrupted batch revocation."""
    store = env.open_store()
    event = store.audit.new_event(
        tenant, audit_mod.ACTION_BATCH_REVOKE, None,
        audit_mod.OUTCOME_SUCCESS,
    )
    marker = {
        "_batch_revoke": True,
        "event": event.to_json(),
        "tenant_id": tenant,
        "key_ids": sorted(keys),
    }
    for key_id in keys:
        record = store._read_record(store._path_for(key_id))
        record.status = "revoked"
        record.reason = "r"
        record.operator = "o"
        record.revoked_at = event.timestamp
        record.pending_event = marker
        store._write_atomic(store._path_for(key_id), record.to_json())
    if commit:
        store.audit.append(event)
    return event


def test_ledger_failure_before_commit_rolls_back_whole_batch(env):
    store = env.open_store()
    keys = [store.create("t1", "AES256", "k").key_id for _ in range(2)]
    from keymgr.audit import LedgerError

    original_append = store.audit.append

    def failing_append(event):
        if event.action == audit_mod.ACTION_BATCH_REVOKE:
            raise LedgerError("simulated ledger failure")
        return original_append(event)

    store.audit.append = failing_append
    with pytest.raises(LedgerError):
        store.batch_revoke("t1", keys, "r", "o", event_id=None)
    # Every file was restored: still active, no marker, no event.
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "active"
        assert record.pending_event is None
    assert not any(
        e.action == "batch_revoke" for e in env.audit_events()
    )


def test_uncommitted_batch_revocation_rolls_back_on_open(env):
    store = env.open_store()
    keys = [store.create("t1", "AES256", "k").key_id for _ in range(2)]
    event = _craft_revoke_scene(env, keys)

    store = env.open_store()  # recovery

    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "active"
        assert record.reason is None and record.operator is None
        assert record.revoked_at is None
        assert record.pending_event is None
    assert not any(e.event_id == event.event_id for e in env.audit_events())


def test_committed_batch_revocation_is_finalized_on_open(env):
    store = env.open_store()
    keys = [store.create("t1", "AES256", "k").key_id for _ in range(2)]
    event = _craft_revoke_scene(env, keys, commit=True)

    store = env.open_store()  # recovery

    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "revoked"
        assert record.reason == "r" and record.operator == "o"
        assert record.revoked_at == event.timestamp
        assert record.pending_event is None
    committed = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(committed) == 1
    assert committed[0].action == "batch_revoke"


# -- backend failures --------------------------------------------------------
def test_policy_store_unavailable_is_500_without_audit(stack):
    client = stack.client
    kid = _make_key(client)
    status, _ = _put_policy(client, [
        {"subject": "alice", "actions": ["revoke"], "effect": "allow"},
    ])
    assert status == 200
    # Corrupt the policy document: enforcement must fail closed with the
    # fixed 500 and record no audit event.
    import hashlib

    digest = hashlib.sha256("t".encode("utf-8")).hexdigest()
    with open(
        os.path.join(stack.data_dir, "policies", digest + ".json"), "w"
    ) as fh:
        fh.write("{corrupt")
    status, body = _batch_revoke(client, [kid])
    assert status == 500, body
    assert body["error"] == "policy store is unavailable"
    assert _events(stack, "batch_revoke") == []
    assert _status_allowing_policy_failure(stack, kid) == "active"


def _status_allowing_policy_failure(stack, key_id):
    # Read the committed record directly (the HTTP read is policy-governed).
    record = stack.store._read_record(stack.store._path_for(key_id))
    return stack.store._committed_record(record).status


def test_corrupt_ledger_is_500_and_hides_uncommitted_revocation(stack):
    client = stack.client
    kids = [_make_key(client) for _ in range(2)]
    # Corrupt the ledger: the commit-point append can neither land nor be
    # verified, so the batch answers 500 and the scene is retained for
    # recovery while reads keep exposing only the committed (active) state.
    with open(stack.audit.path, "a", encoding="utf-8") as fh:
        fh.write("{garbage\n")
    status, body = _batch_revoke(client, kids)
    assert status == 500, body
    assert "operation_id" in body
    for kid in kids:
        assert _status_allowing_policy_failure(stack, kid) == "active"


def test_reads_hide_an_uncommitted_batch_revocation(env):
    store = env.open_store()
    keys = [store.create("t1", "AES256", "k").key_id for _ in range(2)]
    _craft_revoke_scene(env, keys)

    # Without recovery the committed view hides the uncommitted revocation.
    store = env.open_store()
    for key_id in keys:
        # Force the projection path: plant the marker again after recovery
        # rolled it back.
        record = store._read_record(store._path_for(key_id))
        event = store.audit.new_event(
            "t1", audit_mod.ACTION_BATCH_REVOKE, None,
            audit_mod.OUTCOME_SUCCESS,
        )
        record.status = "revoked"
        record.reason = "r"
        record.operator = "o"
        record.revoked_at = event.timestamp
        record.pending_event = {
            "_batch_revoke": True,
            "event": event.to_json(),
            "tenant_id": "t1",
            "key_ids": sorted(keys),
        }
        store._write_atomic(store._path_for(key_id), record.to_json())
        projected = store.get(key_id, "t1")
        assert projected.status == "active"
        assert projected.revoked_at is None


# -- crash recovery at the operation level -----------------------------------
def _reopen_all(data_dir):
    """Reopen every store like a fresh process (recovery runs in order)."""
    from keymgr.server import _resolve_committed_operation

    audit = AuditLog(data_dir)
    store = KeyStore(data_dir, audit)
    policies = PolicyStore(data_dir, audit)
    op_store = OperationStore(data_dir, audit)
    artifact_store = ArtifactStore(data_dir, store, audit)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(
        lambda record, event: _resolve_committed_operation(
            store, policies, record, event
        ),
        is_parked=artifact_store.is_parked,
    )
    return store, op_store


def _bind_operation(op_store, key_ids, tenant="t1", idem="key-1"):
    from keymgr import operations as operations_mod

    body = {
        "tenant_id": tenant, "key_ids": list(key_ids),
        "reason": "r", "operator": "o",
    }
    begin = op_store.begin(
        tenant, "alice", "/v1/keys/batch-revoke",
        operations_mod.normalize_body(body), idem,
    )
    assert begin.kind == "new"
    op_store.update_details(
        begin.record, {"kind": "batch_revoke", "key_ids": list(key_ids)}
    )
    return begin.record


def test_post_commit_crash_recovers_original_result(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    from keymgr.artifacts import PHASE_STAGED

    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir)
    audit = AuditLog(data_dir)
    store = KeyStore(data_dir, audit)
    PolicyStore(data_dir, audit)
    op_store = OperationStore(data_dir, audit)
    artifact_store = ArtifactStore(data_dir, store, audit)
    keys = [store.create("t1", "AES256", "k").key_id for _ in range(2)]
    operation = _bind_operation(op_store, keys)
    mirror = artifact_store.create(operation)
    mirror.describe({"kind": "batch_revoke", "write_set": list(keys)})

    # The request staged its exact 200 and committed the event, then died
    # before clearing the markers/finishing the operation.
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_BATCH_REVOKE, None,
        audit_mod.OUTCOME_SUCCESS, event_id=operation.operation_id,
        operator_id="alice",
    )
    marker = {
        "_batch_revoke": True,
        "event": event.to_json(),
        "tenant_id": "t1",
        "key_ids": sorted(keys),
    }
    staged_items = []
    for key_id in keys:
        record = store._read_record(store._path_for(key_id))
        record.status = "revoked"
        record.reason = "r"
        record.operator = "o"
        record.revoked_at = event.timestamp
        record.pending_event = marker
        store._write_atomic(store._path_for(key_id), record.to_json())
        staged_items.append(record.to_status_response())
    staged = {"items": staged_items, "operation_id": operation.operation_id}
    op_store.stage_terminal(operation, 200, staged)
    mirror.phase(PHASE_STAGED)
    store.audit.append(event)

    store, op_store = _reopen_all(data_dir)

    finished = op_store.get(operation.operation_id, "t1", "alice")
    assert finished.status == "succeeded"
    assert finished.http_status == 200
    assert finished.response == staged
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "revoked"
        assert record.pending_event is None


def test_pre_commit_crash_rolls_back_and_replays_500(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    from keymgr.artifacts import PHASE_STAGED

    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir)
    audit = AuditLog(data_dir)
    store = KeyStore(data_dir, audit)
    PolicyStore(data_dir, audit)
    op_store = OperationStore(data_dir, audit)
    artifact_store = ArtifactStore(data_dir, store, audit)
    keys = [store.create("t1", "AES256", "k").key_id for _ in range(2)]
    operation = _bind_operation(op_store, keys)
    mirror = artifact_store.create(operation)
    mirror.describe({"kind": "batch_revoke", "write_set": list(keys)})

    # The request marked the files but died before the commit-point append.
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_BATCH_REVOKE, None,
        audit_mod.OUTCOME_SUCCESS, event_id=operation.operation_id,
        operator_id="alice",
    )
    marker = {
        "_batch_revoke": True,
        "event": event.to_json(),
        "tenant_id": "t1",
        "key_ids": sorted(keys),
    }
    for key_id in keys:
        record = store._read_record(store._path_for(key_id))
        record.status = "revoked"
        record.reason = "r"
        record.operator = "o"
        record.revoked_at = event.timestamp
        record.pending_event = marker
        store._write_atomic(store._path_for(key_id), record.to_json())
    mirror.phase(PHASE_STAGED)

    store, op_store = _reopen_all(data_dir)

    # The whole batch was restored and the operation replays a 500.
    for key_id in keys:
        record = store.get(key_id, "t1")
        assert record.status == "active"
        assert record.pending_event is None
    finished = op_store.get(operation.operation_id, "t1", "alice")
    assert finished.status == "failed"
    assert finished.http_status == 500
    assert finished.response["operation_id"] == operation.operation_id
    assert not any(
        e.event_id == operation.operation_id
        for e in AuditLog(data_dir)._read_all()
    )
