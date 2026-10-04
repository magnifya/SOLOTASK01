"""Audit event operator attribution (``operator_id``).

Every success, rejection and tenant_conflict event produced after the
upgrade records the validated operator identity of the request (HTTP
``X-Operator-Id`` / CLI ``--operator``), verbatim and case-sensitive, and
GET /v1/audit plus the CLI ``audit`` command project it as ``operator_id``.
The field names the requesting principal only: never a revocation body's
``operator``, a policy rule's ``subject`` or an imported bundle's metadata.

Pre-upgrade ledgers (chain-less legacy bytes and old nine-field chained
lines) carry no ``operator_id``: their events read as null, their bytes,
anchor and signatures are never rewritten, and mixed old/new appends keep
verifying under the same rules. An ``operator_id`` that is neither a string
nor null, an empty string, or a tampered value is ledger corruption:
LedgerError underneath, the fixed 500 body over HTTP, the same body and
exit 1 from the CLI.
"""

import http.client
import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from keymgr import audit as audit_mod
from keymgr.audit import AuditLog, LedgerError
from test_audit_chain import _cli_json, _run_cli
from test_version_history import _build_server, _make_key


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


@pytest.fixture()
def other(tmp_path, monkeypatch):
    """A second, independent server (its own data dir) for import/restore."""
    yield from _build_server(tmp_path / "other", monkeypatch)


def _audit_events(stack, tenant="t", operator="alice", **params):
    query = "tenant_id=%s" % tenant
    for name, value in params.items():
        query += "&%s=%s" % (name, value)
    status, body = stack.client.call(
        "GET", "/v1/audit?%s" % query, operator=operator
    )
    assert status == 200, body
    return body["events"]


def _raw_call(stack, method, path, body=None, operator="alice",
              extra_headers=(), drop_operator=False):
    """One HTTP request with precise control over the operator header."""
    conn = http.client.HTTPConnection(
        urllib.request.urlparse(stack.client.base).netloc, timeout=20
    )
    headers = {"Content-Type": "application/json"}
    if not drop_operator:
        headers["X-Operator-Id"] = operator
    for name, value in extra_headers:
        headers[name] = value
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    payload = json.loads(resp.read())
    conn.close()
    return resp.status, payload


def _raw_duplicate_operator(stack, path, body):
    """POST with two X-Operator-Id headers (urllib cannot emit those)."""
    conn = http.client.HTTPConnection(
        urllib.request.urlparse(stack.client.base).netloc, timeout=20
    )
    conn.putrequest("POST", path)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("X-Operator-Id", "alice")
    conn.putheader("X-Operator-Id", "bob")
    data = json.dumps(body).encode()
    conn.putheader("Content-Length", str(len(data)))
    conn.endheaders(data)
    resp = conn.getresponse()
    payload = json.loads(resp.read())
    conn.close()
    return resp.status, payload


def _rewrite_last_line(data_dir, mutate):
    """Replace the last ledger line by ``mutate(parsed)`` (no re-signing)."""
    path = os.path.join(data_dir, "audit.log")
    with open(path, "rb") as fh:
        lines = fh.read().decode("utf-8").splitlines()
    obj = json.loads(lines[-1])
    lines[-1] = json.dumps(
        mutate(obj), separators=(",", ":"), ensure_ascii=False
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# -- attribution on the happy and refusal paths ------------------------------


def test_http_success_and_rejection_events_carry_operator_verbatim(stack):
    client = stack.client
    kid = _make_key(client)  # operator alice (Client default)
    # Case-sensitive, verbatim identity: "Bob" and "bob" are distinct.
    status, _ = client.call("GET", "/v1/keys/%s?tenant_id=t" % kid,
                            operator="Bob")
    assert status == 200
    # A policy denial records the requester's identity on the rejected
    # event -- never the rule's subject.
    kid2 = _make_key(client, tenant="t2")
    status, body = client.call(
        "PUT", "/v1/policy",
        {"tenant_id": "t2",
         "rules": [
             {"subject": "root", "actions": ["read"], "effect": "allow"},
             {"subject": "alice", "actions": ["audit"], "effect": "allow"},
         ]},
        operator="carol",
    )
    assert status == 200, body
    status, body = client.call("GET", "/v1/keys/%s?tenant_id=t2" % kid2,
                               operator="Mallory")
    assert status == 403

    events = _audit_events(stack)
    assert [e["action"] for e in events] == ["create", "read"]
    assert events[0]["operator_id"] == "alice"
    assert events[1]["outcome"] == "success"
    assert events[1]["operator_id"] == "Bob"
    t2_events = _audit_events(stack, tenant="t2")
    rejected = [e for e in t2_events if e["outcome"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["action"] == "read"
    assert rejected[0]["operator_id"] == "Mallory"
    updates = [e for e in t2_events if e["action"] == "policy_update"]
    assert updates[0]["operator_id"] == "carol"
    # Every event carries the field; none is null in a post-upgrade ledger.
    assert all(
        event["operator_id"] is not None
        for event in events + t2_events
    )


def test_tenant_conflict_event_carries_operator_and_stays_invisible(stack):
    # A header/query tenant disagreement is a 400 plus one invisible
    # tenant_conflict event.
    status, body = _raw_call(
        stack, "GET", "/v1/audit?tenant_id=t",
        extra_headers=(("X-Tenant-Id", "other"),),
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    # The conflict event is invisible to every tenant, but the ledger line
    # still names the validated operator of the rejected request.
    assert _audit_events(stack, tenant="t") == []
    assert _audit_events(stack, tenant="other") == []
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1
    assert conflicts[0].tenant_id is None
    assert conflicts[0].operator_id == "alice"


def test_cli_events_and_audit_output_carry_operator(stack):
    proc = _run_cli(
        stack.data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "Dave",
    )
    assert proc.returncode == 0, proc.stderr
    created = json.loads(proc.stdout)
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t", "--operator", "Dave",
    )
    assert proc.returncode == 0, proc.stderr
    events = json.loads(proc.stdout)["events"]
    creates = [e for e in events if e["action"] == "create"]
    assert len(creates) == 1
    assert creates[0]["operator_id"] == "Dave"
    assert creates[0]["key_id"] == created["key_id"]


def test_operator_is_the_request_principal_not_body_or_rule_subject(stack):
    client = stack.client
    kid = _make_key(client)
    # The revocation body operator is recorded on the key; the audit event
    # names the request's validated operator instead.
    status, body = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "retired", "operator": "mallory"},
        operator="alice",
    )
    assert status == 200, body
    assert body["operator"] == "mallory"
    revokes = _audit_events(stack, action="revoke")
    assert len(revokes) == 1
    assert revokes[0]["operator_id"] == "alice"

    # A policy rule's subject never leaks into another requester's event.
    status, _ = client.call(
        "PUT", "/v1/policy",
        {"tenant_id": "t2",
         "rules": [
             {"subject": "root", "actions": ["create"], "effect": "allow"},
             {"subject": "alice", "actions": ["audit"], "effect": "allow"},
         ]},
    )
    assert status == 200
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t2", "algorithm": "AES256", "label": "k"},
        operator="alice",
    )
    assert status == 403
    t2_events = _audit_events(stack, tenant="t2")
    rejected = [e for e in t2_events if e["outcome"] == "rejected"
                and e["action"] == "create"]
    assert len(rejected) == 1
    assert rejected[0]["operator_id"] == "alice"


def test_import_event_names_the_importer_not_the_bundle(stack, other):
    client = stack.client
    kid = _make_key(client)
    status, body = client.call(
        "POST", "/v1/keys/%s/export" % kid,
        {"tenant_id": "t", "passphrase": "pw"}, operator="alice",
    )
    assert status == 200, body
    # The bundle crosses to an independent backend; the import event names
    # the importing request's operator, never bundle metadata.
    status, body = other.client.call(
        "POST", "/v1/keys/import",
        {"tenant_id": "t2", "passphrase": "pw", "bundle": body["bundle"]},
        operator="bob", headers={"Idempotency-Key": "imp-1"},
    )
    assert status == 201, body
    imports = _audit_events(other, tenant="t2", action="import")
    assert len(imports) == 1
    assert imports[0]["operator_id"] == "bob"


def test_management_batch_backup_and_restore_events_carry_operator(
    stack, other
):
    client = stack.client
    kid = _make_key(client)
    # Batch rotation.
    status, body = client.call(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t",
         "items": [{"key_id": kid, "algorithm": "AES256"}]},
        operator="gina", headers={"Idempotency-Key": "br-1"},
    )
    assert status == 201, body
    # Policy management: update, read, (later) delete.
    assert client.call(
        "PUT", "/v1/policy",
        {"tenant_id": "t",
         "rules": [{"subject": "gina", "actions": ["export"],
                    "effect": "allow"}]},
        operator="gina",
    )[0] == 200
    assert client.call(
        "GET", "/v1/policy?tenant_id=t", operator="gina"
    )[0] == 200
    # Backup and restore (the bundle crosses to an independent backend).
    status, body = client.call(
        "POST", "/v1/backup", {"tenant_id": "t", "passphrase": "pw"},
        operator="gina",
    )
    assert status == 200, body
    status, body = other.client.call(
        "POST", "/v1/restore",
        {"tenant_id": "t", "passphrase": "pw", "bundle": body["bundle"]},
        operator="henry", headers={"Idempotency-Key": "rst-1"},
    )
    assert status == 201, body
    assert client.call(
        "DELETE", "/v1/policy?tenant_id=t", operator="gina"
    )[0] == 200

    events = _audit_events(stack)
    by_action = {}
    for event in events:
        by_action.setdefault(event["action"], []).append(event)
    assert by_action["batch_rotate"][0]["operator_id"] == "gina"
    assert by_action["policy_update"][0]["operator_id"] == "gina"
    assert by_action["policy_read"][0]["operator_id"] == "gina"
    assert by_action["policy_delete"][0]["operator_id"] == "gina"
    assert by_action["export"][0]["operator_id"] == "gina"
    # The restore also imported the restrictive policy, so the restored
    # import event is read from the ledger directly.
    restored = [
        e for e in other.audit._read_all() if e.action == "import"
    ]
    assert len(restored) == 1
    assert restored[0].tenant_id == "t"
    assert restored[0].operator_id == "henry"


def test_policy_revision_conflict_event_carries_operator(stack):
    client = stack.client
    rules = [{"subject": "alice", "actions": ["read", "audit"],
              "effect": "allow"}]
    status, _ = client.call(
        "PUT", "/v1/policy", {"tenant_id": "t", "rules": rules},
    )
    assert status == 200
    status, body = client.call(
        "PUT", "/v1/policy?expected_revision=" + "0" * 64,
        {"tenant_id": "t", "rules": rules},
        operator="carol",
    )
    assert status == 409, body
    rejected = [
        e for e in _audit_events(stack, action="policy_update")
        if e["outcome"] == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0]["operator_id"] == "carol"


# -- legacy ledgers and mixed chains -----------------------------------------


def _legacy_line(seq, event_id, tenant="t1"):
    return json.dumps({
        "event_id": event_id,
        "tenant_id": tenant,
        "action": "create",
        "key_id": None,
        "outcome": "success",
        "timestamp": "2026-09-26T00:00:00+00:00",
        "seq": seq,
    }, separators=(",", ":"))


def test_chain_less_legacy_ledger_upgrades_in_place(tmp_path):
    data_dir = str(tmp_path)
    raw_legacy = (
        _legacy_line(1, "50000000-0000-4000-8000-000000000001") + "\n"
        + _legacy_line(2, "50000000-0000-4000-8000-000000000002") + "\n"
    ).encode("utf-8")
    with open(os.path.join(data_dir, "audit.log"), "wb") as fh:
        fh.write(raw_legacy)

    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "read", None, "success", operator_id="alice")
    )

    # The legacy prefix is byte-for-byte untouched and anchored as-was.
    with open(os.path.join(data_dir, "audit.log"), "rb") as fh:
        raw_now = fh.read()
    assert raw_now[: len(raw_legacy)] == raw_legacy
    events = ledger._read_all()
    assert [e.operator_id for e in events] == [None, None, "alice"]
    # Old events project null; the new one projects its operator.
    page = ledger.query("t1")
    assert [e.operator_id for e in page.events] == [None, None, "alice"]
    assert [e.to_response()["operator_id"] for e in page.events] == [
        None, None, "alice",
    ]
    # Verification still passes and counts the whole ledger.
    result = ledger.verify("t1")
    assert result == {"valid": True, "checked_events": 3, "last_seq": 3}


def test_old_chained_lines_keep_null_operator_and_bytes(tmp_path):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    # Pre-upgrade style chained lines: minted without an operator.
    first = ledger.append(ledger.new_event("t1", "create", None, "success"))
    second = ledger.append(ledger.new_event("t1", "read", None, "success"))
    with open(os.path.join(data_dir, "audit.log"), "rb") as fh:
        raw_before = fh.read()
    old_lines = raw_before.decode("utf-8").splitlines()
    assert all("operator_id" not in line for line in old_lines)

    # Post-upgrade appends carry the operator; old bytes are never rewritten.
    ledger.append(
        ledger.new_event("t1", "rotate", None, "success", operator_id="Bob")
    )
    with open(os.path.join(data_dir, "audit.log"), "rb") as fh:
        lines_now = fh.read().decode("utf-8").splitlines()
    assert lines_now[:2] == old_lines
    assert '"operator_id":"Bob"' in lines_now[2]

    events = ledger._read_all()
    assert [e.event_id for e in events][:2] == [
        first.event_id, second.event_id,
    ]
    assert [e.operator_id for e in events] == [None, None, "Bob"]
    page = ledger.query("t1")
    assert [e.operator_id for e in page.events] == [None, None, "Bob"]
    assert ledger.verify("t1")["valid"] is True


def test_mixed_ledger_pagination_and_verify_counts(tmp_path):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    ledger.append(ledger.new_event("t1", "create", None, "success"))
    ledger.append(
        ledger.new_event("t1", "read", None, "success", operator_id="alice")
    )
    ledger.append(
        ledger.new_event("t1", "read", None, "rejected", operator_id="bob")
    )
    page1 = ledger.query("t1", limit=2)
    assert [e.operator_id for e in page1.events] == [None, "alice"]
    assert page1.next_cursor is not None
    page2 = ledger.query("t1", limit=2, cursor=page1.next_cursor)
    assert [e.operator_id for e in page2.events] == ["bob"]
    assert page2.next_cursor is None
    # The verify entry counts old (null-operator) and new events alike.
    assert ledger.verify("t1") == {
        "valid": True, "checked_events": 3, "last_seq": 3,
    }


# -- corruption: bad or tampered operator_id ---------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda obj: obj.update(operator_id=""),
            id="empty-string",
        ),
        pytest.param(
            lambda obj: obj.update(operator_id=5),
            id="non-string",
        ),
        pytest.param(
            lambda obj: obj.update(operator_id="mallory"),
            id="tampered-value",
        ),
    ],
)
def test_bad_or_tampered_operator_id_is_corruption(tmp_path, mutate):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "create", None, "success", operator_id="alice")
    )
    _rewrite_last_line(data_dir, mutate)
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_tampered_operator_id_http_500_and_cli_exit_1(stack):
    _make_key(stack.client)  # one create event, operator alice
    _rewrite_last_line(
        stack.data_dir, lambda obj: obj.update(operator_id="mallory")
    )
    status, body = stack.client.call("GET", "/v1/audit?tenant_id=t")
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}
    status, body = stack.client.call("GET", "/v1/audit/verify?tenant_id=t")
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t", "--operator", "alice"
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
    proc = _run_cli(
        stack.data_dir, "audit", "verify",
        "--tenant-id", "t", "--operator", "alice",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}


# -- concurrency, idempotency and restart recovery ---------------------------


def test_concurrent_requests_never_cross_attribute_operators(stack):
    client = stack.client
    kid = _make_key(client)
    operators = ["op-%d" % i for i in range(8)]
    errors = []

    def read_five(operator):
        try:
            for _ in range(5):
                status, body = client.call(
                    "GET", "/v1/keys/%s?tenant_id=t" % kid,
                    operator=operator,
                )
                assert status == 200, body
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append(exc)

    threads = [
        threading.Thread(target=read_five, args=(operator,))
        for operator in operators
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    reads = [
        e for e in stack.audit._read_all()
        if e.action == "read" and e.outcome == "success"
    ]
    assert len(reads) == 40
    for operator in operators:
        assert sum(1 for e in reads if e.operator_id == operator) == 5


def test_idempotent_replay_keeps_one_event_and_its_operator(stack):
    client = stack.client
    kid = _make_key(client)
    body = {"tenant_id": "t", "algorithm": "AES256"}
    status, first = client.call(
        "POST", "/v1/keys/%s/rotate" % kid, body,
        operator="alice", headers={"Idempotency-Key": "rot-op-1"},
    )
    assert status == 201
    # An identical retry replays without a second event.
    status, second = client.call(
        "POST", "/v1/keys/%s/rotate" % kid, body,
        operator="alice", headers={"Idempotency-Key": "rot-op-1"},
    )
    assert status == 201
    assert second["operation_id"] == first["operation_id"]
    rotates = _audit_events(stack, action="rotate")
    assert len(rotates) == 1
    assert rotates[0]["event_id"] == first["operation_id"]
    assert rotates[0]["operator_id"] == "alice"


def test_restart_recovery_preserves_pending_event_operator(env):
    """A pending outbox event recovered after a restart keeps its operator."""
    store = env.open_store()
    record = store.create("t1", "AES256", "k", operator_id="alice")
    key_id = record.key_id
    # Craft the crash scene: new version file + pending marker carrying the
    # operator, but the event never reached the ledger.
    store = env.open_store()
    record = store._read_record(store._path_for(key_id))
    provider = store._provider()
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_ROTATE, key_id, audit_mod.OUTCOME_SUCCESS,
        operator_id="carol",
    )
    journal_id, journal_path = store._new_provision_journal(event.event_id)
    triple = provider.rotate(record.current.algorithm)
    store._append_provision(journal_path, provider.provider_id, triple.handle)
    from keymgr.store import VersionRecord

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

    env.open_store()  # recovery commits the pending event here
    events = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(events) == 1
    assert events[0].operator_id == "carol"
    # A second restart does not duplicate the event or change its identity.
    env.open_store()
    events = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(events) == 1
    assert events[0].operator_id == "carol"


# -- operator validation is unchanged and unaudited --------------------------


def test_missing_empty_and_duplicate_operator_header_write_no_audit(stack):
    before = len(stack.audit._read_all())
    status, body = _raw_call(
        stack, "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
        drop_operator=True,
    )
    assert status == 400
    assert body["error"] == "missing required header: X-Operator-Id"
    status, body = _raw_call(
        stack, "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
        operator="",
    )
    assert status == 400
    assert body["error"] == "header X-Operator-Id must be a non-empty string"
    status, body = _raw_duplicate_operator(
        stack, "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
    )
    assert status == 400
    assert "duplicate X-Operator-Id" in body["error"]
    assert len(stack.audit._read_all()) == before


def test_cli_missing_or_empty_operator_exits_2_without_audit(stack):
    before = len(stack.audit._read_all())
    proc = _run_cli(
        stack.data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k",
    )
    assert proc.returncode == 2
    proc = _run_cli(
        stack.data_dir, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "",
    )
    assert proc.returncode == 2
    assert len(stack.audit._read_all()) == before
