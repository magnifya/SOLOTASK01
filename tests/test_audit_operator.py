"""Operator attribution on audit events (``operator_id``).

Every event an entry point writes is attributed to the validated request
operator -- HTTP ``X-Operator-Id``, CLI ``--operator`` -- preserved verbatim
and case-sensitively, for success, rejected and tenant_conflict events
alike. The field names the request principal only: it is never the revoke
body's ``operator``, a policy rule's ``subject`` or bundle-carried data.
Events written before the field existed (legacy pre-chain lines and
pre-upgrade chained lines) read back as null and are never rewritten; the
new field is covered by the same MAC chain, so a non-string, empty or
tampered ``operator_id`` is ledger corruption (HTTP 500
``{"error":"audit ledger is unavailable"}``, CLI same body, exit 1).
"""

import http.client
import json
import os
import threading

import pytest

from keymgr import audit as audit_mod
from keymgr.audit import AuditLog, LedgerError
from keymgr.operations import OperationStore
from keymgr.policy import Rule
from test_audit_chain import (
    _cli_json,
    _event_mac,
    _legacy_line,
    _legacy_mac,
    _run_cli,
    _secret,
    _write_legacy,
)
from test_version_history import _build_server, _make_key


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _events(stack):
    return stack.audit._read_all()


def _audit(client, query, op="alice"):
    return client.call("GET", "/v1/audit?%s" % query, None, operator=op)


def _raw_request(stack, method, path, body, operator_headers):
    """Send a request with an exact set of X-Operator-Id headers."""
    host, port = stack.client.base.replace("http://", "").split(":")
    conn = http.client.HTTPConnection(host, int(port))
    raw = json.dumps(body).encode() if body is not None else b""
    conn.putrequest(method, path)
    for value in operator_headers:
        conn.putheader("X-Operator-Id", value)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(raw)))
    conn.endheaders(raw)
    resp = conn.getresponse()
    payload = json.loads(resp.read())
    conn.close()
    return resp.status, payload


def _old_format_chained_line(data_dir, event_id, tenant="t1"):
    """Append one pre-upgrade (no operator_id) chained line with a valid MAC."""
    path = os.path.join(data_dir, "audit.log")
    with open(path, "rb") as fh:
        raw = fh.read()
    lines = raw.decode("utf-8").splitlines()
    if len(lines) and json.loads(lines[-1]).get("mac"):
        prev_mac = json.loads(lines[-1])["mac"]
        seq = len(lines) + 1
    else:
        with open(os.path.join(data_dir, "audit-anchor.json")) as fh:
            prev_mac = json.load(fh)["legacy_mac"]
        seq = len(lines) + 1
    obj = {
        "event_id": event_id,
        "tenant_id": tenant,
        "action": "create",
        "key_id": None,
        "outcome": "success",
        "timestamp": "2026-09-27T00:00:00+00:00",
        "seq": seq,
        "prev_mac": prev_mac,
    }
    obj["mac"] = _event_mac(data_dir, obj)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
    return event_id


def _rewrite_last_line(data_dir, recompute_mac=False, **changes):
    path = os.path.join(data_dir, "audit.log")
    with open(path, "rb") as fh:
        lines = fh.read().decode("utf-8").splitlines()
    obj = json.loads(lines[-1])
    obj.update(changes)
    if recompute_mac:
        obj["mac"] = _event_mac(data_dir, obj)
    lines[-1] = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# -- ledger format and compatibility ----------------------------------------


def test_new_events_carry_operator_legacy_events_read_null(tmp_path):
    data_dir = str(tmp_path)
    raw = _write_legacy(data_dir, [_legacy_line(1), _legacy_line(2)])
    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "create", None, "success",
                         event_id="ev-3", operator_id="Alice")
    )
    ledger.append(
        ledger.new_event("t1", "read", None, "success", event_id="ev-4")
    )
    events = AuditLog(data_dir)._read_all()
    assert [e.event_id for e in events] == ["ev-1", "ev-2", "ev-3", "ev-4"]
    # History is never rewritten or back-filled: old events read null.
    assert [e.operator_id for e in events] == [None, None, "Alice", None]
    # The anchored legacy bytes are untouched and the new field is inside
    # the MAC-protected line.
    assert _log_bytes(data_dir).startswith(raw)
    last = json.loads(
        _log_bytes(data_dir).decode("utf-8").splitlines()[-2]
    )
    assert list(last.keys()) == [
        "event_id", "tenant_id", "action", "key_id", "outcome", "timestamp",
        "seq", "operator_id", "prev_mac", "mac",
    ]
    assert last["operator_id"] == "Alice"
    assert last["mac"] == _event_mac(data_dir, last)


def _log_bytes(data_dir):
    with open(os.path.join(data_dir, "audit.log"), "rb") as fh:
        return fh.read()


def test_pre_upgrade_chained_lines_still_verify(tmp_path):
    data_dir = str(tmp_path)
    _write_legacy(data_dir, [_legacy_line(1)])
    ledger = AuditLog(data_dir)
    ledger._read_all()  # anchors the legacy prefix
    _old_format_chained_line(data_dir, "ev-old", tenant="t-老")
    # A post-upgrade append chains onto the old-format line.
    ledger.append(
        ledger.new_event("t1", "create", None, "success",
                         event_id="ev-new", operator_id="Bob")
    )
    events = AuditLog(data_dir)._read_all()
    assert [e.event_id for e in events] == ["ev-1", "ev-old", "ev-new"]
    assert [e.operator_id for e in events] == [None, None, "Bob"]
    lines = _log_bytes(data_dir).decode("utf-8").splitlines()
    old_obj = json.loads(lines[1])
    # The old-format line kept its exact 9-key shape (no operator_id).
    assert list(old_obj.keys()) == [
        "event_id", "tenant_id", "action", "key_id", "outcome", "timestamp",
        "seq", "prev_mac", "mac",
    ]
    new_obj = json.loads(lines[2])
    assert new_obj["prev_mac"] == old_obj["mac"]
    assert new_obj["mac"] == _event_mac(data_dir, new_obj)
    # Read-only verification (no anchor/secret initialization) agrees.
    assert [e.event_id for e in AuditLog(data_dir)._verify_read_only()] == [
        "ev-1", "ev-old", "ev-new",
    ]


@pytest.mark.parametrize("bad", [5, True, 1.5, ["x"], {"x": 1}])
def test_non_string_operator_id_is_corruption(tmp_path, bad):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "create", None, "success",
                         event_id="ev-1", operator_id="alice")
    )
    # Even with a recomputed MAC the field's type is validated.
    _rewrite_last_line(data_dir, recompute_mac=True, operator_id=bad)
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_empty_operator_id_is_corruption(tmp_path):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "create", None, "success",
                         event_id="ev-1", operator_id="alice")
    )
    _rewrite_last_line(data_dir, recompute_mac=True, operator_id="")
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_tampered_operator_id_is_corruption(tmp_path):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "create", None, "success",
                         event_id="ev-1", operator_id="alice")
    )
    # A changed operator without a matching MAC breaks the chain.
    _rewrite_last_line(data_dir, operator_id="mallory")
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()
    # Nulling the field out is tampering too.
    _rewrite_last_line(data_dir, operator_id=None)
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_operator_id_case_is_preserved(tmp_path):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    ledger.append(
        ledger.new_event("t1", "create", None, "success",
                         event_id="ev-1", operator_id="Alice.Smith-Ops")
    )
    event = AuditLog(data_dir)._read_all()[0]
    assert event.operator_id == "Alice.Smith-Ops"
    assert event.to_response()["operator_id"] == "Alice.Smith-Ops"


# -- HTTP attribution --------------------------------------------------------


def test_http_success_and_rejected_events_carry_operator(stack):
    client = stack.client
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
        operator="Alice",
    )
    assert status == 201, body
    # Policy denial records the rejected attempt with the same identity.
    stack.policies.put(
        "t",
        [Rule("bob", ["create"], "allow"),
         Rule("Alice", ["audit"], "allow")],
    )
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k2"},
        operator="Alice",
    )
    assert status == 403
    creates = [
        e for e in _events(stack)
        if e.action == "create" and e.tenant_id == "t"
    ]
    assert [(e.outcome, e.operator_id) for e in creates] == [
        ("success", "Alice"),
        ("rejected", "Alice"),
    ]
    # The query projection exposes the field.
    status, body = _audit(client, "tenant_id=t&action=create", op="Alice")
    assert status == 200
    assert [e["operator_id"] for e in body["events"]] == ["Alice", "Alice"]


def test_http_tenant_conflict_event_carries_operator_but_stays_hidden(stack):
    client = stack.client
    # A missing tenant source is a 400 and an invisible tenant_conflict.
    status, body = client.call(
        "POST", "/v1/keys", {"algorithm": "AES256", "label": "k"},
        operator="ConflictCarol",
    )
    assert status == 400
    conflicts = [
        e for e in _events(stack) if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1
    assert conflicts[0].tenant_id is None
    assert conflicts[0].operator_id == "ConflictCarol"
    # Invisible to every tenant through the query API.
    status, body = _audit(client, "tenant_id=t")
    assert status == 200 and body["events"] == []


def test_http_missing_empty_duplicate_operator_header_is_400_no_audit(stack):
    body = {"tenant_id": "t", "algorithm": "AES256", "label": "k"}
    status, out = _raw_request(stack, "POST", "/v1/keys", body, [])
    assert status == 400 and "X-Operator-Id" in out["error"]
    status, out = _raw_request(stack, "POST", "/v1/keys", body, [""])
    assert status == 400 and "X-Operator-Id" in out["error"]
    status, out = _raw_request(
        stack, "POST", "/v1/keys", body, ["alice", "alice"]
    )
    assert status == 400 and "X-Operator-Id" in out["error"]
    # None of the rejections wrote an audit event.
    assert _events(stack) == []


def test_revoke_event_uses_header_operator_not_body_operator(stack):
    client = stack.client
    key_id = _make_key(client)
    status, body = client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "compromise", "operator": "BodyMallory"},
        operator="HeaderAlice",
    )
    assert status == 200, body
    revokes = [e for e in _events(stack) if e.action == "revoke"]
    assert len(revokes) == 1
    assert revokes[0].operator_id == "HeaderAlice"
    # The body's operator keeps its own meaning on the key record.
    assert stack.store.get(key_id, "t").operator == "BodyMallory"


def test_policy_events_carry_request_operator_not_rule_subject(stack):
    client = stack.client
    status, body = client.call(
        "PUT", "/v1/policy",
        {"tenant_id": "t",
         "rules": [{"subject": "rule-subject", "actions": ["read"],
                    "effect": "allow"}]},
        operator="PolicyPam",
    )
    assert status == 200, body
    status, body = client.call(
        "GET", "/v1/policy?tenant_id=t", None, operator="PolicyPam"
    )
    assert status == 200, body
    status, body = client.call(
        "DELETE", "/v1/policy?tenant_id=t", None, operator="PolicyPam"
    )
    assert status == 200, body
    by_action = {
        e.action: e for e in _events(stack)
        if e.action in ("policy_update", "policy_read", "policy_delete")
    }
    assert [by_action[a].operator_id for a in (
        "policy_update", "policy_read", "policy_delete"
    )] == ["PolicyPam"] * 3


def test_batch_rotate_and_backup_events_carry_operator(stack):
    client = stack.client
    k1 = _make_key(client)
    k2 = _make_key(client)
    status, body = client.call(
        "POST", "/v1/keys/batch-rotate",
        {"tenant_id": "t",
         "items": [{"key_id": k1, "algorithm": "AES256"},
                   {"key_id": k2, "algorithm": "AES256"}]},
        operator="BatchBob",
        headers={"Idempotency-Key": "batch-1"},
    )
    assert status == 201, body
    status, body = client.call(
        "POST", "/v1/backup",
        {"tenant_id": "t", "passphrase": "pw"},
        operator="BackupBea",
    )
    assert status == 200, body
    batch = [e for e in _events(stack) if e.action == "batch_rotate"]
    export = [
        e for e in _events(stack)
        if e.action == "export" and e.outcome == "success"
    ]
    assert [e.operator_id for e in batch] == ["BatchBob"]
    assert [e.operator_id for e in export] == ["BackupBea"]


def test_restore_event_carries_request_operator_not_bundle_data(
    env, tmp_path
):
    # Two servers on separate data dirs sharing the fake KMS backend; the
    # bundle is restored into the second one.
    from types import SimpleNamespace

    from test_restore_preflight import HttpServer

    first = HttpServer(env)
    other_dir = str(tmp_path / "other-data")
    os.makedirs(other_dir, exist_ok=True)
    second = HttpServer(SimpleNamespace(data_dir=other_dir))
    try:
        status, body = first.request(
            "POST", "/v1/keys",
            {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
            {"X-Operator-Id": "alice"},
        )
        assert status == 201, body
        key_id = body["key_id"]
        # The bundle will carry a revocation operator that must NOT leak
        # into the restore's audit attribution.
        status, body = first.request(
            "POST", "/v1/keys/%s/revoke" % key_id,
            {"tenant_id": "t", "reason": "compromise",
             "operator": "BundleOp"},
            {"X-Operator-Id": "alice"},
        )
        assert status == 200, body
        status, body = first.request(
            "POST", "/v1/backup",
            {"tenant_id": "t", "passphrase": "pw"},
            {"X-Operator-Id": "alice"},
        )
        assert status == 200, body
        status, body = second.request(
            "POST", "/v1/restore",
            {"tenant_id": "t", "passphrase": "pw", "bundle": body["bundle"]},
            {"X-Operator-Id": "RestoreRuth", "Idempotency-Key": "restore-1"},
        )
        assert status == 201, body
        imports = [
            e for e in AuditLog(other_dir)._read_all()
            if e.action == "import"
        ]
        assert len(imports) == 1
        assert imports[0].operator_id == "RestoreRuth"
        # The restored key keeps the bundle's own revocation facts.
        from keymgr.store import KeyStore

        restored = KeyStore(other_dir, AuditLog(other_dir)).get(key_id, "t")
        assert restored.operator == "BundleOp"
    finally:
        first.stop()
        second.stop()


def test_http_concurrent_requests_never_mix_operators(stack):
    client = stack.client
    errors = []

    def work(tenant, operator):
        try:
            for i in range(5):
                status, body = client.call(
                    "POST", "/v1/keys",
                    {"tenant_id": tenant, "algorithm": "AES256",
                     "label": "k%d" % i},
                    operator=operator,
                )
                assert status == 201, body
        except AssertionError as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [
        threading.Thread(target=work, args=("ta", "AliceA")),
        threading.Thread(target=work, args=("tb", "BobB")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    for tenant, operator in (("ta", "AliceA"), ("tb", "BobB")):
        events = [
            e for e in _events(stack)
            if e.action == "create" and e.tenant_id == tenant
        ]
        assert len(events) == 5
        assert {e.operator_id for e in events} == {operator}


def test_idempotent_replay_keeps_one_event_and_its_operator(stack):
    client = stack.client
    key_id = _make_key(client)
    headers = {"Idempotency-Key": "rot-op-1"}
    status, first = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t", "algorithm": "AES256"},
        operator="RetryRita", headers=headers,
    )
    assert status == 201, first
    status, replay = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t", "algorithm": "AES256"},
        operator="RetryRita", headers=headers,
    )
    assert status == 201 and replay == first
    rotates = [e for e in _events(stack) if e.action == "rotate"]
    assert len(rotates) == 1
    assert rotates[0].event_id == first["operation_id"]
    assert rotates[0].operator_id == "RetryRita"


def test_idempotent_rejection_event_carries_bound_operator(stack):
    client = stack.client
    key_id = _make_key(client)
    stack.policies.put("t", [Rule("someone-else", ["rotate"], "allow")])
    headers = {"Idempotency-Key": "rot-denied-1"}
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t", "algorithm": "AES256"},
        operator="DeniedDan", headers=headers,
    )
    assert status == 403, body
    # A replay returns the same refusal without a second event.
    status, again = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t", "algorithm": "AES256"},
        operator="DeniedDan", headers=headers,
    )
    assert status == 403 and again == body
    rotates = [e for e in _events(stack) if e.action == "rotate"]
    assert len(rotates) == 1
    assert rotates[0].outcome == "rejected"
    assert rotates[0].event_id == body["operation_id"]
    assert rotates[0].operator_id == "DeniedDan"


def test_http_mixed_ledger_queries_and_verifies(stack):
    # Pre-seed the data dir with a legacy line and an old-format chained
    # line before any HTTP event exists.
    _write_legacy(stack.data_dir, [_legacy_line(1, event_id="ev-legacy")])
    AuditLog(stack.data_dir)._read_all()  # anchor the legacy prefix
    _old_format_chained_line(stack.data_dir, "ev-old-chained")
    key_id = _make_key(stack.client)  # post-upgrade event, operator alice

    status, body = _audit(stack.client, "tenant_id=t1")
    assert status == 200
    by_id = {e["event_id"]: e for e in body["events"]}
    assert by_id["ev-legacy"]["operator_id"] is None
    assert by_id["ev-old-chained"]["operator_id"] is None
    status, body = _audit(stack.client, "tenant_id=t&action=create")
    assert status == 200
    assert body["events"][0]["operator_id"] == "alice"
    assert body["events"][0]["key_id"] == key_id
    # Verification covers the whole mixed chain and counts per tenant.
    status, body = stack.client.call(
        "GET", "/v1/audit/verify?tenant_id=t1", None
    )
    assert status == 200
    assert body == {"valid": True, "checked_events": 2, "last_seq": 3}


def test_http_cursor_paginates_mixed_ledger(stack):
    _write_legacy(stack.data_dir, [_legacy_line(1, event_id="ev-legacy")])
    AuditLog(stack.data_dir)._read_all()
    _old_format_chained_line(stack.data_dir, "ev-old-chained")
    stack.audit.append(
        stack.audit.new_event("t1", "create", None, "success",
                              event_id="ev-new", operator_id="alice")
    )
    status, page1 = _audit(stack.client, "tenant_id=t1&limit=2")
    assert status == 200
    assert [e["event_id"] for e in page1["events"]] == [
        "ev-legacy", "ev-old-chained",
    ]
    assert page1["next_cursor"]
    # The cursor stays valid while filters and the visible snapshot are
    # unchanged, and pages carry the projected operator_id throughout.
    status, page2 = _audit(
        stack.client,
        "tenant_id=t1&limit=2&cursor=%s" % page1["next_cursor"],
    )
    assert status == 200
    assert [e["event_id"] for e in page2["events"]] == ["ev-new"]
    assert page2["events"][0]["operator_id"] == "alice"
    assert page2["next_cursor"] is None


@pytest.mark.parametrize("bad", ["", 7, None])
def test_http_invalid_operator_id_in_ledger_is_500(stack, bad):
    _make_key(stack.client)
    if bad is None:
        # Tampering the field away without a matching MAC is corruption.
        _rewrite_last_line(stack.data_dir, operator_id=None)
    else:
        _rewrite_last_line(stack.data_dir, recompute_mac=True,
                           operator_id=bad)
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}
    status, body = stack.client.call(
        "GET", "/v1/audit/verify?tenant_id=t", None
    )
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}


def test_http_tampered_operator_id_is_500(stack):
    _make_key(stack.client)
    _rewrite_last_line(stack.data_dir, operator_id="mallory")
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}


# -- CLI attribution ---------------------------------------------------------


def test_cli_events_carry_operator(tmp_path):
    data_dir = str(tmp_path)
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k",
                    "--operator", "CliBob")
    assert proc.returncode == 0, proc.stderr
    proc = _run_cli(data_dir, "audit", "--tenant-id", "t1",
                    "--operator", "CliBob")
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    creates = [e for e in body["events"] if e["action"] == "create"]
    assert [e["operator_id"] for e in creates] == ["CliBob"]


def test_cli_missing_or_empty_operator_is_exit_2_no_audit(tmp_path):
    data_dir = str(tmp_path)
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k")
    assert proc.returncode == 2
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k",
                    "--operator", "")
    assert proc.returncode == 2
    proc = _run_cli(data_dir, "audit", "--tenant-id", "t1")
    assert proc.returncode == 2
    # Nothing was ever audited.
    proc = _run_cli(data_dir, "audit", "--tenant-id", "t1",
                    "--operator", "alice")
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["events"] == []


def test_cli_tenant_conflict_event_carries_operator(tmp_path):
    data_dir = str(tmp_path)
    # An unusable identifier pair (empty tenant, malformed key) collapses to
    # an invisible tenant_conflict, still attributed to the CLI operator.
    proc = _run_cli(data_dir, "show", "--tenant-id", "",
                    "--key-id", "not-a-uuid", "--operator", "CliConflict")
    assert proc.returncode == 2
    events = AuditLog(data_dir)._read_all()
    conflicts = [e for e in events if e.action == "tenant_conflict"]
    assert len(conflicts) == 1
    assert conflicts[0].tenant_id is None
    assert conflicts[0].operator_id == "CliConflict"


def test_cli_rejected_and_policy_events_carry_operator(tmp_path):
    data_dir = str(tmp_path)
    proc = _run_cli(data_dir, "policy", "--operator", "CliPol", "set",
                    "--tenant-id", "t1",
                    "--rules", '[{"subject":"noone","actions":["create"],'
                    '"effect":"allow"}]')
    assert proc.returncode == 0, proc.stderr
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k",
                    "--operator", "CliDan")
    assert proc.returncode == 3
    events = AuditLog(data_dir)._read_all()
    creates = [e for e in events if e.action == "create"]
    assert [(e.outcome, e.operator_id) for e in creates] == [
        ("rejected", "CliDan")
    ]
    updates = [e for e in events if e.action == "policy_update"]
    assert [e.operator_id for e in updates] == ["CliPol"]


def test_cli_invalid_operator_id_in_ledger_is_exit_1(tmp_path):
    data_dir = str(tmp_path)
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k",
                    "--operator", "alice")
    assert proc.returncode == 0, proc.stderr
    _rewrite_last_line(data_dir, recompute_mac=True, operator_id="")
    proc = _run_cli(data_dir, "audit", "--tenant-id", "t1",
                    "--operator", "alice")
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
    proc = _run_cli(data_dir, "audit", "verify", "--tenant-id", "t1",
                    "--operator", "alice")
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}


def test_cli_tampered_operator_id_is_exit_1(tmp_path):
    data_dir = str(tmp_path)
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k",
                    "--operator", "alice")
    assert proc.returncode == 0, proc.stderr
    _rewrite_last_line(data_dir, operator_id="mallory")
    proc = _run_cli(data_dir, "audit", "--tenant-id", "t1",
                    "--operator", "alice")
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}


# -- crash recovery ----------------------------------------------------------


def test_pending_outbox_event_recovers_with_original_operator(env):
    store = env.open_store()
    record = store.create("t1", "AES256", "k", operator_id="Creator")
    key_id = record.key_id
    # Simulate a crash after the key file landed carrying its pending
    # marker, before the rotate event reached the ledger.
    store = env.open_store()
    record = store._read_record(store._path_for(key_id))
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_ROTATE, key_id, audit_mod.OUTCOME_SUCCESS,
        operator_id="RecoveryRex",
    )
    record.pending_event = event.to_json()
    store._write_atomic(store._path_for(key_id), record.to_json())

    env.open_store()  # recovery commits the pending event here

    events = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(events) == 1
    assert events[0].operator_id == "RecoveryRex"
    # The create event kept its own operator; a retry does not duplicate.
    env.open_store()
    events = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(events) == 1


def test_legacy_pending_marker_recovers_with_null_operator(env):
    store = env.open_store()
    record = store.create("t1", "AES256", "k")
    key_id = record.key_id
    store = env.open_store()
    record = store._read_record(store._path_for(key_id))
    event = store.audit.new_event(
        "t1", audit_mod.ACTION_ROTATE, key_id, audit_mod.OUTCOME_SUCCESS,
    )
    # A pre-upgrade marker has no operator_id key at all.
    marker = event.to_json()
    del marker["operator_id"]
    record.pending_event = marker
    store._write_atomic(store._path_for(key_id), record.to_json())

    env.open_store()

    events = [e for e in env.audit_events() if e.event_id == event.event_id]
    assert len(events) == 1
    assert events[0].operator_id is None


def test_operation_recovery_matches_staged_operator(tmp_path):
    data_dir = str(tmp_path)
    audit_log = AuditLog(data_dir)
    op_store = OperationStore(data_dir, audit_log)
    begin = op_store.begin("t1", "alice", "/v1/keys", "{}", "idem-1")
    record = begin.record
    body = {"error": "action not permitted by policy",
            "operation_id": record.operation_id}
    op_store.stage_terminal(
        record, 403, body,
        audit={"action": "create", "outcome": "rejected",
               "tenant_id": "t1", "key_id": None,
               "operator_id": "alice"},
    )
    # The durable rejection event names the operation and its operator.
    audit_log.append(
        audit_log.new_event(
            "t1", "create", None, "rejected",
            event_id=record.operation_id, operator_id="alice",
        )
    )
    op_store.recover_pending()
    recovered = op_store.get(record.operation_id, "t1", "alice")
    assert recovered.status == "failed"
    assert recovered.http_status == 403
    assert recovered.response == body


def test_operation_recovery_ignores_foreign_operator_event(tmp_path):
    data_dir = str(tmp_path)
    audit_log = AuditLog(data_dir)
    op_store = OperationStore(data_dir, audit_log)
    begin = op_store.begin("t1", "alice", "/v1/keys", "{}", "idem-2")
    record = begin.record
    op_store.stage_terminal(
        record, 403, {"error": "x", "operation_id": record.operation_id},
        audit={"action": "create", "outcome": "rejected",
               "tenant_id": "t1", "key_id": None,
               "operator_id": "alice"},
    )
    # A durable event with the same id but a DIFFERENT operator is not this
    # operation's commit: the operation stays pending for resolution.
    audit_log.append(
        audit_log.new_event(
            "t1", "create", None, "rejected",
            event_id=record.operation_id, operator_id="mallory",
        )
    )
    op_store.recover_pending()
    recovered = op_store.get(record.operation_id, "t1", "alice")
    assert recovered.status == "pending"
