"""GET /v1/audit/verify and `keymgr audit verify` regression coverage.

The read-only verification covers the tenant's persisted events by
re-verifying anchor, anchored prefix and the whole MAC chain in ledger
order: bad JSON, wrong key sets/types, seq gaps, duplicate event_id, and
anchor/prefix/MAC mismatches all surface as the fixed 500 body (CLI exit 1).
Parameter/source failures are 400 (CLI exit 2, tenant_conflict audited on
source failures), policy denials are 403 (CLI exit 3, audit/rejected
audited), and success appends no event.
"""

import json
import os
import subprocess
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, validate_rules
from keymgr.server import make_handler
from keymgr.store import KeyStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LEDGER_BODY = {"error": "audit ledger is unavailable"}
POLICY_BODY = {"error": "action not permitted by policy"}
VERIFY_PATH = "/v1/audit/verify"
_UNSET = object()


def _legacy_line(seq, event_id=None, tenant="t1", action="create"):
    return json.dumps({
        "event_id": event_id or ("ev-%d" % seq),
        "tenant_id": tenant,
        "action": action,
        "key_id": None,
        "outcome": "success",
        "timestamp": "2026-09-26T00:00:00+00:00",
        "seq": seq,
    }, separators=(",", ":"))


def _write_log(data_dir, lines):
    with open(os.path.join(data_dir, "audit.log"), "wb") as fh:
        fh.write(("\n".join(lines) + "\n").encode("utf-8"))


def _log_bytes(data_dir):
    with open(os.path.join(data_dir, "audit.log"), "rb") as fh:
        return fh.read()


def _anchor_bytes(data_dir):
    path = os.path.join(data_dir, "audit-anchor.json")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def _seed_chain(data_dir, count, tenant="t1"):
    ledger = AuditLog(data_dir)
    for seq in range(1, count + 1):
        ledger.append(
            ledger.new_event(
                tenant, "create", None, "success",
                event_id="ev-%s-%d" % (tenant, seq),
            )
        )


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
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
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    yield types.SimpleNamespace(
        data_dir=data_dir, base=base, store=store, policies=policies
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _call(stack, path, headers=None, body=_UNSET):
    data = None
    hdrs = {"X-Operator-Id": "alice"}
    if headers:
        hdrs.update(headers)
    if body is not _UNSET:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(
        stack.base + path, data=data, method="GET", headers=hdrs
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _run_cli(data_dir, *args):
    env = dict(os.environ)
    env.pop("KEYMGR_PROVIDER", None)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", data_dir]
        + [str(a) for a in args],
        capture_output=True, text=True, env=env, timeout=60,
    )


def _cli_json(proc):
    for stream in (proc.stdout, proc.stderr):
        text = stream.strip()
        if text.startswith("{"):
            return json.loads(text)
    raise AssertionError("no JSON body: rc=%d out=%r err=%r"
                         % (proc.returncode, proc.stdout, proc.stderr))


def _deny_audit(policies, tenant="t1", subject="alice"):
    rules = validate_rules([
        {"subject": subject, "actions": ["audit"], "effect": "deny"},
    ])
    policies.put(tenant, rules)


def _expect_ledger_unavailable(stack, tenant="t1"):
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=" + tenant)
    assert status == 500
    assert payload == LEDGER_BODY


# -- successful verification ------------------------------------------------


def test_empty_ledger_is_valid_zero_zero(stack):
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert status == 200
    assert payload == {"valid": True, "checked_events": 0, "last_seq": 0}


def test_single_and_multiple_events_counts_and_head(stack):
    _seed_chain(stack.data_dir, 1)
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert (status, payload) == (
        200, {"valid": True, "checked_events": 1, "last_seq": 1}
    )
    _seed_chain(stack.data_dir, 4)
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert (status, payload) == (
        200, {"valid": True, "checked_events": 4, "last_seq": 4}
    )


def test_count_is_tenant_scoped_last_seq_is_ledger_head(stack):
    _seed_chain(stack.data_dir, 2, tenant="t1")
    _seed_chain(stack.data_dir, 3, tenant="t2")
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert (status, payload) == (
        200, {"valid": True, "checked_events": 2, "last_seq": 5}
    )
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t3")
    assert (status, payload) == (
        200, {"valid": True, "checked_events": 0, "last_seq": 5}
    )


def test_success_appends_no_event_and_touches_nothing(stack):
    _seed_chain(stack.data_dir, 2)
    before_log = _log_bytes(stack.data_dir)
    before_anchor = _anchor_bytes(stack.data_dir)
    events_before = AuditLog(stack.data_dir)._read_all()
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert status == 200 and payload["valid"] is True
    assert _log_bytes(stack.data_dir) == before_log
    assert _anchor_bytes(stack.data_dir) == before_anchor
    events_after = AuditLog(stack.data_dir)._read_all()
    assert [e.event_id for e in events_after] == [
        e.event_id for e in events_before
    ]


def test_header_tenant_source_and_empty_object_body(stack):
    _seed_chain(stack.data_dir, 1)
    status, payload = _call(
        stack, VERIFY_PATH, headers={"X-Tenant-Id": "t1"}
    )
    assert (status, payload) == (
        200, {"valid": True, "checked_events": 1, "last_seq": 1}
    )
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1", body={})
    assert status == 200 and payload["valid"] is True


# -- corruption: fixed 500 --------------------------------------------------


def test_non_json_line_is_ledger_unavailable(stack):
    _write_log(stack.data_dir, ["not-json"])
    _expect_ledger_unavailable(stack)


def test_wrong_key_set_is_ledger_unavailable(stack):
    line = _legacy_line(1)[:-1] + ',"extra":1}'
    _write_log(stack.data_dir, [line])
    _expect_ledger_unavailable(stack)


def test_wrong_field_type_is_ledger_unavailable(stack):
    _write_log(stack.data_dir, [
        json.dumps({
            "event_id": "ev-1", "tenant_id": "t1", "action": "create",
            "key_id": None, "outcome": "success",
            "timestamp": "2026-09-26T00:00:00+00:00", "seq": "1",
        }, separators=(",", ":")),
    ])
    _expect_ledger_unavailable(stack)


def test_seq_gap_is_ledger_unavailable(stack):
    _write_log(stack.data_dir, [_legacy_line(1), _legacy_line(3)])
    _expect_ledger_unavailable(stack)


def test_duplicate_event_id_is_ledger_unavailable(stack):
    _write_log(stack.data_dir, [
        _legacy_line(1, event_id="dup"),
        _legacy_line(2, event_id="dup"),
    ])
    _expect_ledger_unavailable(stack)


def test_corrupt_anchor_is_ledger_unavailable(stack):
    _seed_chain(stack.data_dir, 2)
    anchor_path = os.path.join(stack.data_dir, "audit-anchor.json")
    with open(anchor_path, "w", encoding="utf-8") as fh:
        fh.write('{"schema_version":1,"legacy_bytes":0,"legacy_mac":"'
                 + "0" * 64 + '"}')
    _expect_ledger_unavailable(stack)


def _rewrite_last_line(data_dir, mutate):
    raw = _log_bytes(data_dir)
    lines = raw.decode("utf-8").splitlines()
    obj = json.loads(lines[-1])
    mutate(obj)
    lines[-1] = json.dumps(obj, separators=(",", ":"))
    with open(os.path.join(data_dir, "audit.log"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def test_wrong_mac_is_ledger_unavailable(stack):
    _seed_chain(stack.data_dir, 2)
    _rewrite_last_line(
        stack.data_dir, lambda obj: obj.update(action="rotate")
    )
    _expect_ledger_unavailable(stack)


def test_broken_chain_link_is_ledger_unavailable(stack):
    _seed_chain(stack.data_dir, 2)
    _rewrite_last_line(
        stack.data_dir, lambda obj: obj.update(prev_mac="0" * 64)
    )
    _expect_ledger_unavailable(stack)


def test_tampering_another_tenants_line_is_ledger_unavailable(stack):
    _seed_chain(stack.data_dir, 1, tenant="t1")
    _seed_chain(stack.data_dir, 1, tenant="t2")
    raw = _log_bytes(stack.data_dir)
    lines = raw.decode("utf-8").splitlines()
    first = json.loads(lines[0])
    first["action"] = "rotate"
    lines[0] = json.dumps(first, separators=(",", ":"))
    with open(os.path.join(stack.data_dir, "audit.log"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    _expect_ledger_unavailable(stack, tenant="t2")


# -- parameter / tenant-source failures: 400 --------------------------------


def test_missing_tenant_is_400_and_conflict_audited(stack):
    status, _payload = _call(stack, VERIFY_PATH)
    assert status == 400
    events = AuditLog(stack.data_dir)._read_all()
    assert len(events) == 1
    assert events[0].tenant_id is None
    assert events[0].action == "tenant_conflict"


def test_empty_tenant_is_400_and_conflict_audited(stack):
    status, _payload = _call(stack, VERIFY_PATH + "?tenant_id=")
    assert status == 400
    events = AuditLog(stack.data_dir)._read_all()
    assert [e.action for e in events] == ["tenant_conflict"]


def test_duplicate_tenant_query_is_400(stack):
    status, _payload = _call(
        stack, VERIFY_PATH + "?tenant_id=t1&tenant_id=t1"
    )
    assert status == 400


def test_conflicting_tenant_sources_are_400_and_conflict_audited(stack):
    status, _payload = _call(
        stack, VERIFY_PATH + "?tenant_id=t2",
        headers={"X-Tenant-Id": "t1"},
    )
    assert status == 400
    events = AuditLog(stack.data_dir)._read_all()
    assert [e.action for e in events] == ["tenant_conflict"]


def test_extra_query_parameter_is_400(stack):
    status, _payload = _call(stack, VERIFY_PATH + "?tenant_id=t1&limit=1")
    assert status == 400


def test_extra_body_field_is_400(stack):
    status, _payload = _call(
        stack, VERIFY_PATH + "?tenant_id=t1", body={"tenant_id": "t1"}
    )
    assert status == 400


def test_non_object_body_is_400(stack):
    req = urllib.request.Request(
        stack.base + VERIFY_PATH + "?tenant_id=t1",
        data=b"[1, 2]", method="GET",
        headers={"X-Operator-Id": "alice",
                 "Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=20)
    assert excinfo.value.code == 400


def test_missing_operator_is_400(stack):
    req = urllib.request.Request(
        stack.base + VERIFY_PATH + "?tenant_id=t1", method="GET"
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=20)
    assert excinfo.value.code == 400


# -- policy -----------------------------------------------------------------


def test_policy_denial_is_403_and_rejected_audited(stack):
    _seed_chain(stack.data_dir, 1)
    _deny_audit(stack.policies)
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert status == 403
    assert payload == POLICY_BODY
    events = AuditLog(stack.data_dir)._read_all()
    rejected = [e for e in events if e.outcome == "rejected"]
    assert len(rejected) == 1
    assert rejected[0].action == "audit"
    assert rejected[0].key_id is None
    assert rejected[0].tenant_id == "t1"


# -- CLI parity -------------------------------------------------------------


def test_cli_empty_ledger_exit_0(stack):
    proc = _run_cli(
        stack.data_dir, "audit", "verify",
        "--tenant-id", "t1", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip()) == {
        "valid": True, "checked_events": 0, "last_seq": 0
    }


def test_cli_multiple_events_matches_http(stack):
    _seed_chain(stack.data_dir, 3)
    proc = _run_cli(
        stack.data_dir, "audit", "verify",
        "--tenant-id", "t1", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip()) == {
        "valid": True, "checked_events": 3, "last_seq": 3
    }
    status, payload = _call(stack, VERIFY_PATH + "?tenant_id=t1")
    assert status == 200
    assert payload["checked_events"] == 3


def test_cli_tampered_ledger_is_fixed_body_exit_1(stack):
    _seed_chain(stack.data_dir, 2)
    _rewrite_last_line(
        stack.data_dir, lambda obj: obj.update(action="rotate")
    )
    proc = _run_cli(
        stack.data_dir, "audit", "verify",
        "--tenant-id", "t1", "--operator", "alice",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == LEDGER_BODY


def test_cli_empty_tenant_is_exit_2(stack):
    proc = _run_cli(
        stack.data_dir, "audit", "verify",
        "--tenant-id", "", "--operator", "alice",
    )
    assert proc.returncode == 2


def test_cli_policy_denial_is_exit_3_and_rejected_audited(stack):
    _seed_chain(stack.data_dir, 1)
    _deny_audit(stack.policies)
    proc = _run_cli(
        stack.data_dir, "audit", "verify",
        "--tenant-id", "t1", "--operator", "alice",
    )
    assert proc.returncode == 3
    assert _cli_json(proc) == POLICY_BODY
    events = AuditLog(stack.data_dir)._read_all()
    rejected = [e for e in events if e.outcome == "rejected"]
    assert len(rejected) == 1
    assert rejected[0].action == "audit"


def test_flat_audit_query_still_works(stack):
    _seed_chain(stack.data_dir, 1)
    proc = _run_cli(
        stack.data_dir, "audit",
        "--tenant-id", "t1", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout.strip())
    assert set(body) == {"events", "next_cursor"}
    assert len(body["events"]) == 1
