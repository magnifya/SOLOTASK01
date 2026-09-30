"""GET /v1/audit and the ``audit`` CLI filtered by ``operation_id``.

The optional lowercase-UUID4 ``operation_id`` locates the single event an
idempotent operation committed under that id (its event_id equals the
operation_id). It AND-combines with key_id/action/limit/cursor, yields an
empty page (never 404) when nothing matches, and is bound into the HMAC
cursor. Empty/duplicated/malformed values are 400 naming the field,
validated before policy and recorded nowhere (a missing/conflicting tenant
source still records tenant_conflict). A corrupt ledger is the fixed 500
body; the CLI prints the same body and exits 1.
"""

import json
import uuid

import pytest

from keymgr.policy import Rule
from test_audit_chain import _corrupt_log, _cli_json, _run_cli
from test_version_history import _build_server, _make_key
from test_recovery_cli import run_cli


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _audit(client, query, op="alice"):
    return client.call("GET", "/v1/audit?%s" % query, None, operator=op)


def _rotate(client, key_id, key="rot-1", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": "AES256"},
        headers={"Idempotency-Key": key},
    )
    assert status == 201, body
    return body["operation_id"]


def test_operation_id_filters_to_the_idempotent_event(stack):
    client = stack.client
    kid = _make_key(client)
    op_id = _rotate(client, kid)
    status, body = _audit(client, "tenant_id=t&operation_id=%s" % op_id)
    assert status == 200
    assert body["next_cursor"] is None
    assert [e["event_id"] for e in body["events"]] == [op_id]
    assert body["events"][0]["action"] == "rotate"
    assert body["events"][0]["key_id"] == kid
    actions = [e.action for e in stack.audit._read_all()]
    assert actions.count("audit") == 0


def test_operation_id_and_combines_with_action_and_key_id(stack):
    client = stack.client
    kid = _make_key(client)
    op_id = _rotate(client, kid)
    status, body = _audit(
        client,
        "tenant_id=t&operation_id=%s&action=rotate&key_id=%s"
        % (op_id, kid),
    )
    assert status == 200 and len(body["events"]) == 1
    status, body = _audit(
        client, "tenant_id=t&operation_id=%s&action=create" % op_id
    )
    assert status == 200
    assert body == {"events": [], "next_cursor": None}
    status, body = _audit(
        client, "tenant_id=t&operation_id=%s" % uuid.uuid4()
    )
    assert status == 200
    assert body == {"events": [], "next_cursor": None}


def test_invalid_operation_id_is_400_before_policy_without_audit(stack):
    client = stack.client
    _make_key(client)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    before = len(stack.audit._read_all())
    cases = [
        "tenant_id=t&operation_id=",
        "tenant_id=t&operation_id=NOT-A-UUID",
        "tenant_id=t&operation_id=" + str(uuid.uuid4()).upper(),
        "tenant_id=t&operation_id=%s&operation_id=%s"
        % (uuid.uuid4(), uuid.uuid4()),
    ]
    for query in cases:
        status, body = _audit(client, query)
        assert status == 400, (query, body)
        assert "operation_id" in body["error"], body
    assert len(stack.audit._read_all()) == before


def test_missing_tenant_still_records_tenant_conflict(stack):
    client = stack.client
    status, body = _audit(
        client, "operation_id=%s" % uuid.uuid4()
    )
    assert status == 400 and "tenant_id" in body["error"]
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1
    assert conflicts[0].tenant_id is None


def test_idempotent_endpoint_tenant_conflict_pre_bind_is_audited(stack):
    # Body tenant_id disagreeing with the X-Tenant-Id header on an
    # idempotent endpoint: 400 naming tenant_id plus the invisible
    # tenant_conflict event, even though no operation is bound.
    client = stack.client
    kid = _make_key(client)
    before = len(stack.audit._read_all())
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % kid,
        {"tenant_id": "t", "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-x", "X-Tenant-Id": "other"},
    )
    assert status == 400 and "tenant_id" in body["error"]
    new = stack.audit._read_all()[before:]
    assert [e.action for e in new] == ["tenant_conflict"]
    assert new[0].tenant_id is None

    # A missing body tenant_id on restore behaves the same.
    status, body = client.call(
        "POST", "/v1/restore",
        {"passphrase": "p", "bundle": "b"},
        headers={"Idempotency-Key": "res-x"},
    )
    assert status == 400 and "tenant_id" in body["error"]
    tail = stack.audit._read_all()[before + 1:]
    assert [e.action for e in tail] == ["tenant_conflict"]


def test_policy_denial_is_403_and_records_audit_rejected(stack):
    client = stack.client
    kid = _make_key(client)
    op_id = _rotate(client, kid)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    status, body = _audit(
        client, "tenant_id=t&operation_id=%s" % op_id
    )
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id is None


def test_cursor_is_bound_to_operation_id_filter(stack):
    client = stack.client
    kid = _make_key(client)
    op_id = _rotate(client, kid, key="rot-a")
    _rotate(client, kid, key="rot-b")
    status, body = _audit(client, "tenant_id=t&limit=1")
    assert status == 200 and body["next_cursor"]
    cursor = body["next_cursor"]
    status, body = _audit(
        client,
        "tenant_id=t&limit=1&operation_id=%s&cursor=%s" % (op_id, cursor),
    )
    assert status == 400
    assert "cursor" in body["error"]


def test_operation_id_tenant_isolation(stack):
    client = stack.client
    kid = _make_key(client, tenant="t")
    op_id = _rotate(client, kid)
    status, body = _audit(
        client, "tenant_id=other&operation_id=%s" % op_id
    )
    assert status == 200 and body["events"] == []


def test_cli_operation_id_filter_and_errors(stack):
    env = stack
    kid = _make_key(stack.client)
    op_id = _rotate(stack.client, kid)
    proc = run_cli(
        env, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operation-id", op_id,
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert [e["event_id"] for e in body["events"]] == [op_id]
    proc = run_cli(
        env, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operation-id", "nope",
    )
    assert proc.returncode == 2
    assert "operation_id" in json.loads(proc.stderr)["error"]
    proc = run_cli(
        env, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operation-id", str(uuid.uuid4()),
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"events": [], "next_cursor": None}


def test_corrupt_ledger_with_operation_id_is_fixed_500(stack):
    client = stack.client
    kid = _make_key(client)
    op_id = _rotate(client, kid)
    _corrupt_log(stack.data_dir)
    status, body = _audit(
        client, "tenant_id=t&operation_id=%s" % op_id
    )
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice", "--operation-id", op_id,
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
