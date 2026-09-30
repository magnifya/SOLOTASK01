"""GET /v1/audit ``operation_id`` filter and strict policy-store failures.

Covers the optional lowercase-UUID4 ``operation_id`` audit filter (HTTP and
CLI), its 400 validation order (before policy, no audit except the usual
tenant_conflict), empty result pages, cursor binding to the filter, and the
fail-closed ``500 {"error":"policy store is unavailable"}`` behavior of policy
read/authorize/replace/delete when an existing policy document is unreadable
or unparsable (no allow, no 404, no overwrite, no success/reject audit).
"""

import json
import urllib.error
import urllib.request

import pytest

from keymgr.policy import Rule
from test_recovery_cli import run_cli
from test_version_history import _build_server


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _raw(client, path, op="alice", headers=None):
    req = urllib.request.Request(
        client.base + path, method="GET",
        headers={"X-Operator-Id": op, **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _rotated_operation(stack, index, tenant="t1"):
    status, key = stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": "AES256", "label": "k"},
    )
    assert status == 201
    status, body = stack.client.call(
        "POST",
        "/v1/keys/%s/rotate?tenant_id=%s" % (key["key_id"], tenant),
        {"tenant_id": tenant, "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-%d" % index},
    )
    assert status == 201, body
    return key["key_id"], body["operation_id"]


def test_operation_id_filter_filters_and_combines(stack):
    key_id, op_id = _rotated_operation(stack, 1)
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t1&operation_id=%s" % op_id,
    )
    assert status == 200
    assert [e["event_id"] for e in body["events"]] == [op_id]
    assert body["next_cursor"] is None

    # AND combination with action and key_id.
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t1&operation_id=%s&action=rotate&key_id=%s"
        % (op_id, key_id),
    )
    assert status == 200 and len(body["events"]) == 1

    # A legal but non-matching filter is an empty page, never a 404.
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t1&operation_id=%s&action=create" % op_id,
    )
    assert status == 200
    assert body == {"events": [], "next_cursor": None}
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t1&operation_id="
        "00000000-0000-4000-8000-000000000000",
    )
    assert status == 200
    assert body == {"events": [], "next_cursor": None}

    # Tenant isolation: another tenant cannot see the event this way.
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t2&operation_id=%s" % op_id,
    )
    assert status == 200 and body["events"] == []


def test_operation_id_validation_precedes_policy_and_audit(stack):
    _, op_id = _rotated_operation(stack, 1)
    before = len(stack.audit._read_all())
    cases = [
        "operation_id=",
        "operation_id=not-a-uuid",
        "operation_id=AAAAAAAA-AAAA-4AAA-BAAA-AAAAAAAAAAAA",
        "operation_id=%s&operation_id=%s" % (op_id, op_id),
    ]
    for query in cases:
        status, body = _raw(
            stack.client, "/v1/audit?tenant_id=t1&%s" % query
        )
        assert status == 400, (query, body)
        assert "operation_id" in body["error"]
    # No audit event was written by the parameter failures, and neither was
    # one written by a successful query.
    status, _ = _raw(stack.client, "/v1/audit?tenant_id=t1")
    assert status == 200
    assert len(stack.audit._read_all()) == before


def test_operation_id_cursor_is_bound_to_filter(stack):
    _, op1 = _rotated_operation(stack, 1)
    _, op2 = _rotated_operation(stack, 2)
    status, page1 = _raw(
        stack.client, "/v1/audit?tenant_id=t1&limit=1"
    )
    assert status == 200
    cursor = page1["next_cursor"]
    assert cursor

    # Same cursor with a new operation_id filter: invalid cursor, not a mix.
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t1&limit=1&cursor=%s&operation_id=%s"
        % (cursor, op1),
    )
    assert status == 400
    assert body == {"error": "invalid or expired cursor"}

    # Filtering by either operation id from a clean start stays a single,
    # stable page with no cursor.
    for op_id in (op1, op2):
        status, body = _raw(
            stack.client,
            "/v1/audit?tenant_id=t1&operation_id=%s" % op_id,
        )
        assert status == 200
        assert [e["event_id"] for e in body["events"]] == [op_id]
        assert body["next_cursor"] is None

    # Tampering invalidates the cursor as usual.
    status, body = _raw(
        stack.client,
        "/v1/audit?tenant_id=t1&limit=1&cursor=%s-deadbeef" % cursor,
    )
    assert status == 400


def test_audit_operation_id_cli(stack):
    _, op_id = _rotated_operation(stack, 1)
    proc = run_cli(
        stack, "audit", "--tenant-id", "t1", "--operator", "alice",
        "--operation-id", op_id,
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert [e["event_id"] for e in body["events"]] == [op_id]
    assert body["next_cursor"] is None

    proc = run_cli(
        stack, "audit", "--tenant-id", "t1", "--operator", "alice",
        "--operation-id", "nope",
    )
    assert proc.returncode == 2
    assert json.loads(proc.stderr) == {
        "error": "field operation_id must be a UUID4"
    }


def _corrupt_policy(stack, tenant="t1", raw="{not json"):
    path = stack.policies.path_for(tenant)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw)
    return path


def test_corrupt_policy_fails_closed_everywhere(stack):
    stack.policies.put("t1", [Rule("alice", ["read"], "allow")])
    before = len(stack.audit._read_all())
    path = _corrupt_policy(stack)
    error_body = {"error": "policy store is unavailable"}

    status, body = _raw(
        stack.client, "/v1/policy?tenant_id=t1", op="admin"
    )
    assert (status, body) == (500, error_body)

    # Authorization never falls back to "no policy".
    status, body = stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t1", "algorithm": "AES256", "label": "k"},
    )
    assert (status, body) == (500, error_body)

    # Replace and delete fail without overwriting the original.
    status, body = stack.client.call(
        "PUT", "/v1/policy?tenant_id=t1",
        {"tenant_id": "t1", "rules": []},
        operator="admin",
    )
    assert (status, body) == (500, error_body)
    req = urllib.request.Request(
        stack.client.base + "/v1/policy?tenant_id=t1",
        method="DELETE",
        data=b"{}",
        headers={
            "X-Operator-Id": "admin",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            status, body = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        status, body = exc.code, json.loads(exc.read())
    assert (status, body) == (500, error_body)
    with open(path, encoding="utf-8") as fh:
        assert fh.read() == "{not json"

    # The read-only check endpoint shares the same fixed answer.
    status, body = stack.client.call(
        "POST", "/v1/policy/check?tenant_id=t1",
        {"subject": "alice", "action": "read"}, operator="admin",
    )
    assert (status, body) == (500, error_body)

    # No success or rejected audit event accompanied any of the 500s.
    assert len(stack.audit._read_all()) == before


def test_corrupt_policy_cli_same_body_and_exit(stack):
    stack.policies.put("t1", [Rule("alice", ["read"], "allow")])
    _corrupt_policy(stack)
    error_body = {"error": "policy store is unavailable"}
    for args in (
        ("policy", "--operator", "admin", "show", "--tenant-id", "t1"),
        ("policy", "--operator", "admin", "set", "--tenant-id", "t1",
         "--rules", "[]"),
        ("policy", "--operator", "admin", "delete", "--tenant-id", "t1"),
        ("gen", "--tenant-id", "t1", "--algorithm", "AES256",
         "--label", "k", "--operator", "alice"),
    ):
        proc = run_cli(stack, *args)
        assert proc.returncode == 1, args
        assert json.loads(proc.stderr) == error_body
