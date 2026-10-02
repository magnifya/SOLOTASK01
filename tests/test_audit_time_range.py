"""GET /v1/audit time-range filters and range-bound pagination cursors."""

import json
from urllib.parse import quote

from keymgr.policy import Rule
from test_audit_chain import _cli_json, _run_cli
from test_audit_operation_filter import _audit
from test_recovery_cli import run_cli
from test_version_history import _build_server
import pytest


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _event(audit_log, event_id, timestamp, tenant="t", action="create",
           key_id=None):
    return audit_log.append(
        audit_log.new_event(
            tenant, action, key_id, "success",
            timestamp=timestamp, event_id=event_id,
        )
    )


def _ids(body):
    return [event["event_id"] for event in body["events"]]


def test_since_and_until_are_half_open_with_equal_empty_range(stack):
    ids = {
        "start": "10000000-0000-4000-8000-000000000001",
        "middle": "10000000-0000-4000-8000-000000000002",
        "end": "10000000-0000-4000-8000-000000000003",
    }
    _event(stack.audit, ids["start"], "2024-01-01T10:00:00Z")
    _event(stack.audit, ids["middle"], "2024-01-01T11:00:00Z")
    _event(stack.audit, ids["end"], "2024-01-01T12:00:00Z")

    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2024-01-01T10:00:00Z"
        "&until=2024-01-01T12:00:00Z",
    )
    assert status == 200, body
    assert _ids(body) == [ids["start"], ids["middle"]]
    assert body["next_cursor"] is None

    status, body = _audit(
        stack.client, "tenant_id=t&since=2024-01-01T11:00:00Z"
    )
    assert status == 200 and _ids(body) == [ids["middle"], ids["end"]]
    status, body = _audit(
        stack.client, "tenant_id=t&until=2024-01-01T11:00:00Z"
    )
    assert status == 200 and _ids(body) == [ids["start"]]
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2024-01-01T11:00:00Z"
        "&until=2024-01-01T11:00:00Z",
    )
    assert status == 200 and body == {"events": [], "next_cursor": None}


def test_equivalent_offsets_and_fractions_give_same_result(stack):
    event_id = "20000000-0000-4000-8000-000000000001"
    _event(stack.audit, event_id, "2024-01-01T03:04:05.100000Z")
    query = (
        "tenant_id=t&since={since}&until={until}"
    ).format(
        since=quote("2023-12-31T22:04:05.1-05:00"),
        until=quote("2024-01-01T04:04:05.200000+01:00"),
    )
    status, body = _audit(stack.client, query)
    assert status == 200 and _ids(body) == [event_id]

    equivalent = (
        "tenant_id=t&since=2024-01-01T03:04:05.100Z"
        "&until=" + quote("2024-01-01T03:04:05.200Z")
    )
    status, body2 = _audit(stack.client, equivalent)
    assert status == 200 and _ids(body2) == [event_id]


def test_time_filter_and_combines_with_tenant_key_action_operation_id(stack):
    key_id = "30000000-0000-4000-8000-000000000001"
    operation_id = "30000000-0000-4000-8000-000000000002"
    _event(stack.audit, operation_id, "2024-01-01T10:00:00Z",
           action="rotate", key_id=key_id)
    _event(stack.audit, "30000000-0000-4000-8000-000000000003",
           "2024-01-01T10:00:00Z", action="create", key_id=key_id)
    _event(stack.audit, "30000000-0000-4000-8000-000000000004",
           "2024-01-01T10:00:00Z", tenant="other", action="rotate",
           key_id=key_id)
    _event(stack.audit, "30000000-0000-4000-8000-000000000005",
           "2024-01-01T09:59:59Z", action="rotate", key_id=key_id)

    status, body = _audit(
        stack.client,
        "tenant_id=t&key_id=%s&action=rotate&operation_id=%s"
        "&since=2024-01-01T10:00:00Z"
        % (key_id, operation_id),
    )
    assert status == 200 and _ids(body) == [operation_id]


@pytest.mark.parametrize(
    "query,field",
    [
        ("since=", "since"),
        ("until=", "until"),
        ("since=2024-01-01T10:00:00", "since"),
        ("until=2024-01-01t10:00:00Z", "until"),
        ("since=2024-01-01T10:00:00.1234567Z", "since"),
        ("until=2024-01-01T24:00:00Z", "until"),
        ("since=2024-01-01T10:00:60Z", "since"),
        ("since=2024-01-01T10:00:00+24:00", "since"),
        ("until=2024-02-30T10:00:00Z", "until"),
        ("since=2024-01-01T12:00:00Z&until=2024-01-01T10:00:00Z", "until"),
    ],
)
def test_invalid_time_parameters_are_400_naming_field(stack, query, field):
    status, body = _audit(stack.client, "tenant_id=t&" + query)
    assert status == 400, body
    assert field in body["error"]


def test_duplicate_time_parameter_is_400_naming_field(stack):
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2024-01-01T10:00:00Z"
        "&since=2024-01-01T11:00:00Z",
    )
    assert status == 400 and "since" in body["error"]


def test_time_validation_precedes_audit_authorization_without_audit(stack):
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    before = len(stack.audit._read_all())
    status, body = _audit(
        stack.client, "tenant_id=t&since=not-a-time"
    )
    assert status == 400 and "since" in body["error"]
    assert len(stack.audit._read_all()) == before


def test_equivalent_time_writings_continue_the_same_cursor(stack):
    ids = [
        "40000000-0000-4000-8000-000000000001",
        "40000000-0000-4000-8000-000000000002",
        "40000000-0000-4000-8000-000000000003",
    ]
    for idx, event_id in enumerate(ids, start=1):
        _event(stack.audit, event_id,
               "2024-01-01T%02d:00:00Z" % (9 + idx))

    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2024-01-01T10:00:00Z"
        "&until=2024-01-01T13:00:00Z&limit=2",
    )
    assert status == 200 and _ids(body) == ids[:2]
    cursor = body["next_cursor"]
    assert cursor

    status, body = _audit(
        stack.client,
        "tenant_id=t&since=" + quote("2024-01-01T18:00:00+08:00")
        + "&until=" + quote("2024-01-01T21:00:00.000+08:00")
        + "&limit=2&cursor=%s" % cursor,
    )
    assert status == 200 and _ids(body) == ids[2:]
    assert body["next_cursor"] is None


@pytest.mark.parametrize(
    "next_query",
    [
        "tenant_id=t&since=2024-01-01T11:00:00Z"
        "&until=2024-01-01T13:00:00Z&limit=2",
        "tenant_id=t&since=2024-01-01T10:00:00Z"
        "&until=2024-01-01T12:00:00Z&limit=2",
        "tenant_id=t&since=2024-01-01T10:00:00Z&limit=2",
        "tenant_id=t&until=2024-01-01T13:00:00Z&limit=2",
        "tenant_id=t&limit=2",
    ],
)
def test_cursor_is_rejected_when_actual_time_bounds_change(stack, next_query):
    ids = [
        "41000000-0000-4000-8000-000000000001",
        "41000000-0000-4000-8000-000000000002",
        "41000000-0000-4000-8000-000000000003",
    ]
    for idx, event_id in enumerate(ids, start=1):
        _event(stack.audit, event_id,
               "2024-01-01T%02d:00:00Z" % (9 + idx))
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2024-01-01T10:00:00Z"
        "&until=2024-01-01T13:00:00Z&limit=2",
    )
    cursor = body["next_cursor"]
    status, body = _audit(stack.client, next_query + "&cursor=%s" % cursor)
    assert status == 400 and "cursor" in body["error"]


def _paged_range_setup(stack, action=None):
    suffix_action = action or "create"
    ids = [
        "42000000-0000-4000-8000-000000000001",
        "42000000-0000-4000-8000-000000000002",
    ]
    _event(stack.audit, ids[0], "2024-01-01T10:00:00Z",
           action=suffix_action)
    _event(stack.audit, ids[1], "2024-01-01T11:00:00Z",
           action=suffix_action)
    query = (
        "tenant_id=t&since=2024-01-01T10:00:00Z"
        "&until=2024-01-01T13:00:00Z&limit=1"
    )
    if action:
        query += "&action=" + action
    status, body = _audit(stack.client, query)
    assert status == 200 and _ids(body) == ids[:1]
    return body["next_cursor"], ids, query


def test_visible_range_addition_invalidates_old_cursor(stack):
    cursor, _ids, query = _paged_range_setup(stack)
    _event(stack.audit, "42000000-0000-4000-8000-000000000003",
           "2024-01-01T10:30:00Z")
    status, body = _audit(stack.client, query + "&cursor=%s" % cursor)
    assert status == 400 and "cursor" in body["error"]


def test_foreign_tenant_and_range_outside_additions_keep_cursor(stack):
    cursor, ids, query = _paged_range_setup(stack)
    _event(stack.audit, "42000000-0000-4000-8000-000000000004",
           "2024-01-01T10:30:00Z", tenant="other")
    _event(stack.audit, "42000000-0000-4000-8000-000000000005",
           "2024-01-01T09:30:00Z")
    status, body = _audit(stack.client, query + "&cursor=%s" % cursor)
    assert status == 200, body
    assert _ids(body) == ids[1:]
    assert body["next_cursor"] is None


def test_non_matching_filter_addition_keeps_cursor(stack):
    cursor, ids, query = _paged_range_setup(stack, action="rotate")
    _event(stack.audit, "42000000-0000-4000-8000-000000000006",
           "2024-01-01T10:30:00Z", action="create")
    status, body = _audit(stack.client, query + "&cursor=%s" % cursor)
    assert status == 200 and _ids(body) == ids[1:]


def test_unparseable_matching_timestamp_is_fixed_500_and_not_skipped(stack):
    _event(stack.audit, "43000000-0000-4000-8000-000000000001",
           "2024-01-01T10:00:00Z", action="rotate")
    _event(stack.audit, "43000000-0000-4000-8000-000000000002",
           "not-a-timestamp", action="rotate")
    query = "tenant_id=t&since=2024-01-01T09:00:00Z&action=rotate"
    status, body = _audit(stack.client, query)
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )
    status, body = _audit(
        stack.client,
        "tenant_id=other&since=2024-01-01T09:00:00Z&action=rotate",
    )
    assert status == 200 and body == {"events": [], "next_cursor": None}
    status, body = _audit(
        stack.client, "tenant_id=t&since=2024-01-01T09:00:00Z&action=create"
    )
    assert status == 200 and body == {"events": [], "next_cursor": None}


def test_cli_accepts_range_and_prints_validation_error_body(stack):
    event_id = "44000000-0000-4000-8000-000000000001"
    _event(stack.audit, event_id, "2024-01-01T10:00:00Z")
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--since", "2024-01-01T10:00:00Z",
        "--until", "2024-01-01T11:00:00Z",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [event_id]

    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--since", "2024-01-01T12:00:00Z",
        "--until", "2024-01-01T10:00:00Z",
    )
    assert proc.returncode == 2
    assert _cli_json(proc) == {
        "error": "field until must not be earlier than since"
    }

    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice",
        "--since", "2024-01-01T10:00:00Z",
        "--since", "2024-01-01T11:00:00Z",
    )
    assert proc.returncode == 2
    assert _cli_json(proc) == {"error": "duplicate since parameter"}


def test_cli_unparseable_matching_timestamp_is_fixed_500_exit_1(stack):
    _event(stack.audit, "45000000-0000-4000-8000-000000000001",
           "not-a-timestamp")
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice", "--since", "2024-01-01T09:00:00Z",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
