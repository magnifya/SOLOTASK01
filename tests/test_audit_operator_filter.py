"""GET /v1/audit and the ``audit`` CLI filtered by ``operator_id``.

The optional single-valued ``operator_id`` restricts events to the exact
recorded request identity: a case-sensitive string match that preserves
leading/trailing whitespace and Unicode verbatim (HTTP compares the
URL-decoded value). It AND-combines with key_id/action/operation_id/outcome/
time range; omitting it keeps the full result set, and events carrying a null
(pre-attribution) identity appear only when the filter is omitted -- history
is never back-filled. The filter never replaces the caller identity
(``X-Operator-Id`` / ``--operator``), which still drives authorization. An
empty or duplicated (even twice-identical) value is a 400 naming operator_id
whose body contains only ``error``, validated before policy and recorded
nowhere. A legal value with no match is 200 with ``{"events":[],
"next_cursor":null}`` (CLI exit 0). Policy denial is 403 (CLI exit 3) with
one audit/rejected event attributed to the caller, key_id null; a successful
query writes nothing. The operator condition -- its omission as well as its
value -- is bound into the HMAC cursor: adding, removing or changing it, a
tampered or cross-tenant cursor, or a changed matching snapshot is a 400
naming cursor; pre-upgrade cursors without the binding stay usable only
without operator_id. Only same-tenant events satisfying every filter invalidate
a snapshot; other operators' and other tenants' appends never do. Corruption
is the fixed 500 body (CLI exit 1).
"""

import json
from urllib.parse import quote

import pytest

from keymgr.policy import Rule
from test_audit_chain import _cli_json, _corrupt_log, _run_cli
from test_audit_operation_filter import _audit
from test_recovery_cli import run_cli
from test_version_history import _build_server


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _event(audit_log, event_id, timestamp, tenant="t", action="create",
           key_id=None, outcome="success", operator_id="alice"):
    return audit_log.append(
        audit_log.new_event(
            tenant, action, key_id, outcome,
            timestamp=timestamp, event_id=event_id, operator_id=operator_id,
        )
    )


def _ids(body):
    return [event["event_id"] for event in body["events"]]


# A fixed mixed-operator set for tenant t plus a foreign-tenant event.
E1 = "50000000-0000-4000-8000-000000000001"  # t alice      10:00
E2 = "50000000-0000-4000-8000-000000000002"  # t bob        10:30
E3 = "50000000-0000-4000-8000-000000000003"  # t alice      11:00
E4 = "50000000-0000-4000-8000-000000000004"  # t Carol      11:30
E5 = "50000000-0000-4000-8000-000000000005"  # other alice  10:15
E6 = "50000000-0000-4000-8000-000000000006"  # t null       10:45 (legacy)
E7 = "50000000-0000-4000-8000-000000000007"  # t bob rotate 10:00 rejected


def _seed(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", operator_id="bob")
    _event(stack.audit, E3, "2024-01-01T11:00:00Z")
    _event(stack.audit, E4, "2024-01-01T11:30:00Z", operator_id="Carol")
    _event(stack.audit, E5, "2024-01-01T10:15:00Z", tenant="other")
    _event(stack.audit, E6, "2024-01-01T10:45:00Z", operator_id=None)
    _event(stack.audit, E7, "2024-01-01T10:00:00Z", action="rotate",
           outcome="rejected", operator_id="bob")


def test_operator_id_filters_exact_and_omission_keeps_full_set(stack):
    _seed(stack)
    status, body = _audit(stack.client, "tenant_id=t&operator_id=alice")
    assert status == 200 and _ids(body) == [E1, E3]
    status, body = _audit(stack.client, "tenant_id=t&operator_id=bob")
    assert status == 200 and _ids(body) == [E7, E2]
    # Omission keeps the full set, including the null-identity legacy event.
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 200 and _ids(body) == [E1, E7, E2, E6, E3, E4]
    # The foreign tenant's event is never visible through the filter.
    status, body = _audit(
        stack.client, "tenant_id=other&operator_id=alice"
    )
    assert status == 200 and _ids(body) == [E5]


def test_operator_id_match_is_case_sensitive_and_verbatim(stack):
    _seed(stack)
    # Case differs: no match, but a legal value -> empty page, not an error.
    status, body = _audit(stack.client, "tenant_id=t&operator_id=Alice")
    assert status == 200 and body == {"events": [], "next_cursor": None}
    status, body = _audit(stack.client, "tenant_id=t&operator_id=carol")
    assert status == 200 and body == {"events": [], "next_cursor": None}
    status, body = _audit(stack.client, "tenant_id=t&operator_id=Carol")
    assert status == 200 and _ids(body) == [E4]
    # Whitespace-padded and Unicode values are compared verbatim.
    _event(stack.audit, "50000000-0000-4000-8000-000000000008",
           "2024-01-01T12:00:00Z", operator_id=" alice ")
    _event(stack.audit, "50000000-0000-4000-8000-000000000009",
           "2024-01-01T12:30:00Z", operator_id="张三")
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=" + quote(" alice ")
    )
    assert status == 200
    assert _ids(body) == ["50000000-0000-4000-8000-000000000008"]
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=" + quote("张三")
    )
    assert status == 200
    assert _ids(body) == ["50000000-0000-4000-8000-000000000009"]


def test_null_identity_events_appear_only_when_filter_omitted(stack):
    _seed(stack)
    for query in (
        "tenant_id=t&operator_id=alice",
        "tenant_id=t&operator_id=bob",
        "tenant_id=t&operator_id=nobody",
    ):
        status, body = _audit(stack.client, query)
        assert status == 200
        assert all(e["operator_id"] is not None for e in body["events"])
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 200
    null_events = [e for e in body["events"] if e["operator_id"] is None]
    assert [e["event_id"] for e in null_events] == [E6]


def test_operator_id_and_combines_with_other_filters(stack):
    _seed(stack)
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=bob&action=rotate&outcome=rejected",
    )
    assert status == 200 and _ids(body) == [E7]
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=bob&action=create",
    )
    assert status == 200 and _ids(body) == [E2]
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&since=2024-01-01T11:00:00Z",
    )
    assert status == 200 and _ids(body) == [E3]
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&action=rotate",
    )
    assert status == 200 and body == {"events": [], "next_cursor": None}


@pytest.mark.parametrize(
    "query",
    [
        "operator_id=",
        "operator_id=alice&operator_id=alice",
        "operator_id=alice&operator_id=bob",
    ],
)
def test_invalid_operator_id_is_400_naming_field_with_error_only(
    stack, query
):
    status, body = _audit(stack.client, "tenant_id=t&" + query)
    assert status == 400, body
    assert set(body) == {"error"}
    assert "operator_id" in body["error"]


def test_operator_id_validation_precedes_policy_without_audit(stack):
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    before = len(stack.audit._read_all())
    for query in ("operator_id=", "operator_id=a&operator_id=a"):
        status, body = _audit(stack.client, "tenant_id=t&" + query)
        assert status == 400 and "operator_id" in body["error"]
    assert len(stack.audit._read_all()) == before


def test_policy_denial_is_403_and_records_one_audit_rejected(stack):
    _seed(stack)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    status, body = _audit(stack.client, "tenant_id=t&operator_id=bob")
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id is None
    # The rejection is attributed to the caller, never to the filter value.
    assert rejected[0].operator_id == "alice"


def test_successful_operator_id_query_writes_no_audit(stack):
    _seed(stack)
    status, _ = _audit(stack.client, "tenant_id=t&operator_id=alice")
    assert status == 200
    assert [e.action for e in stack.audit._read_all()].count("audit") == 0


def test_operator_id_pagination_is_complete_without_repeats(stack):
    _seed(stack)
    _event(stack.audit, "50000000-0000-4000-8000-000000000008",
           "2024-01-01T12:00:00Z")
    seen = []
    cursor = None
    for _ in range(10):
        query = "tenant_id=t&operator_id=alice&limit=1"
        if cursor is not None:
            query += "&cursor=%s" % cursor
        status, body = _audit(stack.client, query)
        assert status == 200, body
        seen.extend(_ids(body))
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == [E1, E3, "50000000-0000-4000-8000-000000000008"]


def test_cursor_is_rejected_when_operator_id_is_added_removed_or_changed(
    stack,
):
    _seed(stack)
    # Cursor issued without operator_id.
    status, body = _audit(stack.client, "tenant_id=t&limit=2")
    assert status == 200 and body["next_cursor"]
    plain_cursor = body["next_cursor"]
    status, body = _audit(
        stack.client,
        "tenant_id=t&limit=2&operator_id=alice&cursor=%s" % plain_cursor,
    )
    assert status == 400 and "cursor" in body["error"]

    # Cursor issued with operator_id=alice.
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=alice&limit=1"
    )
    alice_cursor = body["next_cursor"]
    for query in (
        "tenant_id=t&limit=1&cursor=%s",
        "tenant_id=t&operator_id=bob&limit=1&cursor=%s",
    ):
        status, body = _audit(stack.client, query % alice_cursor)
        assert status == 400 and "cursor" in body["error"]

    # The same operator continues the cursor normally.
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&limit=1&cursor=%s" % alice_cursor,
    )
    assert status == 200 and _ids(body) == [E3]
    assert body["next_cursor"] is None


def test_tampered_operator_id_cursor_is_400_naming_cursor(stack):
    _seed(stack)
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=alice&limit=1"
    )
    cursor = body["next_cursor"]
    last = cursor[-1]
    flipped_last = "0" if last != "0" else "1"
    tampered = cursor[:-1] + flipped_last
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&limit=1&cursor=%s" % tampered,
    )
    assert status == 400 and "cursor" in body["error"]


def test_operator_id_cursor_is_not_usable_across_tenants(stack):
    _seed(stack)
    _event(stack.audit, "50000000-0000-4000-8000-00000000000a",
           "2024-01-01T10:20:00Z", tenant="other")
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=alice&limit=1"
    )
    cursor = body["next_cursor"]
    status, body = _audit(
        stack.client,
        "tenant_id=other&operator_id=alice&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def _strip_operator_binding(audit_log, cursor):
    """Re-encode a cursor without its operator binding (pre-upgrade shape)."""
    payload = audit_log._decode_cursor(cursor)
    payload.pop("op", None)
    return audit_log._encode_cursor(payload)


def test_pre_upgrade_cursor_works_without_operator_id_but_not_with(stack):
    _seed(stack)
    status, body = _audit(stack.client, "tenant_id=t&limit=2")
    legacy_cursor = _strip_operator_binding(stack.audit, body["next_cursor"])

    # Other filters and snapshot unchanged, operator_id omitted: still usable.
    status, body = _audit(
        stack.client, "tenant_id=t&limit=2&cursor=%s" % legacy_cursor
    )
    assert status == 200 and _ids(body) == [E2, E6]

    # It cannot drive an operator-filtered query.
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&limit=2&cursor=%s" % legacy_cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_non_matching_and_foreign_additions_keep_cursor_valid(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E3, "2024-01-01T11:00:00Z")
    _event(stack.audit, E4, "2024-01-01T11:30:00Z")
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=alice&limit=1"
    )
    assert status == 200 and _ids(body) == [E1]
    cursor = body["next_cursor"]

    # A same-tenant event of another operator and a foreign alice event do
    # not change the visible snapshot: paging continues without gap or repeat.
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", operator_id="bob")
    _event(stack.audit, E5, "2024-01-01T10:15:00Z", tenant="other")
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&limit=1&cursor=%s" % cursor,
    )
    assert status == 200, body
    assert _ids(body) == [E3]
    cursor = body["next_cursor"]
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&limit=1&cursor=%s" % cursor,
    )
    assert status == 200 and _ids(body) == [E4]
    assert body["next_cursor"] is None


def test_matching_same_tenant_addition_invalidates_cursor(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E3, "2024-01-01T11:00:00Z")
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=alice&limit=1"
    )
    cursor = body["next_cursor"]
    _event(stack.audit, E4, "2024-01-01T11:30:00Z")
    status, body = _audit(
        stack.client,
        "tenant_id=t&operator_id=alice&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_corrupt_ledger_is_500_with_operator_id_filter(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", operator_id="bob")
    _corrupt_log(stack.data_dir)
    # The integrity scan covers every line regardless of the filter.
    status, body = _audit(stack.client, "tenant_id=t&operator_id=alice")
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )


# -- CLI --------------------------------------------------------------------

def test_cli_operator_id_filter_and_validation(stack):
    _seed(stack)
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operator-id", "bob",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [E7, E2]

    # Omission keeps the full result set.
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [E1, E7, E2, E6, E3, E4]

    # An empty value is exit 2 on stderr, naming operator_id.
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operator-id", "",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    body = json.loads(proc.stderr)
    assert set(body) == {"error"} and "operator_id" in body["error"]

    # Repeated (even identical) values are exit 2.
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice",
        "--operator-id", "alice", "--operator-id", "alice",
    )
    assert proc.returncode == 2
    assert _cli_json(proc) == {"error": "duplicate operator_id parameter"}


def test_cli_operator_id_no_match_is_empty_page_exit_0(stack):
    _seed(stack)
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operator-id", "nobody",
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"events": [], "next_cursor": None}


def test_cli_operator_id_policy_denial_is_exit_3(stack):
    _seed(stack)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operator-id", "bob",
    )
    assert proc.returncode == 3
    assert _cli_json(proc) == {"error": "action not permitted by policy"}
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id is None
    assert rejected[0].operator_id == "alice"


def test_cli_operator_id_pagination_and_cursor_reuse(stack):
    _seed(stack)
    status, body = _audit(
        stack.client, "tenant_id=t&operator_id=alice&limit=1"
    )
    assert status == 200
    cursor = body["next_cursor"]
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--operator-id", "alice", "--limit", "1", "--cursor", cursor,
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [E3]

    # Dropping the filter with the same cursor is an exit-2 cursor error.
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--limit", "1", "--cursor", cursor,
    )
    assert proc.returncode == 2
    assert "cursor" in json.loads(proc.stderr)["error"]


def test_cli_corrupt_ledger_with_operator_id_is_exit_1(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _corrupt_log(stack.data_dir)
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice", "--operator-id", "alice",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
