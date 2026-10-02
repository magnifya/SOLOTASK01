"""GET /v1/audit and the ``audit`` CLI filtered by ``outcome``.

The optional single-valued, case-sensitive ``outcome`` (``success`` or
``rejected``) restricts events to one execution result and AND-combines with
key_id/action/operation_id/time range; omitting it keeps the full result set.
An empty, duplicated (even twice-identical), illegal, cased or
whitespace-padded value is a 400 naming outcome whose body contains only
``error``, validated before policy and recorded nowhere (a missing/
conflicting tenant source still records tenant_conflict). Policy denial is
403 (CLI exit 3) with one audit/rejected event (key_id null); a successful
query writes nothing. The outcome condition -- its omission as well as its
value -- is bound into the HMAC cursor: adding, removing or changing it is a
400 naming cursor; pre-upgrade cursors without the binding stay usable only
without outcome. Only same-tenant events satisfying every filter invalidate
a snapshot; corruption is the fixed 500 body (CLI exit 1) even when the
damaged line would not match the filter.
"""

import json
from urllib.parse import quote

import pytest

from keymgr.policy import Rule
from test_audit_chain import _cli_json, _corrupt_log, _run_cli
from test_audit_operation_filter import _audit
from test_recovery_cli import run_cli
from test_version_history import _build_server, _make_key


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _event(audit_log, event_id, timestamp, tenant="t", action="create",
           key_id=None, outcome="success"):
    return audit_log.append(
        audit_log.new_event(
            tenant, action, key_id, outcome,
            timestamp=timestamp, event_id=event_id,
        )
    )


def _ids(body):
    return [event["event_id"] for event in body["events"]]


# A fixed mixed-outcome set for tenant t plus a foreign-tenant event.
E1 = "50000000-0000-4000-8000-000000000001"  # t success 10:00
E2 = "50000000-0000-4000-8000-000000000002"  # t rejected 10:30
E3 = "50000000-0000-4000-8000-000000000003"  # t success 11:00
E4 = "50000000-0000-4000-8000-000000000004"  # t success 11:30
E5 = "50000000-0000-4000-8000-000000000005"  # other success 10:15
KEY = "50000000-0000-4000-8000-0000000000f0"
E6 = "50000000-0000-4000-8000-000000000006"  # t rejected rotate KEY 10:00
E7 = "50000000-0000-4000-8000-000000000007"  # t success rotate KEY 10:00


def _seed(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", outcome="rejected")
    _event(stack.audit, E3, "2024-01-01T11:00:00Z")
    _event(stack.audit, E4, "2024-01-01T11:30:00Z")
    _event(stack.audit, E5, "2024-01-01T10:15:00Z", tenant="other")
    _event(stack.audit, E6, "2024-01-01T10:00:00Z", action="rotate",
           key_id=KEY, outcome="rejected")
    _event(stack.audit, E7, "2024-01-01T10:00:00Z", action="rotate",
           key_id=KEY, outcome="success")


def test_outcome_filters_by_result_and_omission_keeps_full_set(stack):
    _seed(stack)
    status, body = _audit(stack.client, "tenant_id=t&outcome=success")
    assert status == 200 and _ids(body) == [E1, E7, E3, E4]
    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert status == 200 and _ids(body) == [E6, E2]
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 200 and _ids(body) == [E1, E6, E7, E2, E3, E4]
    # The foreign tenant's event is never visible through either filter.
    status, body = _audit(stack.client, "tenant_id=other&outcome=success")
    assert status == 200 and _ids(body) == [E5]


def test_outcome_and_combines_with_action_key_and_time_range(stack):
    _seed(stack)
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=rejected&action=rotate&key_id=%s" % KEY,
    )
    assert status == 200 and _ids(body) == [E6]
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&action=rotate&key_id=%s" % KEY,
    )
    assert status == 200 and _ids(body) == [E7]
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=rejected&since=2024-01-01T11:00:00Z",
    )
    assert status == 200 and body == {"events": [], "next_cursor": None}
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&action=create&key_id=%s" % KEY,
    )
    assert status == 200 and body == {"events": [], "next_cursor": None}


def test_tenant_conflict_event_is_never_visible_through_outcome(stack):
    _seed(stack)
    stack.store.audit_conflict()
    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert status == 200
    assert all(e["tenant_id"] == "t" for e in body["events"])
    assert all(e["action"] != "tenant_conflict" for e in body["events"])


@pytest.mark.parametrize(
    "query",
    [
        "outcome=",
        "outcome=failed",
        "outcome=Success",
        "outcome=SUCCESS",
        "outcome=Rejected",
        "outcome=" + quote(" success"),
        "outcome=" + quote("rejected "),
        "outcome=" + quote("\trejected\t"),
        "outcome=success&outcome=success",
        "outcome=success&outcome=rejected",
    ],
)
def test_invalid_outcome_is_400_naming_field_with_error_only(stack, query):
    status, body = _audit(stack.client, "tenant_id=t&" + query)
    assert status == 400, body
    assert set(body) == {"error"}
    assert "outcome" in body["error"]


def test_outcome_validation_precedes_policy_without_audit(stack):
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    before = len(stack.audit._read_all())
    for query in ("outcome=bogus", "outcome=success&outcome=success"):
        status, body = _audit(stack.client, "tenant_id=t&" + query)
        assert status == 400 and "outcome" in body["error"]
    assert len(stack.audit._read_all()) == before


def test_missing_tenant_with_bad_outcome_still_records_conflict(stack):
    status, body = _audit(stack.client, "outcome=bogus")
    assert status == 400 and "tenant_id" in body["error"]
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1 and conflicts[0].tenant_id is None


def test_policy_denial_is_403_and_records_one_audit_rejected(stack):
    _seed(stack)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id is None


def test_successful_outcome_query_writes_no_audit(stack):
    _make_key(stack.client)
    status, _ = _audit(stack.client, "tenant_id=t&outcome=success")
    assert status == 200
    assert [e.action for e in stack.audit._read_all()].count("audit") == 0


def test_outcome_pagination_is_complete_without_repeats(stack):
    _seed(stack)
    seen = []
    cursor = None
    for _ in range(10):
        query = "tenant_id=t&outcome=success&limit=2"
        if cursor is not None:
            query += "&cursor=%s" % cursor
        status, body = _audit(stack.client, query)
        assert status == 200, body
        seen.extend(_ids(body))
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == [E1, E7, E3, E4]


def test_cursor_is_rejected_when_outcome_is_added_removed_or_changed(stack):
    _seed(stack)
    # Cursor issued without outcome.
    status, body = _audit(stack.client, "tenant_id=t&limit=2")
    assert status == 200 and body["next_cursor"]
    plain_cursor = body["next_cursor"]
    status, body = _audit(
        stack.client,
        "tenant_id=t&limit=2&outcome=success&cursor=%s" % plain_cursor,
    )
    assert status == 400 and "cursor" in body["error"]

    # Cursor issued with outcome=success.
    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=2"
    )
    success_cursor = body["next_cursor"]
    for query in (
        "tenant_id=t&limit=2&cursor=%s",
        "tenant_id=t&outcome=rejected&limit=2&cursor=%s",
    ):
        status, body = _audit(stack.client, query % success_cursor)
        assert status == 400 and "cursor" in body["error"]

    # The same outcome continues the cursor normally.
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=2&cursor=%s" % success_cursor,
    )
    assert status == 200 and _ids(body) == [E3, E4]
    assert body["next_cursor"] is None


def test_tampered_outcome_cursor_is_400_naming_cursor(stack):
    _seed(stack)
    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=1"
    )
    cursor = body["next_cursor"]
    # Flip the last hex nibble of the MAC.
    last = cursor[-1]
    flipped_last = "0" if last != "0" else "1"
    tampered = cursor[:-1] + flipped_last
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%s" % tampered,
    )
    assert status == 400 and "cursor" in body["error"]


def _strip_outcome_binding(audit_log, cursor):
    """Re-encode a cursor without its outcome binding (pre-upgrade shape)."""
    payload = audit_log._decode_cursor(cursor)
    payload.pop("oc", None)
    return audit_log._encode_cursor(payload)


def test_pre_upgrade_cursor_works_without_outcome_but_not_with(stack):
    _seed(stack)
    status, body = _audit(stack.client, "tenant_id=t&limit=2")
    legacy_cursor = _strip_outcome_binding(stack.audit, body["next_cursor"])

    # Other filters and snapshot unchanged, outcome omitted: still usable.
    status, body = _audit(
        stack.client, "tenant_id=t&limit=2&cursor=%s" % legacy_cursor
    )
    assert status == 200 and _ids(body) == [E7, E2]

    # It cannot drive an outcome-filtered query.
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=2&cursor=%s" % legacy_cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_non_matching_and_foreign_additions_keep_cursor_valid(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E3, "2024-01-01T11:00:00Z")
    _event(stack.audit, E4, "2024-01-01T11:30:00Z")
    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=1"
    )
    assert status == 200 and _ids(body) == [E1]
    cursor = body["next_cursor"]

    # A same-tenant rejected event and a foreign success do not change the
    # visible snapshot: paging continues without gap or repeat.
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", outcome="rejected")
    _event(stack.audit, E5, "2024-01-01T10:15:00Z", tenant="other")
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
    )
    assert status == 200, body
    assert _ids(body) == [E3]
    cursor = body["next_cursor"]
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
    )
    assert status == 200 and _ids(body) == [E4]
    assert body["next_cursor"] is None


def test_matching_same_tenant_addition_invalidates_cursor(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z")
    _event(stack.audit, E3, "2024-01-01T11:00:00Z")
    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=1"
    )
    cursor = body["next_cursor"]
    _event(stack.audit, E4, "2024-01-01T11:30:00Z")
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_corrupt_ledger_is_500_even_when_damaged_line_excluded(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z", outcome="success")
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", outcome="rejected")
    _corrupt_log(stack.data_dir)
    # The integrity scan covers every line regardless of the filter.
    status, body = _audit(stack.client, "tenant_id=t&outcome=success")
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )
    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )


# -- CLI -------------------------------------------------------------------

def test_cli_outcome_filter_and_validation(stack):
    _seed(stack)
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--outcome", "rejected",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [E6, E2]

    # Omission keeps the full result set.
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [E1, E6, E7, E2, E3, E4]

    # Illegal, cased and whitespace-padded values are exit 2 on stderr.
    for args in (
        ["--outcome", "bogus"],
        ["--outcome", "Success"],
        ["--outcome", " rejected"],
        ["--outcome", ""],
    ):
        proc = run_cli(
            stack, "audit", "--tenant-id", "t", "--operator", "alice",
            *args,
        )
        assert proc.returncode == 2, args
        assert proc.stdout == ""
        body = json.loads(proc.stderr)
        assert set(body) == {"error"} and "outcome" in body["error"]

    # Repeated (even identical) values are exit 2.
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice",
        "--outcome", "success", "--outcome", "success",
    )
    assert proc.returncode == 2
    assert _cli_json(proc) == {"error": "duplicate outcome parameter"}


def test_cli_outcome_policy_denial_is_exit_3(stack):
    _seed(stack)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--outcome", "success",
    )
    assert proc.returncode == 3
    assert _cli_json(proc) == {"error": "action not permitted by policy"}
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id is None


def test_cli_outcome_pagination_and_empty_page(stack):
    _seed(stack)
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--outcome", "rejected", "--action", "audit",
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"events": [], "next_cursor": None}

    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=2"
    )
    assert status == 200
    cursor = body["next_cursor"]
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--outcome", "success", "--limit", "2", "--cursor", cursor,
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [E3, E4]


def test_cli_corrupt_ledger_with_outcome_is_exit_1(stack):
    _event(stack.audit, E1, "2024-01-01T10:00:00Z", outcome="success")
    _event(stack.audit, E2, "2024-01-01T10:30:00Z", outcome="rejected")
    _corrupt_log(stack.data_dir)
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice", "--outcome", "success",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
