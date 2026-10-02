"""GET /v1/audit and the ``audit`` CLI filtered by ``outcome``.

The optional single-valued, case-sensitive ``outcome`` query parameter
(``success``/``rejected``) and-combines with key_id/action/operation_id/
time range/limit/cursor; omitting it keeps the full result set. An empty,
duplicated (even twice the same value), illegal, case-variant or
whitespace-padded value is a 400 naming ``outcome``, validated before the
policy decision and the ledger query, with no audit event or business state
written (a missing/conflicting tenant source still records
tenant_conflict). A legal query stays under ``audit`` authorization: a
denial is 403 (CLI exit 3) and records one ``audit/rejected`` with null
key_id; a successful query records nothing. No result filter ever exposes
another tenant's events or the invisible tenant_conflict records.

Pagination binds both the omission and the concrete value of ``outcome``
into the HMAC cursor: adding, removing or changing it is a 400 naming
``cursor`` (CLI exit 2); only same-tenant events satisfying every filter
invalidate an old cursor. Cursors issued before the upgrade (no bound
outcome) keep working without ``outcome`` but can never page an
outcome-filtered query. A corrupt/unreadable ledger is the fixed 500 body
even when the corrupt rows would not match the filter; the CLI prints the
same body and exits 1.
"""

import json

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


# -- filtering ---------------------------------------------------------------


def test_outcome_filters_success_and_rejected(stack):
    ids_success = [
        "50000000-0000-4000-8000-000000000001",
        "50000000-0000-4000-8000-000000000002",
    ]
    id_rejected = "50000000-0000-4000-8000-000000000003"
    _event(stack.audit, ids_success[0], "2024-01-01T10:00:00Z")
    _event(stack.audit, ids_success[1], "2024-01-01T11:00:00Z")
    _event(stack.audit, id_rejected, "2024-01-01T12:00:00Z",
           outcome="rejected")

    status, body = _audit(stack.client, "tenant_id=t&outcome=success")
    assert status == 200 and _ids(body) == ids_success
    assert body["next_cursor"] is None

    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert status == 200 and _ids(body) == [id_rejected]

    # Omitting outcome keeps the complete result set, ordered by
    # (timestamp, event_id) ascending.
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 200 and _ids(body) == ids_success + [id_rejected]


def test_outcome_no_match_is_empty_page_not_404(stack):
    _event(stack.audit, "50000001-0000-4000-8000-000000000001",
           "2024-01-01T10:00:00Z", outcome="rejected")
    status, body = _audit(stack.client, "tenant_id=t&outcome=success")
    assert status == 200
    assert body == {"events": [], "next_cursor": None}


def test_outcome_and_combines_with_other_filters(stack):
    key_id = "50000002-0000-4000-8000-000000000001"
    id_match = "50000002-0000-4000-8000-000000000002"
    _event(stack.audit, id_match, "2024-01-01T10:00:00Z",
           action="rotate", key_id=key_id, outcome="success")
    # Same action/key but rejected: outcome alone excludes it.
    _event(stack.audit, "50000002-0000-4000-8000-000000000003",
           "2024-01-01T10:05:00Z", action="rotate", key_id=key_id,
           outcome="rejected")
    # Same outcome but different action: action alone excludes it.
    _event(stack.audit, "50000002-0000-4000-8000-000000000004",
           "2024-01-01T10:06:00Z", action="create", key_id=key_id,
           outcome="success")
    # Same outcome/action, outside the time range.
    _event(stack.audit, "50000002-0000-4000-8000-000000000005",
           "2024-01-01T09:00:00Z", action="rotate", key_id=key_id,
           outcome="success")

    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&action=rotate&key_id=%s"
        "&since=2024-01-01T10:00:00Z&until=2024-01-01T11:00:00Z" % key_id,
    )
    assert status == 200 and _ids(body) == [id_match]


def test_outcome_sees_real_rejected_business_events(stack):
    # A policy-denied create records one create/rejected with null key_id;
    # keep audit explicitly allowed so the query itself stays authorized.
    stack.policies.put("t", [
        Rule("alice", ["create"], "deny"),
        Rule("alice", ["audit"], "allow"),
    ])
    status, _ = stack.client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
    )
    assert status == 403

    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert status == 200 and len(body["events"]) == 1
    event = body["events"][0]
    assert event["action"] == "create"
    assert event["outcome"] == "rejected"
    assert event["key_id"] is None

    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&action=create"
    )
    assert status == 200 and body["events"] == []


def test_tenant_isolation_and_tenant_conflict_invisibility(stack):
    # tenant_conflict is recorded with outcome rejected but a null tenant,
    # so even outcome=rejected must not surface it to anybody.
    status, _ = _audit(stack.client, "outcome=rejected")
    assert status == 400  # missing tenant source
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1 and conflicts[0].outcome == "rejected"

    _event(stack.audit, "50000003-0000-4000-8000-000000000001",
           "2024-01-01T10:00:00Z", tenant="other", outcome="rejected")
    status, body = _audit(stack.client, "tenant_id=t&outcome=rejected")
    assert status == 200
    assert body == {"events": [], "next_cursor": None}


# -- validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "outcome=",
        "outcome=Success",
        "outcome=SUCCESS",
        "outcome=Rejected",
        "outcome=nope",
        "outcome=%20success",
        "outcome=success%20",
        "outcome=success&outcome=success",
        "outcome=success&outcome=rejected",
    ],
)
def test_invalid_outcome_is_400_naming_field(stack, query):
    status, body = _audit(stack.client, "tenant_id=t&" + query)
    assert status == 400, body
    assert "outcome" in body["error"]
    assert set(body) == {"error"}


def test_outcome_validation_precedes_policy_without_audit(stack):
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    before = len(stack.audit._read_all())
    status, body = _audit(stack.client, "tenant_id=t&outcome=bad")
    assert status == 400 and "outcome" in body["error"]
    assert len(stack.audit._read_all()) == before


def test_missing_tenant_with_outcome_still_records_conflict(stack):
    before = len(stack.audit._read_all())
    status, body = _audit(stack.client, "outcome=success")
    assert status == 400 and "tenant_id" in body["error"]
    tail = stack.audit._read_all()[before:]
    assert [e.action for e in tail] == ["tenant_conflict"]
    assert tail[0].tenant_id is None


def test_policy_denial_is_403_and_records_audit_rejected(stack):
    _make_key(stack.client)
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    status, body = _audit(stack.client, "tenant_id=t&outcome=success")
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id is None


def test_successful_outcome_query_writes_no_audit(stack):
    _event(stack.audit, "50000004-0000-4000-8000-000000000001",
           "2024-01-01T10:00:00Z")
    before = len(stack.audit._read_all())
    status, _ = _audit(stack.client, "tenant_id=t&outcome=success")
    assert status == 200
    assert len(stack.audit._read_all()) == before


# -- cursor binding ----------------------------------------------------------


def _outcome_page_setup(stack):
    ids = [
        "51000000-0000-4000-8000-000000000001",
        "51000000-0000-4000-8000-000000000002",
        "51000000-0000-4000-8000-000000000003",
    ]
    for idx, event_id in enumerate(ids, start=1):
        _event(stack.audit, event_id,
               "2024-01-01T%02d:00:00Z" % (9 + idx), outcome="success")
    _event(stack.audit, "51000000-0000-4000-8000-000000000004",
           "2024-01-01T13:00:00Z", outcome="rejected")
    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=1"
    )
    assert status == 200 and _ids(body) == ids[:1]
    return body["next_cursor"], ids


def test_outcome_cursor_pages_without_gap_or_duplicate(stack):
    cursor, ids = _outcome_page_setup(stack)
    seen = ids[:1]
    while cursor:
        status, body = _audit(
            stack.client,
            "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
        )
        assert status == 200, body
        seen.extend(_ids(body))
        cursor = body["next_cursor"]
    assert seen == ids


def test_adding_outcome_to_plain_cursor_is_400_naming_cursor(stack):
    ids = [
        "51000001-0000-4000-8000-000000000001",
        "51000001-0000-4000-8000-000000000002",
    ]
    for idx, event_id in enumerate(ids, start=1):
        _event(stack.audit, event_id,
               "2024-01-01T%02d:00:00Z" % (9 + idx))
    status, body = _audit(stack.client, "tenant_id=t&limit=1")
    cursor = body["next_cursor"]
    # A pre-upgrade (outcome-less) cursor keeps working without outcome...
    status, body = _audit(
        stack.client, "tenant_id=t&limit=1&cursor=%s" % cursor
    )
    assert status == 200 and _ids(body) == ids[1:]
    # ...but adding the condition invalidates it.
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_removing_or_changing_outcome_invalidates_cursor(stack):
    cursor, _ = _outcome_page_setup(stack)
    # Remove the condition.
    status, body = _audit(
        stack.client, "tenant_id=t&limit=1&cursor=%s" % cursor
    )
    assert status == 400 and "cursor" in body["error"]
    # Change the value.
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=rejected&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_tampered_outcome_cursor_is_400(stack):
    cursor, _ = _outcome_page_setup(stack)
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%sx" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_only_matching_tenant_events_invalidate_outcome_cursor(stack):
    cursor, ids = _outcome_page_setup(stack)

    # A same-tenant rejected event does not belong to the visible snapshot.
    _event(stack.audit, "51000002-0000-4000-8000-000000000001",
           "2024-01-01T10:30:00Z", outcome="rejected")
    # Another tenant's success event is invisible to this tenant.
    _event(stack.audit, "51000002-0000-4000-8000-000000000002",
           "2024-01-01T10:31:00Z", tenant="other", outcome="success")

    # Paging still completes without gap or duplicate, and the rejected
    # event never enters the outcome=success pages.
    seen = ids[:1]
    while cursor:
        status, body = _audit(
            stack.client,
            "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
        )
        assert status == 200, body
        seen.extend(_ids(body))
        cursor = body["next_cursor"]
    assert seen == ids

    # Re-issue the first cursor for the staleness check below.
    status, body = _audit(
        stack.client, "tenant_id=t&outcome=success&limit=1"
    )
    cursor = body["next_cursor"]

    # A new same-tenant success event changes the visible snapshot.
    _event(stack.audit, "51000002-0000-4000-8000-000000000003",
           "2024-01-01T10:32:00Z", outcome="success")
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


# -- ledger integrity --------------------------------------------------------


def test_corrupt_ledger_is_500_even_when_nothing_matches_filter(stack):
    _make_key(stack.client)
    _corrupt_log(stack.data_dir)
    # No audit events exist at all, so the filter matches nothing; the full
    # chain must still be verified before filtering.
    status, body = _audit(
        stack.client,
        "tenant_id=t&outcome=success&action=audit",
    )
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )


# -- CLI ---------------------------------------------------------------------


def test_cli_outcome_filter(stack):
    id_success = "52000000-0000-4000-8000-000000000001"
    id_rejected = "52000000-0000-4000-8000-000000000002"
    _event(stack.audit, id_success, "2024-01-01T10:00:00Z")
    _event(stack.audit, id_rejected, "2024-01-01T11:00:00Z",
           outcome="rejected")

    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--outcome", "rejected",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == [id_rejected]


@pytest.mark.parametrize(
    "args",
    [
        ["--outcome", ""],
        ["--outcome", "Success"],
        ["--outcome", "REJECTED"],
        ["--outcome", " success"],
        ["--outcome", "rejected "],
        ["--outcome", "nope"],
        ["--outcome", "rejected", "--outcome", "rejected"],
    ],
)
def test_cli_invalid_outcome_is_exit_2_stderr_json(stack, args):
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice", *args
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    body = json.loads(proc.stderr)
    assert set(body) == {"error"}
    assert "outcome" in body["error"]


def test_cli_outcome_validation_precedes_policy_exit_2(stack):
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    before = len(stack.audit._read_all())
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--outcome", "bad",
    )
    assert proc.returncode == 2
    assert "outcome" in json.loads(proc.stderr)["error"]
    assert len(stack.audit._read_all()) == before


def test_cli_policy_denial_exit_3_records_audit_rejected(stack):
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


def test_cli_cursor_outcome_mismatch_is_exit_2(stack):
    cursor, _ = _outcome_page_setup(stack)
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice", "--limit", "1",
        "--cursor", cursor,
    )
    assert proc.returncode == 2
    assert "cursor" in _cli_json(proc)["error"]


def test_cli_corrupt_ledger_with_outcome_is_exit_1(stack):
    _make_key(stack.client)
    _corrupt_log(stack.data_dir)
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice", "--outcome", "success",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
