"""GET /v1/audit and the ``audit`` CLI filtered by since/until.

The optional single-value ``since`` (inclusive) and ``until`` (exclusive)
parameters take strict RFC3339 date-times (capital T, Z or +/-HH:MM, one
to six fractional digits). Events are judged by their actual instant, so
offset and fractional-second spellings of the same moment are equivalent.
Empty/duplicated/unzoned/malformed values, impossible dates and leap
seconds are 400 naming the field, validated before the audit policy and
recorded nowhere; since > until names ``until``; equal bounds are a legal
empty range. Range cursors bind the normalized boundaries and the visible
snapshot: equivalent spellings page on, changed boundaries (or legacy
cursors) are 400 naming cursor; in-range additions invalidate the cursor
while other-tenant and out-of-range additions leave it intact. A visible
event whose timestamp cannot be parsed is the fixed 500 body; omitting
both parameters keeps the legacy query and cursor behavior.
"""

import json

import pytest

from keymgr.policy import Rule
from test_audit_chain import _cli_json, _run_cli
from test_version_history import _build_server
from test_recovery_cli import run_cli


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _audit(client, query, op="alice"):
    return client.call("GET", "/v1/audit?%s" % query, None, operator=op)


def _event(ledger, event_id, tenant="t", action="create", key_id=None,
           timestamp="2026-09-26T00:00:00Z", outcome="success"):
    return ledger.append(
        ledger.new_event(
            tenant, action, key_id, outcome,
            timestamp=timestamp, event_id=event_id,
        )
    )


def _ids(body):
    return [event["event_id"] for event in body["events"]]


def test_since_inclusive_until_exclusive(stack):
    ledger = stack.audit
    _event(ledger, "e0", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "e1", timestamp="2026-09-26T00:00:01Z")
    _event(ledger, "e2", timestamp="2026-09-26T00:00:02Z")
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:01Z"
        "&until=2026-09-26T00:00:02Z",
    )
    assert status == 200, body
    assert _ids(body) == ["e1"]
    assert body["next_cursor"] is None


def test_single_side_bounds(stack):
    ledger = stack.audit
    _event(ledger, "e0", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "e1", timestamp="2026-09-26T00:00:01Z")
    _event(ledger, "e2", timestamp="2026-09-26T00:00:02Z")
    status, body = _audit(
        stack.client, "tenant_id=t&until=2026-09-26T00:00:01Z"
    )
    assert status == 200 and _ids(body) == ["e0"]
    status, body = _audit(
        stack.client, "tenant_id=t&since=2026-09-26T00:00:01Z"
    )
    assert status == 200 and _ids(body) == ["e1", "e2"]


def test_equal_bounds_are_a_legal_empty_range(stack):
    ledger = stack.audit
    _event(ledger, "e0", timestamp="2026-09-26T00:00:00Z")
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-26T00:00:00Z",
    )
    assert status == 200
    assert body == {"events": [], "next_cursor": None}


def test_offset_and_fraction_spellings_are_equivalent(stack):
    ledger = stack.audit
    _event(ledger, "e0", timestamp="2026-09-26T00:00:00+00:00")
    _event(ledger, "e1", timestamp="2026-09-26T00:00:00.100000+00:00")
    # The same two instants written with offsets and varying fraction
    # digits must produce the same selection.
    queries = [
        ("tenant_id=t&since=2026-09-26T08:00:00%2B08:00", ["e0", "e1"]),
        ("tenant_id=t&since=2026-09-25T19:00:00-05:00", ["e0", "e1"]),
        ("tenant_id=t&since=2026-09-26T00:00:00.1Z", ["e1"]),
        ("tenant_id=t&until=2026-09-26T00:00:00.100Z", ["e0"]),
        (
            "tenant_id=t&since=2026-09-26T00:00:00Z"
            "&until=2026-09-26T00:00:00.1Z",
            ["e0"],
        ),
    ]
    for query, expected in queries:
        status, body = _audit(stack.client, query)
        assert status == 200, (query, body)
        assert _ids(body) == expected, query


def test_bad_time_parameters_are_400_before_policy_without_audit(stack):
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    bad_since = [
        "tenant_id=t&since=",
        "tenant_id=t&since=2026-09-26",
        "tenant_id=t&since=2026-09-26%2000:00:00Z",
        "tenant_id=t&since=2026-09-26t00:00:00z",
        "tenant_id=t&since=2026-09-26T00:00:00",
        "tenant_id=t&since=2026-9-26T00:00:00Z",
        "tenant_id=t&since=2026-02-29T00:00:00Z",
        "tenant_id=t&since=2026-13-01T00:00:00Z",
        "tenant_id=t&since=2026-09-26T24:00:00Z",
        "tenant_id=t&since=2026-09-26T00:60:00Z",
        "tenant_id=t&since=2026-09-26T00:00:60Z",
        "tenant_id=t&since=2026-09-26T00:00:00.1234567Z",
        "tenant_id=t&since=2026-09-26T00:00:00+24:00",
        "tenant_id=t&since=2026-09-26T00:00:00+0000",
        "tenant_id=t&since=2026-09-26T00:00:00Z&since=2026-09-27T00:00:00Z",
    ]
    bad_until = [q.replace("since", "until") for q in bad_since]
    before = len(stack.audit._read_all())
    for query in bad_since:
        status, body = _audit(stack.client, query)
        assert status == 400, (query, body)
        assert "since" in body["error"], body
    for query in bad_until:
        status, body = _audit(stack.client, query)
        assert status == 400, (query, body)
        assert "until" in body["error"], body
    # The deny policy must never fire for the parameter failures.
    assert len(stack.audit._read_all()) == before


def test_since_later_than_until_names_until(stack):
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-27T00:00:00Z"
        "&until=2026-09-26T00:00:00Z",
    )
    assert status == 400
    assert body["error"].startswith("field until")


def test_missing_tenant_with_bad_range_still_conflicts(stack):
    status, body = _audit(
        stack.client, "since=not-a-time"
    )
    assert status == 400 and "tenant_id" in body["error"]
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1


def test_ordering_uses_the_actual_instant(stack):
    ledger = stack.audit
    # Lexicographically "+00:00" sorts after "Z" and "00:00:00" sorts
    # after "23:59:59"; ordering by instant must interleave them.
    _event(ledger, "a", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "b", timestamp="2026-09-26T01:00:00+01:00")
    _event(ledger, "c", timestamp="2026-09-26T00:00:00.500Z")
    _event(ledger, "d", timestamp="2026-09-25T23:29:59.900-00:30")
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-25T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=10",
    )
    assert status == 200, body
    assert _ids(body) == ["d", "a", "b", "c"]


def test_range_pagination_with_equivalent_spellings(stack):
    ledger = stack.audit
    for idx in range(4):
        _event(
            ledger, "e%d" % idx,
            timestamp="2026-09-26T00:00:0%dZ" % idx,
        )
    status, first = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=2",
    )
    assert status == 200 and _ids(first) == ["e0", "e1"]
    cursor = first["next_cursor"]
    assert cursor
    # Continue with an equivalent spelling of both boundaries.
    status, second = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T08:00:00%%2B08:00"
        "&until=2026-09-27T00:00:00.000000Z&limit=2&cursor=%s" % cursor,
    )
    assert status == 200, second
    assert _ids(second) == ["e2", "e3"]
    assert second["next_cursor"] is None
    assert _ids(first) + _ids(second) == ["e0", "e1", "e2", "e3"]


def test_cursor_is_bound_to_range_bounds(stack):
    ledger = stack.audit
    for idx in range(3):
        _event(
            ledger, "e%d" % idx,
            timestamp="2026-09-26T00:00:0%dZ" % idx,
        )
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z&limit=1",
    )
    assert status == 200 and body["next_cursor"]
    cursor = body["next_cursor"]
    # Changed actual boundary -> 400 naming cursor.
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-25T00:00:00Z&limit=1&cursor=%s"
        % cursor,
    )
    assert status == 400 and "cursor" in body["error"]
    # Dropping the range (legacy query) -> 400 naming cursor.
    status, body = _audit(
        stack.client, "tenant_id=t&limit=1&cursor=%s" % cursor
    )
    assert status == 400 and "cursor" in body["error"]
    # Adding a boundary -> 400 naming cursor.
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in body["error"]


def test_legacy_cursor_rejected_for_range_query(stack):
    ledger = stack.audit
    for idx in range(3):
        _event(
            ledger, "e%d" % idx,
            timestamp="2026-09-26T00:00:0%dZ" % idx,
        )
    status, body = _audit(stack.client, "tenant_id=t&limit=1")
    assert status == 200 and body["next_cursor"]
    cursor = body["next_cursor"]
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z&limit=1&cursor=%s"
        % cursor,
    )
    assert status == 400 and "cursor" in body["error"]
    # Legacy behavior is preserved when both bounds are omitted.
    status, body = _audit(
        stack.client, "tenant_id=t&limit=1&cursor=%s" % cursor
    )
    assert status == 200 and _ids(body) == ["e1"]


def test_snapshot_invalidation_scoped_to_visible_range(stack):
    ledger = stack.audit
    _event(ledger, "old", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "old2", timestamp="2026-09-26T00:00:05Z")
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=10",
    )
    assert status == 200 and body["next_cursor"] is None
    status, first = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=1",
    )
    assert _ids(first) == ["old"]
    cursor = first["next_cursor"]
    assert cursor

    # An out-of-range event for the same tenant does not invalidate.
    _event(ledger, "future", timestamp="2026-09-28T00:00:00Z")
    status, page = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=1&cursor=%s" % cursor,
    )
    assert status == 200, page
    assert _ids(page) == ["old2"]

    # Another tenant's in-range activity does not invalidate either.
    _event(ledger, "other", tenant="other",
           timestamp="2026-09-26T12:00:00Z")
    status, page = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=1&cursor=%s" % cursor,
    )
    assert status == 200 and _ids(page) == ["old2"]

    # An in-range addition for this tenant invalidates the cursor.
    _event(ledger, "new", timestamp="2026-09-26T06:00:00Z")
    status, page = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z&limit=1&cursor=%s" % cursor,
    )
    assert status == 400 and "cursor" in page["error"]


def test_range_and_combines_with_tenant_key_action(stack):
    ledger = stack.audit
    kid = "11111111-1111-4111-8111-111111111111"
    _event(ledger, "a", action="create", key_id=kid,
           timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "b", action="rotate", key_id=kid,
           timestamp="2026-09-26T00:00:01Z")
    _event(ledger, "c", action="rotate", key_id=None,
           timestamp="2026-09-26T00:00:02Z")
    _event(ledger, "d", tenant="other", action="rotate", key_id=kid,
           timestamp="2026-09-26T00:00:03Z")
    query = (
        "tenant_id=t&action=rotate&key_id=%s"
        "&since=2026-09-26T00:00:00Z&until=2026-09-27T00:00:00Z" % kid
    )
    status, body = _audit(stack.client, query)
    assert status == 200 and _ids(body) == ["b"]
    # Tenant isolation with a range.
    status, body = _audit(
        stack.client,
        "tenant_id=other&since=2026-09-26T00:00:00Z"
        "&until=2026-09-27T00:00:00Z",
    )
    assert status == 200 and _ids(body) == ["d"]


def test_unparseable_visible_timestamp_is_fixed_500(stack):
    ledger = stack.audit
    _event(ledger, "good", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "bad", timestamp="not-a-timestamp")
    # The malformed event only becomes a ledger failure once it is in the
    # tenant's candidate set AND a time range is requested.
    status, body = _audit(stack.client, "tenant_id=t")
    assert status == 200 and set(_ids(body)) == {"good", "bad"}
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-25T00:00:00Z"
        "&until=2026-09-27T00:00:00Z",
    )
    assert (status, body) == (
        500, {"error": "audit ledger is unavailable"}
    )
    proc = _run_cli(
        stack.data_dir, "audit", "--tenant-id", "t",
        "--operator", "alice",
        "--since", "2026-09-25T00:00:00Z",
        "--until", "2026-09-27T00:00:00Z",
    )
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}


def test_unparseable_other_tenant_record_does_not_500(stack):
    ledger = stack.audit
    _event(ledger, "good", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "badv", tenant="other", timestamp="nope")
    # Another tenant\'s malformed record is invisible to tenant t.
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-01T00:00:00Z",
    )
    assert status == 200 and _ids(body) == ["good"]


def test_policy_denial_with_range_is_403_and_audited(stack):
    ledger = stack.audit
    _event(ledger, "e0", timestamp="2026-09-26T00:00:00Z")
    stack.policies.put("t", [Rule("alice", ["audit"], "deny")])
    status, body = _audit(
        stack.client,
        "tenant_id=t&since=2026-09-26T00:00:00Z",
    )
    assert status == 403
    assert body == {"error": "action not permitted by policy"}
    rejected = [
        e for e in ledger._read_all()
        if e.action == "audit" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id is None


def test_cli_range_filter_pagination_and_errors(stack):
    ledger = stack.audit
    _event(ledger, "e0", timestamp="2026-09-26T00:00:00Z")
    _event(ledger, "e1", timestamp="2026-09-26T00:00:01Z")
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--since", "2026-09-26T00:00:01Z",
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert _ids(body) == ["e1"]
    # Equivalent spellings work through the CLI too.
    proc = run_cli(
        stack, "audit", "--tenant-id", "t", "--operator", "alice",
        "--until", "2026-09-26T08:00:02+08:00",
    )
    assert proc.returncode == 0, proc.stderr
    assert _ids(json.loads(proc.stdout)) == ["e0", "e1"]
    for args, field in (
        (("--since", ""), "since"),
        (("--since", "2026-09-26"), "since"),
        (("--until", "2026-09-26T00:00:00"), "until"),
        (
            ("--since", "2026-09-27T00:00:00Z",
             "--until", "2026-09-26T00:00:00Z"),
            "until",
        ),
    ):
        proc = run_cli(
            stack, "audit", "--tenant-id", "t", "--operator", "alice",
            *args
        )
        assert proc.returncode == 2, args
        error = json.loads(proc.stderr)["error"]
        assert field in error, (args, error)
