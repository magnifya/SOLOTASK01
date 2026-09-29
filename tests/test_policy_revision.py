"""Tests for opaque policy revisions and optimistic concurrency control.

``GET/PUT/DELETE /v1/policy`` carry a content-addressed ``revision`` and the
mutations accept an optional ``expected_revision`` query precondition (CLI
``--expected-revision``): the compare and the write happen under one tenant
lock, a mismatch is a 409 whose body is exactly
``{"error","current_revision"}`` with one policy_*/rejected event and no
rule change; duplicate/empty parameters are side-effect-free 400s.
"""

import json
import threading

import pytest

from keymgr.audit import AuditLog
from keymgr.policy import (
    EXPECTED_NONE,
    revision_for_rules,
    validate_rules,
)

from test_provider_reconnect import OPERATOR, HttpServer
from test_recovery_cli import run_cli

_UNSET = object()


@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield env, server
    server.stop()


def _rule(subject="alice", actions=("read",), effect="allow"):
    return {"subject": subject, "actions": list(actions), "effect": effect}


def _get(srv, tenant="t1", query=""):
    path = "/v1/policy?tenant_id=%s%s" % (tenant, query)
    return srv.request("GET", path, None, OPERATOR)


def _put(srv, rules, tenant="t1", expected=_UNSET, body=None):
    query = ""
    if expected is not _UNSET:
        query = "&expected_revision=%s" % expected
    payload = body if body is not None else {
        "tenant_id": tenant, "rules": rules
    }
    path = "/v1/policy?tenant_id=%s%s" % (tenant, query)
    return srv.request("PUT", path, payload, OPERATOR)


def _delete(srv, tenant="t1", expected=_UNSET):
    query = ""
    if expected is not _UNSET:
        query = "&expected_revision=%s" % expected
    path = "/v1/policy?tenant_id=%s%s" % (tenant, query)
    return srv.request("DELETE", path, None, OPERATOR)


def _policy_events(env, tenant="t1"):
    return [
        e for e in AuditLog(env.data_dir).query(tenant, limit=1000).events
        if e.action in ("policy_read", "policy_update", "policy_delete")
    ]


def _mutation_events(env, tenant="t1"):
    return [
        e for e in _policy_events(env, tenant)
        if e.action in ("policy_update", "policy_delete")
    ]


# -- revision properties ---------------------------------------------------

def test_revision_is_content_addressed_and_normalized():
    rules_a = validate_rules([_rule(actions=["read", "list"])])
    rules_b = validate_rules([_rule(actions=["list", "read"])])
    rules_c = validate_rules([_rule(actions=["read"], effect="deny")])
    assert revision_for_rules(rules_a) == revision_for_rules(rules_b)
    assert revision_for_rules(rules_a) != revision_for_rules(rules_c)
    assert revision_for_rules(validate_rules([])) != revision_for_rules(rules_a)
    assert revision_for_rules(rules_a) != EXPECTED_NONE
    assert len(revision_for_rules(rules_a)) == 64


def test_get_and_put_return_revision_and_rewrite_same_content_is_stable(http):
    env, srv = http
    status, _ = _get(srv)
    assert status == 404

    status, body = _put(srv, [_rule()])
    assert status == 200, body
    assert list(body.keys()) == ["tenant_id", "rules", "revision"]
    revision = body["revision"]

    status, body = _get(srv)
    assert status == 200
    assert body["revision"] == revision

    # An unconditional rewrite with identical content keeps the revision.
    status, body = _put(srv, [_rule(actions=["read"])])
    assert status == 200
    assert body["revision"] == revision


def test_unconditional_put_delete_keep_legacy_behavior(http):
    env, srv = http
    assert _put(srv, [_rule()])[0] == 200
    assert _delete(srv)[0] == 200
    # Deleting an absent tenant stays idempotent and audits success.
    assert _delete(srv)[0] == 200
    assert _get(srv)[0] == 404
    actions = [(e.action, e.outcome) for e in _policy_events(env)]
    assert actions == [
        ("policy_update", "success"),
        ("policy_delete", "success"),
        ("policy_delete", "success"),
    ]


# -- conditional updates ---------------------------------------------------

def test_conditional_update_match_succeeds(http):
    env, srv = http
    revision = _put(srv, [_rule()])[1]["revision"]
    status, body = _put(srv, [_rule(actions=["read", "list"])],
                        expected=revision)
    assert status == 200, body
    assert body["revision"] != revision
    status, read = _get(srv)
    assert read["revision"] == body["revision"]


def test_conditional_update_stale_revision_is_409_without_side_effects(http):
    env, srv = http
    revision = _put(srv, [_rule(actions=["read"])])[1]["revision"]
    # Another writer advances the revision unconditionally.
    newer = _put(srv, [_rule(actions=["list"])])[1]["revision"]
    assert newer != revision

    status, body = _put(srv, [_rule(actions=["create"])], expected=revision)
    assert status == 409, body
    assert list(body.keys()) == ["error", "current_revision"]
    assert body == {
        "error": "policy revision conflict",
        "current_revision": newer,
    }
    # Rules untouched, no success event, exactly one rejected event.
    assert _get(srv)[1]["revision"] == newer
    assert [(e.action, e.outcome) for e in _mutation_events(env)] == [
        ("policy_update", "success"),
        ("policy_update", "success"),
        ("policy_update", "rejected"),
    ]


def test_expected_none_create_and_conflict(http):
    env, srv = http
    status, body = _put(srv, [_rule()], expected=EXPECTED_NONE)
    assert status == 200, body
    revision = body["revision"]

    # A policy already exists: asserting none is a 409 with current revision.
    status, body = _put(srv, [_rule(actions=["list"])],
                        expected=EXPECTED_NONE)
    assert status == 409
    assert body["current_revision"] == revision
    assert _get(srv)[1]["revision"] == revision


def test_conditional_delete_rejects_with_null_current_revision(http):
    env, srv = http
    status, body = _delete(srv, expected="0" * 64)
    assert status == 409, body
    assert body == {"error": "policy revision conflict",
                    "current_revision": None}
    # A delete asserting absence on an absent tenant matches (idempotent).
    assert _delete(srv, expected=EXPECTED_NONE)[0] == 200
    assert [(e.action, e.outcome) for e in _mutation_events(env)] == [
        ("policy_delete", "rejected"),
        ("policy_delete", "success"),
    ]


def test_conditional_delete_match_and_mismatch(http):
    env, srv = http
    revision = _put(srv, [_rule()])[1]["revision"]
    assert _delete(srv, expected=revision)[0] == 200
    assert _get(srv)[0] == 404

    revision = _put(srv, [_rule(actions=["list"])],
                    expected=EXPECTED_NONE)[1]["revision"]
    status, body = _delete(srv, expected="0" * 64)
    assert status == 409
    assert body["current_revision"] == revision
    assert _get(srv)[1]["revision"] == revision
    rejected = [
        e for e in _policy_events(env)
        if (e.action, e.outcome) == ("policy_delete", "rejected")
    ]
    assert len(rejected) == 1


def test_duplicate_or_empty_expected_revision_is_400_zero_side_effects(http):
    env, srv = http
    revision = _put(srv, [_rule()])[1]["revision"]
    before = _mutation_events(env)

    status, _ = srv.request(
        "PUT",
        "/v1/policy?tenant_id=t1&expected_revision=%s&expected_revision=%s"
        % (revision, revision),
        {"tenant_id": "t1", "rules": [_rule(actions=["list"])]},
        OPERATOR,
    )
    assert status == 400
    status, _ = srv.request(
        "PUT", "/v1/policy?tenant_id=t1&expected_revision=",
        {"tenant_id": "t1", "rules": [_rule(actions=["list"])]},
        OPERATOR,
    )
    assert status == 400
    status, _ = srv.raw(
        "DELETE",
        "/v1/policy?tenant_id=t1&expected_revision=&expected_revision=x",
        headers=OPERATOR,
    )
    assert status == 400
    status, _ = _put(srv, [_rule(actions=["list"])], expected="bogus")
    assert status == 400

    # No rule change and no extra audit events.
    assert _get(srv)[1]["revision"] == revision
    assert _mutation_events(env) == before


# -- concurrency -----------------------------------------------------------

def test_concurrent_conditional_puts_one_wins_one_loses(http):
    env, srv = http
    revision = _put(srv, [_rule(actions=["read"])])[1]["revision"]
    results = {}
    barrier = threading.Barrier(2)

    def writer(name, action):
        barrier.wait()
        results[name] = _put(
            srv, [_rule(actions=[action])], expected=revision
        )

    threads = [
        threading.Thread(target=writer, args=("a", "list")),
        threading.Thread(target=writer, args=("b", "create")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    statuses = sorted(results[name][0] for name in ("a", "b"))
    assert statuses == [200, 409]
    winner = next(
        name for name in ("a", "b") if results[name][0] == 200
    )
    new_revision = results[winner][1]["revision"]
    assert _get(srv)[1]["revision"] == new_revision
    rejected = [
        e for e in _policy_events(env)
        if (e.action, e.outcome) == ("policy_update", "rejected")
    ]
    assert len(rejected) == 1


# -- delete/rebuild, empty rules -------------------------------------------

def test_delete_and_rebuild_cycle_with_empty_rules(http):
    env, srv = http
    revision = _put(srv, [])[1]["revision"]
    assert revision  # empty rules still carry an opaque revision
    assert _get(srv)[1]["rules"] == []
    assert _delete(srv, expected=revision)[0] == 200
    status, body = _put(srv, [_rule()], expected=EXPECTED_NONE)
    assert status == 200
    assert body["revision"] != revision


# -- CLI parity ------------------------------------------------------------

def test_cli_policy_revision_flow(http):
    env, srv = http

    result = run_cli(
        env, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules",
        json.dumps([_rule()]), "--expected-revision", "none",
    )
    assert result.returncode == 0, result.stderr
    revision = json.loads(result.stdout)["revision"]

    result = run_cli(
        env, "policy", "--operator", "admin", "show", "--tenant-id", "t1",
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["revision"] == revision

    # Stale precondition after an unconditional change: same body as HTTP.
    assert _put(srv, [_rule(actions=["list"])])[0] == 200
    result = run_cli(
        env, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules", json.dumps([_rule()]),
        "--expected-revision", revision,
    )
    assert result.returncode == 3
    assert json.loads(result.stderr) == {
        "error": "policy revision conflict",
        "current_revision": _get(srv)[1]["revision"],
    }

    current = _get(srv)[1]["revision"]
    result = run_cli(
        env, "policy", "--operator", "admin", "delete",
        "--tenant-id", "t1", "--expected-revision", current,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "tenant_id": "t1", "deleted": True
    }

    # A malformed precondition is an exit-2 parameter error.
    result = run_cli(
        env, "policy", "--operator", "admin", "delete",
        "--tenant-id", "t1", "--expected-revision", "nope",
    )
    assert result.returncode == 2
    assert "expected_revision" in result.stderr
