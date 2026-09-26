"""Tests for the optional optimistic-concurrency precondition on rotation.

``POST /v1/keys/{key_id}/rotate`` accepts an optional ``expected_version``
(CLI ``rotate --expected-version N``) and ``POST /v1/keys/batch-rotate``
accepts one per item. The precondition is compared against the committed
``current_version`` under the per-key locks, before any provider call: a
mismatch is a bound terminal 409 (one ``rotate``/``batch_rotate`` rejected
audit event, batch key_id null) with zero handles/files changed; an invalid
or unexpected field is a side-effect-free 400 (CLI 2) before the
Idempotency-Key is bound.
"""

import json
import threading

import pytest

from keymgr import provider as provider_mod
from keymgr.audit import AuditLog

from test_provider_reconnect import OPERATOR, HttpServer
from test_recovery_cli import run_cli


@pytest.fixture()
def http(env):
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()
    provider_mod.reset_for_tests()


def _create(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


_UNSET = object()


def _rotate(srv, key_id, idem, expected=_UNSET, tenant="t1", extra=None):
    payload = {"tenant_id": tenant, "algorithm": "AES256"}
    if expected is not _UNSET:
        payload["expected_version"] = expected
    if extra:
        payload.update(extra)
    return srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id, payload,
        dict(OPERATOR, **{"Idempotency-Key": idem}),
    )


def _batch(srv, items, idem, tenant="t1", extra=None):
    payload = {"tenant_id": tenant, "items": items}
    if extra:
        payload.update(extra)
    return srv.request(
        "POST", "/v1/keys/batch-rotate", payload,
        dict(OPERATOR, **{"Idempotency-Key": idem}),
    )


def _events(env, tenant="t1"):
    return AuditLog(env.data_dir).query(tenant, limit=1000).events


def _rotation_events(env, tenant="t1"):
    """Rotation audit events only (the key creation event is excluded)."""
    return [
        e for e in _events(env, tenant)
        if e.action in ("rotate", "batch_rotate")
    ]


def _current_version(srv, key_id, tenant="t1"):
    status, body = srv.request(
        "GET", "/v1/keys/%s/current" % key_id, None,
        dict(OPERATOR, **{"X-Tenant-Id": tenant}),
    )
    assert status == 200, body
    return body["version"]


# -- single-key rotate -----------------------------------------------------

def test_rotate_expected_version_match_succeeds(http):
    env, srv = http
    key_id = _create(srv)
    status, body = _rotate(srv, key_id, "ev-1", expected=1)
    assert status == 201, body
    assert body["version"] == 2
    status, body = _rotate(srv, key_id, "ev-2", expected=2)
    assert status == 201, body
    assert body["version"] == 3


def test_rotate_expected_version_mismatch_is_409_without_side_effects(http):
    env, srv = http
    key_id = _create(srv)
    handles_before = env.kms_handles()

    status, body = _rotate(srv, key_id, "ev-mismatch", expected=5)
    assert status == 409, body
    assert list(body.keys()) == ["error", "operation_id"]
    operation_id = body["operation_id"]

    # Zero side effects: no new version, no new handle, one rejected event.
    assert _current_version(srv, key_id) == 1
    assert env.kms_handles() == handles_before
    rejected = [
        e for e in _events(env)
        if e.action == "rotate" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id == key_id
    assert rejected[0].event_id == operation_id

    # The bound operation is a durable conflict, replayed verbatim.
    status, op = srv.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        dict(OPERATOR, **{"X-Tenant-Id": "t1"}),
    )
    assert status == 200
    assert op["status"] == "conflict"
    assert op["http_status"] == 409
    assert op["response"] == body

    # An identical retry replays the same 409; no second event is appended.
    status, replay = _rotate(srv, key_id, "ev-mismatch", expected=5)
    assert status == 409
    assert replay == body
    assert len([
        e for e in _events(env)
        if e.action == "rotate" and e.outcome == "rejected"
    ]) == 1

    # The same Idempotency-Key with a different expected_version is a
    # binding conflict naming the original operation.
    status, conflict = _rotate(srv, key_id, "ev-mismatch", expected=1)
    assert status == 409
    assert conflict["operation_id"] == operation_id
    assert "Idempotency-Key" in conflict["error"]


@pytest.mark.parametrize("bad", [0, -1, "1", 1.5, True, None, [1], {"v": 1}])
def test_rotate_expected_version_invalid_is_400_without_side_effects(
    http, bad,
):
    env, srv = http
    key_id = _create(srv)
    handles_before = env.kms_handles()
    slug = "".join(c if c.isalnum() else "-" for c in repr(bad))
    status, body = _rotate(srv, key_id, "ev-bad-%s" % slug, expected=bad)
    assert status == 400, body
    assert "expected_version" in body["error"]
    assert "operation_id" not in body
    # Pre-binding: no audit event, no operation record, no version, no handle.
    assert _rotation_events(env) == []
    assert _current_version(srv, key_id) == 1
    assert env.kms_handles() == handles_before


def test_rotate_extra_field_is_400_without_side_effects(http):
    env, srv = http
    key_id = _create(srv)
    status, body = _rotate(srv, key_id, "ev-extra", extra={"label": "x"})
    assert status == 400, body
    assert "label" in body["error"]
    assert _rotation_events(env) == []
    assert _current_version(srv, key_id) == 1


def test_rotate_without_expected_version_keeps_old_semantics(http):
    env, srv = http
    key_id = _create(srv)
    status, body = _rotate(srv, key_id, "ev-none")
    assert status == 201, body
    assert body["version"] == 2


def test_presence_of_expected_version_is_part_of_the_binding(http):
    env, srv = http
    key_id = _create(srv)
    # First binding carries no precondition and succeeds.
    status, body = _rotate(srv, key_id, "ev-binding")
    assert status == 201, body
    # The SAME key presenting a precondition is a different binding: 409
    # naming the first operation (not a rotation, no extra event).
    status, conflict = _rotate(srv, key_id, "ev-binding", expected=2)
    assert status == 409, conflict
    assert conflict["operation_id"] == body["operation_id"]
    assert "Idempotency-Key" in conflict["error"]
    assert len([
        e for e in _rotation_events(env) if e.outcome == "rejected"
    ]) == 0


def test_concurrent_same_expected_version_has_exactly_one_winner(http):
    env, srv = http
    key_id = _create(srv)
    results = {}

    def rotate(name):
        results[name] = _rotate(srv, key_id, "ev-race-%s" % name, expected=1)

    threads = [
        threading.Thread(target=rotate, args=(name,))
        for name in ("a", "b")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    statuses = sorted(results[name][0] for name in results)
    assert statuses == [201, 409], results
    assert _current_version(srv, key_id) == 2


def test_conflict_replayed_after_restart(http):
    env, srv = http
    key_id = _create(srv)
    status, body = _rotate(srv, key_id, "ev-restart", expected=9)
    assert status == 409
    operation_id = body["operation_id"]
    srv.stop()

    # A fresh server over the same data dir runs crash recovery: the
    # conflict is replayed from durable facts, never re-evaluated.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        status, op = srv2.request(
            "GET", "/v1/operations/%s" % operation_id, None,
            dict(OPERATOR, **{"X-Tenant-Id": "t1"}),
        )
        assert status == 200
        assert op["status"] == "conflict"
        assert op["http_status"] == 409
        assert op["response"] == body

        status, replay = _rotate(srv2, key_id, "ev-restart", expected=9)
        assert status == 409
        assert replay == body
        assert len([
            e for e in _events(env)
            if e.action == "rotate" and e.outcome == "rejected"
        ]) == 1
        assert _current_version(srv2, key_id) == 1
    finally:
        srv2.stop()


# -- batch rotate ----------------------------------------------------------

def test_batch_rotate_expected_version_all_match(http):
    env, srv = http
    key1 = _create(srv)
    key2 = _create(srv)
    status, body = _batch(srv, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 1},
    ], "bev-1")
    assert status == 201, body
    assert [item["version"] for item in body["items"]] == [2, 2]


def test_batch_rotate_one_mismatch_fails_whole_batch(http):
    env, srv = http
    key1 = _create(srv)
    key2 = _create(srv)
    handles_before = env.kms_handles()

    status, body = _batch(srv, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 7},
    ], "bev-mismatch")
    assert status == 409, body
    assert list(body.keys()) == ["error", "operation_id"]
    operation_id = body["operation_id"]

    # The whole batch is unchanged: no versions, no handles, one rejected
    # batch_rotate event with key_id null.
    assert _current_version(srv, key1) == 1
    assert _current_version(srv, key2) == 1
    assert env.kms_handles() == handles_before
    rejected = [
        e for e in _events(env)
        if e.action == "batch_rotate" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id is None
    assert rejected[0].event_id == operation_id

    status, op = srv.request(
        "GET", "/v1/operations/%s" % operation_id, None,
        dict(OPERATOR, **{"X-Tenant-Id": "t1"}),
    )
    assert status == 200
    assert op["status"] == "conflict"
    assert op["http_status"] == 409

    # Identical retry replays; no second event.
    status, replay = _batch(srv, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 7},
    ], "bev-mismatch")
    assert status == 409
    assert replay == body
    assert len([
        e for e in _events(env)
        if e.action == "batch_rotate" and e.outcome == "rejected"
    ]) == 1


def test_batch_rotate_mixed_present_and_absent_preconditions(http):
    env, srv = http
    key1 = _create(srv)
    key2 = _create(srv)
    status, body = _batch(srv, [
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256"},
    ], "bev-mixed")
    assert status == 201, body
    assert [item["version"] for item in body["items"]] == [2, 2]


@pytest.mark.parametrize("bad", [0, -2, "1", 2.5, False, None, [1]])
def test_batch_item_expected_version_invalid_is_400(http, bad):
    env, srv = http
    key_id = _create(srv)
    slug = "".join(c if c.isalnum() else "-" for c in repr(bad))
    status, body = _batch(srv, [
        {"key_id": key_id, "algorithm": "AES256", "expected_version": bad},
    ], "bev-bad-%s" % slug)
    assert status == 400, body
    assert "expected_version" in body["error"]
    assert "operation_id" not in body
    assert _rotation_events(env) == []
    assert _current_version(srv, key_id) == 1


def test_batch_item_extra_field_is_400(http):
    env, srv = http
    key_id = _create(srv)
    status, body = _batch(srv, [
        {"key_id": key_id, "algorithm": "AES256", "label": "x"},
    ], "bev-extra-item")
    assert status == 400, body
    assert "label" in body["error"]
    assert _rotation_events(env) == []


def test_batch_top_level_extra_field_is_400(http):
    env, srv = http
    key_id = _create(srv)
    status, body = _batch(
        srv,
        [{"key_id": key_id, "algorithm": "AES256"}],
        "bev-extra-top",
        extra={"note": "x"},
    )
    assert status == 400, body
    assert "note" in body["error"]
    assert _rotation_events(env) == []


# -- CLI -------------------------------------------------------------------

def test_cli_rotate_expected_version(http):
    env, srv = http
    key_id = _create(srv)

    result = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-ev-1", "--expected-version", "1",
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["version"] == 2

    # A stale expectation is a bound conflict (exit 3) with no new version.
    result = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-ev-2", "--expected-version", "1",
    )
    assert result.returncode == 3, result.stderr
    assert "expected_version" in result.stderr
    assert _current_version(srv, key_id) == 2

    # An invalid value is an exit-2 parameter error before any binding.
    result = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "cli-ev-3", "--expected-version", "0",
    )
    assert result.returncode == 2
    assert "expected_version" in result.stderr


def test_cli_batch_rotate_expected_version(http):
    env, srv = http
    key1 = _create(srv)
    key2 = _create(srv)
    items = json.dumps([
        {"key_id": key1, "algorithm": "AES256", "expected_version": 1},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 1},
    ])
    result = run_cli(
        env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--idempotency-key", "cli-bev-1", "--items", items,
    )
    assert result.returncode == 0, result.stderr
    assert [i["version"] for i in json.loads(result.stdout)["items"]] == [2, 2]

    stale = json.dumps([
        {"key_id": key1, "algorithm": "AES256", "expected_version": 2},
        {"key_id": key2, "algorithm": "AES256", "expected_version": 1},
    ])
    result = run_cli(
        env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--idempotency-key", "cli-bev-2", "--items", stale,
    )
    assert result.returncode == 3, result.stderr
    assert "expected_version" in result.stderr
    assert _current_version(srv, key1) == 2
    assert _current_version(srv, key2) == 2

    invalid = json.dumps([
        {"key_id": key1, "algorithm": "AES256", "expected_version": "2"},
    ])
    result = run_cli(
        env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--idempotency-key", "cli-bev-3", "--items", invalid,
    )
    assert result.returncode == 2
    assert "expected_version" in result.stderr
