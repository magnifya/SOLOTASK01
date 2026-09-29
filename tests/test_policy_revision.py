"""Opaque policy revisions and optimistic concurrency on /v1/policy."""

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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

from keymgr import provider as provider_mod  # noqa: E402
from keymgr import restore as restore_mod  # noqa: E402
from keymgr.artifacts import ArtifactStore  # noqa: E402
from keymgr.audit import AuditLog  # noqa: E402
from keymgr.operations import OperationStore  # noqa: E402
from keymgr.policy import PolicyStore, compute_revision, validate_rules  # noqa: E402
from keymgr.server import make_handler  # noqa: E402
from keymgr.store import KeyStore  # noqa: E402

RULES_A = [
    {"subject": "alice", "actions": ["read", "list"], "effect": "allow"},
    {"subject": "alice", "actions": ["rotate"], "effect": "deny"},
]
RULES_A_REORDERED = [
    {"subject": "alice", "actions": ["rotate"], "effect": "deny"},
    {"subject": "alice", "actions": ["list", "read"], "effect": "allow"},
]
RULES_B = [
    {"subject": "alice", "actions": ["read"], "effect": "allow"},
]


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
    yield types.SimpleNamespace(
        data_dir=data_dir,
        base="http://127.0.0.1:%d" % httpd.server_address[1],
        policies=policies,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _call(stack, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-Operator-Id": "admin"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(stack.base + path, data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _events(stack, action=None):
    events = AuditLog(stack.data_dir)._read_all()
    if action is not None:
        events = [e for e in events if e.action == action]
    return [(e.action, e.outcome) for e in events]


def _put(stack, rules, expected=None, tenant="t1"):
    path = "/v1/policy"
    if expected is not None:
        path += "?expected_revision=%s" % expected
    return _call(stack, "PUT", path,
                 {"tenant_id": tenant, "rules": rules})


def _get(stack, tenant="t1"):
    return _call(stack, "GET", "/v1/policy?tenant_id=%s" % tenant)


def _delete(stack, expected=None, tenant="t1"):
    path = "/v1/policy?tenant_id=%s" % tenant
    if expected is not None:
        path += "&expected_revision=%s" % expected
    return _call(stack, "DELETE", path)


# -- baseline behavior -------------------------------------------------------

def test_get_missing_is_404(stack):
    status, body = _get(stack)
    assert status == 404
    assert body == {"error": "policy not found"}
    assert stack.policies.get("t1") is None
    assert stack.policies.revision("t1") is None


def test_unconditional_put_get_delete_keep_legacy_shape(stack):
    status, body = _put(stack, RULES_A)
    assert status == 200
    assert set(body) == {"tenant_id", "rules", "revision"}
    revision = body["revision"]
    assert revision and revision != "none"

    status, body = _get(stack)
    assert status == 200
    assert set(body) == {"tenant_id", "rules", "revision"}
    assert body["revision"] == revision

    # Unconditional replace and delete still work without the parameter.
    status, body = _put(stack, RULES_B)
    assert status == 200
    assert body["revision"] != revision
    status, body = _delete(stack)
    assert status == 200
    assert body == {"tenant_id": "t1", "deleted": True}
    assert _get(stack)[0] == 404
    # Deleting again stays idempotent and audits a second success.
    assert _delete(stack)[0] == 200


def test_revision_is_stable_content_addressed_and_opaque(stack):
    assert compute_revision(validate_rules([]))
    assert compute_revision(validate_rules([])) != "none"
    assert (
        compute_revision(validate_rules(RULES_A))
        == compute_revision(validate_rules(RULES_A_REORDERED))
    )
    rev1 = _put(stack, RULES_A)[1]["revision"]
    # Same semantic content (rule order and in-rule action order swapped)
    # keeps the revision; a different content changes it.
    rev2 = _put(stack, RULES_A_REORDERED)[1]["revision"]
    assert rev2 == rev1
    rev3 = _put(stack, RULES_B)[1]["revision"]
    assert rev3 != rev1
    # GET agrees, and the value looks like an opaque digest, not a path.
    assert _get(stack)[1]["revision"] == rev3
    assert "/" not in rev3 and "." not in rev3
    # Empty rules are a document too, with their own stable revision.
    rev_empty = _put(stack, [])[1]["revision"]
    assert rev_empty != rev3
    assert _put(stack, [])[1]["revision"] == rev_empty


# -- conditional updates -----------------------------------------------------

def test_create_with_expected_none_succeeds_then_conflicts(stack):
    status, body = _put(stack, RULES_A, expected="none")
    assert status == 200
    revision = body["revision"]
    # A second create asserting absence fails without touching rules.
    status, body = _put(stack, RULES_B, expected="none")
    assert status == 409
    assert body == {
        "error": "policy revision conflict",
        "current_revision": revision,
    }
    assert _get(stack)[1]["revision"] == revision
    assert _events(stack, "policy_update") == [
        ("policy_update", "success"),
        ("policy_update", "rejected"),
    ]


def test_expected_revision_match_and_stale_conflict(stack):
    revision = _put(stack, RULES_A)[1]["revision"]
    status, body = _put(stack, RULES_B, expected=revision)
    assert status == 200
    new_revision = body["revision"]
    assert new_revision != revision

    status, body = _put(stack, RULES_A, expected=revision)
    assert status == 409
    assert body == {
        "error": "policy revision conflict",
        "current_revision": new_revision,
    }
    # Rules and audit show exactly the two successful replaces.
    assert _get(stack)[1]["revision"] == new_revision
    assert _events(stack, "policy_update") == [
        ("policy_update", "success"),
        ("policy_update", "success"),
        ("policy_update", "rejected"),
    ]


def test_expected_revision_when_no_policy_is_conflict_null(stack):
    status, body = _put(stack, RULES_A, expected="rev-does-not-exist")
    assert status == 409
    assert body == {
        "error": "policy revision conflict",
        "current_revision": None,
    }
    assert _get(stack)[0] == 404
    assert _events(stack, "policy_update") == [
        ("policy_update", "rejected"),
    ]


def test_conditional_delete_match_mismatch_and_none(stack):
    revision = _put(stack, RULES_A)[1]["revision"]

    # A revision given while no policy exists (after an unconditional delete)
    # is a null-current conflict.
    assert _delete(stack)[0] == 200
    status, body = _delete(stack, expected=revision)
    assert status == 409
    assert body == {
        "error": "policy revision conflict",
        "current_revision": None,
    }

    # none asserts absence: matches an empty tenant, fails with a document.
    assert _delete(stack, expected="none")[0] == 200
    revision = _put(stack, RULES_A, expected="none")[1]["revision"]
    status, body = _delete(stack, expected="none")
    assert status == 409
    assert body["current_revision"] == revision
    assert _get(stack)[0] == 200

    # Stale revision conflicts and leaves the document.
    assert _put(stack, RULES_B)[1]["revision"]
    status, body = _delete(stack, expected=revision)
    assert status == 409
    assert body["current_revision"] is not None
    assert _get(stack)[0] == 200

    current = _get(stack)[1]["revision"]
    assert _delete(stack, expected=current)[0] == 200
    assert _get(stack)[0] == 404
    outcomes = _events(stack, "policy_delete")
    assert outcomes.count(("policy_delete", "rejected")) == 3
    assert outcomes[-1] == ("policy_delete", "success")
    # Delete then recreate works; same content earns the same revision.
    recreated = _put(stack, RULES_B, expected="none")[1]["revision"]
    assert recreated == current


def test_malformed_expected_revision_is_400_without_side_effects(stack):
    _put(stack, RULES_A)
    rules_before = _get(stack)[1]
    before = _events(stack)

    status, _ = _call(
        stack, "PUT",
        "/v1/policy?expected_revision=&expected_revision=none",
        {"tenant_id": "t1", "rules": RULES_B},
    )
    assert status == 400
    status, _ = _call(
        stack, "PUT", "/v1/policy?expected_revision=",
        {"tenant_id": "t1", "rules": RULES_B},
    )
    assert status == 400
    status, _ = _call(
        stack, "DELETE",
        "/v1/policy?tenant_id=t1&expected_revision=rev-x"
        "&expected_revision=none",
    )
    assert status == 400
    status, _ = _call(
        stack, "DELETE", "/v1/policy?tenant_id=t1&expected_revision=",
    )
    assert status == 400

    # Nothing changed: no new audit, same rules.
    assert _events(stack) == before
    assert _get(stack)[1] == rules_before


def test_concurrent_same_revision_only_one_wins(stack):
    revision = _put(stack, RULES_A)[1]["revision"]
    results = []

    def worker(rules):
        results.append(_put(stack, rules, expected=revision))

    t1 = threading.Thread(target=worker, args=(RULES_B,))
    t2 = threading.Thread(
        target=worker,
        args=([{"subject": "bob", "actions": ["read"],
                "effect": "allow"}],),
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    statuses = sorted(status for status, _ in results)
    assert statuses == [200, 409]
    winner = next(body for status, body in results if status == 200)
    loser = next(body for status, body in results if status == 409)
    assert loser["error"] == "policy revision conflict"
    assert loser["current_revision"] == winner["revision"]
    assert _get(stack)[1]["revision"] == winner["revision"]
    assert _events(stack, "policy_update") == [
        ("policy_update", "success"),
        ("policy_update", "success"),
        ("policy_update", "rejected"),
    ]


def test_other_tenant_independent(stack):
    rev_a = _put(stack, RULES_A, tenant="t1", expected="none")[1]["revision"]
    rev_b = _put(stack, RULES_B, tenant="t2", expected="none")[1]["revision"]
    assert rev_a != rev_b
    # t1's revision does not authorize a change on t2.
    status, body = _put(stack, RULES_A, expected=rev_a, tenant="t2")
    assert status == 409
    assert body["current_revision"] == rev_b


# -- CLI parity --------------------------------------------------------------

def _run_cli(stack, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = TESTS_DIR + os.pathsep + REPO_ROOT
    env.pop("KEYMGR_PROVIDER", None)
    cmd = [sys.executable, "-m", "keymgr", "--data-dir", stack.data_dir]
    cmd += [str(a) for a in args]
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=30)


def test_cli_show_set_delete_revision_parity(stack):
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules", json.dumps(RULES_A),
        "--expected-revision", "none",
    )
    assert proc.returncode == 0, proc.stderr
    set_body = json.loads(proc.stdout)
    assert set(set_body) == {"tenant_id", "rules", "revision"}
    revision = set_body["revision"]

    proc = _run_cli(
        stack, "policy", "--operator", "admin", "show", "--tenant-id", "t1",
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["revision"] == revision

    # Stale revision: same 409 body as HTTP on stderr, exit code 5.
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "delete",
        "--tenant-id", "t1", "--expected-revision", "rev-stale",
    )
    assert proc.returncode == 5
    assert json.loads(proc.stderr) == {
        "error": "policy revision conflict",
        "current_revision": revision,
    }

    # Matching revision deletes; afterwards show reports not found (4).
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "delete",
        "--tenant-id", "t1", "--expected-revision", revision,
    )
    assert proc.returncode == 0, proc.stderr
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "show", "--tenant-id", "t1",
    )
    assert proc.returncode == 4

    # Empty --expected-revision is a usage error with no side effects.
    revision2 = _put(stack, RULES_A)[1]["revision"]
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules", json.dumps(RULES_B),
        "--expected-revision", "",
    )
    assert proc.returncode == 2
    assert _get(stack)[1]["revision"] == revision2

    # Omitted flag keeps the unconditional legacy behavior.
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "set",
        "--tenant-id", "t1", "--rules", json.dumps(RULES_B),
    )
    assert proc.returncode == 0, proc.stderr
    proc = _run_cli(
        stack, "policy", "--operator", "admin", "delete",
        "--tenant-id", "t1",
    )
    assert proc.returncode == 0, proc.stderr
    assert _get(stack)[0] == 404
