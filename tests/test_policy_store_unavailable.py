"""An existing but unreadable/unparseable policy document fails closed.

Policy read (GET /v1/policy, ``policy show``), authorization on every
governed endpoint, replacement (PUT / ``policy set``) and deletion (DELETE
/ ``policy delete``) all answer the fixed
``{"error":"policy store is unavailable"}`` 500 (CLI: same body, exit 1).
The request must never be allowed through, must not look like a 404, must
not overwrite the original file, and must write neither a success nor a
rejected audit event.
"""

import json
import os

import pytest

from test_version_history import _build_server, _make_key
from test_recovery_cli import run_cli


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


def _policy_path(stack, tenant="t"):
    return stack.policies.path_for(tenant)


def _actions(stack):
    return sorted(
        (e.action, e.outcome) for e in stack.audit._read_all()
    )


def _corrupt(stack, tenant="t", content="{corrupt"):
    stack.policies.put(tenant, [])
    path = _policy_path(stack, tenant)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_http_policy_read_replace_delete_fixed_500_without_audit(stack):
    client = stack.client
    path = _corrupt(stack)
    raw_before = open(path, "rb").read()
    events_before = list(stack.audit._read_all())

    status, body = client.call("GET", "/v1/policy?tenant_id=t")
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )

    status, body = client.call(
        "PUT", "/v1/policy?tenant_id=t",
        {"tenant_id": "t", "rules": []},
        operator="admin",
    )
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )

    status, body = client.call(
        "DELETE", "/v1/policy?tenant_id=t", operator="admin"
    )
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )

    # The corrupt document is neither overwritten nor deleted.
    assert open(path, "rb").read() == raw_before
    assert os.path.exists(path)
    # The failed requests appended no events at all (the setup put event
    # recorded during _corrupt is the only policy_ event).
    assert [e.event_id for e in stack.audit._read_all()] == [
        e.event_id for e in events_before
    ]


def test_missing_policy_is_still_404(stack):
    status, body = stack.client.call("GET", "/v1/policy?tenant_id=ghost")
    assert (status, body) == (404, {"error": "policy not found"})


def test_authorization_fails_closed_on_governed_endpoints(stack):
    client = stack.client
    _corrupt(stack)
    before = _actions(stack)

    # POST /v1/keys (create action) must not be allowed through.
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": "t", "algorithm": "AES256", "label": "k"},
    )
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )

    # GET /v1/audit (audit action), same treatment.
    status, body = client.call("GET", "/v1/audit?tenant_id=t")
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )

    # No rejected/success audit was written by either failed authorization.
    assert _actions(stack) == before


def test_bound_idempotent_authorization_500_writes_nothing(stack):
    client = stack.client
    kid = _make_key(client)
    _corrupt(stack)
    versions_before = len(
        [n for n in os.listdir(stack.data_dir) if n.endswith(".json")]
    )
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % kid,
        {"tenant_id": "t", "algorithm": "AES256"},
        headers={"Idempotency-Key": "rot-corrupt-policy"},
    )
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )
    # No rotate event (success or rejected) and no key-file churn.
    assert not [
        e for e in stack.audit._read_all() if e.action == "rotate"
    ]
    assert len(
        [n for n in os.listdir(stack.data_dir) if n.endswith(".json")]
    ) == versions_before


def test_cli_policy_show_set_delete_and_enforcement_fixed_body_exit_1(stack):
    env = stack
    path = _corrupt(stack)
    raw_before = open(path, "rb").read()
    events_before = list(stack.audit._read_all())

    for argv in (
        ["policy", "--operator", "admin", "show", "--tenant-id", "t"],
        ["policy", "--operator", "admin", "set", "--tenant-id", "t",
         "--rules", "[]"],
        ["policy", "--operator", "admin", "delete", "--tenant-id", "t"],
    ):
        proc = run_cli(env, *argv)
        assert proc.returncode == 1, argv
        assert json.loads(proc.stderr) == {
            "error": "policy store is unavailable"
        }, argv

    # Enforcement on a regular tenant command fails closed as well.
    proc = run_cli(
        env, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert proc.returncode == 1
    assert json.loads(proc.stderr) == {
        "error": "policy store is unavailable"
    }

    assert open(path, "rb").read() == raw_before
    # The corrupt-policy put from setup may legitimately predate the
    # requests; the failed CLI calls must append nothing new.
    assert [e.event_id for e in stack.audit._read_all()] == [
        e.event_id for e in events_before
    ]


def test_structurally_corrupt_rules_also_500(stack):
    client = stack.client
    path = _corrupt(stack, content='{"tenant_id":"t","rules":[{"subject":'
                                  '"a","actions":["nope"],"effect":'
                                  '"allow"}]}')
    assert open(path).read  # sanity
    status, body = client.call("GET", "/v1/policy?tenant_id=t")
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )
    status, body = client.call(
        "POST", "/v1/policy/check?tenant_id=t",
        {"subject": "a", "action": "read"},
    )
    assert (status, body) == (
        500, {"error": "policy store is unavailable"}
    )
