"""Tests for the directed KMS/HSM provider switchover.

Covers ``POST /v1/provider/switchover`` and ``provider switchover``:

* request validation (strict ``{"provider_id": P}`` body, single operator,
  no tenant_id) -- every rejection is a zero-side-effect 400 naming the
  field;
* an unset chain or a target the chain does not build is a 400;
* a successful directed switch commits ``switching`` then ``ready``
  (generation+1, reason ``reconnect``) and answers ``provider_id,status``;
* a target that is already current commits nothing: healthy is 200 with the
  generation unchanged, unhealthy is the fixed 503;
* a target build/health failure keeps the old state byte-for-byte (503);
* a crash between the two commits completes only for a healthy target;
* concurrent switchovers to the same target commit exactly once.
"""

import json
import os
import threading

import pytest

from keymgr import provider as provider_mod

from test_provider_reconnect import HttpServer, OPERATOR
from test_recovery_cli import run_cli

CHAIN = "fake_kms:make_provider,local"


@pytest.fixture()
def http(env):
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()


def _state_file(env):
    path = os.path.join(env.data_dir, "provider-state.json")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _state(env):
    return json.loads(_state_file(env))


def _create_key(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _switch(srv, target, headers=None):
    return srv.request(
        "POST", "/v1/provider/switchover", {"provider_id": target},
        headers or OPERATOR,
    )


# -- request validation ------------------------------------------------------
def test_switchover_requires_operator(http):
    env, srv = http
    status, body = srv.request(
        "POST", "/v1/provider/switchover", {"provider_id": "local"}
    )
    assert status == 400
    assert "X-Operator-Id" in body["error"]


def test_switchover_rejects_tenant_id(http):
    env, srv = http
    for kwargs in (
        {"body": {"provider_id": "local", "tenant_id": "t1"}},
        {"body": {"provider_id": "local"},
         "headers": {**OPERATOR, "X-Tenant-Id": "t1"}},
    ):
        status, body = srv.request(
            "POST", "/v1/provider/switchover",
            kwargs["body"], kwargs.get("headers", OPERATOR),
        )
        assert status == 400
        assert "tenant_id" in body["error"]
    status, body = srv.raw(
        "POST", "/v1/provider/switchover?tenant_id=t1",
        b'{"provider_id":"local"}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400
    assert "tenant_id" in body


def test_switchover_strict_body(http):
    env, srv = http
    # Bad JSON.
    status, body = srv.raw(
        "POST", "/v1/provider/switchover", b"{not json",
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400
    # Non-object body.
    status, _ = srv.request("POST", "/v1/provider/switchover", [], OPERATOR)
    assert status == 400
    # Extra field.
    status, body = srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": "local", "extra": 1}, OPERATOR,
    )
    assert status == 400
    assert "extra" in body["error"]
    # Missing provider_id.
    status, body = srv.request(
        "POST", "/v1/provider/switchover", {}, OPERATOR
    )
    assert status == 400
    assert "provider_id" in body["error"]
    # Empty / non-string provider_id.
    for bad in ("", 7, None):
        status, body = srv.request(
            "POST", "/v1/provider/switchover", {"provider_id": bad}, OPERATOR
        )
        assert status == 400
        assert "provider_id" in body["error"]
    # Zero side effects: no state file, no audit events.
    assert not os.path.exists(
        os.path.join(env.data_dir, "provider-state.json")
    )
    assert env.audit_events() == []


def test_switchover_without_chain_is_400(http):
    env, srv = http
    status, body = _switch(srv, "fakekms")
    assert status == 400
    assert "provider_id" in body["error"]
    assert not os.path.exists(
        os.path.join(env.data_dir, "provider-state.json")
    )


def test_switchover_target_not_in_chain_is_400(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    status, body = _switch(srv, "nosuch")
    assert status == 400
    assert "provider_id" in body["error"]
    assert not os.path.exists(
        os.path.join(env.data_dir, "provider-state.json")
    )


# -- successful directed switch ----------------------------------------------
def test_switchover_success_commits_switching_then_ready(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    _create_key(srv)
    assert _state(env) == {
        "schema_version": 2, "provider_id": "fakekms",
        "target_provider_id": None, "generation": 1,
        "reason": "initial", "phase": "ready",
    }
    status, body = _switch(srv, "local")
    assert status == 200
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "local", "status": "ready"}
    assert _state(env) == {
        "schema_version": 2, "provider_id": "local",
        "target_provider_id": None, "generation": 2,
        "reason": "reconnect", "phase": "ready",
    }
    # The active provider really moved: new keys are owned by local.
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert body == {"provider_id": "local", "status": "ready"}
    # Switching back names the other entry and bumps the generation once.
    status, body = _switch(srv, "fakekms")
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "ready"}
    assert _state(env)["generation"] == 3


def test_switchover_to_current_healthy_keeps_generation(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    _create_key(srv)
    status, body = _switch(srv, "fakekms")
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "ready"}
    assert _state(env)["generation"] == 1


def test_switchover_to_current_unhealthy_is_503_zero_side_effects(
    http, monkeypatch
):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    _create_key(srv)
    before = _state_file(env)
    env.set_faults({"health": False})
    status, body = _switch(srv, "fakekms")
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _state_file(env) == before


def test_switchover_target_unhealthy_keeps_old_state(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    # The KMS probes unhealthy from the start, so activation picks local.
    env.set_faults({"health": False})
    _create_key(srv)
    assert _state(env)["provider_id"] == "local"
    before = _state_file(env)
    # The directed target (fakekms) is unhealthy: 503, old state untouched.
    status, body = _switch(srv, "fakekms")
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _state_file(env) == before


def test_switchover_target_factory_failure_is_503(http, monkeypatch):
    monkeypatch.setenv(
        "KEYMGR_PROVIDER_CHAIN", "local,fake_kms:make_provider"
    )
    env, srv = http
    _create_key(srv)  # activates local (first healthy entry)
    before = _state_file(env)
    env.set_faults({"factory_fails": True})
    status, body = _switch(srv, "fakekms")
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _state_file(env) == before


# -- crash between the two commits -------------------------------------------
def _plant_switching(env, old, target, generation=1):
    payload = json.dumps(
        {
            "schema_version": 2,
            "provider_id": old,
            "target_provider_id": target,
            "generation": generation,
            "reason": "reconnect",
            "phase": "switching",
        },
        separators=(",", ":"),
    )
    with open(
        os.path.join(env.data_dir, "provider-state.json"), "w",
        encoding="utf-8",
    ) as fh:
        fh.write(payload)


def test_interrupted_switch_completes_for_healthy_target(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    _create_key(srv)
    _plant_switching(env, "fakekms", "local")
    status, body = _switch(srv, "local")
    assert status == 200
    assert body == {"provider_id": "local", "status": "ready"}
    assert _state(env) == {
        "schema_version": 2, "provider_id": "local",
        "target_provider_id": None, "generation": 2,
        "reason": "reconnect", "phase": "ready",
    }


def test_interrupted_switch_kept_for_unhealthy_target(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    _create_key(srv)
    _plant_switching(env, "local", "fakekms")
    before = _state_file(env)
    env.set_faults({"health": False})
    status, body = _switch(srv, "fakekms")
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _state_file(env) == before


# -- concurrency ---------------------------------------------------------------
def test_concurrent_switchovers_to_same_target_commit_once(http, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    env, srv = http
    _create_key(srv)
    results = []

    def run():
        try:
            results.append(provider_mod.switchover("local"))
        except Exception as exc:  # pragma: no cover - failure path
            results.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(
        r == {"provider_id": "local", "status": "ready"} for r in results
    )
    # Exactly one commit: generation moved by one, not by four.
    assert _state(env)["generation"] == 2


# -- CLI -----------------------------------------------------------------------
def test_cli_switchover_success(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    result = run_cli(env, "provider", "switchover", "--operator", "alice",
                     "--provider-id", "local")
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "local", "status": "ready"}
    assert "\n" not in result.stdout.strip()
    assert _state(env)["provider_id"] == "local"


def test_cli_switchover_unknown_target_exit_2(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    result = run_cli(env, "provider", "switchover", "--operator", "alice",
                     "--provider-id", "nosuch")
    assert result.returncode == 2
    assert "provider_id" in result.stderr


def test_cli_switchover_without_chain_exit_2(env):
    result = run_cli(env, "provider", "switchover", "--operator", "alice",
                     "--provider-id", "fakekms")
    assert result.returncode == 2
    assert "provider_id" in result.stderr


def test_cli_switchover_unhealthy_target_exit_1(env, monkeypatch):
    monkeypatch.setenv(
        "KEYMGR_PROVIDER_CHAIN", "local,fake_kms:make_provider"
    )
    result = run_cli(env, "provider", "switchover", "--operator", "alice",
                     "--provider-id", "local")
    assert result.returncode == 0, result.stderr
    env.set_faults({"health": False})
    result = run_cli(env, "provider", "switchover", "--operator", "alice",
                     "--provider-id", "fakekms")
    assert result.returncode == 1
    assert json.loads(result.stderr) == {
        "error": "key management provider is unavailable"
    }
    assert _state(env)["provider_id"] == "local"
