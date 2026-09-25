"""Tests for the directed KMS/HSM switchover (POST /v1/provider/switchover).

Covers:

* request validation: single non-empty operator, tenant_id rejected, body
  strictly ``{"provider_id": P}`` with P non-empty -- every violation is a
  side-effect-free 400 naming the field;
* a missing provider chain or a target not in the chain is a 400 naming
  provider_id with zero side effects;
* a successful switch commits ``switching`` (old id, P, original generation,
  reason reconnect) then ``ready`` (P, null, generation+1) and answers 200
  ``provider_id,status`` = (P, ready);
* P already active: healthy -> 200 with the generation unchanged, unhealthy
  -> fixed 503;
* target build/contract/health failure or an exhausted gate budget -> fixed
  503 with the old generation retained byte-for-byte;
* a crash between the two commits is completed only for a healthy target,
  otherwise the ``switching`` record is kept and the answer is 503;
* concurrent switchovers to the same target commit exactly once;
* the CLI ``provider switchover`` maps 400 -> exit 2 and 503 -> exit 1.
"""

import http.client as http_client
import json
import os
import threading
import time

import pytest

from keymgr import provider as provider_mod

from test_provider_reconnect import (
    OPERATOR,
    HttpServer,
    _hold_intent_exclusive,
    _release_intent,
)
from test_recovery_cli import run_cli

CHAIN = "local,fake_kms:make_provider"


@pytest.fixture()
def chain_env(env, monkeypatch):
    """A data dir wired to a two-entry primary/standby chain."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()


def _state_path(env):
    return os.path.join(env.data_dir, "provider-state.json")


def _read_state(env):
    with open(_state_path(env), "rb") as fh:
        return json.loads(fh.read())


def _read_state_raw(env):
    with open(_state_path(env), "rb") as fh:
        return fh.read()


def _write_state(env, payload):
    with open(_state_path(env), "wb") as fh:
        fh.write(json.dumps(payload).encode("utf-8"))


def _activate(env, srv):
    """Force the first healthy activation (local, generation 1)."""
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200
    assert body == {"provider_id": "local", "status": "ready"}
    assert _read_state(env)["generation"] == 1


def _switchover(srv, provider_id, headers=None):
    return srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id}, headers or OPERATOR,
    )


# -- request validation ------------------------------------------------------
def test_switchover_requires_single_operator(http):
    env, srv = http
    # Missing operator.
    status, _ = srv.request(
        "POST", "/v1/provider/switchover", {"provider_id": "fakekms"}
    )
    assert status == 400
    # Duplicate X-Operator-Id headers are a 400 as well.
    raw = b'{"provider_id":"fakekms"}'
    conn = http_client.HTTPConnection("127.0.0.1", srv.port)
    conn.putrequest("POST", "/v1/provider/switchover")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("X-Operator-Id", "a")
    conn.putheader("X-Operator-Id", "b")
    conn.putheader("Content-Length", str(len(raw)))
    conn.endheaders(raw)
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 400
    conn.close()
    assert not os.path.exists(_state_path(env))


def test_switchover_rejects_tenant_id_everywhere(http):
    env, srv = http
    status, body = srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": "fakekms", "tenant_id": "t1"}, OPERATOR,
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    status, body = srv.raw(
        "POST", "/v1/provider/switchover?tenant_id=t1",
        b'{"provider_id":"fakekms"}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400
    assert "tenant_id" in body
    status, body = srv.request(
        "POST", "/v1/provider/switchover", {"provider_id": "fakekms"},
        {"X-Operator-Id": "alice", "X-Tenant-Id": "t1"},
    )
    assert status == 400
    assert "tenant_id" in body["error"]
    # Zero side effects: no activation, no state file.
    assert not os.path.exists(_state_path(env))


def test_switchover_body_must_be_strictly_provider_id(http):
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
    # Missing provider_id.
    status, body = srv.request("POST", "/v1/provider/switchover", {}, OPERATOR)
    assert status == 400
    assert "provider_id" in body["error"]
    # Empty / non-string provider_id.
    for bad in ("", None, 7, ["fakekms"]):
        status, body = _switchover(srv, bad)
        assert status == 400, bad
        assert "provider_id" in body["error"]
    # Extra fields.
    status, body = srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": "fakekms", "x": 1}, OPERATOR,
    )
    assert status == 400
    # Zero side effects.
    assert not os.path.exists(_state_path(env))


def test_switchover_without_chain_is_400_naming_provider_id(env):
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        status, body = _switchover(srv, "fakekms")
        assert status == 400
        assert "provider_id" in body["error"]
        assert not os.path.exists(_state_path(env))
    finally:
        srv.stop()


def test_switchover_target_not_in_chain_is_400(http):
    env, srv = http
    _activate(env, srv)
    before = _read_state_raw(env)
    status, body = _switchover(srv, "nosuch")
    assert status == 400
    assert "provider_id" in body["error"]
    # The committed state is untouched.
    assert _read_state_raw(env) == before


def test_not_in_chain_400_is_instant_and_side_effect_free(chain_env):
    # Even with another switch/reconnect holding the drain gate, an
    # out-of-chain target is a 400 without waiting and creates no state
    # (no provider-state.json, no local DEK).
    provider_mod.bind_data_dir(chain_env.data_dir)
    fd = _hold_intent_exclusive(chain_env)
    t0 = time.monotonic()
    try:
        with pytest.raises(provider_mod.ProviderSwitchoverInvalid):
            provider_mod.switchover("nosuch")
    finally:
        _release_intent(fd)
    # It never entered the gate: the 400 returns immediately rather than
    # burning the five-second budget behind the held intent.
    assert time.monotonic() - t0 < 1.0
    # Only the intent lock file (opened to hold the fence) may exist; no
    # committed state and no local provider state were created.
    entries = set(os.listdir(chain_env.data_dir))
    assert "provider-state.json" not in entries
    assert "local.dek" not in entries
    assert "local-registry.json" not in entries


def test_not_in_chain_400_never_configures_entries(chain_env):
    # On a fresh data dir an unknown P returns 400 and creates nothing at
    # all: membership is proven with unconfigured builds.
    provider_mod.bind_data_dir(chain_env.data_dir)
    with pytest.raises(provider_mod.ProviderSwitchoverInvalid):
        provider_mod.switchover("nosuch")
    assert os.listdir(chain_env.data_dir) == []


# -- successful directed switch ----------------------------------------------
def test_switchover_commits_switching_then_ready(http):
    env, srv = http
    _activate(env, srv)
    status, text = srv.raw(
        "POST", "/v1/provider/switchover", b'{"provider_id":"fakekms"}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 200
    body = json.loads(text)
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}
    # Final committed state: ready(P, null, generation+1, reconnect).
    assert _read_state(env) == {
        "schema_version": 2,
        "provider_id": "fakekms",
        "target_provider_id": None,
        "generation": 2,
        "reason": "reconnect",
        "phase": "ready",
    }
    # The new active instance serves; switching back commits generation 3.
    status, body = _switchover(srv, "local")
    assert status == 200
    assert body == {"provider_id": "local", "status": "ready"}
    assert _read_state(env)["generation"] == 3


def test_switchover_as_first_activation_commits_generation_1(http):
    env, srv = http
    status, body = _switchover(srv, "fakekms")
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "ready"}
    assert _read_state(env) == {
        "schema_version": 2,
        "provider_id": "fakekms",
        "target_provider_id": None,
        "generation": 1,
        "reason": "initial",
        "phase": "ready",
    }


def test_switchover_to_current_healthy_is_200_generation_unchanged(http):
    env, srv = http
    _activate(env, srv)
    before = _read_state_raw(env)
    status, body = _switchover(srv, "local")
    assert status == 200
    assert body == {"provider_id": "local", "status": "ready"}
    # The generation (and the whole file) is unchanged.
    assert _read_state_raw(env) == before


def test_switchover_to_current_unhealthy_is_503(http):
    env, srv = http
    _activate(env, srv)
    assert _switchover(srv, "fakekms")[0] == 200
    before = _read_state_raw(env)
    env.set_faults({"health": False})
    try:
        status, body = _switchover(srv, "fakekms")
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
        assert _read_state_raw(env) == before
    finally:
        env.clear_faults()


# -- failures keep the old generation ----------------------------------------
def test_switchover_target_unhealthy_keeps_old_generation(http):
    env, srv = http
    _activate(env, srv)
    before = _read_state_raw(env)
    env.set_faults({"health": False})
    try:
        status, body = _switchover(srv, "fakekms")
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
        assert _read_state_raw(env) == before
    finally:
        env.clear_faults()
    # Once healthy again the same switch succeeds.
    status, body = _switchover(srv, "fakekms")
    assert status == 200
    assert _read_state(env)["generation"] == 2


def test_switchover_target_factory_failure_keeps_old_generation(http):
    env, srv = http
    _activate(env, srv)
    before = _read_state_raw(env)
    env.set_faults({"factory_fails": True})
    try:
        status, body = _switchover(srv, "fakekms")
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
        assert _read_state_raw(env) == before
    finally:
        env.clear_faults()


def test_switchover_gate_timeout_is_503_zero_side_effects(http, monkeypatch):
    env, srv = http
    _activate(env, srv)
    before = _read_state_raw(env)
    fd = _hold_intent_exclusive(env)
    try:
        monkeypatch.setattr(provider_mod, "CALL_GATE_SECONDS", 0.4)
        t0 = time.monotonic()
        status, body = _switchover(srv, "fakekms")
        waited = time.monotonic() - t0
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
        assert waited >= 0.35
        assert _read_state_raw(env) == before
    finally:
        _release_intent(fd)
    # The gate is clear again; the switch now succeeds.
    status, _ = _switchover(srv, "fakekms")
    assert status == 200


# -- crash between the two commits -------------------------------------------
def _write_switching(env, target="fakekms", generation=1):
    _write_state(env, {
        "schema_version": 2,
        "provider_id": "local",
        "target_provider_id": target,
        "generation": generation,
        "reason": "reconnect",
        "phase": "switching",
    })


def test_interrupted_switch_completed_for_healthy_target(http):
    env, srv = http
    _write_switching(env)
    status, body = _switchover(srv, "fakekms")
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "ready"}
    assert _read_state(env) == {
        "schema_version": 2,
        "provider_id": "fakekms",
        "target_provider_id": None,
        "generation": 2,
        "reason": "reconnect",
        "phase": "ready",
    }


def test_interrupted_switch_kept_for_unhealthy_target(http):
    env, srv = http
    _write_switching(env)
    before = _read_state_raw(env)
    env.set_faults({"health": False})
    try:
        status, body = _switchover(srv, "fakekms")
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
        # The switching record is kept byte-for-byte.
        assert _read_state_raw(env) == before
    finally:
        env.clear_faults()


# -- concurrency: same target commits once ------------------------------------
def test_concurrent_switchovers_to_same_target_commit_once(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    provider_mod.get_provider()  # local, generation 1
    results = []
    errors = []

    def switch():
        try:
            results.append(provider_mod.switchover("fakekms"))
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append(exc)

    threads = [threading.Thread(target=switch) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15.0)
        assert not t.is_alive()
    assert not errors
    assert len(results) == 4
    assert {"provider_id": "fakekms", "status": "ready"} == results[0]
    # Exactly one commit: generation moved 1 -> 2, not once per caller.
    assert _read_state(chain_env)["generation"] == 2


def test_switchover_drains_in_flight_calls(chain_env):
    # An in-flight call finishes on the instance it captured; the switch
    # commits only after it releases.
    provider_mod.bind_data_dir(chain_env.data_dir)
    provider_mod.get_provider()
    entered = threading.Event()
    release = threading.Event()
    seen = {}

    def in_flight():
        with provider_mod.provider_call() as provider:
            seen["old"] = provider
            entered.set()
            release.wait(5.0)
            seen["still"] = provider_mod.get_provider()

    worker = threading.Thread(target=in_flight)
    worker.start()
    assert entered.wait(2.0)

    done = threading.Event()

    def switching():
        provider_mod.switchover("fakekms")
        done.set()

    sw = threading.Thread(target=switching)
    sw.start()
    time.sleep(0.2)
    # The switch is parked behind the in-flight call's lease.
    assert not done.is_set()
    release.set()
    sw.join(5.0)
    worker.join(5.0)
    assert done.is_set()
    assert seen["old"].provider_id == "local"
    assert seen["still"].provider_id == "local"
    assert provider_mod.get_provider().provider_id == "fakekms"
    assert _read_state(chain_env)["generation"] == 2


# -- CLI ----------------------------------------------------------------------
def test_cli_switchover_success_and_key_order(chain_env):
    result = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout.strip())
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}
    assert _read_state(chain_env)["generation"] == 1


def test_cli_switchover_without_chain_exit_2(env):
    result = run_cli(
        env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert result.returncode == 2
    assert "provider_id" in json.loads(result.stderr.strip())["error"]


def test_cli_switchover_unknown_provider_id_exit_2(chain_env):
    result = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "nosuch",
    )
    assert result.returncode == 2
    assert "provider_id" in json.loads(result.stderr.strip())["error"]


def test_cli_switchover_unhealthy_target_exit_1(chain_env):
    chain_env.set_faults({"health": False})
    result = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "fakekms",
    )
    assert result.returncode == 1
    assert json.loads(result.stderr.strip()) == {
        "error": "key management provider is unavailable",
    }


def test_cli_switchover_requires_operator_and_provider_id(chain_env):
    result = run_cli(chain_env, "provider", "switchover")
    assert result.returncode == 2
    result = run_cli(
        chain_env, "provider", "switchover", "--operator", "alice"
    )
    assert result.returncode == 2
    result = run_cli(
        chain_env, "provider", "switchover",
        "--operator", "alice", "--provider-id", "",
    )
    assert result.returncode == 2
