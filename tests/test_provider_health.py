"""Tests for the persistent KMS/HSM primary/standby failure threshold.

Every ordinary provider call probes the ACTIVE instance first:

* a probe returning exactly ``True`` clears the persisted failure count and the
  call proceeds;
* a probe returning ``False``/a non-bool/raising (or one past the shared
  five-second budget) increments the active entry's persisted failure count,
  capped at three, and pins the call to the fixed 503;
* the first two failures never switch; the THIRD re-verifies the active entry
  inside the existing five-second cross-process intent/drain gate: a recovered
  active clears the count and serves the call, otherwise the active generation
  fails over exactly once to the first healthy standby and increments the
  generation;
* with no healthy standby (or on gate timeout) the old generation is retained.

The threshold lives in ``provider-health.json`` (0600): compact UTF-8 JSON,
fixed key order ``schema_version,provider_id,generation,status,
consecutive_failures``, non-ASCII as-is, no trailing newline, fsync + atomic
rename. It is a satellite of a READY ``provider-state.json`` with the same id
and generation: missing/lagging is rebuilt ready/0; corrupt, ahead, or
same-generation-wrong-id is a fixed 503 and never rewritten. A switch commits
``provider-state.json`` first and the new generation's ready/0 health second.
Pending idempotent operations stay bound to their original provider_id and are
never replayed on the standby after an automatic failover.
"""

import json
import os
import threading
import time

import pytest

from keymgr import provider as provider_mod

from test_provider_reconnect import OPERATOR, HttpServer, _create_key
from test_recovery_cli import run_cli

# fakekms first so the first healthy activation makes the *fault-injectable*
# provider active; local is the healthy standby a failover lands on.
CHAIN = "fake_kms:make_provider,local"


@pytest.fixture()
def chain_env(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def bound(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    provider_mod.get_provider()  # first healthy activation: fakekms, gen 1
    return chain_env


@pytest.fixture()
def http(chain_env):
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()


def _state_path(env):
    return os.path.join(env.data_dir, "provider-state.json")


def _health_path(env):
    return os.path.join(env.data_dir, "provider-health.json")


def _read_state(env):
    with open(_state_path(env), "rb") as fh:
        return json.loads(fh.read())


def _read_health_raw(env):
    with open(_health_path(env), "rb") as fh:
        return fh.read()


def _write_health(env, payload_bytes):
    with open(_health_path(env), "wb") as fh:
        fh.write(payload_bytes)


def _write_state(env, payload):
    with open(_state_path(env), "wb") as fh:
        fh.write(json.dumps(payload).encode("utf-8"))


def _call():
    """One ordinary provider call; returns (ok, provider_id) or the error."""
    try:
        with provider_mod.provider_call() as provider:
            return ("ok", provider.provider_id)
    except Exception as exc:  # pragma: no cover - exercised below
        return ("err", type(exc).__name__)


# -- health file shape -------------------------------------------------------
def test_first_activation_writes_health_satellite(bound):
    env = bound
    assert _read_state(env)["generation"] == 1
    # Exact bytes: compact UTF-8, fixed order, no trailing newline.
    assert _read_health_raw(env) == (
        b'{"schema_version":1,"provider_id":"fakekms",'
        b'"generation":1,"status":"ready","consecutive_failures":0}'
    )
    assert os.stat(_health_path(env)).st_mode & 0o777 == 0o600


def test_health_satellite_written_in_single_spec_mode_too(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    assert _read_health_raw(env) == (
        b'{"schema_version":1,"provider_id":"fakekms",'
        b'"generation":1,"status":"ready","consecutive_failures":0}'
    )


def test_health_file_writes_non_ascii_provider_id_unescaped(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    monkeypatch.setenv("FAKE_KMS_PROVIDER_ID", "fakekms-ü")
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    assert _read_health_raw(env) == (
        '{"schema_version":1,"provider_id":"fakekms-ü",'
        '"generation":1,"status":"ready","consecutive_failures":0}'
    ).encode("utf-8")


# -- first two failures: count + pinned 503, no switch -----------------------
@pytest.mark.parametrize(
    "fault",
    [{"health": False}, {"health_nonbool": "yes"}, {"health_raises": True}],
)
def test_first_two_failures_count_and_pin_503_without_switch(bound, fault):
    env = bound
    env.set_faults(fault)
    before = _read_state(env)
    for n in (1, 2):
        result, detail = _call()
        assert result == "err" and detail == "ProviderReconnectPending"
        health = json.loads(_read_health_raw(env))
        assert health == {
            "schema_version": 1,
            "provider_id": "fakekms",
            "generation": 1,
            "status": "unavailable",
            "consecutive_failures": n,
        }
    # No switch happened: the committed active generation is untouched.
    assert _read_state(env) == before


def test_failure_count_is_capped_at_three(bound, monkeypatch):
    env = bound
    env.set_faults({"health": False})
    # Break the standby as well so the third strike cannot fail over and keeps
    # bumping the same generation; the persisted counter must stop at three.
    monkeypatch.setattr(
        provider_mod.get_local_provider(), "health", lambda: False
    )
    for _ in range(5):
        _call()
    health = json.loads(_read_health_raw(env))
    assert health["consecutive_failures"] == 3
    assert health["status"] == "unavailable"
    assert _read_state(env)["generation"] == 1


def test_true_probe_clears_failures_and_serves(bound):
    env = bound
    env.set_faults({"health": False})
    _call()
    _call()
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 2
    env.clear_faults()
    result, provider_id = _call()
    assert result == "ok" and provider_id == "fakekms"
    assert json.loads(_read_health_raw(env)) == {
        "schema_version": 1,
        "provider_id": "fakekms",
        "generation": 1,
        "status": "ready",
        "consecutive_failures": 0,
    }
    assert _read_state(env)["generation"] == 1


def test_third_strike_reverify_recovery_clears_without_switch(
    bound, monkeypatch
):
    env = bound
    # fail, fail, then at the third call fail the first probe but let the
    # in-gate re-verification succeed (the fault clears on the 3rd read).
    calls = {"n": 0}

    def flapping():
        calls["n"] += 1
        return calls["n"] >= 4  # probes 1,2,3 unhealthy; 4th (re-verify) ok

    monkeypatch.setattr(provider_mod.get_provider(), "health", flapping)
    assert _call()[:1] == ("err",)
    assert _call()[:1] == ("err",)
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 2
    result, provider_id = _call()
    assert result == "ok" and provider_id == "fakekms"
    # Recovery on re-verification: no generation move, count reset.
    assert _read_state(env)["generation"] == 1
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 0


# -- per-probe 1 s cap sharing the non-resettable 5 s attempt budget ----------
def test_slow_probe_counts_once_and_waits_about_one_second(bound, monkeypatch):
    env = bound
    # A hanging health() costs at most the 1 s per-probe cap (NOT the whole
    # five-second budget) and counts exactly one failure per call.
    def hanging():
        time.sleep(60.0)
        return True

    monkeypatch.setattr(provider_mod.get_provider(), "health", hanging)
    for n in (1, 2):
        t0 = time.monotonic()
        result, detail = _call()
        elapsed = time.monotonic() - t0
        assert result == "err" and detail == "ProviderReconnectPending"
        assert 0.9 <= elapsed < 2.5, elapsed
        assert json.loads(_read_health_raw(env))[
            "consecutive_failures"
        ] == n
    assert _read_state(env)["generation"] == 1


def test_late_probe_result_is_void(bound, monkeypatch):
    env = bound
    # A True landing AFTER the bounded 1 s probe wait is discarded: the call
    # is one failure and nothing retroactively clears the persisted count.
    def slow_true():
        time.sleep(1.4)
        return True

    monkeypatch.setattr(provider_mod.get_provider(), "health", slow_true)
    t0 = time.monotonic()
    assert _call()[:1] == ("err",)
    assert time.monotonic() - t0 < 2.0
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 1
    time.sleep(1.2)  # let the underlying health() return its late True
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 1
    assert _read_state(env)["generation"] == 1


def test_slow_active_third_strike_reaches_healthy_standby_in_budget(
    bound, monkeypatch
):
    env = bound
    # Calls one and two fail instantly (count 2). On the third call the
    # active health() HANGS on its first probe only; every later active
    # re-verification returns False at once. The failover must still reach
    # the healthy local standby with the LEFTOVER shared budget (the hanging
    # probe capped at 1 s), rather than spending all five seconds on the
    # active probe and never failing over -- the threshold-exhaustion bug.
    invocations = {"n": 0}

    def active_health():
        invocations["n"] += 1
        if invocations["n"] == 3:  # the initial probe on the third call
            time.sleep(60.0)
        return False

    # The faults file keeps EVERY (rebuilt) fakekms instance unhealthy, while
    # the patch makes only the cached active's third-call first probe hang.
    env.set_faults({"health": False})
    monkeypatch.setattr(provider_mod.get_provider(), "health", active_health)
    assert _call()[:1] == ("err",)
    assert _call()[:1] == ("err",)
    t0 = time.monotonic()
    result, provider_id = _call()
    elapsed = time.monotonic() - t0
    assert result == "ok" and provider_id == "local"
    # The single hanging probe was capped to ~1 s; the standby was probed in
    # the remaining ~4 s of the same non-resettable five-second budget.
    assert 0.9 <= elapsed < 2.5, elapsed
    assert _read_state(env)["generation"] == 2
    assert json.loads(_read_health_raw(env)) == {
        "schema_version": 1,
        "provider_id": "local",
        "generation": 2,
        "status": "ready",
        "consecutive_failures": 0,
    }


def test_third_strike_with_no_room_for_standby_keeps_old_generation(
    bound, monkeypatch
):
    env = bound
    # A small shared budget: after the active's capped probes only a sliver
    # remains, and the standby's 1 s probe cannot fit that leftover. The
    # standby is therefore not reached: fixed 503, old generation retained,
    # count capped at three (no reset and no fresh budget).
    monkeypatch.setattr(provider_mod, "CALL_GATE_SECONDS", 2.2)
    env.set_faults({"health_sleep": 60.0})

    def hang():
        time.sleep(60.0)

    monkeypatch.setattr(provider_mod.get_local_provider(), "health", hang)
    results = [_call() for _ in range(3)]
    assert all(
        result == ("err", "ProviderReconnectPending") for result in results
    )
    assert _read_state(env)["generation"] == 1
    health = json.loads(_read_health_raw(env))
    assert health["consecutive_failures"] == 3
    assert health["status"] == "unavailable"


def test_status_probe_does_not_touch_failure_count(bound):
    env = bound
    env.set_faults({"health": False})
    for _ in range(3):
        assert provider_mod.provider_status() == {
            "provider_id": "fakekms",
            "status": "unavailable",
        }
    # status is observability only: it never increments the threshold.
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 0


# -- third strike: exactly one failover to the first healthy standby ----------
def test_third_strike_fails_over_once_and_serves_standby(bound):
    env = bound
    env.set_faults({"health": False})
    assert _call()[:1] == ("err",)
    assert _call()[:1] == ("err",)
    assert _read_state(env)["generation"] == 1
    # Third strike: local standby is healthy -> failover, generation 2, and the
    # same call lands on the standby.
    result, provider_id = _call()
    assert result == "ok" and provider_id == "local"
    state = _read_state(env)
    assert state == {
        "schema_version": 2,
        "provider_id": "local",
        "target_provider_id": None,
        "generation": 2,
        "reason": "failover",
        "phase": "ready",
    }
    # The switch committed state FIRST and the new generation's ready/0 health
    # SECOND, and the two agree.
    assert json.loads(_read_health_raw(env)) == {
        "schema_version": 1,
        "provider_id": "local",
        "generation": 2,
        "status": "ready",
        "consecutive_failures": 0,
    }
    # Later calls stay on the new generation; there is no automatic failback.
    assert _call() == ("ok", "local")
    assert _read_state(env)["generation"] == 2


def test_concurrent_third_strikes_commit_one_switch(bound):
    env = bound
    env.set_faults({"health": False})
    _call()
    _call()  # parked at two failures
    results = []

    def worker():
        results.append(_call())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
        assert not t.is_alive()
    assert results == [("ok", "local")] * 8
    # Exactly one switch: 1 -> 2, not once per caller.
    assert _read_state(env)["generation"] == 2


def test_no_healthy_standby_keeps_old_generation_and_persists_three(
    bound, monkeypatch
):
    env = bound
    env.set_faults({"health": False})
    local = provider_mod.get_local_provider()
    monkeypatch.setattr(local, "health", lambda: False)
    for _ in range(3):
        result, detail = _call()
        assert result == "err" and detail == "ProviderReconnectPending"
    assert _read_state(env) == {
        "schema_version": 2,
        "provider_id": "fakekms",
        "target_provider_id": None,
        "generation": 1,
        "reason": "initial",
        "phase": "ready",
    }
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 3
    # A recovered standby on the next call fails over (count was persisted).
    monkeypatch.setattr(local, "health", lambda: True)
    assert _call() == ("ok", "local")
    assert _read_state(env)["generation"] == 2


# -- persistence across a restart --------------------------------------------
def test_failures_persist_across_restart_then_failover(chain_env):
    env = chain_env
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    env.set_faults({"health": False})
    _call()
    _call()  # two failures durable on disk
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 2

    # A brand-new process inherits the persisted count: one more failure is the
    # third strike and triggers the single failover.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    assert _call() == ("ok", "local")
    assert _read_state(env)["generation"] == 2
    assert json.loads(_read_health_raw(env)) == {
        "schema_version": 1,
        "provider_id": "local",
        "generation": 2,
        "status": "ready",
        "consecutive_failures": 0,
    }


# -- health satellite convergence / corruption -------------------------------
def test_missing_health_file_is_rebuilt_ready_zero(bound):
    env = bound
    os.unlink(_health_path(env))
    assert _call() == ("ok", "fakekms")
    assert _read_health_raw(env) == (
        b'{"schema_version":1,"provider_id":"fakekms",'
        b'"generation":1,"status":"ready","consecutive_failures":0}'
    )


def test_lagging_health_generation_is_rebuilt_ready_zero(env):
    # State is already at generation 2; a generation-1 health record lags and
    # is rebuilt ready/0 for the current generation.
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    provider_mod.reconnect()  # gen 2
    _write_health(
        env,
        b'{"schema_version":1,"provider_id":"fakekms",'
        b'"generation":1,"status":"unavailable","consecutive_failures":3}',
    )
    assert _call() == ("ok", "fakekms")
    assert _read_health_raw(env) == (
        b'{"schema_version":1,"provider_id":"fakekms",'
        b'"generation":2,"status":"ready","consecutive_failures":0}'
    )


def test_corrupt_health_file_is_503_and_never_rewritten(bound):
    env = bound
    _write_health(env, b"{not json")
    before = _read_health_raw(env)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert _read_health_raw(env) == before


@pytest.mark.parametrize(
    "bad",
    [
        b'{"schema_version":2,"provider_id":"fakekms","generation":1,'
        b'"status":"ready","consecutive_failures":0}',
        b'{"schema_version":1,"provider_id":"","generation":1,'
        b'"status":"ready","consecutive_failures":0}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":0,'
        b'"status":"ready","consecutive_failures":0}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":1,'
        b'"status":"maybe","consecutive_failures":0}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":1,'
        b'"status":"ready","consecutive_failures":4}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":1,'
        b'"status":"ready","consecutive_failures":-1}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":1,'
        b'"status":"ready","consecutive_failures":true}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":1,'
        b'"status":"ready","consecutive_failures":0,"x":1}',
        b'[1,2,3]',
    ],
)
def test_invalid_health_fields_are_503_and_untouched(bound, bad):
    env = bound
    _write_health(env, bad)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert _read_health_raw(env) == bad


def test_health_ahead_of_committed_generation_is_503_untouched(bound):
    env = bound
    payload = (
        b'{"schema_version":1,"provider_id":"fakekms","generation":9,'
        b'"status":"ready","consecutive_failures":0}'
    )
    _write_health(env, payload)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert _read_health_raw(env) == payload


def test_health_same_generation_wrong_id_is_503_untouched(bound):
    env = bound
    payload = (
        b'{"schema_version":1,"provider_id":"other","generation":1,'
        b'"status":"ready","consecutive_failures":0}'
    )
    _write_health(env, payload)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert _read_health_raw(env) == payload


def test_corrupt_health_poisons_calls_reconnect_status_without_rewrite(bound):
    env = bound
    _write_health(env, b"{bad")
    bad = _read_health_raw(env)
    # Ordinary provider calls are poisoned (fixed 503) and do not rewrite it.
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    # Reconnect is blocked before committing and leaves both files untouched.
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    # Status reports unavailable with null id and rewrites nothing.
    assert provider_mod.provider_status() == {
        "provider_id": None,
        "status": "unavailable",
    }
    assert _read_health_raw(env) == bad


# -- reconnect / switchover reset the health satellite -----------------------
def test_reconnect_resets_health_ready_zero(bound):
    env = bound
    env.set_faults({"health": False})
    _call()
    _call()
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 2
    env.clear_faults()
    body = provider_mod.reconnect()
    assert body == {"provider_id": "fakekms", "status": "ready"}
    state = _read_state(env)
    assert json.loads(_read_health_raw(env)) == {
        "schema_version": 1,
        "provider_id": "fakekms",
        "generation": state["generation"],
        "status": "ready",
        "consecutive_failures": 0,
    }


def test_switchover_commits_health_for_new_generation(http):
    env, srv = http
    # First healthy activation (fakekms, generation 1).
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200 and body["provider_id"] == "fakekms"
    # A directed switch to local is a generation bump (1 -> 2).
    status, body = srv.request(
        "POST", "/v1/provider/switchover", {"provider_id": "local"}, OPERATOR
    )
    assert status == 200 and body == {
        "provider_id": "local", "status": "ready"
    }
    state = _read_state(env)
    assert state["generation"] == 2 and state["provider_id"] == "local"
    assert json.loads(_read_health_raw(env)) == {
        "schema_version": 1,
        "provider_id": "local",
        "generation": 2,
        "status": "ready",
        "consecutive_failures": 0,
    }


# -- HTTP end to end ----------------------------------------------------------
def test_http_two_503_then_third_fails_over_and_create_succeeds(http):
    env, srv = http
    body_create = {
        "tenant_id": "t1", "algorithm": "AES256", "label": "k",
    }
    # First healthy activation selects the first chain entry (fakekms).
    assert srv.request("POST", "/v1/keys", body_create, OPERATOR)[0] == 201
    assert _read_state(env)["provider_id"] == "fakekms"
    # Now the active fakekms goes unhealthy.
    env.set_faults({"health": False})
    for _ in range(2):
        status, body = srv.request("POST", "/v1/keys", body_create, OPERATOR)
        assert status == 503
        assert body == {"error": "key management provider is unavailable"}
    assert _read_state(env)["generation"] == 1
    # Third call fails over to the healthy local standby and then succeeds.
    status, body = srv.request("POST", "/v1/keys", body_create, OPERATOR)
    assert status == 201, body
    assert _read_state(env)["provider_id"] == "local"
    assert _read_state(env)["generation"] == 2


def test_pending_idempotent_op_is_not_replayed_on_standby_after_failover(http):
    env, srv = http
    # A key owned by the initially active fakekms provider.
    key_id = _create_key(srv)
    # Drive the third strike: fakekms fails over to local.
    env.set_faults({"health": False})
    body_create = {
        "tenant_id": "t1", "algorithm": "AES256", "label": "k",
    }
    for _ in range(2):
        assert srv.request("POST", "/v1/keys", body_create, OPERATOR)[0] == 503
    assert srv.request("POST", "/v1/keys", body_create, OPERATOR)[0] == 201
    assert _read_state(env)["provider_id"] == "local"

    # A rotation of the fakekms-owned key must NOT be replayed on local: the
    # operation stays pending (bound to its original provider_id).
    status, body = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "rot-after-failover"},
    )
    assert status == 503
    op_id = body["operation_id"]
    status, body = srv.request(
        "GET", "/v1/operations/%s?tenant_id=t1" % op_id, headers=OPERATOR
    )
    assert body["status"] == "pending"
    assert body["http_status"] is None and body["response"] is None


# -- CLI ----------------------------------------------------------------------
def test_cli_provider_commands_fields_and_exit_codes_unchanged(http):
    env, _srv = http
    result = run_cli(env, "provider", "status", "--operator", "alice")
    assert result.returncode == 0
    body = json.loads(result.stdout.strip())
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}

    env.set_faults({"health": False})
    # A FRESH CLI process has no cached instance: a committed-but-unhealthy
    # chain active cannot be adopted, so status is rc0 with a null id
    # (unchanged cold-cache status semantics; no backend text leaks).
    result = run_cli(env, "provider", "status", "--operator", "alice")
    assert result.returncode == 0
    assert json.loads(result.stdout.strip()) == {
        "provider_id": None, "status": "unavailable",
    }
    # reconnect in chain mode re-selects the FIRST HEALTHY entry: with
    # fakekms down it moves to the healthy local standby (200, generation +1,
    # health satellite reset) -- the same fields/key order as always.
    result = run_cli(env, "provider", "reconnect", "--operator", "alice")
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout.strip())
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "local", "status": "ready"}
    assert _read_state(env)["provider_id"] == "local"
    assert json.loads(_read_health_raw(env))["consecutive_failures"] == 0

    # A subsequent status (standby healthy) is rc0 and names local.
    result = run_cli(env, "provider", "status", "--operator", "alice")
    assert result.returncode == 0
    assert json.loads(result.stdout.strip()) == {
        "provider_id": "local", "status": "ready",
    }


def test_cli_key_op_fails_over_on_third_unhealthy_probe(chain_env):
    env = chain_env
    # First activation via a healthy CLI key create (fakekms, generation 1).
    result = run_cli(
        env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert result.returncode == 0
    env.set_faults({"health": False})
    for _ in range(2):
        result = run_cli(
            env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
            "--label", "k", "--operator", "alice",
        )
        assert result.returncode == 1
    # Third CLI process fails over to local and succeeds.
    result = run_cli(
        env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert result.returncode == 0, result.stderr
    assert _read_state(env)["generation"] == 2
    assert _read_state(env)["provider_id"] == "local"
