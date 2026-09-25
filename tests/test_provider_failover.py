"""Tests for KEYMGR_PROVIDER_CHAIN primary/standby failover.

Covers:

* chain configuration parsing (unset -> KEYMGR_PROVIDER; empty item, bad
  format, duplicate item or duplicate built provider_id -> unavailable);
* initial activation selecting the first healthy chain item;
* gated failover to the first healthy standby when the active instance is
  unhealthy (two-phase switching/ready commit, single commit under
  concurrency, old generation kept on failure);
* no automatic failback to a recovered primary; reconnect re-selects the
  first healthy item;
* a crashed switch (phase=switching) completed on restart when the target
  is healthy, kept with a 503 otherwise;
* pending operations stay bound to their original provider_id on the
  standby and continue exactly once after a same-id reconnect.
"""

import json
import os
import threading

import pytest

from keymgr import provider as provider_mod

from test_provider_reconnect import HttpServer, OPERATOR, _create_key
from test_recovery_cli import run_cli


CHAIN = "fake_kms:make_provider,fake_kms_b:make_provider"


@pytest.fixture()
def chain(env, monkeypatch, tmp_path):
    """The fakekms env plus a second backend, wired as a two-item chain."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    monkeypatch.setenv("FAKE_KMS_B_STATE", str(tmp_path / "kms-b-state.json"))
    monkeypatch.setenv(
        "FAKE_KMS_B_FAULTS", str(tmp_path / "kms-b-faults.json")
    )
    env.b_state_path = os.environ["FAKE_KMS_B_STATE"]
    env.b_faults_path = os.environ["FAKE_KMS_B_FAULTS"]
    return env


def _set_b_faults(env, faults):
    with open(env.b_faults_path, "w", encoding="utf-8") as fh:
        json.dump(faults, fh)


def _clear_b_faults(env):
    try:
        os.unlink(env.b_faults_path)
    except OSError:
        pass


def _b_handles(env):
    try:
        with open(env.b_state_path, "r", encoding="utf-8") as fh:
            return set(json.load(fh)["handles"])
    except (OSError, ValueError, KeyError):
        return set()


def _state_path(env):
    return os.path.join(env.data_dir, "provider-state.json")


def _read_state(env):
    with open(_state_path(env), "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


@pytest.fixture()
def http(chain):
    provider_mod.bind_data_dir(chain.data_dir)
    server = HttpServer(chain)
    yield chain, server
    server.stop()


# -- chain configuration parsing ----------------------------------------------
@pytest.mark.parametrize(
    "bad_chain",
    [
        "",  # set but empty
        " , ",  # only whitespace
        "fake_kms:make_provider,,fake_kms_b:make_provider",  # empty item
        "fake_kms:make_provider,",  # trailing empty item
        "bogus",  # neither local nor module:factory
        "fake_kms",  # missing :factory
        ":make_provider",  # empty module
        "fake_kms:",  # empty factory
        "fake_kms:make_provider,fake_kms:make_provider",  # duplicate item
    ],
)
def test_invalid_chain_is_unavailable(chain, monkeypatch, bad_chain):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", bad_chain)
    provider_mod.bind_data_dir(chain.data_dir)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    assert provider_mod.provider_status() == {
        "provider_id": None,
        "status": "unavailable",
    }
    assert not os.path.exists(_state_path(chain))


def test_chain_unset_falls_back_to_single_provider(env, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER_CHAIN", raising=False)
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms"


def test_chain_duplicate_built_provider_id_is_unavailable(
    chain, monkeypatch
):
    monkeypatch.setenv("FAKE_KMS_B_PROVIDER_ID", "fakekms")
    provider_mod.bind_data_dir(chain.data_dir)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert not os.path.exists(_state_path(chain))


def test_chain_overrides_keymgr_provider(chain, monkeypatch):
    # A bogus KEYMGR_PROVIDER is ignored while the chain is set.
    monkeypatch.setenv("KEYMGR_PROVIDER", "no_such_module:make")
    provider_mod.bind_data_dir(chain.data_dir)
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms"


# -- initial selection ----------------------------------------------------------
def test_initial_activation_selects_first_healthy_item(chain):
    provider_mod.bind_data_dir(chain.data_dir)
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms"
    assert _read_state(chain) == {
        "schema_version": 2,
        "provider_id": "fakekms",
        "target_provider_id": None,
        "generation": 1,
        "reason": "initial",
        "phase": "ready",
    }


def test_initial_activation_skips_unhealthy_primary(chain):
    chain.set_faults({"health": False})
    provider_mod.bind_data_dir(chain.data_dir)
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms-b"
    state = _read_state(chain)
    assert state["provider_id"] == "fakekms-b"
    assert state["generation"] == 1
    assert state["reason"] == "initial"
    assert state["phase"] == "ready"


def test_initial_activation_all_unhealthy_is_503_without_state_file(chain):
    chain.set_faults({"health": False})
    _set_b_faults(chain, {"health": False})
    provider_mod.bind_data_dir(chain.data_dir)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert not os.path.exists(_state_path(chain))


# -- failover -------------------------------------------------------------------
def test_unhealthy_active_fails_over_to_first_healthy_standby(http):
    env, srv = http
    _create_key(srv)
    assert env.kms_handles()  # primary minted the first key's handle
    env.set_faults({"health": False})
    # The next call detects the unhealthy active and fails over: it is
    # admitted against the standby and succeeds there.
    key_id = _create_key(srv, tenant="t2")
    assert key_id
    state = _read_state(env)
    assert state == {
        "schema_version": 2,
        "provider_id": "fakekms-b",
        "target_provider_id": None,
        "generation": 2,
        "reason": "failover",
        "phase": "ready",
    }
    # The new handle lives on the standby backend; the primary minted
    # nothing after going unhealthy.
    assert len(_b_handles(env)) == 1
    assert len(env.kms_handles()) == 1


def test_failover_failure_keeps_generation_and_writes_nothing(http):
    env, srv = http
    _create_key(srv)
    before = _read_state(env)
    before_handles = env.kms_handles()
    before_events = len(env.audit_events())
    env.set_faults({"health": False})
    _set_b_faults(env, {"health": False})
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": "t9", "algorithm": "AES256", "label": "k"},
        OPERATOR,
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    # Old generation untouched; no handle, no audit event, no leaked text.
    assert _read_state(env) == before
    assert env.kms_handles() == before_handles
    assert _b_handles(env) == set()
    assert len(env.audit_events()) == before_events


def test_no_automatic_failback_to_recovered_primary(http):
    env, srv = http
    _create_key(srv)
    env.set_faults({"health": False})
    _create_key(srv, tenant="t2")
    assert _read_state(env)["provider_id"] == "fakekms-b"
    # The primary recovers: service stays on the standby, no switch back.
    env.clear_faults()
    _create_key(srv, tenant="t3")
    state = _read_state(env)
    assert state["provider_id"] == "fakekms-b"
    assert state["generation"] == 2


def test_reconnect_reselects_first_healthy_item(http):
    env, srv = http
    _create_key(srv)
    env.set_faults({"health": False})
    _create_key(srv, tenant="t2")
    assert _read_state(env)["provider_id"] == "fakekms-b"
    env.clear_faults()
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "ready"}
    state = _read_state(env)
    assert state["provider_id"] == "fakekms"
    assert state["generation"] == 3
    assert state["reason"] == "reconnect"
    assert state["phase"] == "ready"
    assert state["target_provider_id"] is None


def test_concurrent_calls_fail_over_exactly_once(chain):
    provider_mod.bind_data_dir(chain.data_dir)
    provider_mod.get_provider()
    chain.set_faults({"health": False})
    errors = []
    seen = []

    def call():
        try:
            with provider_mod.provider_call() as provider:
                seen.append(provider.provider_id)
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15.0)
        assert not t.is_alive()
    assert not errors
    # One commit despite the race: generation 2, everyone on the standby.
    assert _read_state(chain)["generation"] == 2
    assert seen and set(seen) == {"fakekms-b"}


def test_in_flight_call_completes_then_later_call_uses_new_generation(chain):
    import time

    provider_mod.bind_data_dir(chain.data_dir)
    provider_mod.get_provider()  # generation 1 on the primary
    entered = threading.Event()
    release = threading.Event()
    seen = {}

    def in_flight():
        with provider_mod.provider_call() as provider:
            seen["old"] = provider.provider_id
            entered.set()
            release.wait(5.0)
            # TLS pinning: still the instance captured at admission.
            seen["still"] = provider_mod.get_provider().provider_id

    worker = threading.Thread(target=in_flight)
    worker.start()
    assert entered.wait(2.0)
    chain.set_faults({"health": False})

    def later_call():
        with provider_mod.provider_call() as provider:
            seen["new"] = provider.provider_id

    later = threading.Thread(target=later_call)
    later.start()
    time.sleep(0.3)
    # The later call triggered the failover but is held at the drain while
    # the old call is still in flight.
    assert "new" not in seen
    release.set()
    later.join(10.0)
    worker.join(5.0)
    assert not later.is_alive() and not worker.is_alive()
    # The old call completed on the instance it captured; the later call
    # was admitted against the new generation on the standby.
    assert seen["old"] == "fakekms"
    assert seen["still"] == "fakekms"
    assert seen["new"] == "fakekms-b"
    state = _read_state(chain)
    assert state["provider_id"] == "fakekms-b"
    assert state["generation"] == 2
    assert state["reason"] == "failover"


# -- crashed two-phase switch ----------------------------------------------------
def _write_switching(env, old="fakekms", target="fakekms-b", generation=1):
    payload = json.dumps(
        {
            "schema_version": 2,
            "provider_id": old,
            "target_provider_id": target,
            "generation": generation,
            "reason": "failover",
            "phase": "switching",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    with open(_state_path(env), "wb") as fh:
        fh.write(payload)


def test_restart_completes_switching_when_target_healthy(chain):
    provider_mod.bind_data_dir(chain.data_dir)
    provider_mod.get_provider()
    _write_switching(chain)
    # A fresh process (cached state forgotten) re-verifies the recorded
    # target and completes the switch.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(chain.data_dir)
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms-b"
    assert _read_state(chain) == {
        "schema_version": 2,
        "provider_id": "fakekms-b",
        "target_provider_id": None,
        "generation": 2,
        "reason": "failover",
        "phase": "ready",
    }


def test_restart_keeps_switching_and_503_when_target_unhealthy(chain):
    provider_mod.bind_data_dir(chain.data_dir)
    provider_mod.get_provider()
    _write_switching(chain)
    _set_b_faults(chain, {"health": False})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(chain.data_dir)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    with open(_state_path(chain), "rb") as fh:
        assert json.loads(fh.read().decode("utf-8"))["phase"] == "switching"
    # The record survives until the target recovers; then it completes.
    _clear_b_faults(chain)
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(chain.data_dir)
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms-b"
    assert _read_state(chain)["phase"] == "ready"


# -- pending operations stay bound to the original provider_id -------------------
def _rotate(srv, key_id, idem_key, tenant="t1"):
    return srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": idem_key},
    )


def test_pending_op_not_replayed_on_standby_continues_after_same_id_reconnect(
    http,
):
    env, srv = http
    key_id = _create_key(srv)
    # The primary goes unhealthy: the rotate's admission fails over to the
    # standby, but the operation is bound to a key owned by fakekms, so it
    # stays pending instead of running on the standby.
    env.set_faults({"health": False})
    idem = "rotate-failover-0001"
    status, body = _rotate(srv, key_id, idem)
    assert status == 503
    assert body == {
        "error": "key management provider is unavailable",
        "operation_id": body["operation_id"],
    }
    op_id = body["operation_id"]
    assert _read_state(env)["provider_id"] == "fakekms-b"

    status, body = srv.request(
        "GET", "/v1/operations/%s?tenant_id=t1" % op_id, headers=OPERATOR
    )
    assert body["status"] == "pending"
    assert body["http_status"] is None and body["response"] is None
    assert sum(1 for e in env.audit_events() if e.event_id == op_id) == 0

    # A retry while the standby is active stays pending (never replayed
    # against a different provider_id).
    status, body = _rotate(srv, key_id, idem)
    assert status == 503
    assert body["operation_id"] == op_id

    # Primary healthy again: reconnect re-selects it and the identical
    # request continues under the same operation_id, exactly one event.
    env.clear_faults()
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200 and body["provider_id"] == "fakekms"
    status, body = _rotate(srv, key_id, idem)
    assert status == 201, body
    assert body["operation_id"] == op_id
    assert body["version"] == 2
    assert sum(1 for e in env.audit_events() if e.event_id == op_id) == 1


# -- CLI -------------------------------------------------------------------------
def test_cli_provider_status_and_reconnect_with_chain(chain):
    result = run_cli(chain, "provider", "status", "--operator", "alice")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip()) == {
        "provider_id": "fakekms",
        "status": "ready",
    }
    # Primary unhealthy: the CLI reconnect re-selects the standby.
    chain.set_faults({"health": False})
    result = run_cli(chain, "provider", "reconnect", "--operator", "alice")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip()) == {
        "provider_id": "fakekms-b",
        "status": "ready",
    }
    assert _read_state(chain)["reason"] == "reconnect"


def test_cli_operation_fails_over_and_invalid_chain_exits_1(chain):
    # A normal CLI operation transparently fails over to the standby.
    chain.set_faults({"health": False})
    result = run_cli(
        chain, "gen", "--tenant-id", "t", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    assert result.returncode == 0, result.stderr
    assert _read_state(chain)["provider_id"] == "fakekms-b"
