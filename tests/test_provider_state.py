"""Tests for the cross-process provider activation state and gate.

Covers:

* ``provider-state.json``: written atomically (0600) by the first healthy
  activation and every successful reconnect; exact key order
  ``schema_version,provider_id,generation``, compact UTF-8 JSON, non-ASCII
  as-is, no trailing newline;
* corrupt or invalid state fails provider calls and reconnect with the
  fixed 503 text and is never rewritten;
* only healthy candidates increment the generation; a failed reconnect
  keeps the old generation;
* a process adopts a generation committed elsewhere: a rebuilt id that
  does not match the committed provider_id is a pending-preserving 503,
  an unhealthy rebuild is the classic terminal 503;
* the cross-process gate: while another process holds the intent/gate
  locks, a new call waits and times out with zero side effects;
* ``GET /v1/provider/status`` rejects a tenant_id carried in a non-empty
  body before any factory build or probe.
"""

import fcntl
import json
import os
import stat

import pytest

from keymgr import provider as provider_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.restore import RestoreCoordinator
from keymgr.server import make_handler
from keymgr.store import KeyStore

from test_provider_reconnect import HttpServer, OPERATOR


@pytest.fixture()
def http(env):
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()


def _state_path(env):
    return os.path.join(env.data_dir, "provider-state.json")


def _read_raw(env):
    with open(_state_path(env), "rb") as fh:
        return fh.read()


def _write_raw(env, payload):
    with open(_state_path(env), "wb") as fh:
        fh.write(payload)


# -- activation file ---------------------------------------------------------
def test_first_healthy_activation_writes_exact_state_file(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    assert _read_raw(env) == (
        b'{"schema_version":1,"provider_id":"fakekms","generation":1}'
    )
    mode = stat.S_IMODE(os.stat(_state_path(env)).st_mode)
    assert mode == 0o600


def test_reconnect_increments_generation_and_failure_keeps_old(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    assert provider_mod.reconnect() == {
        "provider_id": "fakekms", "status": "ready",
    }
    assert _read_raw(env).endswith(b'"generation":2}')

    env.set_faults({"health": False})
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    env.clear_faults()
    # The failed candidate never committed: the old generation stands.
    assert _read_raw(env).endswith(b'"generation":2}')
    # The retained instance still serves.
    with provider_mod.provider_call():
        pass


# -- corrupt / invalid state --------------------------------------------------
BAD_STATES = [
    b"{not json",
    b"[1,2,3]",
    b'"just a string"',
    b'{"schema_version":2,"provider_id":"fakekms","generation":1}',
    b'{"schema_version":"1","provider_id":"fakekms","generation":1}',
    b'{"schema_version":true,"provider_id":"fakekms","generation":1}',
    b'{"schema_version":1,"provider_id":"","generation":1}',
    b'{"schema_version":1,"provider_id":7,"generation":1}',
    b'{"schema_version":1,"generation":1}',
    b'{"schema_version":1,"provider_id":"fakekms","generation":0}',
    b'{"schema_version":1,"provider_id":"fakekms","generation":-1}',
    b'{"schema_version":1,"provider_id":"fakekms","generation":"2"}',
    b'{"schema_version":1,"provider_id":"fakekms","generation":true}',
    b'{"schema_version":1,"provider_id":"fakekms"}',
]


@pytest.mark.parametrize("payload", BAD_STATES)
def test_corrupt_state_fails_calls_and_reconnect_without_rewrite(
    env, payload
):
    provider_mod.bind_data_dir(env.data_dir)
    _write_raw(env, payload)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    # Never rewritten, byte for byte.
    assert _read_raw(env) == payload


def test_corrupt_state_surfaces_fixed_503_over_http(http):
    env, srv = http
    key_id = None
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": "t1", "algorithm": "AES256", "label": "k"},
        OPERATOR,
    )
    assert status == 201
    key_id = body["key_id"]
    _write_raw(env, b'{"schema_version":1,"provider_id":5,"generation":1}')
    status, body = srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "rot-corrupt"},
    )
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _read_raw(env) == (
        b'{"schema_version":1,"provider_id":5,"generation":1}'
    )


# -- cross-process adoption ----------------------------------------------------
def test_fresh_process_adopts_committed_generation(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    assert provider_mod.reconnect()["status"] == "ready"
    # Simulate a fresh process over the same data directory.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    assert _read_raw(env).endswith(b'"generation":2}')


def test_committed_id_mismatch_is_pending_preserving(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    # Another process committed a different provider_id.
    _write_raw(
        env, b'{"schema_version":1,"provider_id":"other-kms","generation":2}'
    )
    with pytest.raises(provider_mod.ProviderIdentityMismatch):
        with provider_mod.provider_call():
            pass


def test_unhealthy_adoption_is_plain_unavailable(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    _write_raw(
        env, b'{"schema_version":1,"provider_id":"fakekms","generation":2}'
    )
    env.set_faults({"unreachable": True})
    with pytest.raises(provider_mod.ProviderUnavailable) as excinfo:
        with provider_mod.provider_call():
            pass
    env.clear_faults()
    assert not isinstance(
        excinfo.value, provider_mod.ProviderIdentityMismatch
    )


# -- the cross-process gate ----------------------------------------------------
def test_call_times_out_behind_foreign_gate_lock(env, monkeypatch):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    # Another process holds the gate exclusively (a reconnect in progress).
    fd = os.open(
        os.path.join(env.data_dir, "provider-state.lock"),
        os.O_RDWR | os.O_CREAT, 0o600,
    )
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        before = env.kms_handles()
        with pytest.raises(provider_mod.ProviderReconnectPending):
            with provider_mod.provider_call(timeout=0.3):
                pass
        assert env.kms_handles() == before
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    # Released: calls are admitted again.
    with provider_mod.provider_call():
        pass


def test_call_times_out_behind_foreign_intent_lock(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    fd = os.open(
        os.path.join(env.data_dir, "provider-reconnect.lock"),
        os.O_RDWR | os.O_CREAT, 0o600,
    )
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(provider_mod.ProviderReconnectPending):
            with provider_mod.provider_call(timeout=0.3):
                pass
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_reconnect_times_out_behind_foreign_in_flight_call(env):
    provider_mod.bind_data_dir(env.data_dir)
    with provider_mod.provider_call():
        pass
    # Another process holds an in-flight call (shared gate lease).
    fd = os.open(
        os.path.join(env.data_dir, "provider-state.lock"),
        os.O_RDWR | os.O_CREAT, 0o600,
    )
    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    try:
        with pytest.raises(provider_mod.ProviderReconnectPending):
            provider_mod.reconnect(timeout=0.3)
        # Nothing committed: the old generation is untouched.
        assert _read_raw(env).endswith(b'"generation":1}')
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    assert provider_mod.reconnect()["status"] == "ready"
    assert _read_raw(env).endswith(b'"generation":2}')


# -- status endpoint body validation ------------------------------------------
def test_status_rejects_tenant_id_in_non_empty_body(http):
    env, srv = http
    # Even with a broken factory the 400 comes first (no build, no probe).
    env.set_faults({"factory_fails": True})
    status, body = srv.raw(
        "GET", "/v1/provider/status", b'{"tenant_id":"t1"}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400
    assert "tenant_id" in json.loads(body)["error"]
    env.clear_faults()
    # A non-empty body without tenant_id is tolerated.
    status, body = srv.raw(
        "GET", "/v1/provider/status", b'{"other":1}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 200
    assert json.loads(body) == {
        "provider_id": "fakekms", "status": "ready",
    }
