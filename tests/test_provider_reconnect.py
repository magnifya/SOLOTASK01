"""Tests for the KMS/HSM health probe and non-disruptive reconnect.

Covers:

* the optional ``health()`` contract (missing -> ready; non-bool/raise ->
  unavailable, no text leaked);
* ``GET /v1/provider/status`` and ``POST /v1/provider/reconnect`` request
  validation, key order and the fixed 503 body;
* a failed rebuild/health check retains the previously active instance;
* the shared five-second gate: in-flight calls finish on the old instance,
  new calls wait and a wait past the budget is a zero-side-effect 503;
* a pending operation bound to a displaced provider_id stays pending until a
  provider with the same id reconnects, then continues with one event_id.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import provider as provider_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.restore import RestoreCoordinator
from keymgr.server import make_handler
from keymgr.store import KeyStore

from test_recovery_cli import run_cli


# -- health() contract -------------------------------------------------------
class _NoHealth:
    provider_id = "nohealth"
    capabilities = {
        "algorithms": ["AES256", "RSA2048"],
        "operations": [
            "generate", "rotate", "import_material",
            "export_material", "delete",
        ],
    }

    def configure(self, data_dir):
        pass

    def generate(self, algorithm):
        raise NotImplementedError

    def rotate(self, algorithm):
        raise NotImplementedError

    def import_material(self, algorithm, public_key, material):
        raise NotImplementedError

    def export_material(self, handle):
        raise NotImplementedError

    def delete(self, handle):
        return None


class _HealthRaises(_NoHealth):
    provider_id = "raises"

    def health(self):
        raise RuntimeError("secret backend detail must not leak")


class _HealthNonBool(_NoHealth):
    provider_id = "nonbool"

    def health(self):
        return "yes"  # truthy but not a bool -> unavailable


class _HealthFalse(_NoHealth):
    provider_id = "false"

    def health(self):
        return False


def test_health_missing_method_is_ready():
    assert provider_mod._SafeProvider(_NoHealth()).health() is True


def test_health_raises_and_nonbool_and_false_are_unavailable():
    assert provider_mod._SafeProvider(_HealthRaises()).health() is False
    assert provider_mod._SafeProvider(_HealthNonBool()).health() is False
    assert provider_mod._SafeProvider(_HealthFalse()).health() is False


def test_health_non_callable_attribute_fails_contract():
    obj = _NoHealth()
    obj.health = "nope"
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod._validate_external(obj)


# -- HTTP server -------------------------------------------------------------
class HttpServer:
    def __init__(self, env):
        audit_log = AuditLog(env.data_dir)
        self.store = KeyStore(env.data_dir, audit_log)
        policy_store = PolicyStore(env.data_dir, audit_log)
        coordinator = RestoreCoordinator(self.store, policy_store)
        self.op_store = OperationStore(env.data_dir, audit_log)
        self.artifact_store = ArtifactStore(
            env.data_dir, self.store, audit_log
        )
        self.artifact_store.settle_pending(self.op_store)
        self.op_store.recover_pending(
            is_parked=self.artifact_store.is_parked
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                self.store, policy_store, coordinator, self.op_store,
                self.artifact_store,
            ),
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    def raw(self, method, path, raw=b"", headers=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        req = urllib.request.Request(url, data=raw or None, method=method)
        for name, value in (headers or {}).items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def request(self, method, path, body=None, headers=None):
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        raw = None if body is None else json.dumps(body).encode("utf-8")
        status, text = self.raw(method, path, raw or b"", hdrs)
        return status, json.loads(text)


@pytest.fixture()
def http(env):
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()


OPERATOR = {"X-Operator-Id": "alice"}


def _create_key(srv, tenant="t1", algorithm="AES256"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


# -- status endpoint ---------------------------------------------------------
def test_status_ready_and_key_order(http):
    env, srv = http
    # Force a lazy load through a normal call first.
    _create_key(srv)
    status, text = srv.raw("GET", "/v1/provider/status", headers=OPERATOR)
    assert status == 200
    body = json.loads(text)
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}


def test_status_load_failure_reports_null_provider_id(http):
    env, srv = http
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    env.set_faults({"factory_fails": True})
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200
    assert body == {"provider_id": None, "status": "unavailable"}


def test_status_unavailable_when_health_false(http):
    env, srv = http
    _create_key(srv)
    env.set_faults({"health": False})
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "unavailable"}


def test_status_health_raises_does_not_leak_text(http):
    env, srv = http
    _create_key(srv)
    env.set_faults({"health_raises": True})
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "unavailable"}
    assert "secret" not in json.dumps(body)


def test_status_requires_operator_and_rejects_tenant(http):
    env, srv = http
    status, body = srv.request("GET", "/v1/provider/status")
    assert status == 400
    status, body = srv.request(
        "GET", "/v1/provider/status?tenant_id=t1", headers=OPERATOR
    )
    assert status == 400
    status, body = srv.request(
        "GET", "/v1/provider/status",
        headers={"X-Operator-Id": "alice", "X-Tenant-Id": "t1"},
    )
    assert status == 400


# -- reconnect validation ----------------------------------------------------
def test_reconnect_requires_exactly_empty_object(http):
    env, srv = http
    # Bad JSON.
    status, body = srv.raw(
        "POST", "/v1/provider/reconnect", b"{not json",
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400
    # Non-object body.
    status, _ = srv.request(
        "POST", "/v1/provider/reconnect", [], OPERATOR
    )
    assert status == 400
    # Extra fields.
    status, _ = srv.request(
        "POST", "/v1/provider/reconnect", {"tenant_id": "t1"}, OPERATOR
    )
    assert status == 400
    status, _ = srv.request(
        "POST", "/v1/provider/reconnect", {"x": 1}, OPERATOR
    )
    assert status == 400
    # Tenant in the query string is rejected too.
    status, body = srv.raw(
        "POST", "/v1/provider/reconnect?tenant_id=t1", b"{}",
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400


def test_reconnect_success_returns_status(http):
    env, srv = http
    _create_key(srv)
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}


def test_reconnect_unhealthy_keeps_old_instance(http):
    env, srv = http
    _create_key(srv)
    env.set_faults({"health": False})
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    # The old instance is retained and still serves.
    env.clear_faults()
    status, body = srv.request(
        "GET", "/v1/provider/status", headers=OPERATOR
    )
    assert body == {"provider_id": "fakekms", "status": "ready"}
    # A follow-up key operation still works against the retained instance.
    assert _create_key(srv)


def test_reconnect_factory_failure_keeps_old_instance(http):
    env, srv = http
    _create_key(srv)
    env.set_faults({"factory_fails": True})
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    env.clear_faults()
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200
    assert body["status"] == "ready"


# -- the five-second gate ----------------------------------------------------
def test_gate_new_call_times_out_with_zero_side_effects(
    http, monkeypatch
):
    env, srv = http
    provider_mod.bind_data_dir(env.data_dir)
    entered = threading.Event()
    release = threading.Event()

    def in_flight():
        # An ordinary operation already admitted and using the (old)
        # provider while a reconnect begins.
        with provider_mod.provider_call():
            entered.set()
            release.wait(5.0)

    worker = threading.Thread(target=in_flight)
    worker.start()
    assert entered.wait(2.0)

    reconn_started = threading.Event()
    reconn_error = {}

    def reconnecting():
        reconn_started.set()
        try:
            provider_mod.reconnect()
        except Exception as exc:  # the budget can elapse in this thread
            reconn_error["exc"] = exc

    reconn = threading.Thread(target=reconnecting)
    reconn.start()
    assert reconn_started.wait(2.0)
    # Give the reconnect a moment to mark the gate draining.
    time.sleep(0.1)

    # A new call with a short explicit wait shares the threshold semantics:
    # it must fail before invoking any provider, minting no backend object.
    before = env.kms_handles()
    with pytest.raises(provider_mod.ProviderReconnectPending):
        with provider_mod.provider_call(timeout=0.2):
            pass  # body never entered
    assert env.kms_handles() == before

    release.set()
    reconn.join(6.0)
    worker.join(5.0)
    assert not reconn.is_alive() and not worker.is_alive()


def test_gate_in_flight_call_completes_on_old_instance(
    http, monkeypatch
):
    env, srv = http
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()  # load fakekms
    entered = threading.Event()
    release = threading.Event()
    seen = {}

    def in_flight():
        with provider_mod.provider_call() as provider:
            seen["old"] = provider
            entered.set()
            release.wait(5.0)
            # Even after the swap below, this thread is still pinned to the
            # instance it started on.
            seen["still"] = provider_mod.get_provider()

    worker = threading.Thread(target=in_flight)
    worker.start()
    assert entered.wait(2.0)

    # A reconnect builds and installs a different-id healthy instance.
    monkeypatch.setenv("FAKE_KMS_PROVIDER_ID", "fakekms-alt")
    reconn = threading.Thread(target=provider_mod.reconnect)
    reconn.start()
    time.sleep(0.1)
    release.set()
    reconn.join(5.0)
    worker.join(5.0)
    assert not reconn.is_alive() and not worker.is_alive()

    assert seen["old"].provider_id == "fakekms"
    assert seen["still"].provider_id == "fakekms"
    assert provider_mod.get_provider().provider_id == "fakekms-alt"

    # Restore the configured id for later teardown/tests.
    monkeypatch.delenv("FAKE_KMS_PROVIDER_ID", raising=False)
    provider_mod.reconnect()


# -- pending operation displacement ------------------------------------------
def _rotate(srv, key_id, idem_key, tenant="t1"):
    return srv.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": idem_key},
    )


def test_http_call_gets_zero_side_effect_503_during_drain(
    http, monkeypatch
):
    env, srv = http
    provider_mod.bind_data_dir(env.data_dir)
    entered = threading.Event()
    release = threading.Event()

    def in_flight():
        with provider_mod.provider_call():
            entered.set()
            release.wait(5.0)

    worker = threading.Thread(target=in_flight)
    worker.start()
    assert entered.wait(2.0)

    # Begin a reconnect that drains on the in-flight call.
    done = threading.Event()

    def reconnecting():
        try:
            provider_mod.reconnect()
        finally:
            done.set()

    reconn = threading.Thread(target=reconnecting)
    reconn.start()
    time.sleep(0.1)

    # Shrink the shared threshold so a new key-generation call gives up while
    # the gate is draining; it must answer a fixed safe 503 and create nothing.
    monkeypatch.setattr(provider_mod, "CALL_GATE_SECONDS", 0.2)
    before = env.kms_handles()
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": "t9", "algorithm": "AES256", "label": "k"},
        OPERATOR,
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert env.kms_handles() == before

    release.set()
    reconn.join(6.0)
    worker.join(5.0)
    assert done.is_set()
    # After the reconnect settles, normal service resumes.
    assert _create_key(srv, tenant="t9")


def test_pending_op_stays_pending_then_continues_after_same_id_reconnect(
    http, monkeypatch
):
    env, srv = http
    key_id = _create_key(srv)
    # Reconnect to a healthy provider with a DIFFERENT id.
    monkeypatch.setenv("FAKE_KMS_PROVIDER_ID", "fakekms-alt")
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200 and body["provider_id"] == "fakekms-alt"

    idem = "rotate-displace-0001"
    status, body = _rotate(srv, key_id, idem)
    assert status == 503
    assert body == {
        "error": "key management provider is unavailable",
        "operation_id": body["operation_id"],
    }
    op_id = body["operation_id"]

    # The operation is still PENDING: GET reports no terminal/response.
    status, body = srv.request(
        "GET", "/v1/operations/%s?tenant_id=t1" % op_id,
        headers=OPERATOR,
    )
    assert status == 200
    assert body["status"] == "pending"
    assert body["http_status"] is None and body["response"] is None

    # A retry while the foreign id stays active keeps it pending again.
    status, body2 = _rotate(srv, key_id, idem)
    assert status == 503
    assert body2["operation_id"] == op_id

    # No audit event for the operation was written while displaced.
    events = env.audit_events()
    assert sum(1 for e in events if e.event_id == op_id) == 0

    # Reconnect a provider with the SAME id the record owns.
    monkeypatch.delenv("FAKE_KMS_PROVIDER_ID", raising=False)
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200 and body["provider_id"] == "fakekms"

    # The identical request now continues under the same operation_id and
    # commits the rotation exactly once.
    status, body = _rotate(srv, key_id, idem)
    assert status == 201, body
    assert body["operation_id"] == op_id
    assert body["version"] == 2

    status, body = srv.request(
        "GET", "/v1/operations/%s?tenant_id=t1" % op_id,
        headers=OPERATOR,
    )
    assert body["status"] == "succeeded"
    events = env.audit_events()
    assert sum(1 for e in events if e.event_id == op_id) == 1


def test_pending_import_continues_after_same_id_reconnect(http, monkeypatch):
    import uuid

    from keymgr import keybundle

    env, srv = http
    # A key owned by the original provider, exported into a sealed bundle.
    key_id = _create_key(srv, tenant="t1")
    status, exported = srv.request(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t1", "passphrase": "pw"}, OPERATOR,
    )
    assert status == 200, exported
    # Re-key the payload to a fresh key_id so the import is a genuine CREATE
    # (the provenance block still names fakekms, which the active provider
    # must own).
    payload = keybundle.decode_bundle(exported["bundle"], "pw")
    payload["key_id"] = str(uuid.uuid4())
    bundle = keybundle.encode_bundle(payload, "pw")

    # Reconnect to a DIFFERENT provider id: importing the bundle (whose
    # provenance names fakekms) must stay pending rather than terminal.
    monkeypatch.setenv("FAKE_KMS_PROVIDER_ID", "fakekms-alt")
    status, _ = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200

    idem = "import-displace-0001"
    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": idem},
    )
    assert status == 503, body
    op_id = body["operation_id"]
    status, body = srv.request(
        "GET", "/v1/operations/%s?tenant_id=t1" % op_id, headers=OPERATOR
    )
    assert body["status"] == "pending"
    # Nothing was appended for the displaced import.
    assert sum(1 for e in env.audit_events() if e.event_id == op_id) == 0

    # Same id back; the identical import continues once and commits.
    monkeypatch.delenv("FAKE_KMS_PROVIDER_ID", raising=False)
    status, _ = srv.request(
        "POST", "/v1/provider/reconnect", {}, OPERATOR
    )
    assert status == 200
    status, body = srv.request(
        "POST", "/v1/keys/import",
        {"tenant_id": "t1", "passphrase": "pw", "bundle": bundle},
        {"X-Operator-Id": "alice", "Idempotency-Key": idem},
    )
    assert status == 201, body
    assert body["operation_id"] == op_id
    assert sum(1 for e in env.audit_events() if e.event_id == op_id) == 1


def test_active_provider_history_persists_across_processes(env):
    # The data directory remembers the original provider_id, so a *new*
    # process that only ever loaded a different-id provider still recognizes a
    # pending op's original owner (rather than treating it as never-active).
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()  # loads fakekms, records history
    provider_mod.reset_for_tests()

    history_file = os.path.join(env.data_dir, "provider-ids.json")
    assert os.path.exists(history_file)
    with open(history_file, encoding="utf-8") as fh:
        assert "fakekms" in json.load(fh)["ids"]
    # A fresh module state rehydrates from disk on bind.
    provider_mod._active_history.clear()
    provider_mod.bind_data_dir(env.data_dir)
    assert provider_mod.provider_was_active("fakekms")


# -- committed cross-process provider state (provider-state.json) ------------
def _state_path(env):
    return os.path.join(env.data_dir, "provider-state.json")


def _read_state_raw(env):
    with open(_state_path(env), "rb") as fh:
        return fh.read()


def test_first_healthy_activation_writes_state_file(env):
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    raw = _read_state_raw(env)
    # Compact UTF-8 JSON, fixed key order, no trailing newline, mode 0600.
    assert raw == (
        b'{"schema_version":1,"provider_id":"fakekms","generation":1}'
    )
    assert os.stat(_state_path(env)).st_mode & 0o777 == 0o600


def test_successful_reconnect_increments_generation(env):
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    provider_mod.reconnect()
    assert json.loads(_read_state_raw(env)) == {
        "schema_version": 1,
        "provider_id": "fakekms",
        "generation": 2,
    }
    provider_mod.reconnect()
    assert json.loads(_read_state_raw(env))["generation"] == 3


def test_failed_reconnect_keeps_old_generation(env):
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    before = _read_state_raw(env)
    env.set_faults({"health": False})
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    assert _read_state_raw(env) == before


def test_non_ascii_provider_id_written_unescaped(env, monkeypatch):
    provider_mod.bind_data_dir(env.data_dir)
    monkeypatch.setenv("FAKE_KMS_PROVIDER_ID", "fakekms-ü")
    provider_mod.reconnect()
    assert _read_state_raw(env) == (
        '{"schema_version":1,"provider_id":"fakekms-ü","generation":1}'
    ).encode("utf-8")


def test_corrupt_state_file_is_503_and_never_rewritten(env):
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    with open(_state_path(env), "wb") as fh:
        fh.write(b'{"schema_version":1,"provider_id":')
    before = _read_state_raw(env)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    assert provider_mod.provider_status() == {
        "provider_id": None,
        "status": "unavailable",
    }
    assert _read_state_raw(env) == before


@pytest.mark.parametrize(
    "bad",
    [
        b'{"schema_version":2,"provider_id":"fakekms","generation":1}',
        b'{"schema_version":1,"provider_id":"","generation":1}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":0}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":true}',
        b'{"schema_version":1,"provider_id":"fakekms"}',
        b'{"schema_version":1,"provider_id":"fakekms","generation":1,"x":0}',
        b'[1,2,3]',
    ],
)
def test_invalid_state_fields_are_503_and_untouched(env, bad):
    provider_mod.bind_data_dir(env.data_dir)
    with open(_state_path(env), "wb") as fh:
        fh.write(bad)
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    with pytest.raises(provider_mod.ProviderUnavailable):
        provider_mod.reconnect()
    assert _read_state_raw(env) == bad


def test_call_after_foreign_commit_rebuilds_and_adopts(env):
    # A CLI process commits a new generation; this process's next provider
    # call rebuilds from the current configuration and adopts it.
    provider_mod.bind_data_dir(env.data_dir)
    provider_mod.get_provider()
    assert json.loads(_read_state_raw(env))["generation"] == 1
    result = run_cli(env, "provider", "reconnect", "--operator", "alice")
    assert result.returncode == 0, result.stderr
    assert json.loads(_read_state_raw(env))["generation"] == 2
    with provider_mod.provider_call() as provider:
        assert provider.provider_id == "fakekms"
    assert provider_mod._active_state == ("fakekms", 2)


def test_call_with_mismatched_committed_id_is_zero_side_effect_503(env):
    # The committed state names a provider_id this process's configuration
    # cannot build: the next call fails 503 before any backend object.
    provider_mod.bind_data_dir(env.data_dir)
    with open(_state_path(env), "wb") as fh:
        fh.write(b'{"schema_version":1,"provider_id":"otherkms","generation":4}')
    before = env.kms_handles()
    with pytest.raises(provider_mod.ProviderUnavailable):
        with provider_mod.provider_call():
            pass
    assert env.kms_handles() == before
    assert _read_state_raw(env).endswith(b'"generation":4}')


def test_status_rejects_tenant_id_in_body_before_probe(http):
    env, srv = http
    # Even with the factory failing (the probe could not build anything), a
    # tenant_id in a non-empty body is a 400 naming the field, before any
    # factory build or health probe.
    env.set_faults({"factory_fails": True})
    status, body = srv.raw(
        "GET", "/v1/provider/status", b'{"tenant_id": "t1"}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 400
    assert "tenant_id" in body
    # A body without tenant_id does not trip the check.
    status, body = srv.raw(
        "GET", "/v1/provider/status", b'{"other": 1}',
        {"Content-Type": "application/json", **OPERATOR},
    )
    assert status == 200
    env.clear_faults()


def test_reconnect_body_tenant_id_names_field(http):
    env, srv = http
    status, body = srv.request(
        "POST", "/v1/provider/reconnect", {"tenant_id": "t1"}, OPERATOR
    )
    assert status == 400
    assert "tenant_id" in body["error"]


# -- CLI ---------------------------------------------------------------------
def test_cli_provider_status_and_reconnect(env):
    result = run_cli(env, "provider", "status", "--operator", "alice")
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout.strip())
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}

    result = run_cli(env, "provider", "reconnect", "--operator", "alice")
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout.strip())
    assert body["provider_id"] == "fakekms" and body["status"] == "ready"


def test_cli_provider_status_unavailable_is_still_rc0(env):
    env.set_faults({"factory_fails": True})
    result = run_cli(env, "provider", "status", "--operator", "alice")
    assert result.returncode == 0
    assert json.loads(result.stdout.strip()) == {
        "provider_id": None, "status": "unavailable",
    }


def test_cli_provider_reconnect_failure_exit_1_fixed_body(env):
    # Load a healthy instance in one process, then make a fresh process's
    # rebuild fail: there is no cached instance in the new process, so the
    # rebuild fails and reconnect exits 1 with the fixed message.
    run_cli(env, "provider", "reconnect", "--operator", "alice")
    env.set_faults({"health": False})
    result = run_cli(env, "provider", "reconnect", "--operator", "alice")
    assert result.returncode == 1
    assert json.loads(result.stderr.strip()) == {
        "error": "key management provider is unavailable",
    }


def test_cli_provider_requires_operator_exit_2(env):
    result = run_cli(env, "provider", "status")
    assert result.returncode == 2
    result = run_cli(env, "provider", "reconnect")
    assert result.returncode == 2
