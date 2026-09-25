"""KMS/HSM health checks and non-disruptive provider reconnect.

Covers:

* the optional ``health()`` contract (missing method -> healthy; non-bool or
  raised exception -> unavailable, with no backend text leaking);
* ``GET /v1/provider/status`` and ``POST /v1/provider/reconnect`` (operator
  header only, no tenant_id; reconnect body must be exactly ``{}``; fixed
  ``provider_id,status`` key order; provider_id null on a failed load; the
  fixed 503 body with the old instance retained on a rebuild/health/drain
  failure);
* the shared five-second gate: an in-flight call finishes on the old
  instance, a new call waits and then runs on the fresh instance, and a gate
  that expires is a 503 with zero side effects;
* pending operations stay bound to their original provider_id: a retry while
  a different provider is active stays PENDING and answers 503, a reconnect
  back to the SAME id lets the identical retry continue, and the
  operation_id/event_id is never duplicated;
* the CLI ``provider status|reconnect --operator O`` output and exit codes.
"""

import json
import os
import sys
import threading
import time
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import provider as provider_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr.operations import (
    OperationStore,
    STATUS_PENDING,
    STATUS_SUCCEEDED,
)
from keymgr.policy import PolicyStore
from keymgr.provider import (
    ProviderMismatch,
    ProviderSwitchTimeout,
    ProviderUnavailable,
)
from keymgr.restore import RestoreCoordinator
from keymgr.server import make_handler
from keymgr.store import KeyStore


# ---------------------------------------------------------------- health()
class _NoHealth:
    provider_id = "no-health"
    capabilities = {
        "algorithms": ["AES256", "RSA2048"],
        "operations": [
            "generate", "rotate", "import_material",
            "export_material", "delete",
        ],
    }


def test_missing_health_method_is_healthy():
    assert provider_mod._is_healthy(_NoHealth()) is True
    # The reconnect gate treats a missing method as passing the check too.
    provider_mod._check_health(_NoHealth())


def test_health_false_is_unavailable_without_text():
    class Bad(_NoHealth):
        def health(self):
            return False

    assert provider_mod._is_healthy(Bad()) is False
    with pytest.raises(ProviderUnavailable) as exc:
        provider_mod._check_health(Bad())
    # The fixed message must not carry the backend's wording.
    assert "secret" not in str(exc.value).lower()


def test_health_nonbool_is_unavailable():
    class Bad(_NoHealth):
        def health(self):
            return "yes"

    assert provider_mod._is_healthy(Bad()) is False
    with pytest.raises(ProviderUnavailable):
        provider_mod._check_health(Bad())


def test_health_exception_is_unavailable_without_text():
    class Bad(_NoHealth):
        def health(self):
            raise RuntimeError("secret backend detail: handle=h-9d2f")

    assert provider_mod._is_healthy(Bad()) is False
    with pytest.raises(ProviderUnavailable) as exc:
        provider_mod._check_health(Bad())
    assert "h-9d2f" not in str(exc.value)


# ------------------------------------------------------------------ fixtures
@pytest.fixture()
def stack(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    state_path = str(tmp_path / "kms-state.json")
    faults_path = str(tmp_path / "kms-faults.json")
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", state_path)
    monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
    provider_mod.reset_for_tests()
    import fake_kms

    fake_kms.reset()

    # A second, distinct external provider (same code, different id) so a
    # reconnect can genuinely change the active provider_id in-process.
    class FakeKms2(fake_kms.FakeKmsProvider):
        provider_id = "fakekms2"

    fake_kms2 = types.ModuleType("fake_kms2")
    fake_kms2.make_provider = lambda: FakeKms2()
    monkeypatch.setitem(sys.modules, "fake_kms2", fake_kms2)

    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = RestoreCoordinator(store, policies)
    op_store = OperationStore(data_dir, audit_log)
    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(op_store)
    op_store.recover_pending(is_parked=artifact_store.is_parked)
    handler = make_handler(
        store, policies, coordinator, op_store, artifact_store
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    class Client:
        def __init__(self, base):
            self.base = base

        def call(self, method, path, body=None, headers=None, raw=None):
            if raw is None:
                data = (
                    json.dumps(body).encode()
                    if body is not None else None
                )
            else:
                data = raw
            h = {"X-Operator-Id": "alice"}
            if data is not None:
                h["Content-Type"] = "application/json"
            if headers:
                h.update(headers)
            req = urllib.request.Request(
                self.base + path, data=data, method=method, headers=h
            )
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    yield types.SimpleNamespace(
        data_dir=data_dir, audit=audit_log, store=store,
        policies=policies, op_store=op_store,
        artifacts=artifact_store, client=client,
        state_path=state_path, faults_path=faults_path,
        tmp=tmp_path,
    )
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


# ------------------------------------------------------- status / reconnect
def test_status_reports_ready_and_key_order(stack):
    status, body = stack.client.call("GET", "/v1/provider/status")
    assert status == 200
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}


def test_status_load_failure_has_null_provider_id(monkeypatch):
    provider_mod.reset_for_tests()
    monkeypatch.setenv("KEYMGR_PROVIDER", "no_such_module_zzz:factory")
    assert provider_mod.provider_status() == (None, False)
    provider_mod.reset_for_tests()


def test_status_unavailable_when_health_false(stack):
    with open(stack.faults_path, "w") as fh:
        json.dump({"health": False}, fh)
    # The already-installed instance is probed directly.
    provider_mod.get_provider()
    assert provider_mod.provider_status() == ("fakekms", False)
    status, body = stack.client.call("GET", "/v1/provider/status")
    assert status == 200
    assert body == {"provider_id": "fakekms", "status": "unavailable"}


def test_status_health_raises_and_nonbool(stack):
    provider_mod.get_provider()
    for fault in ("health_raises", "health_nonbool"):
        with open(stack.faults_path, "w") as fh:
            json.dump({fault: True}, fh)
        assert provider_mod.provider_status() == ("fakekms", False)


def test_reconnect_success_returns_status_body(stack):
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {}
    )
    assert status == 200
    assert list(body.keys()) == ["provider_id", "status"]
    assert body == {"provider_id": "fakekms", "status": "ready"}


def test_reconnect_rejects_nonempty_body(stack):
    for bad in (b"{", b"[]", b'{"extra":1}', b'{"provider_id":"x"}', b"null"):
        status, body = stack.client.call(
            "POST", "/v1/provider/reconnect", raw=bad
        )
        assert status == 400, bad
        assert set(body) == {"error"}


def test_reconnect_requires_empty_object_not_null(stack):
    status, _ = stack.client.call(
        "POST", "/v1/provider/reconnect", raw=b"{}"
    )
    assert status == 200


def test_provider_endpoints_reject_tenant(stack):
    status, body = stack.client.call(
        "GET", "/v1/provider/status", headers={"X-Tenant-Id": "t"}
    )
    assert status == 400 and "tenant_id" in body["error"]
    status, body = stack.client.call(
        "GET", "/v1/provider/status?tenant_id=t"
    )
    assert status == 400 and "tenant_id" in body["error"]
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {},
        headers={"X-Tenant-Id": "t"},
    )
    assert status == 400 and "tenant_id" in body["error"]
    # A body carrying tenant_id is also rejected (it is not the exact {}):
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {"tenant_id": "t"}
    )
    assert status == 400


def test_provider_endpoints_require_operator(stack):
    req = urllib.request.Request(
        stack.client.base + "/v1/provider/status", method="GET"
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400


def test_reconnect_health_failure_keeps_old_instance(stack, monkeypatch):
    old = provider_mod.get_provider()
    assert old.provider_id == "fakekms"
    with open(stack.faults_path, "w") as fh:
        json.dump({"health": False}, fh)
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {}
    )
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    # The old instance is retained and still the installed provider.
    assert provider_mod.get_provider() is old
    # Status still probes the (unhealthy) retained instance.
    assert provider_mod.provider_status() == ("fakekms", False)


def test_reconnect_swap_changes_provider_id(stack, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms2:make_provider")
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {}
    )
    assert status == 200
    assert body == {"provider_id": "fakekms2", "status": "ready"}
    assert provider_mod.get_provider().provider_id == "fakekms2"


# --------------------------------------------------------- the 5-second gate
def test_inflight_call_finishes_on_old_new_call_waits(monkeypatch, tmp_path):
    provider_mod.reset_for_tests()
    state = str(tmp_path / "s.json")
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", state)
    monkeypatch.setenv("FAKE_KMS_FAULTS", str(tmp_path / "f.json"))
    import fake_kms

    fake_kms.reset()
    old = provider_mod.get_provider()
    ready = threading.Event()
    seen = {}

    def inflight():
        with provider_mod.activity() as pinned:
            seen["old"] = pinned
            ready.set()
            time.sleep(0.5)

    t = threading.Thread(target=inflight)
    t.start()
    ready.wait(2)

    # A reconnect now must wait for the in-flight activity to drain.
    t0 = time.monotonic()
    new = provider_mod.reconnect(timeout=5)
    elapsed = time.monotonic() - t0
    t.join()
    assert elapsed >= 0.45
    assert seen["old"] is old
    assert new is not old
    assert provider_mod.get_provider() is new


def test_drain_timeout_retains_old_with_zero_side_effects(
    monkeypatch, tmp_path
):
    provider_mod.reset_for_tests()
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "s.json"))
    monkeypatch.setenv("FAKE_KMS_FAULTS", str(tmp_path / "f.json"))
    import fake_kms

    fake_kms.reset()
    old = provider_mod.get_provider()
    ready = threading.Event()

    def inflight():
        with provider_mod.activity():
            ready.set()
            time.sleep(0.6)

    t = threading.Thread(target=inflight)
    t.start()
    ready.wait(2)
    with pytest.raises(ProviderSwitchTimeout):
        provider_mod.reconnect(timeout=0.15)
    t.join()
    # Old instance retained.
    assert provider_mod.get_provider() is old

    # A new call arriving WHILE a switch is draining shares the gate: it
    # waits, and when its own budget expires answers 503 before touching a
    # provider; the failed switch then retains the old instance.
    ready2 = threading.Event()

    def inflight2():
        with provider_mod.activity(timeout=5):
            ready2.set()
            time.sleep(2.0)

    t2 = threading.Thread(target=inflight2)
    t2.start()
    ready2.wait(2)

    switch_error = {}

    def do_switch():
        try:
            provider_mod.reconnect(timeout=1.0)
        except ProviderSwitchTimeout as exc:
            switch_error["exc"] = exc

    st = threading.Thread(target=do_switch)
    st.start()
    deadline = time.monotonic() + 2
    while (
        not provider_mod._registry._switching
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert provider_mod._registry._switching

    t0 = time.monotonic()
    with pytest.raises(ProviderSwitchTimeout):
        with provider_mod.activity(timeout=0.2):
            pass  # pragma: no cover - must never enter the body
    assert 0.15 < time.monotonic() - t0 < 0.6
    st.join()
    t2.join()
    assert "exc" in switch_error
    assert provider_mod.get_provider() is old


# --------------------------------------------- end-to-end gate through HTTP
def test_http_reconnect_waits_for_inflight_rotate(stack, monkeypatch):
    key_id = _make_key(stack.client)
    # Make every rotate call pause inside the (old) provider.
    with open(stack.faults_path, "w") as fh:
        json.dump({"sleep": {"rotate": 1.0}}, fh)

    result = {}

    def do_rotate():
        result["rotate"] = stack.client.call(
            "POST", "/v1/keys/%s/rotate" % key_id,
            {"tenant_id": "t", "algorithm": "AES256"},
            headers={"Idempotency-Key": "rot-slow-1"},
        )

    t = threading.Thread(target=do_rotate)
    t.start()
    # Wait until the rotate has pinned the old instance and is inside the
    # slow provider call (one drain token outstanding), rather than a fixed
    # settle delay that can be too short under test-suite load.
    deadline = time.monotonic() + 3
    while (
        not provider_mod._registry._tokens
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert provider_mod._registry._tokens

    # Shorten ONLY the gate the about-to-issue reconnect uses; the rotate
    # already pinned its 5 s budget and keeps running on the old instance.
    monkeypatch.setattr(provider_mod, "SWITCH_WAIT_SECONDS", 0.3)
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {}
    )
    assert status == 503, body
    assert body == {"error": "key management provider is unavailable"}

    # The in-flight rotate still completes on the OLD instance (201).
    t.join()
    rstatus, rbody = result["rotate"]
    assert rstatus == 201, rbody
    assert rbody["version"] == 2

    # Once the call drains, a reconnect (full budget) succeeds.
    monkeypatch.undo()
    status, body = stack.client.call(
        "POST", "/v1/provider/reconnect", {}
    )
    assert status == 200
    assert body["status"] == "ready"


def test_new_call_waits_then_runs_on_fresh_instance(
    monkeypatch, tmp_path
):
    provider_mod.reset_for_tests()
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "s.json"))
    monkeypatch.setenv("FAKE_KMS_FAULTS", str(tmp_path / "f.json"))
    import fake_kms

    fake_kms.reset()
    old = provider_mod.get_provider()
    gate = threading.Event()       # released once the new call is waiting
    proceed = threading.Event()    # holds the in-flight old call
    seen = {}

    def inflight():
        with provider_mod.activity() as pinned:
            seen["old"] = pinned
            proceed.wait(2)

    t = threading.Thread(target=inflight)
    t.start()
    # Ensure the old call reserved its token.
    deadline = time.monotonic() + 2
    while not provider_mod._registry._tokens and time.monotonic() < deadline:
        time.sleep(0.01)

    def reconnecter():
        gate.set()
        seen["new"] = provider_mod.reconnect(timeout=5)

    rt = threading.Thread(target=reconnecter)
    rt.start()
    gate.wait(2)
    # Small delay so the reconnect is draining before the new call arrives.
    time.sleep(0.1)
    with provider_mod.activity(timeout=5) as pinned_by_new:
        # At this point the drain completed: this is the fresh instance.
        seen["new_call"] = pinned_by_new
        proceed.set()
    rt.join()
    t.join()
    assert seen["old"] is old
    assert seen["new"] is not old
    assert seen["new_call"] is seen["new"]


# ------------------------------------------------ pending/provider_id binding
def _bind_pending_rotate(stack, key_id, op_id):
    """Persist a bound, pre-provider pending rotate for ``key_id``."""
    from keymgr.operations import OperationRecord
    from datetime import datetime, timezone

    path = "/v1/keys/%s/rotate" % key_id
    body = json.dumps(
        {"tenant_id": "t", "algorithm": "AES256"},
        sort_keys=True, separators=(",", ":"),
    )
    now = datetime.now(timezone.utc).isoformat()
    record = OperationRecord(
        operation_id=op_id,
        tenant_id="t",
        operator_id="alice",
        path=path,
        request_body=body,
        idempotency_key="rotate-bound-1",
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details={
            "kind": "rotate",
            "key_id": key_id,
            "algorithm": "AES256",
            "provider_id": "fakekms",
        },
        mirror_required=True,
    )
    stack.op_store._write_record(record)
    # The idempotency index points at it so an identical retry replays/takes
    # over rather than binding a new operation.
    scope = stack.op_store._scope("t", "alice", "rotate-bound-1")
    fd = stack.op_store._locked()
    try:
        index = stack.op_store._load_index()
        index["bindings"][scope] = op_id
        stack.op_store._write_atomic(stack.op_store._index_path, index)
    finally:
        stack.op_store._unlocked(fd)
    # An intact, never-provisioned bound mirror for the write set.
    mirror = stack.artifacts.create(record)
    mirror.describe({"kind": "rotate", "write_set": [key_id]})
    return record


def test_pending_rotate_bound_to_provider_id(stack, monkeypatch):
    key_id = _make_key(stack.client)
    op_id = "11111111-1111-4111-8111-111111111111"
    _bind_pending_rotate(stack, key_id, op_id)

    # The bound id must be recorded in the durable details.
    rec = stack.op_store._read_record(op_id)
    assert (rec.details or {}).get("provider_id") == "fakekms"

    def rotate_body():
        return {"tenant_id": "t", "algorithm": "AES256"}

    # While a DIFFERENT provider is active the identical retry stays pending
    # and answers the fixed 503, with no event written.
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms2:make_provider")
    provider_mod.reconnect()
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        rotate_body(),
        headers={"Idempotency-Key": "rotate-bound-1"},
    )
    assert status == 503
    assert body == {
        "error": "key management provider is unavailable",
        "operation_id": op_id,
    }
    rec = stack.op_store._read_record(op_id)
    assert rec.status == STATUS_PENDING
    assert stack.audit.get_event(op_id) is None

    # GET operation still shows a pending op with hidden terminal fields.
    status, body = stack.client.call(
        "GET", "/v1/operations/%s?tenant_id=t" % op_id
    )
    assert status == 200
    assert body["status"] == "pending"
    assert body["http_status"] is None and body["response"] is None

    # Reconnect back to the SAME provider id, then the identical retry
    # continues under the same operation_id.
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    provider_mod.reconnect()
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        rotate_body(),
        headers={"Idempotency-Key": "rotate-bound-1"},
    )
    assert status == 201, body
    assert body["operation_id"] == op_id
    assert body["version"] == 2
    rec = stack.op_store._read_record(op_id)
    assert rec.status == STATUS_SUCCEEDED
    # Exactly one event, named after the operation_id (never duplicated).
    events = [
        e for e in stack.audit._read_all()
        if e.action == "rotate" and e.tenant_id == "t"
    ]
    assert [e.event_id for e in events] == [op_id]


def test_gate_mismatch_before_any_backend_call(stack, monkeypatch):
    from keymgr.operations import OperationRecord
    from datetime import datetime, timezone

    op_id = "22222222-2222-4222-8222-222222222222"
    now = datetime.now(timezone.utc).isoformat()
    record = OperationRecord(
        operation_id=op_id,
        tenant_id="t",
        operator_id="alice",
        path="/v1/keys/x/rotate",
        request_body="{}",
        idempotency_key="k2",
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        details={"kind": "rotate", "key_id": "x", "provider_id": "fakekms"},
        mirror_required=True,
    )
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms2:make_provider")
    provider_mod.reconnect()
    with pytest.raises(ProviderMismatch):
        with provider_mod.operation_gate(record, stack.op_store) as gate:
            gate.resolve("fakekms")
    # No new detail was written on mismatch.
    assert (record.details or {}).get("provider_id") == "fakekms"


def test_gate_preflight_fresh_cross_provider_is_terminal_503(
    stack, monkeypatch
):
    from keymgr.operations import OperationRecord
    from datetime import datetime, timezone

    # A brand-new (unbound) op importing material owned by an inactive
    # provider: terminal ProviderUnavailable, the same 503 as before the gate.
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms2:make_provider")
    provider_mod.reconnect()
    now = datetime.now(timezone.utc).isoformat()
    fresh = OperationRecord(
        operation_id="33333333-3333-4333-8333-333333333333",
        tenant_id="t", operator_id="alice", path="/v1/keys/import",
        request_body="{}", idempotency_key="k3",
        created_at=now, updated_at=now,
        details={"kind": "import", "key_id": "x"},
    )
    with provider_mod.operation_gate(fresh, stack.op_store) as gate:
        with pytest.raises(ProviderUnavailable):
            gate.preflight(["fakekms"])
    # Nothing was bound on the refusal.
    assert (fresh.details or {}).get("provider_id") is None

    # A RETRIED op already bound to the old provider: pending mismatch.
    bound = OperationRecord(
        operation_id="44444444-4444-4444-8444-444444444444",
        tenant_id="t", operator_id="alice", path="/v1/keys/import",
        request_body="{}", idempotency_key="k4",
        created_at=now, updated_at=now,
        details={"kind": "import", "key_id": "x", "provider_id": "fakekms"},
    )
    with provider_mod.operation_gate(bound, stack.op_store) as gate:
        with pytest.raises(ProviderMismatch):
            gate.preflight(["fakekms"])


# ----------------------------------------------------------------------- CLI
def _cli_env(data_dir):
    env = dict(os.environ)
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(tests_dir)
    env["PYTHONPATH"] = tests_dir + os.pathsep + repo_root
    env["KEYMGR_DATA_DIR"] = data_dir
    return env


def test_cli_provider_status_and_reconnect(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    env = _cli_env(data_dir)
    env["KEYMGR_PROVIDER"] = "fake_kms:make_provider"
    env["FAKE_KMS_STATE"] = str(tmp_path / "s.json")
    env["FAKE_KMS_FAULTS"] = str(tmp_path / "f.json")

    proc = run_cli_env(env, "provider", "status", "--operator", "alice")
    assert proc.returncode == 0, proc.stderr
    line = proc.stdout.strip()
    assert list(json.loads(line).keys()) == ["provider_id", "status"]
    assert json.loads(line) == {"provider_id": "fakekms", "status": "ready"}

    proc = run_cli_env(env, "provider", "reconnect", "--operator", "alice")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip()) == {
        "provider_id": "fakekms", "status": "ready",
    }


def test_cli_provider_status_unavailable_exit_zero(tmp_path):
    data_dir = str(tmp_path / "data")
    env = _cli_env(data_dir)
    env["KEYMGR_PROVIDER"] = "no_such_module_zzz:factory"
    proc = run_cli_env(env, "provider", "status", "--operator", "alice")
    assert proc.returncode == 0
    assert json.loads(proc.stdout.strip()) == {
        "provider_id": None, "status": "unavailable",
    }


def test_cli_provider_reconnect_failure_exit_1(tmp_path):
    data_dir = str(tmp_path / "data")
    env = _cli_env(data_dir)
    env["KEYMGR_PROVIDER"] = "no_such_module_zzz:factory"
    proc = run_cli_env(env, "provider", "reconnect", "--operator", "alice")
    assert proc.returncode == 1
    assert json.loads(proc.stderr.strip()) == {
        "error": "key management provider is unavailable",
    }


def run_cli_env(env, *args):
    import subprocess
    import sys

    cmd = [
        sys.executable, "-m", "keymgr", "--data-dir",
        env["KEYMGR_DATA_DIR"],
    ] + [str(a) for a in args]
    return subprocess.run(
        cmd, capture_output=True, text=True, env=env, timeout=60
    )
