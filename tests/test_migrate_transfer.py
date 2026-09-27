"""Tests for the optional native ciphertext-transfer migrate path.

When a migrated version's owning provider AND the chain's ready entry both
declare the ``transfer_out``/``transfer_in`` operations, migrate moves that
version through ``transfer_out(handle, target_provider_id)`` /
``transfer_in(source_provider_id, blob)`` -- an opaque sealed blob crosses
the boundary, ``export_material`` is never called and plaintext key
material never enters the service. These tests cover:

* the provider contract: both operations must be declared together with
  callable methods (anything else fails the contract), the argument
  ``TypeError``/``ValueError`` rules, ``ProviderUnavailable`` for an
  unknown handle/peer or a backend fault, ``ProviderInvalidMaterial`` for
  an authentication/algorithm/public-key mismatch, the non-empty bytes
  result of ``transfer_out`` and the fixed-order
  ``handle, public_key, encrypted_material`` triple of ``transfer_in``;
* the built-in local provider declaring and implementing both operations;
* the migrate path selection: transfer when both sides declare it (no
  ``export_material``/``import_material`` call), the old export/import
  path otherwise;
* failure semantics: the fixed 503 with NO audit event, new handles
  deleted and the old record kept before the commit point, the operation
  finishing failed and replaying the same 503;
* success semantics: only the provider triple changes, exactly one
  ``migrate`` success event, post-commit old-handle cleanup.
"""

import json
import os
import uuid

import pytest

from keymgr import provider as provider_mod
from keymgr.audit import AuditLog
from keymgr.provider import (
    LocalProvider,
    ProviderInvalidMaterial,
    ProviderTransferFailed,
    ProviderUnavailable,
)

from test_provider_reconnect import OPERATOR, HttpServer
from test_key_migrate import (
    _create,
    _migrate,
    _migrate_events,
    _rotate,
    _switchover,
    _versions_on_disk,
)

CHAIN = "local,fake_kms:make_provider"
CHAIN_REVERSED = "fake_kms:make_provider,local"


@pytest.fixture()
def chain_env(env, monkeypatch):
    """A data dir wired to a two-entry local/fakekms chain."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def reversed_chain_env(env, monkeypatch):
    """A data dir whose primary is fakekms and standby is local."""
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN_REVERSED)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()
    provider_mod.reset_for_tests()


@pytest.fixture()
def local(tmp_path):
    provider = LocalProvider()
    provider.configure(str(tmp_path / "data"))
    return provider


# -- declaration --------------------------------------------------------------
def test_local_provider_declares_transfer():
    operations = LocalProvider.capabilities["operations"]
    assert "transfer_out" in operations
    assert "transfer_in" in operations
    assert provider_mod.declares_transfer(LocalProvider())
    assert provider_mod.declares_transfer(provider_mod.get_local_provider())


def test_declares_transfer_requires_both_operations():
    class _OneWay:
        capabilities = {
            "algorithms": ("AES256", "RSA2048"),
            "operations": ("transfer_out",),
        }

    assert not provider_mod.declares_transfer(_OneWay())
    assert not provider_mod.declares_transfer(object())
    assert not provider_mod.declares_transfer(None)


class _ContractStub:
    """A minimally valid external provider for contract-validation tests."""

    provider_id = "stub"
    capabilities = {
        "algorithms": ["AES256", "RSA2048"],
        "operations": [
            "generate",
            "rotate",
            "import_material",
            "export_material",
            "delete",
        ],
    }

    def generate(self, algorithm):
        raise NotImplementedError

    def rotate(self, algorithm):
        raise NotImplementedError

    def import_material(self, algorithm, public_key, material):
        raise NotImplementedError

    def export_material(self, handle):
        raise NotImplementedError

    def delete(self, handle):
        raise NotImplementedError


def _with_transfer(stub, operations, out=True, into=True):
    stub.capabilities = dict(stub.capabilities)
    stub.capabilities["operations"] = (
        stub.capabilities["operations"] + operations
    )
    if out:
        stub.transfer_out = lambda handle, target: b"blob"
    if into:
        stub.transfer_in = lambda source, blob: {
            "handle": "h",
            "public_key": None,
            "encrypted_material": "m",
        }
    return stub


def test_contract_requires_both_transfer_operations_declared():
    # Declaring exactly one of the pair fails the contract.
    only_out = _with_transfer(_ContractStub(), ["transfer_out"])
    with pytest.raises(ProviderUnavailable):
        provider_mod._validate_external(only_out)
    only_in = _with_transfer(_ContractStub(), ["transfer_in"])
    with pytest.raises(ProviderUnavailable):
        provider_mod._validate_external(only_in)
    # Declaring both with callable methods passes.
    both = _with_transfer(
        _ContractStub(), ["transfer_out", "transfer_in"]
    )
    provider_mod._validate_external(both)
    # Declaring both without a callable method fails the contract.
    broken = _with_transfer(
        _ContractStub(), ["transfer_out", "transfer_in"], into=False
    )
    with pytest.raises(ProviderUnavailable):
        provider_mod._validate_external(broken)
    broken2 = _with_transfer(
        _ContractStub(), ["transfer_out", "transfer_in"], out=False
    )
    with pytest.raises(ProviderUnavailable):
        provider_mod._validate_external(broken2)
    # Not declaring either keeps the provider valid.
    provider_mod._validate_external(_ContractStub())


# -- local provider contract ---------------------------------------------------
def test_local_transfer_argument_contract(local):
    triple = local.generate("AES256")
    # String arguments: non-str -> TypeError, empty -> ValueError.
    for bad in (None, 7, b"x", ["h"]):
        with pytest.raises(TypeError):
            local.transfer_out(bad, "peer")
        with pytest.raises(TypeError):
            local.transfer_out(triple.handle, bad)
        with pytest.raises(TypeError):
            local.transfer_in(bad, b"blob")
    with pytest.raises(ValueError):
        local.transfer_out("", "peer")
    with pytest.raises(ValueError):
        local.transfer_out(triple.handle, "")
    with pytest.raises(ValueError):
        local.transfer_in("", b"blob")
    # blob: non-bytes -> TypeError, empty -> ValueError.
    for bad in (None, "text", 7, [1]):
        with pytest.raises(TypeError):
            local.transfer_in("peer", bad)
    with pytest.raises(ValueError):
        local.transfer_in("peer", b"")
    # An unknown handle is ProviderUnavailable.
    with pytest.raises(ProviderUnavailable):
        local.transfer_out("no-such-handle", "peer")


def test_local_transfer_round_trip_and_result_shape(local):
    for algorithm in ("AES256", "RSA2048"):
        triple = local.generate(algorithm)
        blob = local.transfer_out(triple.handle, "other-provider")
        assert isinstance(blob, bytes) and blob
        # The blob is opaque ciphertext: no plaintext material inside.
        exported = local.export_material(triple.handle)
        assert exported.encrypted_material.encode("utf-8") not in blob
        # A second local provider addressed by the blob opens and adopts it.
        other = LocalProvider()
        other.configure(os.path.join(local._data_dir, "other"))
        object.__setattr__(other, "provider_id", "other-provider")
        result = other.transfer_in("local", blob)
        assert list(result.keys()) == [
            "handle",
            "public_key",
            "encrypted_material",
        ]
        assert isinstance(result["handle"], str) and result["handle"]
        assert isinstance(result["encrypted_material"], str)
        assert result["encrypted_material"]
        assert result["public_key"] == triple.public_key
        # The adopted material is the same key.
        reexported = other.export_material(result["handle"])
        assert reexported.encrypted_material == exported.encrypted_material
        assert reexported.public_key == exported.public_key


def test_local_transfer_authentication_failures(local):
    triple = local.generate("RSA2048")
    blob = local.transfer_out(triple.handle, "local")
    # A tampered blob cannot be authenticated.
    tampered = bytearray(blob)
    tampered[-3] ^= 0x01
    with pytest.raises(ProviderInvalidMaterial):
        local.transfer_in("peer", bytes(tampered))
    # A blob sealed for a different provider cannot be authenticated.
    foreign = local.transfer_out(triple.handle, "someone-else")
    with pytest.raises(ProviderInvalidMaterial):
        local.transfer_in("peer", foreign)
    # Garbage is not a transfer blob.
    with pytest.raises(ProviderInvalidMaterial):
        local.transfer_in("peer", b"not-a-transfer-blob")


# -- _SafeProvider boundary ----------------------------------------------------
class _InnerTransfer:
    """Inner provider stub driving the _SafeProvider transfer wrappers."""

    provider_id = "inner"
    capabilities = {
        "algorithms": ("AES256", "RSA2048"),
        "operations": (
            "generate",
            "rotate",
            "import_material",
            "export_material",
            "delete",
            "transfer_out",
            "transfer_in",
        ),
    }

    def __init__(self, out_result=b"blob", in_result=None, exc=None):
        self.out_result = out_result
        self.in_result = (
            {
                "handle": "h",
                "public_key": None,
                "encrypted_material": "m",
            }
            if in_result is None
            else in_result
        )
        self.exc = exc
        self.calls = []

    def transfer_out(self, handle, target_provider_id):
        self.calls.append(("out", handle, target_provider_id))
        if self.exc is not None:
            raise self.exc
        return self.out_result

    def transfer_in(self, source_provider_id, blob):
        self.calls.append(("in", source_provider_id, blob))
        if self.exc is not None:
            raise self.exc
        return self.in_result


def _safe(inner):
    return provider_mod._SafeProvider(inner)


def test_safe_provider_transfer_argument_contract():
    safe = _safe(_InnerTransfer())
    for bad in (None, 7, b"x"):
        with pytest.raises(TypeError):
            safe.transfer_out(bad, "peer")
        with pytest.raises(TypeError):
            safe.transfer_out("h", bad)
        with pytest.raises(TypeError):
            safe.transfer_in(bad, b"blob")
    with pytest.raises(ValueError):
        safe.transfer_out("", "peer")
    with pytest.raises(ValueError):
        safe.transfer_out("h", "")
    with pytest.raises(ValueError):
        safe.transfer_in("", b"blob")
    for bad in (None, "text", 7):
        with pytest.raises(TypeError):
            safe.transfer_in("peer", bad)
    with pytest.raises(ValueError):
        safe.transfer_in("peer", b"")


def test_safe_provider_transfer_result_contract():
    # transfer_out must return non-empty bytes.
    for bad in (None, b"", "text", {}, 7):
        with pytest.raises(ProviderUnavailable):
            _safe(_InnerTransfer(out_result=bad)).transfer_out("h", "p")
    assert _safe(_InnerTransfer(out_result=b"x")).transfer_out("h", "p") == b"x"
    # transfer_in must return the fixed-order triple.
    good = {"handle": "h", "public_key": None, "encrypted_material": "m"}
    result = _safe(_InnerTransfer(in_result=good)).transfer_in("s", b"b")
    assert list(result.keys()) == ["handle", "public_key", "encrypted_material"]
    bad_results = [
        b"blob",
        "text",
        {},
        {"handle": "h"},
        {"public_key": None, "handle": "h", "encrypted_material": "m"},  # order
        {"handle": "", "public_key": None, "encrypted_material": "m"},
        {"handle": 7, "public_key": None, "encrypted_material": "m"},
        {"handle": "h", "public_key": None, "encrypted_material": ""},
        {"handle": "h", "public_key": None, "encrypted_material": 7},
        {"handle": "h", "public_key": 7, "encrypted_material": "m"},
        {"handle": "h", "public_key": None, "encrypted_material": "m", "x": 1},
    ]
    for bad in bad_results:
        with pytest.raises(ProviderUnavailable):
            _safe(_InnerTransfer(in_result=bad)).transfer_in("s", b"b")
    # A public_key string is accepted.
    ok = {"handle": "h", "public_key": "pem", "encrypted_material": "m"}
    assert _safe(_InnerTransfer(in_result=ok)).transfer_in("s", b"b") == ok


def test_safe_provider_transfer_error_mapping():
    # Provider errors pass through unchanged.
    with pytest.raises(ProviderInvalidMaterial):
        _safe(_InnerTransfer(exc=ProviderInvalidMaterial("bad blob"))).transfer_in(
            "s", b"b"
        )
    with pytest.raises(ProviderUnavailable):
        _safe(_InnerTransfer(exc=ProviderUnavailable("down"))).transfer_out(
            "h", "p"
        )
    # ValueError/TypeError from the provider pass through.
    with pytest.raises(ValueError):
        _safe(_InnerTransfer(exc=ValueError("empty"))).transfer_out("h", "p")
    # Any other exception is a backend fault -> ProviderUnavailable.
    with pytest.raises(ProviderUnavailable):
        _safe(_InnerTransfer(exc=RuntimeError("boom"))).transfer_out("h", "p")
    with pytest.raises(ProviderUnavailable):
        _safe(_InnerTransfer(exc=RuntimeError("boom"))).transfer_in("s", b"b")


# -- migrate path selection -----------------------------------------------------
def test_migrate_uses_transfer_when_both_sides_declare(http):
    env, srv = http
    env.set_faults({"declare_transfer": True})
    import fake_kms

    fake_kms.reset()
    key_id = _create(srv, algorithm="RSA2048")
    assert _rotate(srv, key_id, algorithm="RSA2048", key="rot-1")[0] == 201
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = _migrate(srv, key_id, key="mig-transfer")
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id",
        "provider_id",
        "versions",
        "operation_id",
    ]
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1, 2]
    # The transfer path ran: no export/import material calls at all.
    assert fake_kms.call_count("transfer_in") == 2
    assert fake_kms.call_count("export_material") == 0
    assert fake_kms.call_count("import_material") == 0
    # Only the provider triples changed; one migrate success event.
    versions, data = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"fakekms"}
    assert len(env.kms_handles()) == 2
    with open(os.path.join(env.data_dir, "local-registry.json")) as fh:
        assert json.load(fh) == {}
    assert _migrate_events(env) == [("migrate", "success", key_id)]
    # The migrated key still decrypts.
    status, enc = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": "aGVsbG8="},
        {**OPERATOR, "Idempotency-Key": "enc-after"},
    )
    assert status == 200, enc


def test_migrate_uses_transfer_from_external_to_local(reversed_chain_env):
    env = reversed_chain_env
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        import fake_kms

        fake_kms.reset()
        key_id = _create(srv)
        assert _rotate(srv, key_id, key="rot-1")[0] == 201
        assert _switchover(srv, "local")[0] == 200
        status, body = _migrate(srv, key_id, key="mig-to-local")
        assert status == 200, body
        assert body["provider_id"] == "local"
        # fakekms exported via transfer_out; nothing via export_material.
        assert fake_kms.call_count("transfer_out") == 2
        assert fake_kms.call_count("export_material") == 0
        assert fake_kms.call_count("import_material") == 0
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert env.kms_handles() == set()
        assert _migrate_events(env) == [("migrate", "success", key_id)]
    finally:
        srv.stop()
        env.clear_faults()
        provider_mod.reset_for_tests()


def test_migrate_falls_back_to_export_when_peer_does_not_declare(http):
    env, srv = http
    # fakekms does NOT declare the transfer operations: the local provider
    # declaring them alone keeps the old export/import path.
    import fake_kms

    fake_kms.reset()
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id, key="mig-export")
    assert status == 200, body
    assert fake_kms.call_count("transfer_in") == 0
    assert fake_kms.call_count("import_material") == 1
    assert _migrate_events(env) == [("migrate", "success", key_id)]


# -- failure semantics -----------------------------------------------------------
def test_migrate_transfer_failure_is_503_without_audit(http):
    env, srv = http
    env.set_faults({"declare_transfer": True, "transfer_fail": True})
    import fake_kms

    fake_kms.reset()
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200

    status, body = _migrate(srv, key_id, key="mig-fail")
    assert status == 503, body
    assert body == {
        "error": "key management provider is unavailable",
        "operation_id": body["operation_id"],
    }
    assert list(body.keys()) == ["error", "operation_id"]
    op_id = body["operation_id"]
    uuid.UUID(op_id)
    # No audit event at all for the failed transfer.
    assert _migrate_events(env) == []
    # The old record is kept verbatim and no new handle survives.
    versions, data = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}
    assert data["pending_event"] is None
    assert env.kms_handles() == set()
    # The operation finished failed and replays the same 503 verbatim --
    # still without an audit event.
    status, opbody = srv.request(
        "GET", "/v1/operations/%s" % op_id,
        headers={**OPERATOR, "X-Tenant-Id": "t1"},
    )
    assert status == 200
    assert opbody["status"] == "failed"
    assert opbody["http_status"] == 503
    status, replay = _migrate(srv, key_id, key="mig-fail")
    assert status == 503
    assert replay == body
    assert _migrate_events(env) == []
    # Rollback artifacts are gone.
    assert not os.path.exists(
        os.path.join(env.data_dir, "migrations", op_id + ".json")
    )
    assert not os.path.exists(
        os.path.join(env.data_dir, "provisions", op_id + ".json")
    )
    assert not os.path.exists(
        os.path.join(env.data_dir, "operation-artifacts", op_id + ".json")
    )


def test_migrate_transfer_malformed_result_is_503_without_audit(http):
    env, srv = http
    env.set_faults({"declare_transfer": True, "transfer_short": True})
    import fake_kms

    fake_kms.reset()
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    status, body = _migrate(srv, key_id, key="mig-short")
    assert status == 503, body
    assert body["error"] == "key management provider is unavailable"
    assert _migrate_events(env) == []
    versions, _ = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}
    assert env.kms_handles() == set()


def test_migrate_transfer_failure_on_source_side_is_503_without_audit(
    reversed_chain_env,
):
    env = reversed_chain_env
    env.set_faults({"declare_transfer": True, "transfer_fail": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        import fake_kms

        fake_kms.reset()
        key_id = _create(srv)
        assert _switchover(srv, "local")[0] == 200
        status, body = _migrate(srv, key_id, key="mig-src-fail")
        assert status == 503, body
        assert body["error"] == "key management provider is unavailable"
        assert _migrate_events(env) == []
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"fakekms"}
        assert len(env.kms_handles()) == 1
    finally:
        srv.stop()
        env.clear_faults()
        provider_mod.reset_for_tests()


def test_migrate_transfer_partial_declaration_breaks_provider(http):
    env, srv = http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    # Declaring only one of the pair fails the provider contract: the
    # migrate's peer resolution rebuilds the chain entries and the broken
    # entry makes it the fixed 503.
    env.set_faults({"declare_transfer_out": True})
    status, body = _migrate(srv, key_id, key="mig-broken")
    assert status == 503, body
    assert body["error"] == "key management provider is unavailable"


def test_migrate_transfer_unconfirmed_rollback_delete_leaves_artifacts(
    chain_env,
):
    """A failed transfer whose NEW handle delete cannot be confirmed keeps
    the migration snapshot for the startup sweep; the old record stays
    authoritative throughout and no audit event is ever written."""
    env = chain_env
    # declare_transfer must be visible when the chain entries are first
    # built (capabilities are captured at build); the failure faults are
    # read per call and can be armed later.
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        assert _rotate(srv, key_id, key="rot-1")[0] == 201
        assert _switchover(srv, "fakekms")[0] == 200
        # v1 transfers fine; v2's transfer_in fails; the rollback delete of
        # v1's new handle then fails too.
        env.set_faults(
            {
                "declare_transfer": True,
                "fail_after": {"transfer_in": 1},
                "fail": {"delete": True},
            }
        )
        status, body = _migrate(srv, key_id, key="mig-delfail")
        assert status == 503, body
        assert body["error"] == "key management provider is unavailable"
        op_id = body["operation_id"]
        assert _migrate_events(env) == []
        # The old record is authoritative; the new handle and the snapshot
        # survive for the restart cleanup.
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert len(env.kms_handles()) == 1
        snapshot = os.path.join(env.data_dir, "migrations", op_id + ".json")
        assert os.path.exists(snapshot)
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    env.clear_faults()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        # Startup rollback reaped the new handle and dropped the snapshot;
        # the old record is untouched and still no event was booked.
        assert env.kms_handles() == set()
        assert not os.path.exists(snapshot)
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert _migrate_events(env) == []
    finally:
        srv2.stop()
        provider_mod.reset_for_tests()


def test_migrate_transfer_post_commit_cleanup_failure_replays_200(
    reversed_chain_env,
):
    """Committing the transfer makes the new triples authoritative: a
    failing OLD-handle delete afterwards never changes the 200, the
    snapshot finishes on restart and the success replays verbatim."""
    env = reversed_chain_env
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        import fake_kms

        fake_kms.reset()
        key_id = _create(srv)
        old_handles = set(env.kms_handles())
        assert len(old_handles) == 1
        assert _switchover(srv, "local")[0] == 200
        env.set_faults(
            {"declare_transfer": True, "fail": {"delete": True}}
        )
        status, body = _migrate(srv, key_id, key="mig-1")
        assert status == 200, body
        op_id = body["operation_id"]
        # The transfer path ran; the old fake handle survives for now.
        assert fake_kms.call_count("transfer_out") == 1
        assert fake_kms.call_count("export_material") == 0
        assert old_handles <= env.kms_handles()
        snapshot = os.path.join(env.data_dir, "migrations", op_id + ".json")
        assert os.path.exists(snapshot)
        # The committed success replays verbatim despite the cleanup
        # failure; exactly one migrate event exists.
        status, replay = _migrate(srv, key_id, key="mig-1")
        assert status == 200 and replay == body
        assert _migrate_events(env) == [("migrate", "success", key_id)]
    finally:
        srv.stop()
        env.clear_faults()
        provider_mod.reset_for_tests()

    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        assert env.kms_handles() == set()
        assert not os.path.exists(snapshot)
        status, replay = _migrate(srv2, key_id, key="mig-1")
        assert status == 200
        assert replay["operation_id"] == op_id
        assert len(_migrate_events(env)) == 1
    finally:
        srv2.stop()
        provider_mod.reset_for_tests()


def test_transfer_failed_exception_is_provider_unavailable():
    assert issubclass(ProviderTransferFailed, ProviderUnavailable)


# -- CLI -----------------------------------------------------------------------
def test_cli_migrate_transfer_success_and_failure(chain_env):
    from test_recovery_cli import run_cli

    env = chain_env
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        assert _switchover(srv, "fakekms")[0] == 200
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    result = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "cli-transfer",
    )
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout.strip())
    assert list(body.keys()) == [
        "key_id",
        "provider_id",
        "versions",
        "operation_id",
    ]
    assert body["provider_id"] == "fakekms"
    assert _migrate_events(env) == [("migrate", "success", key_id)]

    # A transfer failure on a second key: exit 1, fixed text, no audit.
    # The key is minted on local so the migrate moves it to fakekms.
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        assert _switchover(srv, "local")[0] == 200
        second = _create(srv)
        assert _switchover(srv, "fakekms")[0] == 200
    finally:
        srv.stop()
        provider_mod.reset_for_tests()
    env.set_faults({"declare_transfer": True, "transfer_fail": True})
    try:
        failed = run_cli(
            env, "migrate", "--tenant-id", "t1", "--key-id", second,
            "--operator", "alice", "--idempotency-key", "cli-transfer-fail",
        )
        assert failed.returncode == 1
        err = json.loads(failed.stderr.strip())
        assert list(err.keys()) == ["error", "operation_id"]
        assert err["error"] == "key management provider is unavailable"
        # Still exactly one migrate event (the first key's success).
        assert _migrate_events(env) == [("migrate", "success", key_id)]
    finally:
        env.clear_faults()
        provider_mod.reset_for_tests()
