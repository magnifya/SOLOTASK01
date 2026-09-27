"""Tests for the direct ciphertext-transfer path of whole-key migrate.

When BOTH the ready provider and a version's source provider declare the
``transfer_out``/``transfer_in`` pair, ``POST /v1/keys/{key_id}/migrate``
moves each version as an opaque sealed blob -- it never calls
``export_material`` and raw key material never enters the service. When
either side does not declare the pair, the legacy export/import path is used
unchanged. These tests cover:

* the transfer path happy path (local->fake and fake->local), for AES256 and
  RSA2048: 200, rebound triples, old handles reaped, one migrate event, no
  surviving artifacts, and envelope decrypt still works afterwards;
* the blob never lands on disk (the sealed ``kmt1`` prefix appears in no data
  directory file) and export_material is never called;
* pre-commit transfer failures (source/target backend fault, an illegal
  triple, a wrong public key, a non-bytes blob) are the fixed 503 with NO
  audit event and the operation PENDING; after the fault clears a same-key
  retry succeeds under the SAME operation_id and books exactly one event;
* unconfirmed new-handle cleanup retains the migration snapshot/journal/
  mirror for a restart, which rolls the scene back and lets the pending
  operation be taken over successfully;
* a provider declaring the pair without a callable method fails the chain
  contract (the entry is unavailable).
"""

import json
import os

import pytest

from keymgr import provider as provider_mod
from keymgr.audit import AuditLog

from test_provider_reconnect import OPERATOR, HttpServer
from test_key_migrate import (
    CHAIN,
    CHAIN_REVERSED,
    _create,
    _migrate,
    _migrate_events,
    _rotate,
    _switchover,
    _versions_on_disk,
)

from test_recovery_cli import run_cli

import fake_kms


@pytest.fixture()
def chain_env(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def reversed_chain_env(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN_REVERSED)
    yield env


@pytest.fixture()
def legacy_http(chain_env):
    """local/fakekms chain with the default fake (no transfer pair)."""
    env = chain_env
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()
    provider_mod.reset_for_tests()


@pytest.fixture()
def transfer_http(chain_env, monkeypatch):
    """local/fakekms chain with the fake declaring the transfer pair."""
    env = chain_env
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()
    provider_mod.reset_for_tests()


@pytest.fixture()
def transfer_reversed_http(reversed_chain_env, monkeypatch):
    """fakekms/local chain (fake primary) with the pair declared."""
    env = reversed_chain_env
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    server = HttpServer(env)
    yield env, server
    server.stop()
    provider_mod.reset_for_tests()


def _grep_data_dir(env, needle):
    """Whether ``needle`` (bytes) appears in any data-dir file."""
    for root, _dirs, names in os.walk(env.data_dir):
        for name in names:
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as fh:
                    if needle in fh.read():
                        return True
            except OSError:
                continue
    return False


def _op_pending(srv, op_id, tenant="t1"):
    status, body = srv.request(
        "GET", "/v1/operations/%s" % op_id,
        headers={**OPERATOR, "X-Tenant-Id": tenant},
    )
    assert status == 200, body
    return body


# -- happy path ---------------------------------------------------------------
@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_transfer_path_success_local_to_fake(transfer_http, algorithm):
    env, srv = transfer_http
    key_id = _create(srv, algorithm=algorithm)
    assert _rotate(srv, key_id, algorithm=algorithm, key="rot-1")[0] == 201
    assert _switchover(srv, "fakekms")[0] == 200

    fake_kms.reset()
    status, body = _migrate(srv, key_id, key="tx-1")
    assert status == 200, body
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1, 2]
    op_id = body["operation_id"]

    # The direct path was taken: no export/import, exactly the transfer pair.
    assert fake_kms.call_count("transfer_in") == 2
    assert fake_kms.call_count("transfer_out") == 0
    assert fake_kms.call_count("export_material") == 0
    assert fake_kms.call_count("import_material") == 0

    versions, data = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"fakekms"}
    assert data["current_version"] == 2
    assert data["pending_event"] is None
    # Old local handles reaped; two new fake handles.
    with open(os.path.join(env.data_dir, "local-registry.json")) as fh:
        assert json.load(fh) == {}
    assert len(env.kms_handles()) == 2
    # Exactly one migrate success event; no surviving artifacts.
    assert _migrate_events(env) == [("migrate", "success", key_id)]
    for sub in ("migrations", "provisions", "operation-artifacts"):
        assert not os.path.exists(
            os.path.join(env.data_dir, sub, op_id + ".json")
        )
    # The sealed transfer blob never landed on disk.
    assert not _grep_data_dir(env, b"kmt1.")


def test_transfer_path_success_fake_to_local(transfer_reversed_http):
    env, srv = transfer_reversed_http
    key_id = _create(srv, algorithm="RSA2048")
    assert _switchover(srv, "local")[0] == 200

    fake_kms.reset()
    status, body = _migrate(srv, key_id, key="tx-r-1")
    assert status == 200, body
    assert body["provider_id"] == "local"
    assert body["versions"] == [1]
    # Source half runs on fake, target half on local: no raw export.
    assert fake_kms.call_count("transfer_out") == 1
    assert fake_kms.call_count("export_material") == 0
    versions, _ = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"local"}
    assert env.kms_handles() == set()
    assert _migrate_events(env) == [("migrate", "success", key_id)]
    assert not _grep_data_dir(env, b"kmt1.")


def test_transfer_path_decrypt_still_works(transfer_http):
    env, srv = transfer_http
    key_id = _create(srv, algorithm="RSA2048")
    plaintext = "aGVsbG8="
    status, enc = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": plaintext},
        {**OPERATOR, "Idempotency-Key": "enc-1"},
    )
    assert status == 200, enc
    assert _switchover(srv, "fakekms")[0] == 200
    assert _migrate(srv, key_id, key="tx-dec")[0] == 200
    status, dec = srv.request(
        "POST", "/v1/keys/%s/decrypt" % key_id,
        {"tenant_id": "t1", "envelope": enc["envelope"]}, OPERATOR,
    )
    assert status == 200, dec
    assert dec["plaintext"] == plaintext


def test_without_pair_declaration_uses_legacy_path(legacy_http):
    # The default fake does NOT declare the transfer pair: migrate keeps the
    # export/import path even though the ready provider changed.
    env, srv = legacy_http
    key_id = _create(srv)
    assert _switchover(srv, "fakekms")[0] == 200
    fake_kms.reset()
    assert _migrate(srv, key_id, key="legacy-1")[0] == 200
    assert fake_kms.call_count("import_material") == 1
    assert fake_kms.call_count("transfer_in") == 0
    versions, _ = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"fakekms"}


# -- pre-commit failures: fixed 503, no audit, retryable ---------------------
# Chain local-first; after a switchover the ready target is fake, so the
# target half is fake.transfer_in (source local.transfer_out).
@pytest.mark.parametrize(
    "fault",
    [
        {"declare_transfer": True, "fail": {"transfer_in": True}},
        {"declare_transfer": True, "transfer_bad_triple": True},
        {"declare_transfer": True, "transfer_pk_mismatch": True},
    ],
)
def test_transfer_failure_is_503_no_audit_pending_and_retry_succeeds(
    chain_env, fault
):
    env = chain_env
    env.set_faults(fault)
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv, algorithm="RSA2048")
        assert _switchover(srv, "fakekms")[0] == 200
        status, body = _migrate(srv, key_id, key="tx-fail")
        assert status == 503, body
        assert body == {
            "error": "key management provider is unavailable",
            "operation_id": body["operation_id"],
        }
        op_id = body["operation_id"]
        # No audit event at all (not even a rejected one).
        assert _migrate_events(env, op_id) == []
        assert _migrate_events(env) == []
        # Operation stays pending; record untouched, no new fake handles.
        opbody = _op_pending(srv, op_id)
        assert opbody["status"] == "pending"
        assert opbody["http_status"] is None
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert env.kms_handles() == set()
        # No snapshot/journal survived the clean rollback.
        assert not os.path.exists(
            os.path.join(env.data_dir, "migrations", op_id + ".json")
        )
        assert not os.path.exists(
            os.path.join(env.data_dir, "provisions", op_id + ".json")
        )
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    # Fault clears: the SAME Idempotency-Key continues under the same
    # operation_id, succeeds and books exactly one event.
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        fake_kms.reset()
        status, body = _migrate(srv2, key_id, key="tx-fail")
        assert status == 200, body
        assert body["operation_id"] == op_id
        assert fake_kms.call_count("transfer_in") == 1
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"fakekms"}
        assert _migrate_events(env, op_id) == [
            ("migrate", "success", key_id)
        ]
        assert len(_migrate_events(env)) == 1
    finally:
        srv2.stop()
        provider_mod.reset_for_tests()


# -- source-side failures (fake primary -> local ready) ----------------------
@pytest.mark.parametrize(
    "fault",
    [
        {"declare_transfer": True, "fail": {"transfer_out": True}},
        {"declare_transfer": True, "transfer_out_bad_result": True},
    ],
)
def test_source_transfer_failure_is_503_no_audit_pending(reversed_chain_env, fault):
    env = reversed_chain_env
    # First build a healthy chain and create a key on the fake primary.
    env.set_faults({})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv, algorithm="RSA2048")
        assert _switchover(srv, "local")[0] == 200
    finally:
        srv.stop()
        provider_mod.reset_for_tests()
    # Now make the source fake's transfer_out fail.
    env.set_faults(fault)
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        status, body = _migrate(srv, key_id, key="tx-src-fail")
        assert status == 503, body
        op_id = body["operation_id"]
        assert _migrate_events(env) == []
        opbody = _op_pending(srv, op_id)
        assert opbody["status"] == "pending"
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"fakekms"}
    finally:
        srv.stop()
        provider_mod.reset_for_tests()


# -- unconfirmed cleanup parks the scene for restart --------------------------
def test_transfer_unconfirmed_cleanup_parks_then_restart_retry(chain_env):
    env = chain_env
    # First transfer_in succeeds and mints a fake handle; the SECOND raises.
    # Deletes also fail, so the freshly minted first-version handle cannot be
    # confirmed removed (source is local, target is fake).
    env.set_faults(
        {
            "declare_transfer": True,
            "fail_after": {"transfer_in": 1},
            "fail": {"delete": True},
        }
    )
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        assert _rotate(srv, key_id, key="rot-1")[0] == 201
        assert _switchover(srv, "fakekms")[0] == 200
        status, body = _migrate(srv, key_id, key="tx-park")
        assert status == 503, body
        op_id = body["operation_id"]
        assert _migrate_events(env, op_id) == []
        # The unconfirmed cleanup retains the whole evidence set.
        assert os.path.exists(
            os.path.join(env.data_dir, "migrations", op_id + ".json")
        )
        assert os.path.exists(
            os.path.join(env.data_dir, "provisions", op_id + ".json")
        )
        assert os.path.exists(
            os.path.join(env.data_dir, "operation-artifacts", op_id + ".json")
        )
        # Old record still authoritative; the minted-but-unreaped fake handle
        # survives for the startup sweep.
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    # New process with a healthy backend: startup reaps the orphan handle,
    # restores/keeps the old record, and keeps the operation PENDING (no
    # event) with a clean takeover strand.
    env.set_faults({"declare_transfer": True})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv2 = HttpServer(env)
    try:
        assert env.kms_handles() == set()
        assert not os.path.exists(
            os.path.join(env.data_dir, "migrations", op_id + ".json")
        )
        assert not os.path.exists(
            os.path.join(env.data_dir, "provisions", op_id + ".json")
        )
        versions, data = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
        assert data["pending_event"] is None
        assert _migrate_events(env, op_id) == []
        # The mirror is retained as a clean bound strand.
        assert os.path.exists(
            os.path.join(env.data_dir, "operation-artifacts", op_id + ".json")
        )
        # Same key takes the pending operation over and succeeds once.
        fake_kms.reset()
        status, body = _migrate(srv2, key_id, key="tx-park")
        assert status == 200, body
        assert body["operation_id"] == op_id
        assert fake_kms.call_count("transfer_in") == 2
        assert _migrate_events(env, op_id) == [
            ("migrate", "success", key_id)
        ]
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"fakekms"}
    finally:
        srv2.stop()
        provider_mod.reset_for_tests()


# -- contract: the pair is all-or-nothing -------------------------------------
def test_declaring_pair_without_callable_method_breaks_contract(chain_env):
    env = chain_env
    # Bring the chain up healthy (local primary, fake standby) and create a
    # local key while the fake still satisfies the base contract.
    env.set_faults({})
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv)
        # The fake now declares the transfer pair without a callable method:
        # rebuilding it for a switchover fails the contract, so the target
        # entry cannot become ready (fixed 503) and local stays active.
        env.set_faults(
            {"declare_transfer": True, "transfer_not_callable": True}
        )
        status, body = _switchover(srv, "fakekms")
        assert status == 503, body
        status, probe = srv.request(
            "GET", "/v1/provider/status", headers=OPERATOR
        )
        assert status == 200
        assert probe["provider_id"] == "local"
        # With the ready provider still local the migrate has nothing to
        # move: 409 (bound conflict), never a use of the broken entry.
        status, body = _migrate(srv, key_id, key="tx-contract")
        assert status == 409, body
    finally:
        srv.stop()
        provider_mod.reset_for_tests()


# -- CLI ----------------------------------------------------------------------
def test_cli_transfer_path_success(chain_env):
    env = chain_env
    # Create the key on local and move ready to fake via the HTTP server, then
    # drive the actual migrate over the CLI. The legacy import_material is
    # forced to fail: a successful migrate therefore proves the CLI took the
    # direct transfer_in path (the CLI is a subprocess, so in-process call
    # counters cannot be inspected from here).
    env.set_faults(
        {
            "declare_transfer": True,
            "fail": {"import_material": True},
        }
    )
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    srv = HttpServer(env)
    try:
        key_id = _create(srv, algorithm="RSA2048")
        assert _switchover(srv, "fakekms")[0] == 200
    finally:
        srv.stop()
        provider_mod.reset_for_tests()

    result = run_cli(
        env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice", "--idempotency-key", "cli-tx-1",
    )
    assert result.returncode == 0, result.stderr
    import json as _json

    body = _json.loads(result.stdout.strip())
    assert list(body.keys()) == [
        "key_id", "provider_id", "versions", "operation_id"
    ]
    assert body["provider_id"] == "fakekms"
    assert body["versions"] == [1]
    versions, _ = _versions_on_disk(env, key_id)
    assert {pid for _, pid, _ in versions} == {"fakekms"}
    assert _migrate_events(env) == [("migrate", "success", key_id)]
    assert not _grep_data_dir(env, b"kmt1.")


def test_cli_transfer_failure_exit_1_pending_no_audit(chain_env):
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

    # The target transfer_in backend fails.
    env.set_faults(
        {"declare_transfer": True, "fail": {"transfer_in": True}}
    )
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(env.data_dir)
    try:
        result = run_cli(
            env, "migrate", "--tenant-id", "t1", "--key-id", key_id,
            "--operator", "alice", "--idempotency-key", "cli-tx-fail",
        )
        assert result.returncode == 1, result.stdout
        import json as _json

        err = _json.loads(result.stderr.strip())
        assert list(err.keys()) == ["error", "operation_id"]
        assert err["error"] == "key management provider is unavailable"
        op_id = err["operation_id"]
        assert _migrate_events(env, op_id) == []
        versions, _ = _versions_on_disk(env, key_id)
        assert {pid for _, pid, _ in versions} == {"local"}
    finally:
        provider_mod.reset_for_tests()
