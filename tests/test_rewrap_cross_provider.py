"""Cross-PROVIDER cross-key rewrap tests.

The cross-key rewrap used to require both selected versions bound to one
provider_id (different providers were a fixed 503). It now supports the same
tenant's keys on two DIFFERENT providers: each side must uniquely match one
healthy entry of the configured KEYMGR_PROVIDER_CHAIN; an inactive (standby)
entry participates without being activated. Across providers ``rewrap_key``
is never used: a source ``unwrap_key`` / target ``wrap_key`` declaration keeps
that side's KEK unexported, only the undeclared side exports, and a native
failure never falls back. These tests exercise both directions, the four
algorithm combinations, the no-failover/no-migration guarantee, the fixed 503
for an unhealthy peer and the 400/503/audit contract.

Decrypting an envelope whose key is bound to a non-active standby provider is
(by the existing routing rules) only possible once that entry is active; the
rewrap itself never activates it, so these tests prove "decryptable under the
target key" by switching over EXPLICITLY, strictly after the rewrap and its
no-activation assertions completed.
"""

import base64
import json

import pytest

from keymgr import provider as provider_mod
from keymgr.audit import AuditLog

from test_provider_reconnect import OPERATOR, HttpServer

CHAIN = "local,fake_kms:make_provider"
ALGORITHMS = ("AES256", "RSA2048")


@pytest.fixture()
def chain_env(env, monkeypatch):
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", CHAIN)
    yield env


@pytest.fixture()
def http(chain_env):
    provider_mod.reset_for_tests()
    provider_mod.bind_data_dir(chain_env.data_dir)
    server = HttpServer(chain_env)
    yield chain_env, server
    server.stop()
    provider_mod.reset_for_tests()


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _create(srv, algorithm, tenant="t1"):
    status, body = srv.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        OPERATOR,
    )
    assert status == 201, body
    return body["key_id"]


def _switchover(srv, provider_id):
    return srv.request(
        "POST", "/v1/provider/switchover",
        {"provider_id": provider_id}, OPERATOR,
    )


def _reconnect(srv):
    status, text = srv.raw("POST", "/v1/provider/reconnect", b"{}", OPERATOR)
    return status, json.loads(text)


def _encrypt(srv, key_id, plaintext, key, tenant="t1"):
    status, reply = srv.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": tenant, "plaintext": b64(plaintext)},
        {**OPERATOR, "Idempotency-Key": key},
    )
    assert status == 200, reply
    return reply["envelope"]


def _decrypt(srv, key_id, token, tenant="t1"):
    return srv.request(
        "POST", "/v1/keys/%s/decrypt" % key_id,
        {"tenant_id": tenant, "envelope": token}, OPERATOR,
    )


def _rewrap(srv, key_id, token, **extra):
    body = {"tenant_id": "t1", "envelope": token}
    body.update(extra)
    return srv.request(
        "POST", "/v1/keys/%s/rewrap" % key_id, body, OPERATOR
    )


def _inner(token):
    return json.loads(base64.b64decode(token))


def _rewrap_events(env):
    return [
        e for e in AuditLog(env.data_dir)._read_all() if e.action == "rewrap"
    ]


def _active(env):
    with open(env.data_dir + "/provider-state.json") as fh:
        state = json.load(fh)
    return state["provider_id"], state["generation"]


def _version_providers(env, key_id):
    with open(env.data_dir + "/%s.json" % key_id) as fh:
        return {
            v["version"]: v["provider_id"]
            for v in json.load(fh)["versions"]
        }


def _assert_decrypts(srv, key_id, token, expected):
    status, reply = _decrypt(srv, key_id, token)
    assert status == 200, reply
    assert base64.b64decode(reply["plaintext"]) == expected


def _make_local_and_fake_keys(srv, env, fake_declares=None):
    """With local initially active (the first healthy chain entry), mint one
    key per algorithm on local and seal an envelope per algorithm; then switch
    the active entry to fakekms and mint one key per algorithm there. Returns
    ``(local_keys, local_tokens, fake_keys)`` with the active entry fakekms.

    ``fake_declares`` are fault keys written BEFORE the fakekms entry is first
    built (the switchover builds it): the safe adapter snapshots a provider's
    capabilities at factory time, so a native declaration must already be in
    the faults file then. Runtime faults (e.g. unwrap_short, health) can still
    be toggled afterwards.
    """
    import fake_kms

    env.set_faults(dict(fake_declares or {}))
    local_keys = {alg: _create(srv, alg) for alg in ALGORITHMS}
    local_tokens = {
        alg: _encrypt(
            srv, local_keys[alg], b"payload-%s" % alg.encode(),
            key="enc-local-%s" % alg,
        )
        for alg in ALGORITHMS
    }
    status, _ = _switchover(srv, "fakekms")
    assert status == 200
    assert _active(env)[0] == "fakekms"
    # The switchover built fakekms and snapshotted the declared capabilities;
    # clear runtime-only faults for key creation without changing the now
    # bound declarations.
    env.set_faults(dict(fake_declares or {}))
    fake_kms.reset()
    fake_keys = {alg: _create(srv, alg) for alg in ALGORITHMS}
    return local_keys, local_tokens, fake_keys


# -- fakekms(ready) source -> local(standby) target -------------------------

@pytest.mark.parametrize("src_algorithm", ALGORITHMS)
@pytest.mark.parametrize("dst_algorithm", ALGORITHMS)
@pytest.mark.parametrize("source_native", [False, True])
def test_fake_ready_to_local_standby(
    http, src_algorithm, dst_algorithm, source_native,
):
    env, srv = http
    import fake_kms

    declares = {"declare_unwrap_key": True} if source_native else {}
    local_keys, _local_tokens, fake_keys = _make_local_and_fake_keys(
        srv, env, fake_declares=declares,
    )
    fake_kms.reset()

    src = fake_keys[src_algorithm]
    dst = local_keys[dst_algorithm]
    token = _encrypt(srv, src, b"cross-x", key="enc-src")
    # Baseline taken AFTER the source encrypt: with no wrap_key declaration
    # the encrypt itself exports the source KEK, which must not be confused
    # with the rewrap's side choice.
    base_export = fake_kms.call_count("export_material")
    before_active = _active(env)
    status, body = _rewrap(srv, src, token, target_key_id=dst)
    assert status == 200, body
    assert list(body.keys()) == ["format", "envelope"]

    before, after = _inner(token), _inner(body["envelope"])
    assert after["key_id"] == dst
    assert after["version"] == 1
    assert after["algorithm"] == dst_algorithm
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field

    events = _rewrap_events(env)
    assert len(events) == 1 and events[0].outcome == "success"
    assert events[0].key_id == src

    # Across providers rewrap_key is never used; the ready fakekms source side
    # is a native unwrap exactly when declared and exports its KEK otherwise.
    assert fake_kms.call_count("rewrap_key") == 0
    if source_native:
        assert fake_kms.call_count("unwrap_key") >= 1
        assert fake_kms.call_count("export_material") == base_export
    else:
        assert fake_kms.call_count("export_material") > base_export

    # The standby local entry participated but was NOT activated by the
    # rewrap, and neither key was migrated.
    assert _active(env) == before_active
    assert _version_providers(env, src)[1] == "fakekms"
    assert _version_providers(env, dst)[1] == "local"

    # The original envelope still decrypts under the ready source key.
    _assert_decrypts(srv, src, token, b"cross-x")
    # The new envelope decrypts under the target once local is active: the
    # switch happens strictly AFTER the no-activation assertions above.
    assert _switchover(srv, "local")[0] == 200
    _assert_decrypts(srv, dst, body["envelope"], b"cross-x")


# -- local(standby) source -> fakekms(ready) target -------------------------

@pytest.mark.parametrize("src_algorithm", ALGORITHMS)
@pytest.mark.parametrize("dst_algorithm", ALGORITHMS)
@pytest.mark.parametrize("target_native", [False, True])
def test_local_standby_to_fake_ready(
    http, src_algorithm, dst_algorithm, target_native,
):
    env, srv = http
    import fake_kms

    declares = {"declare_wrap_key": True} if target_native else {}
    local_keys, local_tokens, fake_keys = _make_local_and_fake_keys(
        srv, env, fake_declares=declares,
    )
    base_export = fake_kms.call_count("export_material")

    src = local_keys[src_algorithm]
    dst = fake_keys[dst_algorithm]
    token = local_tokens[src_algorithm]
    expected = b"payload-%s" % src_algorithm.encode()
    before_active = _active(env)
    status, body = _rewrap(srv, src, token, target_key_id=dst)
    assert status == 200, body

    before, after = _inner(token), _inner(body["envelope"])
    assert after["key_id"] == dst
    assert after["algorithm"] == dst_algorithm
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field

    events = _rewrap_events(env)
    assert len(events) == 1 and events[0].outcome == "success"
    assert events[0].key_id == src
    assert fake_kms.call_count("rewrap_key") == 0
    if target_native:
        assert fake_kms.call_count("wrap_key") >= 1
        assert fake_kms.call_count("export_material") == base_export
    else:
        assert fake_kms.call_count("export_material") > base_export

    assert _active(env) == before_active
    assert _version_providers(env, src)[1] == "local"
    assert _version_providers(env, dst)[1] == "fakekms"

    # New envelope decrypts under the ready target immediately.
    _assert_decrypts(srv, dst, body["envelope"], expected)
    # Original envelope still decrypts under the source once local is active.
    assert _switchover(srv, "local")[0] == 200
    _assert_decrypts(srv, src, token, expected)


def test_equal_version_numbers_across_providers_not_a_conflict(http):
    env, srv = http
    local_keys, _tokens, fake_keys = _make_local_and_fake_keys(srv, env)
    # Ready fakekms source v1 -> standby local target v1: identical version
    # numbers on two different keys/providers are not a same-version conflict.
    token = _encrypt(srv, fake_keys["AES256"], b"v", key="enc-eq")
    status, body = _rewrap(
        srv, fake_keys["AES256"], token,
        target_key_id=local_keys["AES256"], target_version=1,
    )
    assert status == 200, body
    after = _inner(body["envelope"])
    assert after["version"] == 1
    assert after["key_id"] == local_keys["AES256"]


def test_target_current_committed_version_when_omitted(http):
    """target_version omitted uses the target key's committed current version,
    even when the standby-local target has rotated."""
    env, srv = http
    local_keys, _tokens, fake_keys = _make_local_and_fake_keys(srv, env)
    # Rotate the standby-local target AFTER the switchover: ordinary crypto on
    # a standby-bound key is not possible, so rotate it before switching away.
    # Rebuild a fresh arrangement for that: switch back to local, rotate, then
    # return to fakekms for the rewrap.
    assert _switchover(srv, "local")[0] == 200
    status, rot = srv.request(
        "POST", "/v1/keys/%s/rotate" % local_keys["AES256"],
        {"tenant_id": "t1", "algorithm": "RSA2048"},
        {**OPERATOR, "Idempotency-Key": "rot-dst"},
    )
    assert status == 201, rot
    assert rot["version"] == 2 and rot["algorithm"] == "RSA2048"
    import fake_kms

    env.set_faults({})
    fake_kms.reset()
    assert _switchover(srv, "fakekms")[0] == 200
    # Re-mint a ready fakekms source envelope for the rewrap.
    token = _encrypt(srv, fake_keys["AES256"], b"cur", key="enc-cur")
    status, body = _rewrap(
        srv, fake_keys["AES256"], token,
        target_key_id=local_keys["AES256"],
    )
    assert status == 200, body
    after = _inner(body["envelope"])
    assert after["key_id"] == local_keys["AES256"]
    assert after["version"] == 2
    assert after["algorithm"] == "RSA2048"


# -- failures ----------------------------------------------------------------

def test_unhealthy_standby_peer_is_503_not_audited_no_activation(http):
    """Source on the ready local entry, target on a fakekms STANDBY entry that
    fails its one-second health probe: fixed 503, no audit, and the standby is
    not activated (the generation does not move for the rewrap)."""
    env, srv = http
    import fake_kms

    src = _create(srv, "AES256")
    token = _encrypt(srv, src, b"x", key="enc-unhealthy")
    assert _switchover(srv, "fakekms")[0] == 200
    dst = _create(srv, "AES256")
    # Make fakekms unhealthy and reconnect: the chain's first healthy entry is
    # local again, so the ready entry becomes local and fakekms is standby.
    env.set_faults({"health": False})
    status, body = _reconnect(srv)
    assert status == 200, body
    provider_id, generation = _active(env)
    assert provider_id == "local"

    fake_kms.reset()
    status, body = _rewrap(srv, src, token, target_key_id=dst)
    assert status == 503, body
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(env) == []
    # The unhealthy standby was resolved and probed but NOT activated by the
    # failed rewrap, and no key was migrated.
    assert _active(env) == ("local", generation)
    assert _version_providers(env, src)[1] == "local"
    assert _version_providers(env, dst)[1] == "fakekms"


def test_identity_not_in_chain_is_503(http):
    """A provider_id that no configured chain entry builds is the fixed 503
    (the unique registered-identity match failed)."""
    env, srv = http
    from keymgr.provider import ProviderUnavailable

    assert _switchover(srv, "fakekms")[0] == 200
    with provider_mod.provider_call():
        with pytest.raises(ProviderUnavailable):
            provider_mod.migration_peer_provider("not-a-chain-entry")


def test_cross_provider_auth_failure_is_400_and_target_wrap_skipped(http):
    """A tampered source envelope across providers is a 400 naming the
    envelope, not audited; the target wrap never runs (source authenticates
    first)."""
    env, srv = http
    import fake_kms

    local_keys, local_tokens, fake_keys = _make_local_and_fake_keys(
        srv, env, fake_declares={"declare_wrap_key": True},
    )
    base_wrap = fake_kms.call_count("wrap_key")
    base_export = fake_kms.call_count("export_material")

    src = local_keys["AES256"]
    dst = fake_keys["RSA2048"]
    token = local_tokens["AES256"]
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(srv, src, tampered, target_key_id=dst)
    assert status == 400, err
    assert "field envelope" in err["error"]
    assert _rewrap_events(env) == []
    # Source authentication precedes the target wrap: no wrap and no export.
    assert fake_kms.call_count("wrap_key") == base_wrap
    assert fake_kms.call_count("export_material") == base_export


def test_cross_provider_native_unwrap_contract_failure_is_503_no_fallback(http):
    """A native source unwrap violating the 32-byte result contract is the
    fixed 503, never a fallback export, and is not audited."""
    env, srv = http
    import fake_kms

    local_keys, _tokens, fake_keys = _make_local_and_fake_keys(
        srv, env, fake_declares={"declare_unwrap_key": True},
    )
    # Keep the (factory-time) declaration and add the runtime contract fault.
    env.set_faults(
        {"declare_unwrap_key": True, "unwrap_short": True}
    )
    fake_kms.reset()

    src = fake_keys["AES256"]
    dst = local_keys["RSA2048"]
    token = _encrypt(srv, src, b"contract", key="enc-contract")
    # The source encrypt wraps the DEK via export (wrap_key is not declared);
    # the rewrap must not add ANY export on the native-unwrap failure.
    base_export = fake_kms.call_count("export_material")
    status, body = _rewrap(srv, src, token, target_key_id=dst)
    assert status == 503, body
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(env) == []
    assert fake_kms.call_count("unwrap_key") >= 1
    # A native failure never falls back to exporting that side's KEK.
    assert fake_kms.call_count("export_material") == base_export
