"""POST /v1/keys/{key_id}/rewrap -- envelope re-wrapping without CLI.

Covers the rewrap crypto primitive (the SAME authenticated data key is
re-wrapped under the target KEK while nonce/tag/ciphertext/aad/key_id bytes
stay identical), the fixed ``{"format","envelope"}`` response, same- and
cross-algorithm targets (AES256<->RSA2048), AAD binding, the pre-auth 400
contract (bad body/UUID4/base64/envelope/key_id mismatch -- none of it
audited, only a bad tenant source writes tenant_conflict), the policy
``rewrap`` action (403 + rewrap/rejected carrying key_id), post-auth 404
(unknown/cross-tenant key or version), 409 (revoked / same version), 400
(algorithm mismatch with the SOURCE version, failed authentication -- not
audited), the fixed-text 503 (not audited), ledger-failure 500, audit
content (metadata only, plaintext/AAD/envelope never land) and the absence
of any Idempotency-Key requirement or operation_id.
"""

import base64
import itertools
import json
import os
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keymgr import envelope as env_mod
from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog, LedgerError
from keymgr.crypto import generate_key
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore, Rule
from keymgr.server import make_handler
from keymgr.store import KeyStore


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _build_server(tmp_path, monkeypatch, external=False):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    faults_path = str(tmp_path / "kms-faults.json")
    if external:
        sys.path.insert(0, os.path.dirname(__file__))
        monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
        monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
        monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
        import fake_kms

        fake_kms.reset()
    else:
        monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    provider_mod.reset_for_tests()
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
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
    client = Client("http://127.0.0.1:%d" % httpd.server_address[1])
    stack = types.SimpleNamespace(
        data_dir=data_dir, store=store, policies=policies,
        audit=audit_log, client=client, faults_path=faults_path,
    )
    yield stack
    httpd.shutdown()
    provider_mod.reset_for_tests()


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, operator="alice", headers=None,
             raw=None):
        if raw is None:
            data = json.dumps(body).encode() if body is not None else None
        else:
            data = raw
        h = {"X-Operator-Id": operator}
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


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch)


@pytest.fixture()
def ext_stack(tmp_path, monkeypatch):
    yield from _build_server(tmp_path, monkeypatch, external=True)


# -- helpers ---------------------------------------------------------------
def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(client, key_id, algorithm, key, tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": key},
    )
    assert status == 201, body
    return body


_idem_counter = itertools.count(1)


def _encrypt(client, key_id, plaintext, tenant="t", **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    status, reply = client.call(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        headers={"Idempotency-Key": "enc-%d" % next(_idem_counter)},
    )
    assert status == 200, reply
    return reply["envelope"]


def _decrypt(client, key_id, token, tenant="t", **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    status, reply = client.call(
        "POST", "/v1/keys/%s/decrypt" % key_id, body
    )
    return status, reply


def _rewrap(client, key_id, token, tenant="t", headers=None, **extra):
    body = {"tenant_id": tenant, "envelope": token}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/rewrap" % key_id, body, headers=headers
    )


def _inner(token):
    return json.loads(base64.b64decode(token))


def _audit_events(st, tenant="t"):
    return st.audit.query(tenant, limit=1000).events


def _rewrap_events(st):
    return [e for e in _audit_events(st) if e.action == "rewrap"]


# -- envelope primitive ----------------------------------------------------
def test_primitive_rewraps_same_dek_aes():
    kek1 = base64.b64decode(generate_key("AES256").private_material)
    kek2 = base64.b64decode(generate_key("AES256").private_material)
    kid = "11111111-1111-4111-8111-111111111111"
    token = env_mod.encode_envelope(
        key_id=kid, version=1, algorithm="AES256", kek=kek1,
        plaintext=b"same plaintext", aad=b"ctx",
    )
    opened = env_mod.decode_envelope(token)
    rewrapped = env_mod.rewrap_envelope(
        opened, kek1, target_version=2,
        target_algorithm="AES256", target_kek=kek2,
    )
    out = env_mod.decode_envelope(rewrapped)
    assert out.version == 2
    # Carried over byte for byte.
    assert out.key_id == kid
    assert (out.nonce, out.tag, out.ciphertext, out.aad) == (
        opened.nonce, opened.tag, opened.ciphertext, opened.aad,
    )
    # Only the wrap fields are rebuilt.
    assert out.wrapped_key != opened.wrapped_key
    assert out.wrap_nonce != opened.wrap_nonce
    # The new envelope opens under the NEW kek and yields the same plaintext.
    assert env_mod.open_envelope(out, kek2) == b"same plaintext"
    # The old envelope is unaffected and the new one fails under the old kek.
    assert env_mod.open_envelope(opened, kek1) == b"same plaintext"
    with pytest.raises(env_mod.EnvelopeError):
        env_mod.open_envelope(out, kek1)


def test_primitive_cross_algorithm_changes_wrap_fields():
    from cryptography.hazmat.primitives import serialization

    aes_kek = base64.b64decode(generate_key("AES256").private_material)
    rsa_generated = generate_key("RSA2048")
    rsa_kek = serialization.load_pem_private_key(
        rsa_generated.private_material.encode("utf-8"), password=None
    )
    token = env_mod.encode_envelope(
        key_id="22222222-2222-4222-8222-222222222222",
        version=1, algorithm="AES256", kek=aes_kek, plaintext=b"cross",
    )
    opened = env_mod.decode_envelope(token)
    rewrapped = env_mod.rewrap_envelope(
        opened, aes_kek, target_version=2,
        target_algorithm="RSA2048", target_kek=rsa_kek,
    )
    out = env_mod.decode_envelope(rewrapped)
    assert (out.algorithm, out.wrap) == (
        "RSA2048", env_mod.WRAP_RSA_OAEP_SHA256
    )
    assert out.wrap_nonce is None
    assert len(out.wrapped_key) == 256
    assert env_mod.open_envelope(out, rsa_kek) == b"cross"


def test_primitive_authenticates_before_rewrap():
    kek1 = base64.b64decode(generate_key("AES256").private_material)
    kek2 = base64.b64decode(generate_key("AES256").private_material)
    token = env_mod.encode_envelope(
        key_id="11111111-1111-4111-8111-111111111111",
        version=1, algorithm="AES256", kek=kek1, plaintext=b"secret",
    )
    # Wrong source KEK: the data key cannot be unwrapped.
    with pytest.raises(env_mod.EnvelopeError):
        env_mod.rewrap_envelope(
            env_mod.decode_envelope(token), kek2,
            target_version=2, target_algorithm="AES256", target_kek=kek2,
        )
    # Tampered ciphertext: the content tag fails even with the right KEK.
    obj = _inner(token)
    ct = bytearray(base64.b64decode(obj["ciphertext"]))
    ct[0] ^= 0x01
    obj["ciphertext"] = b64(bytes(ct))
    bad = b64(json.dumps(obj, sort_keys=True).encode())
    with pytest.raises(env_mod.EnvelopeError):
        env_mod.rewrap_envelope(
            env_mod.decode_envelope(bad), kek1,
            target_version=2, target_algorithm="AES256", target_kek=kek2,
        )


# -- HTTP happy path -------------------------------------------------------
def test_rewrap_default_current_preserves_bytes_and_key_order(stack):
    client = stack.client
    kid = _make_key(client, algorithm="AES256")
    token = _encrypt(client, kid, b"payload", version=1, aad=b64(b"ctx"))
    _rotate(client, kid, "AES256", "rot-aes-1")
    status, body = _rewrap(client, kid, token, aad=b64(b"ctx"))
    assert status == 200, body
    assert list(body.keys()) == ["format", "envelope"]
    assert body["format"] == env_mod.FORMAT
    before, after = _inner(token), _inner(body["envelope"])
    assert before["version"] == 1 and after["version"] == 2
    for field in ("key_id", "nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field
    assert after["wrapped_key"] != before["wrapped_key"]
    # The new envelope decrypts against the current version with the AAD...
    status, reply = _decrypt(client, kid, body["envelope"], aad=b64(b"ctx"))
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"payload"
    # ...and the old envelope still decrypts against its own old version.
    status, reply = _decrypt(client, kid, token, aad=b64(b"ctx"))
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"payload"


def test_rewrap_explicit_target_and_backwards(stack):
    client = stack.client
    kid = _make_key(client, algorithm="AES256")
    _rotate(client, kid, "AES256", "rot-aes-2")
    # Envelope on the current v2, then explicitly rewrap BACK to v1.
    token = _encrypt(client, kid, b"back")
    assert _inner(token)["version"] == 2
    status, body = _rewrap(client, kid, token, target_version=1)
    assert status == 200, body
    assert _inner(body["envelope"])["version"] == 1
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"back"


def test_rewrap_rsa_to_rsa(stack):
    client = stack.client
    kid = _make_key(client, algorithm="RSA2048")
    token = _encrypt(client, kid, b"rsa payload", version=1)
    _rotate(client, kid, "RSA2048", "rot-rsa-1")
    status, body = _rewrap(client, kid, token)
    assert status == 200
    out = _inner(body["envelope"])
    assert out["version"] == 2
    assert out["wrap"] == env_mod.WRAP_RSA_OAEP_SHA256
    assert "wrap_nonce" not in out
    assert len(base64.b64decode(out["wrapped_key"])) == 256
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"rsa payload"


def test_rewrap_cross_algorithm(stack):
    client = stack.client
    kid = _make_key(client, algorithm="AES256")
    token = _encrypt(client, kid, b"cross-alg", version=1)
    _rotate(client, kid, "RSA2048", "rot-to-rsa")
    status, body = _rewrap(client, kid, token)
    assert status == 200, body
    out = _inner(body["envelope"])
    assert out["version"] == 2 and out["algorithm"] == "RSA2048"
    assert out["wrap"] == env_mod.WRAP_RSA_OAEP_SHA256
    assert "wrap_nonce" not in out
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and base64.b64decode(reply["plaintext"]) == b"cross-alg"


def test_rewrap_without_aad_and_empty_plaintext(stack):
    client = stack.client
    kid = _make_key(client, algorithm="AES256")
    token = _encrypt(client, kid, b"", version=1)
    _rotate(client, kid, "AES256", "rot-empty")
    assert _inner(token)["aad"] == ""
    status, body = _rewrap(client, kid, token)
    assert status == 200
    assert _inner(body["envelope"])["aad"] == ""
    status, reply = _decrypt(client, kid, body["envelope"])
    assert status == 200 and reply["plaintext"] == ""


def test_rewrap_needs_no_idempotency_key(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-no-idem")
    status, body = _rewrap(
        client, kid, token, headers={"Idempotency-Key": "ignored-1"}
    )
    assert status == 200, body
    assert "operation_id" not in body


# -- pre-auth 400s: nothing is audited except tenant-source failures -------
def test_body_400s_are_not_audited(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-400")
    valid_aad = b64(b"ctx")
    cases = [
        (None, {"raw": b"{not json"}, "valid JSON"),
        (None, {"raw": b"[1,2,3]"}, "JSON object"),
        ({"tenant_id": "t"}, None, "envelope"),
        ({"tenant_id": "t", "envelope": 123}, None, "envelope"),
        ({"tenant_id": "t", "envelope": "not base64!!"}, None, "envelope"),
        ({"tenant_id": "t", "envelope": b64(b"not json obj")}, None,
         "envelope"),
        ({"tenant_id": "t", "envelope": token, "target_version": 0}, None,
         "target_version"),
        ({"tenant_id": "t", "envelope": token, "target_version": -2}, None,
         "target_version"),
        ({"tenant_id": "t", "envelope": token, "target_version": "2"}, None,
         "target_version"),
        ({"tenant_id": "t", "envelope": token, "target_version": True}, None,
         "target_version"),
        ({"tenant_id": "t", "envelope": token, "aad": "a*b"}, None, "aad"),
        ({"tenant_id": "t", "envelope": token, "aad": 7}, None, "aad"),
        ({"tenant_id": "t", "envelope": token, "bogus": 1}, None, "bogus"),
    ]
    for body, kwargs, field in cases:
        kwargs = kwargs or {}
        status, err = client.call(
            "POST", "/v1/keys/%s/rewrap" % kid, body, **kwargs
        )
        assert status == 400, (body, err)
        assert field in err["error"], (body, err)    # An envelope naming a different key_id: structurally valid, rejected
    # before authorization.
    other = _make_key(client)
    other_token = _encrypt(client, other, b"y", version=1)
    status, err = _rewrap(client, kid, other_token)
    assert status == 400 and "key_id" in err["error"]
    # A malformed path key_id is likewise a plain, unaudited 400.
    status, err = client.call(
        "POST", "/v1/keys/not-a-uuid/rewrap",
        {"tenant_id": "t", "envelope": token},
    )
    assert status == 400 and "key_id" in err["error"]
    # AAD disagreement with the sealed envelope.
    status, err = _rewrap(client, kid, token, aad=valid_aad)
    assert status == 400 and "aad" in err["error"]
    # Nothing was audited for any of these: no rewrap events, no conflicts.
    assert _rewrap_events(stack) == []
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert b"tenant_conflict" not in raw


def test_tenant_source_failures_record_tenant_conflict(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-conflict")
    # Missing / empty body tenant.
    status, err = client.call(
        "POST", "/v1/keys/%s/rewrap" % kid, {"envelope": token}
    )
    assert status == 400 and "tenant_id" in err["error"]
    status, err = client.call(
        "POST", "/v1/keys/%s/rewrap" % kid,
        {"tenant_id": "", "envelope": token},
    )
    assert status == 400 and "tenant_id" in err["error"]
    # Header disagreeing with the body.
    status, err = _rewrap(
        client, kid, token, headers={"X-Tenant-Id": "other"}
    )
    assert status == 400 and "tenant_id" in err["error"]
    conflicts = [
        e for e in stack.audit.query("t", limit=1000).events
        if e.action == "tenant_conflict"
    ]
    # tenant_conflict carries a null tenant and is invisible per tenant; read
    # the raw ledger to confirm it was written (three times, no rewrap event).
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert raw.count(b"tenant_conflict") == 3
    assert _rewrap_events(stack) == []
    assert conflicts == []


# -- authorization / business rejections -----------------------------------
def test_policy_denial_is_403_and_audited_with_key_id(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-403")
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["rewrap"], effect="deny")]
    )
    status, body = _rewrap(client, kid, token)
    assert status == 403, body
    rejected = _rewrap_events(stack)
    assert len(rejected) == 1
    assert rejected[0].outcome == "rejected" and rejected[0].key_id == kid


def test_unknown_foreign_key_and_versions_are_404(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-404")
    unknown = "00000000-0000-4000-8000-000000000000"
    # An envelope that itself names the unknown key id.
    obj = _inner(token)
    obj["key_id"] = unknown
    unknown_named = b64(json.dumps(obj, sort_keys=True).encode())
    assert _rewrap(client, unknown, unknown_named)[0] == 404
    # Cross-tenant: same answer as a missing key.
    assert _rewrap(client, kid, token, tenant="other")[0] == 404
    # An existing envelope/algorithm on a nonexistent SOURCE version.
    obj = _inner(token)
    obj["version"] = 99
    src_missing = b64(json.dumps(obj, sort_keys=True).encode())
    assert _rewrap(client, kid, src_missing, target_version=1)[0] == 404
    # A nonexistent explicit TARGET version.
    assert _rewrap(client, kid, token, target_version=99)[0] == 404
    # One rejected event per attempt (the cross-tenant one belongs to
    # "other"); every business rejection carries the key_id when known.
    all_events = [
        e for e in stack.audit._read_all() if e.action == "rewrap"
    ]
    assert len(all_events) == 4
    assert {e.outcome for e in all_events} == {"rejected"}
    by_tenant = {}
    for event in all_events:
        by_tenant.setdefault(event.tenant_id, []).append(event)
    assert len(by_tenant["t"]) == 3
    assert len(by_tenant["other"]) == 1


def test_revoked_key_is_409_including_old_versions(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-revoke")
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "done", "operator": "alice"},
    )
    assert status == 200
    assert _rewrap(client, kid, token)[0] == 409
    rejected = _rewrap_events(stack)
    assert len(rejected) == 1 and rejected[0].key_id == kid


def test_same_version_is_409(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256", "rot-same")
    # An envelope on the current version, default target: same version.
    current_token = _encrypt(client, kid, b"cur")
    assert _inner(current_token)["version"] == 2
    assert _rewrap(client, kid, current_token)[0] == 409
    # Explicitly pinning the same version is the same answer.
    old_token = _encrypt(client, kid, b"old", version=1)
    assert _rewrap(client, kid, old_token, target_version=1)[0] == 409
    rejected = _rewrap_events(stack)
    assert len(rejected) == 2
    assert all(e.outcome == "rejected" and e.key_id == kid for e in rejected)


def test_algorithm_mismatch_with_source_version_is_400_not_audited(stack):
    client = stack.client
    kid = _make_key(client, algorithm="AES256")
    # v1 AES256 -> v2 RSA2048.
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "RSA2048", "rot-aes-to-rsa")
    # A structurally valid AES-shaped envelope that CLAIMS source version 2
    # (the real v2 is RSA2048); target v1 keeps source and target distinct.
    obj = _inner(token)
    obj["version"] = 2
    forged = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, kid, forged, target_version=1)
    assert status == 400, err
    assert "algorithm" in err["error"]
    assert _rewrap_events(stack) == []


def test_failed_authentication_is_400_not_audited(stack):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"auth", version=1)
    _rotate(client, kid, "AES256", "rot-auth")
    obj = _inner(token)
    wrapped = bytearray(base64.b64decode(obj["wrapped_key"]))
    wrapped[0] ^= 0x01
    obj["wrapped_key"] = b64(bytes(wrapped))
    tampered = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, kid, tampered)
    assert status == 400, err
    assert "field envelope" in err["error"]
    assert _rewrap_events(stack) == []


# -- provider / ledger failures -------------------------------------------
def test_provider_failure_is_503_fixed_text_and_not_audited(ext_stack):
    client = ext_stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-503")
    with open(ext_stack.faults_path, "w") as fh:
        json.dump({"fail": {"export_material": True}}, fh)
    status, body = _rewrap(client, kid, token)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert _rewrap_events(ext_stack) == []


def test_409_and_400_are_answered_while_provider_is_down(ext_stack):
    # Version resolution and the source-algorithm check never contact the
    # KMS/HSM, so a same-version conflict and an algorithm mismatch still
    # answer exactly while every material export fails.
    client = ext_stack.client
    kid = _make_key(client)
    _rotate(client, kid, "RSA2048", "rot-down")
    current_token = _encrypt(client, kid, b"cur")
    aes_shaped = _make_key(client, algorithm="AES256")
    aes_token = _encrypt(client, aes_shaped, b"x", version=1)
    with open(ext_stack.faults_path, "w") as fh:
        json.dump({"fail": {"export_material": True}}, fh)
    # Same current version: 409 despite the outage.
    assert _rewrap(client, kid, current_token)[0] == 409
    # An AES-shaped envelope claiming the now-RSA current version: 400.
    obj = _inner(aes_token)
    obj["key_id"] = kid
    obj["version"] = 2
    forged = b64(json.dumps(obj, sort_keys=True).encode())
    status, err = _rewrap(client, kid, forged, target_version=1)
    assert status == 400 and "algorithm" in err["error"]
    # The 409 is a business rejection (one rewrap/rejected with key_id); the
    # 400 and the outage itself write nothing more.
    events = _rewrap_events(ext_stack)
    assert len(events) == 1
    assert events[0].outcome == "rejected" and events[0].key_id == kid


def test_ledger_failure_after_success_is_500(stack, monkeypatch):
    client = stack.client
    kid = _make_key(client)
    token = _encrypt(client, kid, b"x", version=1)
    _rotate(client, kid, "AES256", "rot-500")

    def boom(event):
        raise LedgerError("disk full")

    monkeypatch.setattr(stack.audit, "append", boom)
    status, body = _rewrap(client, kid, token)
    assert status == 500
    assert "operation_id" not in body


# -- audit content: metadata only ------------------------------------------
def test_success_event_metadata_only(stack):
    client = stack.client
    kid = _make_key(client)
    secret = b"ledger-secret-payload"
    token = _encrypt(client, kid, secret, version=1, aad=b64(b"secret-aad"))
    _rotate(client, kid, "AES256", "rot-meta")
    status, body = _rewrap(client, kid, token, aad=b64(b"secret-aad"))
    assert status == 200
    events = _rewrap_events(stack)
    assert len(events) == 1
    assert events[0].outcome == "success"
    assert events[0].key_id == kid
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert b"ledger-secret-payload" not in raw
    assert b"secret-aad" not in raw
    assert body["envelope"].encode() not in raw
    assert token.encode() not in raw
