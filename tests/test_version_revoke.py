"""Per-version revocation: POST .../versions/{v}/revoke and GET .../status.

Covers the strict three-field body contract (exactly
``{tenant_id, reason, operator}`` non-empty strings; 400s write no audit
event, only a bad tenant source records tenant_conflict), the fixed
``key_id,version,status,reason,operator,revoked_at`` 200 key order (null
triplet while active), first-write-wins idempotency with a SINGLE
``revoke_version`` audit event across repeats and concurrency, the new
``revoke_version`` policy/audit action (403 with key_id), indistinct 404
for unknown/cross-tenant keys and versions, whole-key revocation taking
priority (409), storage/ledger failure 500 with rollback, version-revoked
409 enforcement in encrypt/decrypt/rewrap/sign/verify without touching the
provider, rotation minting active versions, and preservation of the
per-version revocation fields across export/import, backup/restore and
provider migration.
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

from keymgr import provider as provider_mod
from keymgr import restore as restore_mod
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog, LedgerError
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


@pytest.fixture()
def pair(tmp_path, monkeypatch):
    """Two independent servers (separate data dirs) sharing one process."""
    gen_a = _build_server(tmp_path / "a", monkeypatch)
    stack_a = next(gen_a)
    gen_b = _build_server(tmp_path / "b", monkeypatch)
    stack_b = next(gen_b)
    yield stack_a, stack_b
    for gen in (gen_a, gen_b):
        try:
            next(gen)
        except StopIteration:
            pass


@pytest.fixture()
def chain_stack(tmp_path, monkeypatch):
    """A server on a local/fakekms provider chain (for migration)."""
    sys.path.insert(0, os.path.dirname(__file__))
    monkeypatch.setenv("KEYMGR_PROVIDER_CHAIN", "local,fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", str(tmp_path / "kms-state.json"))
    monkeypatch.setenv("FAKE_KMS_FAULTS", str(tmp_path / "kms-faults.json"))
    import fake_kms

    fake_kms.reset()
    yield from _build_server(tmp_path, monkeypatch)


# -- helpers ---------------------------------------------------------------
def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


_idem_counter = itertools.count(1)


def _idem(prefix="op"):
    return "%s-%d" % (prefix, next(_idem_counter))


def _rotate(client, key_id, algorithm, tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": _idem("rot")},
    )
    assert status == 201, body
    return body


def _revoke_version(client, key_id, version, tenant="t", reason="old",
                    operator="bob", **extra):
    body = {"tenant_id": tenant, "reason": reason, "operator": operator}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/versions/%d/revoke" % (key_id, version), body
    )


def _version_status(client, key_id, version, tenant="t"):
    return client.call(
        "GET", "/v1/keys/%s/versions/%d/status?tenant_id=%s"
        % (key_id, version, tenant)
    )


def _encrypt(client, key_id, plaintext, tenant="t", **extra):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        headers={"Idempotency-Key": _idem("enc")},
    )


def _audit_events(st, tenant="t"):
    return st.audit.query(tenant, limit=1000).events


def _events(st, action, tenant="t"):
    return [e for e in _audit_events(st, tenant) if e.action == action]


# -- happy path / response shape -------------------------------------------
def test_revoke_version_happy_path_and_status(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256")
    # Active version: fixed key order, null revocation triplet.
    status, body = _version_status(client, kid, 1)
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "version", "status", "reason", "operator", "revoked_at",
    ]
    assert body == {
        "key_id": kid, "version": 1, "status": "active",
        "reason": None, "operator": None, "revoked_at": None,
    }
    # Revoke version 1 only; version 2 and the key stay active.
    status, body = _revoke_version(client, kid, 1, reason="compromised",
                                   operator="carol")
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "version", "status", "reason", "operator", "revoked_at",
    ]
    assert body["status"] == "revoked"
    assert body["reason"] == "compromised"
    assert body["operator"] == "carol"
    assert isinstance(body["revoked_at"], str) and body["revoked_at"]
    # The status read agrees, and version 2 / the key are unaffected.
    assert _version_status(client, kid, 1)[1] == body
    assert _version_status(client, kid, 2)[1]["status"] == "active"
    status, key_status = client.call(
        "GET", "/v1/keys/%s/status?tenant_id=t" % kid
    )
    assert status == 200 and key_status["status"] == "active"
    # One single success event, carrying the key_id.
    events = _events(stack, "revoke_version")
    assert len(events) == 1
    assert events[0].outcome == "success" and events[0].key_id == kid


def test_repeat_and_concurrent_revoke_keep_first_values_single_audit(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256")
    status, first = _revoke_version(client, kid, 1, reason="first",
                                    operator="op1")
    assert status == 200
    # A serial repeat keeps the first values and writes no second event.
    status, again = _revoke_version(client, kid, 1, reason="second",
                                    operator="op2")
    assert status == 200 and again == first
    # Concurrent revokes race; every caller gets the first values and the
    # ledger still holds exactly one revoke_version event.
    results = []

    def worker(reason):
        results.append(
            _revoke_version(client, kid, 2, reason=reason, operator="w")
        )

    threads = [
        threading.Thread(target=worker, args=("race-%d" % i,))
        for i in range(6)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(status == 200 for status, _ in results)
    bodies = {json.dumps(body, sort_keys=True) for _, body in results}
    assert len(bodies) == 1
    events = _events(stack, "revoke_version")
    assert len(events) == 2  # one for v1, one for v2 -- never per attempt
    assert {e.outcome for e in events} == {"success"}


# -- body / parameter validation (400, not audited) -------------------------
def test_body_must_be_exactly_three_non_empty_strings(stack):
    client = stack.client
    kid = _make_key(client)
    cases = [
        {"tenant_id": "t", "reason": "r"},                      # missing operator
        {"tenant_id": "t", "operator": "o"},                    # missing reason
        {"tenant_id": "t", "reason": "", "operator": "o"},      # empty reason
        {"tenant_id": "t", "reason": "r", "operator": ""},      # empty operator
        {"tenant_id": "t", "reason": 1, "operator": "o"},       # non-string
        {"tenant_id": "t", "reason": "r", "operator": "o",
         "extra": 1},                                           # unknown field
    ]
    for body in cases:
        status, reply = client.call(
            "POST", "/v1/keys/%s/versions/1/revoke" % kid, body
        )
        assert status == 400, (body, reply)
        assert "error" in reply
    # Non-object and unparseable bodies are 400 as well.
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid, raw=b"[1,2]"
    )
    assert status == 400
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid, raw=b"{bad"
    )
    assert status == 400
    # None of the 400s wrote any audit event (and no tenant_conflict either:
    # the tenant source itself was valid).
    assert _events(stack, "revoke_version") == []
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert b"tenant_conflict" not in raw
    # The version is still active afterwards.
    assert _version_status(client, kid, 1)[1]["status"] == "active"


def test_bad_key_id_and_version_are_400_not_audited(stack):
    client = stack.client
    kid = _make_key(client)
    body = {"tenant_id": "t", "reason": "r", "operator": "o"}
    status, reply = client.call(
        "POST", "/v1/keys/not-a-uuid/versions/1/revoke", body
    )
    assert status == 400 and "key_id" in reply["error"]
    for bad in ("0", "-1", "x", "1.5"):
        status, reply = client.call(
            "POST", "/v1/keys/%s/versions/%s/revoke" % (kid, bad), body
        )
        assert status == 400 and "version" in reply["error"]
    assert _events(stack, "revoke_version") == []
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert b"tenant_conflict" not in raw


def test_tenant_source_failures_record_tenant_conflict(stack):
    client = stack.client
    kid = _make_key(client)
    # Missing tenant_id in the body.
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid,
        {"reason": "r", "operator": "o"},
    )
    assert status == 400
    # Conflicting tenant sources.
    status, _ = client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % kid,
        {"tenant_id": "t", "reason": "r", "operator": "o"},
        headers={"X-Tenant-Id": "other"},
    )
    assert status == 400
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert raw.count(b"tenant_conflict") == 2
    assert _events(stack, "revoke_version") == []


# -- authorization / business rejections ------------------------------------
def test_policy_denial_is_403_and_audited_with_key_id(stack):
    client = stack.client
    kid = _make_key(client)
    stack.policies.put(
        "t", [
            Rule(subject="alice", actions=["revoke_version"], effect="deny"),
            Rule(subject="alice", actions=["read"], effect="allow"),
        ]
    )
    status, body = _revoke_version(client, kid, 1)
    assert status == 403, body
    events = _events(stack, "revoke_version")
    assert len(events) == 1
    assert events[0].outcome == "rejected" and events[0].key_id == kid
    # The version was not revoked.
    assert _version_status(client, kid, 1)[1]["status"] == "active"


def test_revoke_action_does_not_cover_revoke_version(stack):
    # The new endpoint is governed by its own action: allowing the whole-key
    # "revoke" does not authorize a version revoke.
    client = stack.client
    kid = _make_key(client)
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["revoke", "read"],
                   effect="allow")]
    )
    status, _ = _revoke_version(client, kid, 1)
    assert status == 403
    # Granting the new action lets the same caller through.
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["revoke_version", "read"],
                   effect="allow")]
    )
    status, body = _revoke_version(client, kid, 1)
    assert status == 200 and body["status"] == "revoked"


def test_unknown_and_cross_tenant_objects_are_404(stack):
    client = stack.client
    kid = _make_key(client)
    unknown = "00000000-0000-4000-8000-000000000000"
    status, body = _revoke_version(client, unknown, 1)
    assert status == 404 and body == {"error": "key not found"}
    status, body = _revoke_version(client, kid, 99)
    assert status == 404 and body == {"error": "version not found"}
    # Cross-tenant access is indistinguishable from a missing object.
    status, body = _revoke_version(client, kid, 1, tenant="other")
    assert status == 404 and body == {"error": "key not found"}
    assert _version_status(client, unknown, 1)[0] == 404
    assert _version_status(client, kid, 99)[0] == 404
    assert _version_status(client, kid, 1, tenant="other")[0] == 404
    # Each rejected attempt is audited with the key_id (tenant "other" gets
    # its own event).
    rejected = [
        e for e in stack.audit._read_all()
        if e.action == "revoke_version" and e.outcome == "rejected"
    ]
    assert len(rejected) == 3
    assert all(e.key_id in (kid, unknown) for e in rejected)


def test_whole_key_revocation_takes_priority_409(stack):
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256")
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % kid,
        {"tenant_id": "t", "reason": "key done", "operator": "alice"},
    )
    assert status == 200
    # A version revoke on a revoked key is a 409 and shadows nothing.
    status, body = _revoke_version(client, kid, 1, reason="v", operator="o")
    assert status == 409 and body == {"error": "key is revoked"}
    # The version status read defers to the key-level revocation as well.
    status, body = _version_status(client, kid, 1)
    assert status == 409 and body == {"error": "key is revoked"}
    events = _events(stack, "revoke_version")
    assert len(events) == 1 and events[0].outcome == "rejected"
    # The stored version keeps no version-level revocation facts.
    record = stack.store.get(kid, "t")
    assert all(v.status == "active" for v in record.versions)


# -- crypto enforcement ------------------------------------------------------
def test_encrypt_decrypt_on_revoked_version_409_no_provider(ext_stack):
    import fake_kms

    client = ext_stack.client
    kid = _make_key(client)
    token_status, enc = _encrypt(client, kid, b"payload", version=1)
    assert token_status == 200, enc
    token = enc["envelope"]
    _rotate(client, kid, "AES256")
    status, _ = _revoke_version(client, kid, 1)
    assert status == 200
    before = fake_kms.call_count("export_material")
    status, body = _encrypt(client, kid, b"more", version=1)
    assert status == 409, body
    status, body = client.call(
        "POST", "/v1/keys/%s/decrypt" % kid,
        {"tenant_id": "t", "envelope": token},
    )
    assert status == 409, body
    # The provider was never asked for the revoked version's material.
    assert fake_kms.call_count("export_material") == before
    # The rejections carry the ORIGINAL action names with the key_id.
    rejected = [
        (e.action, e.outcome, e.key_id)
        for e in ext_stack.audit._read_all()
        if e.outcome == "rejected" and e.action in ("encrypt", "decrypt")
    ]
    assert ("encrypt", "rejected", kid) in rejected
    assert ("decrypt", "rejected", kid) in rejected
    # The current version still works.
    assert _encrypt(client, kid, b"still fine")[0] == 200


def test_rewrap_on_revoked_version_409(ext_stack):
    import fake_kms

    client = ext_stack.client
    kid = _make_key(client)
    status, enc = _encrypt(client, kid, b"payload", version=1)
    assert status == 200, enc
    token = enc["envelope"]
    _rotate(client, kid, "AES256")
    status, _ = _revoke_version(client, kid, 2)
    assert status == 200
    before = fake_kms.call_count("export_material")
    # Target (default current) is the revoked version 2.
    status, body = client.call(
        "POST", "/v1/keys/%s/rewrap" % kid,
        {"tenant_id": "t", "envelope": token},
    )
    assert status == 409, body
    assert fake_kms.call_count("export_material") == before
    events = _events(ext_stack, "rewrap")
    assert len(events) == 1
    assert events[0].outcome == "rejected" and events[0].key_id == kid


def test_sign_verify_on_revoked_version_409(ext_stack):
    import fake_kms

    client = ext_stack.client
    kid = _make_key(client, algorithm="RSA2048")
    _rotate(client, kid, "RSA2048")
    message = b64(b"message")
    status, signed = client.call(
        "POST", "/v1/keys/%s/sign" % kid,
        {"tenant_id": "t", "message": message, "version": 1},
    )
    assert status == 200, signed
    status, _ = _revoke_version(client, kid, 1)
    assert status == 200
    before = fake_kms.call_count("export_material")
    status, body = client.call(
        "POST", "/v1/keys/%s/sign" % kid,
        {"tenant_id": "t", "message": message, "version": 1},
    )
    assert status == 409, body
    status, body = client.call(
        "POST", "/v1/keys/%s/verify" % kid,
        {"tenant_id": "t", "message": message,
         "signature": signed["signature"], "version": 1},
    )
    assert status == 409, body
    assert fake_kms.call_count("export_material") == before
    rejected = [
        (e.action, e.outcome, e.key_id)
        for e in ext_stack.audit._read_all()
        if e.outcome == "rejected" and e.action in ("sign", "verify")
    ]
    assert ("sign", "rejected", kid) in rejected
    assert ("verify", "rejected", kid) in rejected
    # Version 2 still signs and verifies.
    status, signed2 = client.call(
        "POST", "/v1/keys/%s/sign" % kid,
        {"tenant_id": "t", "message": message},
    )
    assert status == 200, signed2
    status, verdict = client.call(
        "POST", "/v1/keys/%s/verify" % kid,
        {"tenant_id": "t", "message": message,
         "signature": signed2["signature"]},
    )
    assert status == 200 and verdict == {"valid": True}


def test_rotate_after_version_revoke_produces_active_version(stack):
    client = stack.client
    kid = _make_key(client)
    status, _ = _revoke_version(client, kid, 1)
    assert status == 200
    body = _rotate(client, kid, "AES256")
    assert body["version"] == 2
    # The fresh version is active and usable; the old one stays revoked.
    assert _version_status(client, kid, 2)[1]["status"] == "active"
    assert _version_status(client, kid, 1)[1]["status"] == "revoked"
    assert _encrypt(client, kid, b"new")[0] == 200


# -- persistence / bundles ---------------------------------------------------
def _decode_export(stack, bundle, passphrase):
    from keymgr import keybundle

    return keybundle.decode_bundle(bundle, passphrase)


def test_export_import_preserves_version_revocation(pair):
    stack, other = pair
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256")
    status, _ = _revoke_version(client, kid, 1, reason="old", operator="bob")
    assert status == 200
    status, exported = client.call(
        "POST", "/v1/keys/%s/export" % kid,
        {"tenant_id": "t", "passphrase": "pw"},
    )
    assert status == 200, exported
    payload = _decode_export(stack, exported["bundle"], "pw")
    by_version = {v["version"]: v for v in payload["versions"]}
    assert by_version[1]["status"] == "revoked"
    assert by_version[1]["reason"] == "old"
    assert by_version[1]["operator"] == "bob"
    assert isinstance(by_version[1]["revoked_at"], str)
    assert by_version[2]["status"] == "active"
    assert by_version[2]["reason"] is None
    assert by_version[2]["operator"] is None
    assert by_version[2]["revoked_at"] is None
    # Import into a second data dir: the per-version state survives.
    status, imported = other.client.call(
        "POST", "/v1/keys/import",
        {"tenant_id": "t", "passphrase": "pw",
         "bundle": exported["bundle"]},
        headers={"Idempotency-Key": _idem("imp")},
    )
    assert status == 201, imported
    assert _version_status(other.client, kid, 1)[1]["status"] == "revoked"
    got = _version_status(other.client, kid, 1)[1]
    assert got["reason"] == "old" and got["operator"] == "bob"
    assert _version_status(other.client, kid, 2)[1]["status"] == "active"
    # And crypto on the imported revoked version is refused.
    status, _ = _encrypt(other.client, kid, b"x", version=1)
    assert status == 409


def test_backup_restore_preserves_version_revocation(pair):
    stack, other = pair
    client = stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256")
    status, _ = _revoke_version(client, kid, 1, reason="old", operator="bob")
    assert status == 200
    status, backup = client.call(
        "POST", "/v1/backup", {"tenant_id": "t", "passphrase": "pw"}
    )
    assert status == 200, backup
    status, restored = other.client.call(
        "POST", "/v1/restore",
        {"tenant_id": "t", "passphrase": "pw",
         "bundle": backup["bundle"]},
        headers={"Idempotency-Key": _idem("res")},
    )
    assert status == 201, restored
    got = _version_status(other.client, kid, 1)[1]
    assert got["status"] == "revoked"
    assert got["reason"] == "old" and got["operator"] == "bob"
    assert _version_status(other.client, kid, 2)[1]["status"] == "active"


def test_bundle_rejects_inconsistent_version_revocation_fields(stack):
    from keymgr import keybundle

    client = stack.client
    kid = _make_key(client)
    status, exported = client.call(
        "POST", "/v1/keys/%s/export" % kid,
        {"tenant_id": "t", "passphrase": "pw"},
    )
    assert status == 200
    payload = _decode_export(stack, exported["bundle"], "pw")
    # A revoked version missing its facts is rejected.
    broken = json.loads(json.dumps(payload))
    broken["versions"][0]["status"] = "revoked"
    broken["versions"][0]["reason"] = None
    with pytest.raises(keybundle.InvalidBundle):
        keybundle.validate_payload(broken)
    # An active version carrying revocation facts is rejected.
    broken = json.loads(json.dumps(payload))
    broken["versions"][0]["reason"] = "why"
    with pytest.raises(keybundle.InvalidBundle):
        keybundle.validate_payload(broken)
    # An unknown status value is rejected.
    broken = json.loads(json.dumps(payload))
    broken["versions"][0]["status"] = "retired"
    with pytest.raises(keybundle.InvalidBundle):
        keybundle.validate_payload(broken)
    # A legacy version block without the fields validates as active.
    legacy = json.loads(json.dumps(payload))
    for ver in legacy["versions"]:
        for field in ("status", "reason", "operator", "revoked_at"):
            ver.pop(field, None)
    cleaned = keybundle.validate_payload(legacy)
    assert all(v["status"] == "active" for v in cleaned["versions"])


def test_migrate_preserves_version_revocation(chain_stack):
    client = chain_stack.client
    kid = _make_key(client)
    _rotate(client, kid, "AES256")
    status, _ = _revoke_version(client, kid, 1, reason="old", operator="bob")
    assert status == 200
    # The key starts on local; direct the active provider to the fake KMS
    # chain entry and migrate all versions onto it.
    status, body = client.call(
        "POST", "/v1/provider/switchover",
        {"provider_id": "fakekms"},
    )
    assert status == 200 and body["provider_id"] == "fakekms", body
    status, body = client.call(
        "POST", "/v1/keys/%s/migrate" % kid, {"tenant_id": "t"},
        headers={"Idempotency-Key": _idem("mig")},
    )
    assert status == 200, body
    status, body = _version_status(client, kid, 1)
    assert status == 200 and body["status"] == "revoked"
    assert body["reason"] == "old" and body["operator"] == "bob"
    assert _version_status(client, kid, 2)[1]["status"] == "active"
    # The revoked version is unusable after migration too; v2 still works.
    assert _encrypt(client, kid, b"x", version=1)[0] == 409
    assert _encrypt(client, kid, b"y")[0] == 200


# -- failure handling --------------------------------------------------------
def test_ledger_failure_rolls_back_and_is_500(stack, monkeypatch):
    client = stack.client
    kid = _make_key(client)

    def boom(event):
        raise LedgerError("disk full")

    monkeypatch.setattr(stack.audit, "append", boom)
    status, body = _revoke_version(client, kid, 1)
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}
    monkeypatch.undo()
    # The failed commit rolled the file back: still active, no event.
    assert _version_status(client, kid, 1)[1]["status"] == "active"
    assert _events(stack, "revoke_version") == []
    # And a later revoke succeeds cleanly.
    status, body = _revoke_version(client, kid, 1)
    assert status == 200 and body["status"] == "revoked"
    assert len(_events(stack, "revoke_version")) == 1


def test_get_status_read_policy_and_audit(stack):
    client = stack.client
    kid = _make_key(client)
    # A bad version parameter is a 400 with a read/rejected event.
    status, body = client.call(
        "GET", "/v1/keys/%s/versions/x/status?tenant_id=t" % kid
    )
    assert status == 400 and "version" in body["error"]
    rejected = [
        e for e in _events(stack, "read") if e.outcome == "rejected"
    ]
    assert len(rejected) == 1 and rejected[0].key_id == kid
    # A read denial is 403 with a read/rejected event.
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["read"], effect="deny")]
    )
    status, _ = _version_status(client, kid, 1)
    assert status == 403
