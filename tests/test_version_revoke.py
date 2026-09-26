"""POST/GET /v1/keys/{key_id}/versions/{version}/revoke|status.

Covers the fixed 200 key order ``key_id,version,status,reason,operator,
revoked_at`` (active versions project the last three as null), the strict
three-field body contract (every body/parameter 400 is unaudited; only
tenant/key_id identity failures record the usual tenant_conflict), the new
``revoke_version`` policy/audit action (403/404/409 with rejected events
carrying key_id), first-value-wins idempotency with a single audit event
across repeated and concurrent revokes, the 409 refusal of every crypto
endpoint (encrypt/decrypt/rewrap/sign/verify) on a revoked version without
a provider call, whole-key revocation outranking per-version state, new
versions rotating in as active, and the per-version revocation fields
riding the key file, the export bundle and the tenant backup through
import/restore (missing fields read as active).
"""

import base64
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
from keymgr import keybundle, tenantbundle
from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
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
        sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
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


def _make_key(client, algorithm="AES256", tenant="t"):
    status, body = client.call(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
    )
    assert status == 201, body
    return body["key_id"]


def _rotate(client, key_id, tenant="t", algorithm="AES256", key="rot-1"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": key},
    )
    assert status == 201, body
    return body


def _revoke_version(client, key_id, version, tenant="t", reason="r",
                    operator="op", **extra):
    body = {"tenant_id": tenant, "reason": reason, "operator": operator}
    body.update(extra)
    return client.call(
        "POST", "/v1/keys/%s/versions/%s/revoke" % (key_id, version), body
    )


def _status(client, key_id, version, tenant="t"):
    return client.call(
        "GET", "/v1/keys/%s/versions/%s/status?tenant_id=%s"
        % (key_id, version, tenant)
    )


def _audit_events(stack, tenant="t"):
    return stack.audit.query(tenant, limit=1000).events


def _revoke_version_events(stack, tenant="t"):
    return [
        e for e in _audit_events(stack, tenant)
        if e.action == "revoke_version"
    ]


# -- happy path -------------------------------------------------------------
def test_revoke_version_fixed_key_order(stack):
    key_id = _make_key(stack.client)
    status, body = _revoke_version(stack.client, key_id, 1)
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "version", "status", "reason", "operator", "revoked_at",
    ]
    assert body["key_id"] == key_id
    assert body["version"] == 1
    assert body["status"] == "revoked"
    assert body["reason"] == "r"
    assert body["operator"] == "op"
    assert isinstance(body["revoked_at"], str) and body["revoked_at"]


def test_status_of_active_version_has_null_fields(stack):
    key_id = _make_key(stack.client)
    status, body = _status(stack.client, key_id, 1)
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "version", "status", "reason", "operator", "revoked_at",
    ]
    assert body["status"] == "active"
    assert body["reason"] is None
    assert body["operator"] is None
    assert body["revoked_at"] is None


def test_status_after_revoke_matches_revoke_response(stack):
    key_id = _make_key(stack.client)
    _, revoked = _revoke_version(stack.client, key_id, 1)
    status, body = _status(stack.client, key_id, 1)
    assert status == 200, body
    assert body == revoked


def test_get_status_uses_read_action(stack):
    key_id = _make_key(stack.client)
    _status(stack.client, key_id, 1)
    reads = [
        e for e in _audit_events(stack)
        if e.action == "read" and e.outcome == "success"
    ]
    assert len(reads) == 1
    assert reads[0].key_id == key_id


def test_revoke_writes_one_success_event_with_key_id(stack):
    key_id = _make_key(stack.client)
    _revoke_version(stack.client, key_id, 1)
    events = _revoke_version_events(stack)
    assert len(events) == 1
    assert events[0].outcome == "success"
    assert events[0].key_id == key_id


def test_repeat_revoke_keeps_first_values_and_audits_once(stack):
    key_id = _make_key(stack.client)
    _, first = _revoke_version(stack.client, key_id, 1)
    status, second = _revoke_version(
        stack.client, key_id, 1, reason="other", operator="someone-else"
    )
    assert status == 200, second
    assert second == first
    _, third = _status(stack.client, key_id, 1)
    assert third == first
    events = _revoke_version_events(stack)
    assert [e.outcome for e in events] == ["success"]


def test_concurrent_revokes_keep_one_value_and_one_event(stack):
    key_id = _make_key(stack.client)
    results = []
    barrier = threading.Barrier(2)

    def worker(reason):
        barrier.wait()
        results.append(_revoke_version(stack.client, key_id, 1, reason=reason))

    threads = [
        threading.Thread(target=worker, args=("r%d" % i,)) for i in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [status for status, _ in results] == [200, 200]
    assert results[0][1] == results[1][1]
    assert results[0][1]["reason"] in ("r0", "r1")
    events = _revoke_version_events(stack)
    assert [e.outcome for e in events] == ["success"]


def test_only_target_version_is_revoked(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    _revoke_version(stack.client, key_id, 1)
    _, v1 = _status(stack.client, key_id, 1)
    _, v2 = _status(stack.client, key_id, 2)
    assert v1["status"] == "revoked"
    assert v2["status"] == "active"
    assert v2["reason"] is None


def test_rotate_after_version_revoke_produces_active_version(stack):
    key_id = _make_key(stack.client)
    _revoke_version(stack.client, key_id, 1)
    rotated = _rotate(stack.client, key_id, key="rot-after-revoke")
    assert rotated["version"] == 2
    _, body = _status(stack.client, key_id, 2)
    assert body["status"] == "active"
    assert body["revoked_at"] is None


def test_key_file_carries_per_version_revocation_fields(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    _revoke_version(stack.client, key_id, 1)
    with open(os.path.join(stack.data_dir, key_id + ".json")) as fh:
        doc = json.load(fh)
    versions = {v["version"]: v for v in doc["versions"]}
    assert list(versions[1].keys())[-4:] == [
        "status", "reason", "operator", "revoked_at",
    ]
    assert versions[1]["status"] == "revoked"
    assert versions[1]["reason"] == "r"
    assert versions[1]["operator"] == "op"
    assert versions[1]["revoked_at"]
    assert versions[2]["status"] == "active"
    assert versions[2]["reason"] is None
    assert versions[2]["operator"] is None
    assert versions[2]["revoked_at"] is None


def test_record_without_version_fields_reads_as_active(stack):
    key_id = _make_key(stack.client)
    path = os.path.join(stack.data_dir, key_id + ".json")
    with open(path) as fh:
        doc = json.load(fh)
    for ver in doc["versions"]:
        for field in ("status", "reason", "operator", "revoked_at"):
            ver.pop(field, None)
    with open(path, "w") as fh:
        json.dump(doc, fh)
    status, body = _status(stack.client, key_id, 1)
    assert status == 200, body
    assert body["status"] == "active"
    assert body["reason"] is None


def test_get_version_response_contract_unchanged(stack):
    key_id = _make_key(stack.client)
    _revoke_version(stack.client, key_id, 1)
    status, body = stack.client.call(
        "GET", "/v1/keys/%s/versions/1?tenant_id=t" % key_id
    )
    assert status == 200, body
    assert list(body.keys()) == [
        "key_id", "version", "created_at", "algorithm", "public_key",
    ]


# -- body / parameter 400s (never audited) ----------------------------------
def test_extra_body_field_is_unaudited_400(stack):
    key_id = _make_key(stack.client)
    status, body = _revoke_version(stack.client, key_id, 1, extra="x")
    assert status == 400, body
    assert body["error"] == "field extra is not accepted by this endpoint"
    assert _revoke_version_events(stack) == []


@pytest.mark.parametrize(
    "field,value",
    [("reason", ""), ("reason", 1), ("operator", ""), ("operator", None)],
)
def test_bad_reason_or_operator_is_unaudited_400(stack, field, value):
    key_id = _make_key(stack.client)
    status, body = _revoke_version(stack.client, key_id, 1, **{field: value})
    assert status == 400, body
    assert field in body["error"]
    assert _revoke_version_events(stack) == []


def test_missing_reason_is_unaudited_400(stack):
    key_id = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % key_id,
        {"tenant_id": "t", "operator": "op"},
    )
    assert status == 400, body
    assert body["error"] == "missing required field: reason"
    assert _revoke_version_events(stack) == []


@pytest.mark.parametrize("raw", ["0", "-1", "x", "1.5"])
def test_bad_version_is_unaudited_400(stack, raw):
    key_id = _make_key(stack.client)
    status, body = _revoke_version(stack.client, key_id, raw)
    assert status == 400, body
    assert body["error"] == "field version must be a positive integer"
    assert _revoke_version_events(stack) == []


def test_bad_key_id_is_tenant_conflict_400(stack):
    status, body = _revoke_version(stack.client, "not-a-uuid", 1)
    assert status == 400, body
    assert body["error"] == "field key_id must be a UUID4"
    # The identity failure follows the old contract: an invisible
    # tenant_conflict event, never a revoke_version event.
    assert _revoke_version_events(stack) == []
    conflicts = [
        e for e in stack.audit._read_all() if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 1


def test_non_object_body_is_400(stack):
    key_id = _make_key(stack.client)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/versions/1/revoke" % key_id, raw=b"[1, 2]"
    )
    assert status == 400, body
    assert _revoke_version_events(stack) == []


# -- 403 / 404 / 409 ---------------------------------------------------------
def test_policy_denial_is_403_with_rejected_event(stack):
    key_id = _make_key(stack.client)
    stack.policies.put(
        "t",
        [
            Rule(subject="alice", actions=["revoke_version"], effect="deny"),
            Rule(subject="alice", actions=["read"], effect="allow"),
        ],
    )
    status, body = _revoke_version(stack.client, key_id, 1)
    assert status == 403, body
    assert body["error"] == "action not permitted by policy"
    events = _revoke_version_events(stack)
    assert [e.outcome for e in events] == ["rejected"]
    assert events[0].key_id == key_id
    _, after = _status(stack.client, key_id, 1)
    assert after["status"] == "active"


def test_unknown_key_is_404_with_rejected_event(stack):
    key_id = "12345678-1234-4123-8123-123456789012"
    status, body = _revoke_version(stack.client, key_id, 1)
    assert status == 404, body
    assert body["error"] == "key not found"
    events = _revoke_version_events(stack)
    assert [e.outcome for e in events] == ["rejected"]
    assert events[0].key_id == key_id


def test_cross_tenant_key_is_404(stack):
    key_id = _make_key(stack.client, tenant="other")
    status, body = _revoke_version(stack.client, key_id, 1)
    assert status == 404, body
    assert body["error"] == "key not found"
    _, after = _status(stack.client, key_id, 1, tenant="other")
    assert after["status"] == "active"


def test_unknown_version_is_404(stack):
    key_id = _make_key(stack.client)
    status, body = _revoke_version(stack.client, key_id, 9)
    assert status == 404, body
    assert body["error"] == "version not found"
    events = _revoke_version_events(stack)
    assert [e.outcome for e in events] == ["rejected"]


def test_revoked_key_gives_409(stack):
    key_id = _make_key(stack.client)
    status, _ = stack.client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "key", "operator": "op"},
    )
    assert status == 200
    status, body = _revoke_version(stack.client, key_id, 1)
    assert status == 409, body
    assert body["error"] == "key is revoked"
    events = _revoke_version_events(stack)
    assert [e.outcome for e in events] == ["rejected"]


def test_get_status_unknown_and_cross_tenant_are_404(stack):
    key_id = _make_key(stack.client)
    status, _ = _status(stack.client, key_id, 9)
    assert status == 404
    status, _ = _status(
        stack.client, "12345678-1234-4123-8123-123456789012", 1
    )
    assert status == 404
    other = _make_key(stack.client, tenant="other")
    status, _ = _status(stack.client, other, 1)
    assert status == 404


# -- crypto endpoints refuse a revoked version with 409 ----------------------
def _encrypt(client, key_id, version=None, idem="enc-1"):
    body = {"tenant_id": "t", "plaintext": b64(b"hi")}
    if version is not None:
        body["version"] = version
    return client.call(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        headers={"Idempotency-Key": idem},
    )


def test_encrypt_on_revoked_version_is_409_without_provider_call(ext_stack):
    import fake_kms

    key_id = _make_key(ext_stack.client)
    _rotate(ext_stack.client, key_id)
    _revoke_version(ext_stack.client, key_id, 1)
    before = fake_kms.call_count("export_material")
    status, body = _encrypt(ext_stack.client, key_id, version=1)
    assert status == 409, body
    assert body["error"] == "key version is revoked"
    assert fake_kms.call_count("export_material") == before
    rejected = [
        e for e in _audit_events(ext_stack)
        if e.action == "encrypt" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].key_id == key_id


def test_encrypt_on_active_version_still_works(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    _revoke_version(stack.client, key_id, 1)
    status, body = _encrypt(stack.client, key_id, idem="enc-active")
    assert status == 200, body
    assert body["format"] == "keymgr-envelope-v1"


def test_decrypt_on_revoked_version_is_409(stack):
    key_id = _make_key(stack.client)
    _, sealed = _encrypt(stack.client, key_id)
    _revoke_version(stack.client, key_id, 1)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/decrypt" % key_id,
        {"tenant_id": "t", "envelope": sealed["envelope"]},
    )
    assert status == 409, body
    assert body["error"] == "key version is revoked"
    rejected = [
        e for e in _audit_events(stack)
        if e.action == "decrypt" and e.outcome == "rejected"
    ]
    assert len(rejected) == 1


def test_rewrap_to_or_from_revoked_version_is_409(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    _, sealed = _encrypt(stack.client, key_id, idem="enc-rewrap")
    _revoke_version(stack.client, key_id, 2)
    # Target (current) version revoked.
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/rewrap" % key_id,
        {"tenant_id": "t", "envelope": sealed["envelope"],
         "target_version": 2},
    )
    assert status == 409, body
    assert body["error"] == "key version is revoked"
    # Source version revoked.
    _revoke_version(stack.client, key_id, 1)
    status, body = stack.client.call(
        "POST", "/v1/keys/%s/rewrap" % key_id,
        {"tenant_id": "t", "envelope": sealed["envelope"],
         "target_version": 2},
    )
    assert status == 409, body
    rejected = [
        e for e in _audit_events(stack)
        if e.action == "rewrap" and e.outcome == "rejected"
    ]
    assert len(rejected) == 2


def test_sign_and_verify_on_revoked_version_are_409(ext_stack):
    import fake_kms

    key_id = _make_key(ext_stack.client, algorithm="RSA2048")
    _rotate(ext_stack.client, key_id, algorithm="RSA2048")
    _, signed = ext_stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "message": b64(b"m")},
    )
    _revoke_version(ext_stack.client, key_id, 1)
    before_sign = fake_kms.call_count("sign")
    before_export = fake_kms.call_count("export_material")
    status, body = ext_stack.client.call(
        "POST", "/v1/keys/%s/sign" % key_id,
        {"tenant_id": "t", "version": 1, "message": b64(b"m")},
    )
    assert status == 409, body
    assert body["error"] == "key version is revoked"
    status, body = ext_stack.client.call(
        "POST", "/v1/keys/%s/verify" % key_id,
        {"tenant_id": "t", "version": 1, "message": b64(b"m"),
         "signature": signed["signature"]},
    )
    assert status == 409, body
    assert fake_kms.call_count("sign") == before_sign
    assert fake_kms.call_count("export_material") == before_export
    rejected = [
        e for e in _audit_events(ext_stack)
        if e.action in ("sign", "verify") and e.outcome == "rejected"
    ]
    assert len(rejected) == 2


def test_whole_key_revocation_outranks_version_state(stack):
    key_id = _make_key(stack.client)
    stack.client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "key", "operator": "op"},
    )
    status, body = _encrypt(stack.client, key_id, idem="enc-key-revoked")
    assert status == 409, body
    assert body["error"] == "key is revoked"


# -- export / import / backup / restore --------------------------------------
def test_export_and_import_preserve_version_revocation(stack):
    key_id = _make_key(stack.client)
    _rotate(stack.client, key_id)
    _, revoked = _revoke_version(stack.client, key_id, 1)
    status, exported = stack.client.call(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t", "passphrase": "pw"},
    )
    assert status == 200, exported
    payload = keybundle.decode_bundle(exported["bundle"], "pw")
    versions = {v["version"]: v for v in payload["versions"]}
    assert versions[1]["status"] == "revoked"
    assert versions[1]["reason"] == "r"
    assert versions[1]["operator"] == "op"
    assert versions[1]["revoked_at"] == revoked["revoked_at"]
    assert versions[2]["status"] == "active"
    assert versions[2]["reason"] is None

    # Import under a fresh key_id into the same tenant and confirm the
    # per-version state survives the round trip.
    payload["key_id"] = "12345678-1234-4123-8123-123456789012"
    bundle = keybundle.encode_bundle(payload, "pw")
    status, _ = stack.client.call(
        "POST", "/v1/keys/import",
        {"tenant_id": "t", "passphrase": "pw", "bundle": bundle},
        headers={"Idempotency-Key": "imp-1"},
    )
    assert status == 201
    _, v1 = _status(stack.client, payload["key_id"], 1)
    _, v2 = _status(stack.client, payload["key_id"], 2)
    assert v1["status"] == "revoked"
    assert v1["reason"] == "r"
    assert v1["revoked_at"] == revoked["revoked_at"]
    assert v2["status"] == "active"


def test_legacy_bundle_without_version_fields_imports_active(stack):
    key_id = _make_key(stack.client)
    status, exported = stack.client.call(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t", "passphrase": "pw"},
    )
    assert status == 200, exported
    payload = keybundle.decode_bundle(exported["bundle"], "pw")
    payload["key_id"] = "12345678-1234-4123-8123-123456789012"
    for ver in payload["versions"]:
        for field in ("status", "reason", "operator", "revoked_at"):
            ver.pop(field, None)
    bundle = keybundle.encode_bundle(payload, "pw")
    status, _ = stack.client.call(
        "POST", "/v1/keys/import",
        {"tenant_id": "t", "passphrase": "pw", "bundle": bundle},
        headers={"Idempotency-Key": "imp-legacy"},
    )
    assert status == 201
    _, body = _status(stack.client, payload["key_id"], 1)
    assert body["status"] == "active"
    assert body["revoked_at"] is None


def test_backup_and_restore_preserve_version_revocation(stack):
    key_id = _make_key(stack.client)
    _revoke_version(stack.client, key_id, 1)
    status, backup = stack.client.call(
        "POST", "/v1/backup", {"tenant_id": "t", "passphrase": "pw"},
    )
    assert status == 200, backup
    payload = tenantbundle.decode_bundle(backup["bundle"], "pw")
    versions = payload["keys"][0]["versions"]
    assert versions[0]["status"] == "revoked"
    assert versions[0]["reason"] == "r"

    payload["tenant_id"] = "restored"
    payload["keys"][0]["key_id"] = (
        "12345678-1234-4123-8123-123456789012"
    )
    bundle = tenantbundle.encode_bundle(payload, "pw")
    status, _ = stack.client.call(
        "POST", "/v1/restore",
        {"tenant_id": "restored", "passphrase": "pw", "bundle": bundle},
        headers={"Idempotency-Key": "restore-1"},
    )
    assert status == 201
    _, body = _status(
        stack.client, "12345678-1234-4123-8123-123456789012", 1,
        tenant="restored",
    )
    assert body["status"] == "revoked"
    assert body["reason"] == "r"
    assert body["operator"] == "op"


def test_bundle_rejects_malformed_version_revocation(stack):
    key_id = _make_key(stack.client)
    status, exported = stack.client.call(
        "POST", "/v1/keys/%s/export" % key_id,
        {"tenant_id": "t", "passphrase": "pw"},
    )
    assert status == 200, exported
    payload = keybundle.decode_bundle(exported["bundle"], "pw")
    payload["key_id"] = "12345678-1234-4123-8123-123456789012"
    payload["versions"][0]["status"] = "revoked"  # missing reason/operator
    bundle = keybundle.encode_bundle(payload, "pw")
    status, body = stack.client.call(
        "POST", "/v1/keys/import",
        {"tenant_id": "t", "passphrase": "pw", "bundle": bundle},
        headers={"Idempotency-Key": "imp-bad"},
    )
    assert status == 400, body
    assert "reason" in body["error"]
