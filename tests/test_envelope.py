"""Envelope encryption/decryption tests (keymgr-envelope-v1).

Covers the store layer, the HTTP endpoints and the CLI: roundtrips for
AES256 (AES-GCM wrap) and RSA2048 (RSA-OAEP-SHA256 wrap), rotation
consistency, revocation, tampering/AAD mismatches, tenant isolation, policy
enforcement, audit projections and provider outages.
"""

import base64
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keymgr import envelope as envelope_mod  # noqa: E402
from keymgr.audit import AuditLog  # noqa: E402
from keymgr.policy import PolicyStore  # noqa: E402
from keymgr.restore import RestoreCoordinator  # noqa: E402
from keymgr.operations import OperationStore  # noqa: E402
from keymgr.store import KeyStore  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# -- HTTP harness (mirrors test_recovery_misc) ------------------------------
class HttpServer:
    def __init__(self, env):
        from keymgr.artifacts import ArtifactStore
        from keymgr.server import make_handler
        from http.server import ThreadingHTTPServer

        audit_log = AuditLog(env.data_dir)
        store = KeyStore(env.data_dir, audit_log)
        policy_store = PolicyStore(env.data_dir, audit_log)
        coordinator = RestoreCoordinator(store, policy_store)
        operation_store = OperationStore(env.data_dir, audit_log)
        artifact_store = ArtifactStore(env.data_dir, store, audit_log)
        artifact_store.settle_pending(operation_store)
        operation_store.recover_pending(is_parked=artifact_store.is_parked)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                store, policy_store, coordinator, operation_store,
                artifact_store,
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

    def request(self, method, path, body=None, headers=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture()
def http(env):
    server = HttpServer(env)
    yield server
    server.stop()


def _create(http, tenant="t1", algorithm="AES256", operator="alice"):
    status, body = http.request(
        "POST", "/v1/keys",
        {"tenant_id": tenant, "algorithm": algorithm, "label": "k"},
        {"X-Operator-Id": operator},
    )
    assert status == 201, body
    return body["key_id"]


def _encrypt(http, key_id, plaintext=b"hello", aad=None, version=None,
             tenant="t1", operator="alice"):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    if aad is not None:
        body["aad"] = b64(aad)
    if version is not None:
        body["version"] = version
    return http.request(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        {"X-Operator-Id": operator},
    )


def _decrypt(http, key_id, token, aad=None, tenant="t1", operator="alice"):
    body = {"tenant_id": tenant, "envelope": token}
    if aad is not None:
        body["aad"] = b64(aad)
    return http.request(
        "POST", "/v1/keys/%s/decrypt" % key_id, body,
        {"X-Operator-Id": operator},
    )


# -- HTTP roundtrips ---------------------------------------------------------
@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_http_roundtrip(http, env, algorithm):
    key_id = _create(http, algorithm=algorithm)
    status, body = _encrypt(http, key_id, b"secret-data", aad=b"ctx")
    assert status == 200, body
    assert body["format"] == "keymgr-envelope-v1"
    token = body["envelope"]
    # The envelope carries only metadata and ciphertext.
    parsed = envelope_mod.parse_envelope(token)
    assert parsed["key_id"] == key_id
    assert parsed["version"] == 1
    assert parsed["algorithm"] == algorithm
    assert b"secret-data" not in token.encode("ascii")

    status, body = _decrypt(http, key_id, token, aad=b"ctx")
    assert status == 200, body
    assert body == {"plaintext": b64(b"secret-data")}


def test_http_envelope_metadata(http, env):
    key_id = _create(http)
    status, body = _encrypt(http, key_id, b"x")
    assert status == 200
    raw = json.loads(
        base64.urlsafe_b64decode(
            body["envelope"] + "=" * (-len(body["envelope"]) % 4)
        ).decode("utf-8")
    )
    assert raw["format"] == "keymgr-envelope-v1"
    for field in ("key_id", "version", "algorithm", "nonce", "tag",
                  "ciphertext", "wrapped_key", "wrap_nonce"):
        assert field in raw


def test_http_rotation_keeps_old_versions_decryptable(http, env):
    key_id = _create(http)
    status, body = _encrypt(http, key_id, b"v1-data")
    token_v1 = body["envelope"]
    status, _ = http.request(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "t1", "algorithm": "AES256"},
        {"X-Operator-Id": "alice", "Idempotency-Key": "env-rot-1"},
    )
    assert status == 201
    # The old envelope still opens against version 1.
    status, body = _decrypt(http, key_id, token_v1)
    assert status == 200, body
    assert body["plaintext"] == b64(b"v1-data")
    # Default version follows current; explicit versions are honored.
    status, body = _encrypt(http, key_id, b"v2-data")
    assert envelope_mod.parse_envelope(body["envelope"])["version"] == 2
    status, body = _encrypt(http, key_id, b"back-to-v1", version=1)
    assert envelope_mod.parse_envelope(body["envelope"])["version"] == 1
    status, body = _decrypt(http, key_id, body["envelope"])
    assert body["plaintext"] == b64(b"back-to-v1")


def test_http_restart_keeps_view(http, env):
    key_id = _create(http)
    status, body = _encrypt(http, key_id, b"durable")
    token = body["envelope"]
    http.stop()
    # A fresh server over the same data dir (startup recovery) sees the same.
    server = HttpServer(env)
    try:
        status, body = _decrypt(server, key_id, token)
        assert status == 200, body
        assert body["plaintext"] == b64(b"durable")
    finally:
        server.stop()


# -- HTTP error mapping ------------------------------------------------------
def test_http_missing_and_invalid_fields(http, env):
    key_id = _create(http)
    # Missing plaintext.
    status, body = http.request(
        "POST", "/v1/keys/%s/encrypt" % key_id, {"tenant_id": "t1"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 400 and "plaintext" in body["error"]
    # Invalid base64 plaintext.
    status, body = _encrypt(http, key_id, b"x")
    assert status == 200
    status, body = http.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": "!!!not-base64!!!"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 400 and "plaintext" in body["error"]
    # Invalid base64 aad.
    status, body = http.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": b64(b"x"), "aad": "%%%"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 400 and "aad" in body["error"]
    # Bad version parameter.
    status, body = http.request(
        "POST", "/v1/keys/%s/encrypt" % key_id,
        {"tenant_id": "t1", "plaintext": b64(b"x"), "version": 0},
        {"X-Operator-Id": "alice"},
    )
    assert status == 400 and "version" in body["error"]
    # Missing envelope on decrypt.
    status, body = http.request(
        "POST", "/v1/keys/%s/decrypt" % key_id, {"tenant_id": "t1"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 400 and "envelope" in body["error"]
    # Malformed envelope token.
    status, body = _decrypt(http, key_id, "not-an-envelope")
    assert status == 400 and "envelope" in body["error"]


def test_http_tamper_and_aad_mismatch(http, env):
    key_id = _create(http)
    status, body = _encrypt(http, key_id, b"data", aad=b"right")
    token = body["envelope"]
    # AAD mismatch.
    status, body = _decrypt(http, key_id, token, aad=b"wrong")
    assert status == 400 and "aad" in body["error"]
    # Tampered ciphertext.
    parsed = envelope_mod.parse_envelope(token)
    raw = {
        "format": "keymgr-envelope-v1",
        "key_id": parsed["key_id"],
        "version": parsed["version"],
        "algorithm": parsed["algorithm"],
        "nonce": base64.urlsafe_b64encode(parsed["nonce"]).rstrip(b"=").decode(),
        "tag": base64.urlsafe_b64encode(parsed["tag"]).rstrip(b"=").decode(),
        "ciphertext": base64.urlsafe_b64encode(
            bytes([parsed["ciphertext"][0] ^ 1]) + parsed["ciphertext"][1:]
        ).rstrip(b"=").decode(),
        "wrapped_key": base64.urlsafe_b64encode(parsed["wrapped_key"]).rstrip(b"=").decode(),
        "wrap_nonce": base64.urlsafe_b64encode(parsed["wrap_nonce"]).rstrip(b"=").decode(),
    }
    tampered = base64.urlsafe_b64encode(
        json.dumps(raw).encode("utf-8")
    ).rstrip(b"=").decode()
    status, body = _decrypt(http, key_id, tampered, aad=b"right")
    assert status == 400 and "envelope" in body["error"]


def test_http_unknown_foreign_and_version_404(http, env):
    key_id = _create(http)
    other = _create(http, tenant="t2")
    status, body = _encrypt(http, key_id, b"x")
    token = body["envelope"]
    # Unknown key.
    missing = "00000000-0000-4000-8000-000000000000"
    status, _ = _encrypt(http, missing, b"x")
    assert status == 404
    status, _ = _decrypt(http, missing, token)
    assert status == 404
    # Cross-tenant access is indistinguishable from unknown.
    status, _ = _encrypt(http, key_id, b"x", tenant="t2")
    assert status == 404
    status, _ = _decrypt(http, key_id, token, tenant="t2")
    assert status == 404
    # Unknown version (encrypt and decrypt).
    status, body = _encrypt(http, key_id, b"x", version=7)
    assert status == 404 and "version" in body["error"]
    parsed = envelope_mod.parse_envelope(token)
    raw = json.loads(
        base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
    )
    raw["version"] = 7
    token_v7 = base64.urlsafe_b64encode(
        json.dumps(raw).encode()
    ).rstrip(b"=").decode()
    status, body = _decrypt(http, key_id, token_v7)
    assert status == 404 and "version" in body["error"]
    # An envelope naming another key_id is a 400, not a leak.
    status, body = _decrypt(http, other, token, tenant="t2")
    assert status == 400 and "key_id" in body["error"]


def test_http_revoked_is_409(http, env):
    key_id = _create(http)
    status, body = _encrypt(http, key_id, b"x")
    token = body["envelope"]
    status, _ = http.request(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t1", "reason": "r", "operator": "alice"},
        {"X-Operator-Id": "alice"},
    )
    assert status == 200
    status, _ = _encrypt(http, key_id, b"x")
    assert status == 409
    status, _ = _decrypt(http, key_id, token)
    assert status == 409


def test_http_provider_down_is_503_with_fixed_text(http, env):
    key_id = _create(http)
    env.set_faults({"unreachable": True})
    status, body = _encrypt(http, key_id, b"x")
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    env.clear_faults()
    status, body = _encrypt(http, key_id, b"x")
    assert status == 200
    token = body["envelope"]
    env.set_faults({"unreachable": True})
    status, body = _decrypt(http, key_id, token)
    assert status == 503
    assert body["error"] == "key management provider is unavailable"
    env.clear_faults()


# -- policy / audit ----------------------------------------------------------
def test_http_policy_and_audit(http, env):
    key_id = _create(http)
    # Allow everything but decrypt for alice; deny encrypt outright.
    status, _ = http.request(
        "PUT", "/v1/policy",
        {"tenant_id": "t1", "rules": [
            {"subject": "alice",
             "actions": ["create", "read", "rotate", "decrypt"],
             "effect": "allow"},
        ]},
        {"X-Operator-Id": "admin"},
    )
    assert status == 200
    # encrypt is not allowed by any rule -> default deny.
    status, body = _encrypt(http, key_id, b"x")
    assert status == 403
    # decrypt is allowed but there is nothing to open yet; encrypt as a
    # privileged operator first.
    status, body = _encrypt(http, key_id, b"x", operator="mallory")
    assert status == 403
    # Grant encrypt to alice, deny decrypt.
    status, _ = http.request(
        "PUT", "/v1/policy",
        {"tenant_id": "t1", "rules": [
            {"subject": "alice", "actions": ["encrypt", "decrypt"],
             "effect": "allow"},
            {"subject": "alice", "actions": ["decrypt"], "effect": "deny"},
        ]},
        {"X-Operator-Id": "admin"},
    )
    status, body = _encrypt(http, key_id, b"audited")
    assert status == 200
    token = body["envelope"]
    status, body = _decrypt(http, key_id, token)
    assert status == 403

    events = [e for e in env.audit_events() if e.action in ("encrypt", "decrypt")]
    outcomes = {(e.action, e.outcome) for e in events}
    assert ("encrypt", "rejected") in outcomes
    assert ("encrypt", "success") in outcomes
    assert ("decrypt", "rejected") in outcomes
    # Events carry metadata only: no plaintext, material or handle fields.
    for event in events:
        assert event.key_id == key_id
        projection = json.dumps(event.to_json())
        assert "audited" not in projection
        assert "wrapped" not in projection


def test_policy_accepts_new_actions(env):
    from keymgr.policy import validate_rules

    store = PolicyStore(env.data_dir, AuditLog(env.data_dir))
    store.put("t", validate_rules([
        {"subject": "s", "actions": ["encrypt", "decrypt"], "effect": "allow"},
    ]))
    assert store.is_allowed("t", "encrypt", "s")
    assert store.is_allowed("t", "decrypt", "s")
    assert not store.is_allowed("t", "read", "s")


# -- CLI ---------------------------------------------------------------------
def _cli_env(env):
    proc_env = dict(os.environ)
    proc_env["PYTHONPATH"] = TESTS_DIR + os.pathsep + REPO_ROOT
    return proc_env


def run_cli(env, *args, timeout=60):
    cmd = [sys.executable, "-m", "keymgr", "--data-dir", env.data_dir] + [
        str(a) for a in args
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, env=_cli_env(env), timeout=timeout
    )


@pytest.mark.parametrize("algorithm", ["AES256", "RSA2048"])
def test_cli_roundtrip(http, env, algorithm):
    created = run_cli(
        env, "gen", "--tenant-id", "t1", "--algorithm", algorithm,
        "--label", "k", "--operator", "alice",
    )
    assert created.returncode == 0, created.stderr
    key_id = json.loads(created.stdout)["key_id"]

    enc = run_cli(
        env, "encrypt", "--tenant-id", "t1", "--key-id", key_id,
        "--plaintext", b64(b"cli-secret"), "--aad", b64(b"ctx"),
        "--operator", "alice",
    )
    assert enc.returncode == 0, enc.stderr
    out = json.loads(enc.stdout)
    assert out["format"] == "keymgr-envelope-v1"

    dec = run_cli(
        env, "decrypt", "--tenant-id", "t1", "--key-id", key_id,
        "--envelope", out["envelope"], "--aad", b64(b"ctx"),
        "--operator", "alice",
    )
    assert dec.returncode == 0, dec.stderr
    assert json.loads(dec.stdout) == {"plaintext": b64(b"cli-secret")}

    # Wrong AAD -> exit 2 (HTTP 400).
    dec = run_cli(
        env, "decrypt", "--tenant-id", "t1", "--key-id", key_id,
        "--envelope", out["envelope"], "--aad", b64(b"nope"),
        "--operator", "alice",
    )
    assert dec.returncode == 2
    # Unknown key -> exit 4.
    enc = run_cli(
        env, "encrypt", "--tenant-id", "t1",
        "--key-id", "00000000-0000-4000-8000-000000000000",
        "--plaintext", b64(b"x"), "--operator", "alice",
    )
    assert enc.returncode == 4
    # Revoked -> exit 3.
    rev = run_cli(
        env, "revoke", "--tenant-id", "t1", "--key-id", key_id,
        "--reason", "r", "--operator", "alice",
    )
    assert rev.returncode == 0
    enc = run_cli(
        env, "encrypt", "--tenant-id", "t1", "--key-id", key_id,
        "--plaintext", b64(b"x"), "--operator", "alice",
    )
    assert enc.returncode == 3
    dec = run_cli(
        env, "decrypt", "--tenant-id", "t1", "--key-id", key_id,
        "--envelope", out["envelope"], "--aad", b64(b"ctx"),
        "--operator", "alice",
    )
    assert dec.returncode == 3


def test_cli_provider_down_exit_1(http, env):
    created = run_cli(
        env, "gen", "--tenant-id", "t1", "--algorithm", "AES256",
        "--label", "k", "--operator", "alice",
    )
    key_id = json.loads(created.stdout)["key_id"]
    env.set_faults({"unreachable": True})
    enc = run_cli(
        env, "encrypt", "--tenant-id", "t1", "--key-id", key_id,
        "--plaintext", b64(b"x"), "--operator", "alice",
    )
    assert enc.returncode == 1
    assert json.loads(enc.stderr)["error"] == (
        "key management provider is unavailable"
    )
    env.clear_faults()


# -- store layer (local provider) --------------------------------------------
def test_store_roundtrip_local_provider(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYMGR_PROVIDER", raising=False)
    from keymgr import provider as provider_mod

    provider_mod.reset_for_tests()
    data_dir = str(tmp_path / "data")
    store = KeyStore(data_dir, AuditLog(data_dir))
    record = store.create("t1", "AES256", "k")
    status, (token, version) = store.envelope_encrypt(
        record.key_id, "t1", None, b"plain", b"aad"
    )
    assert status == store.ENVELOPE_OK and version == 1
    parsed = envelope_mod.parse_envelope(token)
    status, plaintext = store.envelope_decrypt(
        record.key_id, "t1", parsed, b"aad"
    )
    assert plaintext == b"plain"
    provider_mod.reset_for_tests()
