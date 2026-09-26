"""POST /v1/keys/{key_id}/rewrap (envelope re-wrapping, format v1).

Covers: re-wrapping the SAME data key to a newer/older/current-default
version and across the AES256<->RSA2048 algorithm boundary with nonce, tag,
ciphertext, AAD and key_id bytes carried over unchanged and the new envelope
still decrypting to the same plaintext; the fixed ``{format, envelope}``
200 key order; pre-authorization parameter 400s (body shape, UUID4, base64,
target_version, envelope structure, key_id disagreement) that are never
audited while tenant-source failures still record tenant_conflict; the
``rewrap`` policy action (403 + rejected with key_id); 404 unknown/foreign
key and source/target version; 409 revoked and same-version; post-auth 400s
for algorithm mismatch, AAD mismatch and tampering (never audited); the
fixed-text 503 on a provider/material fault (never audited); and the
guarantee that plaintext, AAD, envelope tokens and data keys never reach the
audit ledger.

There is deliberately no CLI for rewrap (the HTTP entry point is the only
one), and it takes no Idempotency-Key.
"""

import base64
import json
import os
import urllib.error
import urllib.request

from test_sign_verify import b64, ext_stack, stack, _audit_events, _make_key  # noqa: F401


def _rotate(client, key_id, algorithm="RSA2048", tenant="t", key="rot-1"):
    status, body = client.call(
        "POST", "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": tenant, "algorithm": algorithm},
        headers={"Idempotency-Key": key},
    )
    assert status == 201, body
    return body


def _encrypt(client, key_id, plaintext, aad=None, version=None, tenant="t",
             idem="enc-1"):
    body = {"tenant_id": tenant, "plaintext": b64(plaintext)}
    if aad is not None:
        body["aad"] = b64(aad)
    if version is not None:
        body["version"] = version
    status, resp = client.call(
        "POST", "/v1/keys/%s/encrypt" % key_id, body,
        headers={"Idempotency-Key": idem},
    )
    assert status == 200, resp
    return resp["envelope"]


def _rewrap(client, key_id, envelope_token, target_version=None, aad=None,
            tenant="t", raw_body=None):
    if raw_body is not None:
        return client.call(
            "POST", "/v1/keys/%s/rewrap" % key_id, None, raw=raw_body
        )
    body = {"tenant_id": tenant, "envelope": envelope_token}
    if target_version is not None:
        body["target_version"] = target_version
    if aad is not None:
        body["aad"] = b64(aad)
    return client.call("POST", "/v1/keys/%s/rewrap" % key_id, body)


def _parse_envelope(token):
    return json.loads(base64.b64decode(token.encode("ascii")).decode("utf-8"))


def _build_envelope(payload):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return b64(raw.encode("utf-8"))


def _decrypt(client, key_id, envelope_token, aad=None, tenant="t"):
    body = {"tenant_id": tenant, "envelope": envelope_token}
    if aad is not None:
        body["aad"] = b64(aad)
    status, resp = client.call(
        "POST", "/v1/keys/%s/decrypt" % key_id, body
    )
    return status, resp


def _rewrap_events(stack):
    return [e for e in _audit_events(stack) if e.action == "rewrap"]


def _raw_post(client, path, body):
    """POST returning (status, body_text) so the JSON key order is visible."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        client.base + path, data=data, method="POST",
        headers={
            "X-Operator-Id": "alice",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


# -- happy path --------------------------------------------------------------
def test_rewrap_to_new_version_keeps_payload_bytes_and_order(stack):
    client = stack.client
    key_id = _make_key(client, algorithm="AES256")
    plaintext = b"same secret bytes"
    token = _encrypt(client, key_id, plaintext, idem="enc-1")
    before = _parse_envelope(token)
    _rotate(client, key_id, algorithm="AES256", key="rot-1")
    status, body = _rewrap(client, key_id, token, target_version=2)
    assert status == 200, body
    # Fixed key order and format constant.
    assert list(body.keys()) == ["format", "envelope"]
    assert body["format"] == "keymgr-envelope-v1"
    assert "operation_id" not in body
    after = _parse_envelope(body["envelope"])
    assert after["key_id"] == key_id
    assert after["version"] == 2
    # Payload-carrying bytes are untouched ...
    for field in ("key_id", "nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field], field
    # ... while version/algorithm/wrap material are rebuilt.
    assert after["wrap_nonce"] != before["wrap_nonce"]
    assert after["wrapped_key"] != before["wrapped_key"]
    # The rewrapped envelope authenticates and decrypts to the same plaintext.
    status, resp = _decrypt(client, key_id, body["envelope"])
    assert status == 200, resp
    assert base64.b64decode(resp["plaintext"]) == plaintext


def test_rewrap_default_target_is_current_version(stack):
    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"x", idem="enc-1")
    _rotate(client, key_id, key="rot-1")
    status, body = _rewrap(client, key_id, token)
    assert status == 200, body
    assert _parse_envelope(body["envelope"])["version"] == 2


def test_rewrap_back_to_an_older_version(stack):
    client = stack.client
    key_id = _make_key(client)
    token_v1 = _encrypt(client, key_id, b"old dek", idem="enc-1")
    _rotate(client, key_id, key="rot-1")
    token_v2 = _encrypt(client, key_id, b"new dek", idem="enc-2")
    status, body = _rewrap(client, key_id, token_v2, target_version=1)
    assert status == 200, body
    after = _parse_envelope(body["envelope"])
    assert after["version"] == 1
    before = _parse_envelope(token_v2)
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field]
    status, resp = _decrypt(client, key_id, body["envelope"])
    assert status == 200
    assert base64.b64decode(resp["plaintext"]) == b"new dek"
    # The old v1 envelope is untouched and still works.
    status, resp = _decrypt(client, key_id, token_v1)
    assert status == 200
    assert base64.b64decode(resp["plaintext"]) == b"old dek"


def test_rewrap_across_algorithms_both_directions(stack):
    client = stack.client
    key_id = _make_key(client, algorithm="AES256")
    token = _encrypt(client, key_id, b"cross alg", idem="enc-1")
    before = _parse_envelope(token)
    assert before["algorithm"] == "AES256"
    _rotate(client, key_id, algorithm="RSA2048", key="rot-1")
    status, body = _rewrap(client, key_id, token, target_version=2)
    assert status == 200, body
    after = _parse_envelope(body["envelope"])
    assert after["version"] == 2
    assert after["algorithm"] == "RSA2048"
    assert after["wrap"] == "RSA-OAEP-SHA256"
    assert "wrap_nonce" not in after
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert after[field] == before[field]
    status, resp = _decrypt(client, key_id, body["envelope"])
    assert status == 200
    assert base64.b64decode(resp["plaintext"]) == b"cross alg"
    # And back to the AES256 version.
    status, body2 = _rewrap(client, key_id, body["envelope"], target_version=1)
    assert status == 200, body2
    back = _parse_envelope(body2["envelope"])
    assert back["version"] == 1 and back["algorithm"] == "AES256"
    assert back["wrap"] == "AES-GCM" and "wrap_nonce" in back
    for field in ("nonce", "tag", "ciphertext", "aad"):
        assert back[field] == after[field]
    status, resp = _decrypt(client, key_id, body2["envelope"])
    assert status == 200
    assert base64.b64decode(resp["plaintext"]) == b"cross alg"


def test_rewrap_preserves_aad_and_response_key_order_is_wire_stable(stack):
    client = stack.client
    key_id = _make_key(client)
    aad = b"bound aad data"
    token = _encrypt(client, key_id, b"secret with aad", aad=aad, idem="e1")
    _rotate(client, key_id, key="rot-1")
    status, body = _rewrap(client, key_id, token, target_version=2, aad=aad)
    assert status == 200, body
    assert _parse_envelope(body["envelope"])["aad"] == b64(aad)
    status, resp = _decrypt(client, key_id, body["envelope"], aad=aad)
    assert status == 200
    assert base64.b64decode(resp["plaintext"]) == b"secret with aad"
    # Wire-level key order: format first, envelope second.
    status, text = _raw_post(
        client, "/v1/keys/%s/rewrap" % key_id,
        {"tenant_id": "t", "envelope": token, "target_version": 2,
         "aad": b64(aad)},
    )
    assert status == 200
    # Wire-level key order: format first, envelope second.
    assert list(json.loads(text).keys()) == ["format", "envelope"]


# -- parameter 400s (never audited) ------------------------------------------
def test_pre_auth_parameter_failures_are_400_and_not_audited(stack):
    client = stack.client
    key_id = _make_key(client)
    other = "11111111-1111-4111-8111-111111111111"
    good_token = _encrypt(client, key_id, b"x", idem="enc-1")
    good_env = _parse_envelope(good_token)

    cases = [
        # Corrupt JSON and non-object bodies.
        (None, b"{not json"),
        (None, b"[1,2,3]"),
        (None, b'"a string"'),
        # Missing/non-string envelope.
        ({"tenant_id": "t"}, None),
        ({"tenant_id": "t", "envelope": 7}, None),
        ({"tenant_id": "t", "envelope": ""}, None),
        # Envelope bad base64 and bad structure.
        ({"tenant_id": "t", "envelope": "a*b"}, None),
        ({"tenant_id": "t", "envelope": b64(b"{}")}, None),
        ({"tenant_id": "t",
          "envelope": b64(json.dumps({"format": "nope"}).encode())}, None),
        # Bad aad base64 / non-string aad.
        ({"tenant_id": "t", "envelope": good_token, "aad": "a*b"}, None),
        ({"tenant_id": "t", "envelope": good_token, "aad": 9}, None),
        # target_version must be a positive integer.
        ({"tenant_id": "t", "envelope": good_token, "target_version": 0},
         None),
        ({"tenant_id": "t", "envelope": good_token, "target_version": -2},
         None),
        ({"tenant_id": "t", "envelope": good_token, "target_version": "2"},
         None),
        ({"tenant_id": "t", "envelope": good_token, "target_version": True},
         None),
        # Envelope names another key.
        ({"tenant_id": "t",
          "envelope": _build_envelope(dict(good_env, key_id=other))}, None),
        # Extra/unknown field rejected like the other body contracts.
        ({"tenant_id": "t", "envelope": good_token, "bogus": 1}, None),
    ]
    for body, raw in cases:
        status, err = _rewrap(client, key_id, None, raw_body=raw) \
            if raw is not None else client.call(
                "POST", "/v1/keys/%s/rewrap" % key_id, body
            )
        assert status == 400, (body, raw, err)
        assert "error" in err and err["error"]
    # Malformed key_id in the path.
    status, err = _rewrap(client, "not-a-uuid", good_token)
    assert status == 400 and "key_id" in err["error"]
    # No rewrap event and no tenant_conflict from any of these.
    assert [
        e for e in _audit_events(stack)
        if e.action in ("rewrap", "tenant_conflict")
    ] == []


def test_tenant_source_failures_record_tenant_conflict(stack):
    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"x", idem="enc-1")
    # Missing tenant_id.
    status, err = client.call(
        "POST", "/v1/keys/%s/rewrap" % key_id, {"envelope": token}
    )
    assert status == 400 and "tenant_id" in err["error"]
    # Empty tenant_id.
    status, err = _rewrap(client, key_id, token, tenant="")
    assert status == 400 and "tenant_id" in err["error"]
    # Conflicting tenant sources (header vs body).
    status, err = client.call(
        "POST", "/v1/keys/%s/rewrap" % key_id,
        {"tenant_id": "t", "envelope": token},
        headers={"X-Tenant-Id": "other"},
    )
    assert status == 400 and "tenant_id" in err["error"]
    conflicts = [
        e for e in stack.audit._read_all()
        if e.action == "tenant_conflict"
    ]
    assert len(conflicts) == 3
    # Still no rewrap event.
    assert _rewrap_events(stack) == []


# -- authorization ------------------------------------------------------------
def test_policy_denial_is_403_and_audited_with_key_id(stack):
    from keymgr.policy import Rule

    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"x", idem="enc-1")
    _rotate(client, key_id, key="rot-1")
    stack.policies.put(
        "t", [Rule(subject="alice", actions=["rewrap"], effect="deny")]
    )
    status, body = _rewrap(client, key_id, token, target_version=2)
    assert status == 403, body
    rejected = _rewrap_events(stack)
    assert len(rejected) == 1
    assert rejected[0].outcome == "rejected"
    assert rejected[0].key_id == key_id


# -- post-auth business outcomes ---------------------------------------------
def test_unknown_foreign_key_and_versions_are_404_and_audited(stack):
    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"x", idem="enc-1")
    _rotate(client, key_id, key="rot-1")
    unknown = "00000000-0000-4000-8000-000000000000"
    # Unknown key (envelope key_id must match the path, so craft one).
    env = _parse_envelope(token)
    env_unknown = _build_envelope(dict(env, key_id=unknown))
    status, _ = _rewrap(client, unknown, env_unknown, target_version=2)
    assert status == 404
    # Cross-tenant access looks identical.
    status, _ = _rewrap(client, key_id, token, target_version=2,
                        tenant="other")
    assert status == 404
    # Unknown target version.
    status, _ = _rewrap(client, key_id, token, target_version=99)
    assert status == 404
    # Unknown source version named inside an otherwise-valid envelope.
    env_bad_src = _build_envelope(dict(env, version=98))
    status, _ = _rewrap(client, key_id, env_bad_src, target_version=2)
    assert status == 404
    rejected_t = [e for e in _rewrap_events(stack) if e.outcome == "rejected"]
    assert [e.key_id for e in rejected_t] == [unknown, key_id, key_id]
    rejected_other = [
        e for e in stack.audit.query("other", limit=100).events
        if e.action == "rewrap"
    ]
    assert len(rejected_other) == 1
    assert rejected_other[0].outcome == "rejected"
    assert rejected_other[0].key_id == key_id


def test_revoked_key_is_409_including_source_and_target(stack):
    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"x", idem="enc-1")
    _rotate(client, key_id, key="rot-1")
    status, _ = client.call(
        "POST", "/v1/keys/%s/revoke" % key_id,
        {"tenant_id": "t", "reason": "done", "operator": "alice"},
    )
    assert status == 200
    status, body = _rewrap(client, key_id, token, target_version=2)
    assert status == 409, body
    rejected = _rewrap_events(stack)
    assert len(rejected) == 1 and rejected[0].key_id == key_id


def test_same_version_target_is_409_explicit_and_default_current(stack):
    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"x", idem="enc-1")
    # Envelope already on the current version, explicit and default alike.
    status, body = _rewrap(client, key_id, token, target_version=1)
    assert status == 409, body
    status, body = _rewrap(client, key_id, token)
    assert status == 409, body
    # After rotation, re-wrapping back onto the envelope's own version too.
    _rotate(client, key_id, key="rot-1")
    token_v2 = _encrypt(client, key_id, b"y", idem="enc-2")
    status, _ = _rewrap(client, key_id, token_v2)
    assert status == 409
    rejected = _rewrap_events(stack)
    assert len(rejected) == 3
    assert all(e.outcome == "rejected" for e in rejected)


def test_algorithm_mismatch_is_post_auth_400_and_not_audited(stack):
    client = stack.client
    rsa_id = _make_key(client, algorithm="RSA2048")
    aes_id = _make_key(client, algorithm="AES256")
    # A structurally-valid AES256 envelope that claims the RSA key's id and
    # current version: structure passes, authorization passes, then the
    # stored version's algorithm disagrees -> 400, no event.
    aes_env = _parse_envelope(_encrypt(client, aes_id, b"x", idem="e-aes"))
    forged = _build_envelope(dict(aes_env, key_id=rsa_id, version=1))
    status, body = _rewrap(client, rsa_id, forged, target_version=1)
    assert status == 400, body
    assert "algorithm" in body["error"]
    assert _rewrap_events(stack) == []


def test_aad_mismatch_and_tampered_envelope_are_400_and_not_audited(stack):
    client = stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"secret", aad=b"the aad", idem="e1")
    _rotate(client, key_id, key="rot-1")
    # Request AAD disagrees with the sealed one.
    status, body = _rewrap(
        client, key_id, token, target_version=2, aad=b"different aad"
    )
    assert status == 400 and "aad" in body["error"]
    # Tamper with the ciphertext of an otherwise-valid envelope.
    env = _parse_envelope(token)
    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[0] ^= 0x01
    env["ciphertext"] = b64(bytes(ct))
    status, body = _rewrap(
        client, key_id, _build_envelope(env), target_version=2, aad=b"the aad"
    )
    assert status == 400 and "authenticate" in body["error"]
    # Tamper with the wrapped key: unwrap against the real KEK fails.
    env2 = _parse_envelope(token)
    wk = bytearray(base64.b64decode(env2["wrapped_key"]))
    wk[0] ^= 0x01
    env2["wrapped_key"] = b64(bytes(wk))
    status, body = _rewrap(
        client, key_id, _build_envelope(env2), target_version=2,
        aad=b"the aad",
    )
    assert status == 400 and "authenticate" in body["error"]
    assert _rewrap_events(stack) == []


# -- provider failures -------------------------------------------------------
def test_provider_failure_is_fixed_503_and_not_audited(ext_stack):
    client = ext_stack.client
    key_id = _make_key(client)
    token = _encrypt(client, key_id, b"hi", idem="enc-1")
    _rotate(client, key_id, key="rot-1")
    with open(ext_stack.faults_path, "w") as fh:
        json.dump({"fail": {"export_material": True}}, fh)
    status, body = _rewrap(client, key_id, token, target_version=2)
    assert status == 503
    assert body == {"error": "key management provider is unavailable"}
    assert [
        e for e in _audit_events(ext_stack) if e.action == "rewrap"
    ] == []


# -- audit content ------------------------------------------------------------
def test_success_is_audited_and_never_leaks_material(stack):
    client = stack.client
    key_id = _make_key(client)
    plaintext = b"ledger-secret-marker"
    aad = b"ledger-aad-marker"
    token = _encrypt(client, key_id, plaintext, aad=aad, idem="e1")
    _rotate(client, key_id, key="rot-1")
    status, body = _rewrap(
        client, key_id, token, target_version=2, aad=aad
    )
    assert status == 200
    events = _rewrap_events(stack)
    assert len(events) == 1
    assert events[0].outcome == "success"
    assert events[0].key_id == key_id
    raw = open(os.path.join(stack.data_dir, "audit.log"), "rb").read()
    assert b"ledger-secret-marker" not in raw
    assert b"ledger-aad-marker" not in raw
    assert token.encode() not in raw
    assert body["envelope"].encode() not in raw
