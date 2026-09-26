"""Tamper-evident audit ledger chain.

The first load validates any pre-chain (legacy) lines and anchors their byte
count and HMAC in ``audit-anchor.json`` (0600, temp-file fsync + rename);
later lines carry ``prev_mac``/``mac`` chaining back to that anchor. Every
read and append re-verifies anchor, prefix and full chain under the file
lock: corruption raises LedgerError, is never skipped and never re-signed.
HTTP answers a fixed 500 ``{"error":"audit ledger is unavailable"}``, the CLI
prints the same body and exits 1, both with zero side effects.
"""

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
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
from keymgr.policy import PolicyStore
from keymgr.server import make_handler
from keymgr.store import KeyStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FIELDS = ["event_id", "tenant_id", "action", "key_id", "outcome",
          "timestamp", "seq"]
CHAIN_FIELDS = FIELDS + ["prev_mac", "mac"]


def _secret(data_dir):
    with open(os.path.join(data_dir, "audit.secret"), "rb") as fh:
        return fh.read()


def _legacy_mac(data_dir, raw):
    return hmac.new(
        _secret(data_dir), b"legacy\0" + raw, hashlib.sha256
    ).hexdigest()


def _event_mac(data_dir, obj):
    payload = {k: obj[k] for k in FIELDS + ["prev_mac"]}
    raw = json.dumps(payload, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hmac.new(_secret(data_dir), raw, hashlib.sha256).hexdigest()


def _legacy_line(seq, event_id="ev-%d", tenant="t1"):
    return json.dumps({
        "event_id": event_id % seq if "%d" in event_id else event_id,
        "tenant_id": tenant,
        "action": "create",
        "key_id": None,
        "outcome": "success",
        "timestamp": "2026-09-26T00:00:00+00:00",
        "seq": seq,
    }, separators=(",", ":"))


def _write_legacy(data_dir, lines):
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    with open(os.path.join(data_dir, "audit.log"), "wb") as fh:
        fh.write(raw)
    return raw


def _log_bytes(data_dir):
    with open(os.path.join(data_dir, "audit.log"), "rb") as fh:
        return fh.read()


def _log_lines(data_dir):
    return [json.loads(line) for line in
            _log_bytes(data_dir).decode("utf-8").splitlines()]


def _append(ledger, event_id, tenant="t1", action="create"):
    return ledger.append(
        ledger.new_event(tenant, action, None, "success", event_id=event_id)
    )


# -- anchoring ---------------------------------------------------------------


def test_first_load_of_empty_dir_creates_anchor(tmp_path):
    data_dir = str(tmp_path)
    events = AuditLog(data_dir)._read_all()
    assert events == []
    anchor_path = os.path.join(data_dir, "audit-anchor.json")
    with open(anchor_path, "rb") as fh:
        raw = fh.read()
    assert not raw.endswith(b"\n")
    assert raw.decode("utf-8") == json.dumps(
        {
            "schema_version": 1,
            "legacy_bytes": 0,
            "legacy_mac": _legacy_mac(data_dir, b""),
        },
        separators=(",", ":"),
    )
    mode = stat.S_IMODE(os.stat(anchor_path).st_mode)
    assert mode == 0o600


def test_legacy_log_validated_then_anchored(tmp_path):
    data_dir = str(tmp_path)
    raw = _write_legacy(data_dir, [_legacy_line(1), _legacy_line(2)])
    events = AuditLog(data_dir)._read_all()
    assert [e.seq for e in events] == [1, 2]
    with open(os.path.join(data_dir, "audit-anchor.json"), "rb") as fh:
        anchor = json.load(fh)
    assert list(anchor.keys()) == ["schema_version", "legacy_bytes",
                                   "legacy_mac"]
    assert anchor["schema_version"] == 1
    assert anchor["legacy_bytes"] == len(raw)
    assert anchor["legacy_mac"] == _legacy_mac(data_dir, raw)


def test_appended_lines_are_chained(tmp_path):
    data_dir = str(tmp_path)
    raw = _write_legacy(data_dir, [_legacy_line(1)])
    ledger = AuditLog(data_dir)
    _append(ledger, "ev-2")
    _append(ledger, "ev-3", tenant="t-租户")

    lines = _log_lines(data_dir)
    assert len(lines) == 3
    # The legacy line is untouched byte-for-byte.
    assert _log_bytes(data_dir).startswith(raw)
    legacy_mac = _legacy_mac(data_dir, raw)
    for i, obj in enumerate(lines[1:], start=2):
        assert list(obj.keys()) == CHAIN_FIELDS
        assert obj["seq"] == i
        assert obj["prev_mac"] == (legacy_mac if i == 2
                                   else lines[i - 2]["mac"])
        assert obj["mac"] == _event_mac(data_dir, obj)
    # Non-ASCII tenant ids are written as-is (UTF-8, not \u escapes).
    assert "t-租户".encode("utf-8") in _log_bytes(data_dir)
    # A fresh instance (another "process") verifies the whole chain.
    assert [e.event_id for e in AuditLog(data_dir)._read_all()] == [
        "ev-1", "ev-2", "ev-3",
    ]


def test_idempotent_reappend_does_not_duplicate(tmp_path):
    data_dir = str(tmp_path)
    ledger = AuditLog(data_dir)
    _append(ledger, "ev-1")
    event = _append(ledger, "ev-1")
    assert event.seq == 1
    assert len(_log_lines(data_dir)) == 1


# -- legacy corruption -------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "\n",                                        # empty line
        _legacy_line(1) + "\n\n",                    # empty line after
        "{not json\n",                               # bad JSON
        "[1,2]\n",                                   # not an object
        _legacy_line(1)[:-1] + ',"extra":1}\n',      # unknown key
        json.dumps({"event_id": "e", "tenant_id": "t", "action": "create",
                    "key_id": None, "outcome": "success",
                    "timestamp": "x", "seq": True}) + "\n",   # bool seq
        json.dumps({"event_id": "e", "tenant_id": 5, "action": "create",
                    "key_id": None, "outcome": "success",
                    "timestamp": "x", "seq": 1}) + "\n",      # bad type
        json.dumps({"event_id": "e", "tenant_id": "t", "action": "create",
                    "key_id": None, "outcome": "success",
                    "timestamp": "x", "seq": 0}) + "\n",      # seq not >= 1
        _legacy_line(2) + "\n",                      # seq not starting at 1
        _legacy_line(1) + "\n" + _legacy_line(1, "other") + "\n",  # seq gap
        _legacy_line(1, "dup") + "\n" + _legacy_line(2, "dup") + "\n",
    ],
    ids=[
        "empty-line", "trailing-empty-line", "bad-json", "not-object",
        "unknown-key", "bool-seq", "bad-tenant-type", "seq-zero",
        "seq-not-one", "seq-gap", "dup-event-id",
    ],
)
def test_corrupt_legacy_log_rejected(tmp_path, content):
    data_dir = str(tmp_path)
    with open(os.path.join(data_dir, "audit.log"), "w",
              encoding="utf-8") as fh:
        fh.write(content)
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()
    # No anchor is created for a corrupt legacy log.
    assert not os.path.exists(os.path.join(data_dir, "audit-anchor.json"))


# -- chain tampering ---------------------------------------------------------


def _seed_chain(data_dir):
    ledger = AuditLog(data_dir)
    _append(ledger, "ev-1")
    _append(ledger, "ev-2")
    return ledger


def test_tampered_line_detected_and_nothing_resigned(tmp_path):
    data_dir = str(tmp_path)
    _seed_chain(data_dir)
    before = _log_bytes(data_dir)
    with open(os.path.join(data_dir, "audit-anchor.json"), "rb") as fh:
        anchor_before = fh.read()
    # Flip one byte inside the first chained line.
    pos = before.index(b'"success"')
    tampered = before[:pos] + b"X" + before[pos + 1:]
    with open(os.path.join(data_dir, "audit.log"), "wb") as fh:
        fh.write(tampered)
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()
    with pytest.raises(LedgerError):
        AuditLog(data_dir).append(
            AuditLog(data_dir).new_event("t1", "create", None, "success")
        )
    # The failed verification neither rewrites the log nor the anchor.
    assert _log_bytes(data_dir) == tampered
    with open(os.path.join(data_dir, "audit-anchor.json"), "rb") as fh:
        assert fh.read() == anchor_before


def test_truncated_log_detected(tmp_path):
    data_dir = str(tmp_path)
    _seed_chain(data_dir)
    raw = _log_bytes(data_dir)
    with open(os.path.join(data_dir, "audit.log"), "wb") as fh:
        fh.write(raw[:-10])
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_forged_appended_line_detected(tmp_path):
    data_dir = str(tmp_path)
    _seed_chain(data_dir)
    forged = json.dumps({
        "event_id": "evil", "tenant_id": "t1", "action": "create",
        "key_id": None, "outcome": "success",
        "timestamp": "2026-09-26T00:00:00+00:00", "seq": 3,
        "prev_mac": "0" * 64, "mac": "0" * 64,
    }, separators=(",", ":"))
    with open(os.path.join(data_dir, "audit.log"), "a",
              encoding="utf-8") as fh:
        fh.write(forged + "\n")
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_deleted_anchor_detected(tmp_path):
    data_dir = str(tmp_path)
    _seed_chain(data_dir)
    os.unlink(os.path.join(data_dir, "audit-anchor.json"))
    # Chained lines are not valid legacy lines: re-anchoring is refused.
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()
    assert not os.path.exists(os.path.join(data_dir, "audit-anchor.json"))


def test_corrupt_anchor_detected(tmp_path):
    data_dir = str(tmp_path)
    _seed_chain(data_dir)
    anchor_path = os.path.join(data_dir, "audit-anchor.json")
    with open(anchor_path, "w", encoding="utf-8") as fh:
        fh.write('{"schema_version":1,"legacy_bytes":0,"legacy_mac":"'
                 + "0" * 64 + '"}')
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


def test_tampered_legacy_prefix_detected(tmp_path):
    data_dir = str(tmp_path)
    raw = _write_legacy(data_dir, [_legacy_line(1), _legacy_line(2)])
    ledger = AuditLog(data_dir)
    _append(ledger, "ev-3")
    tampered = raw.replace(b"create", b"CREATE", 1)
    rest = _log_bytes(data_dir)[len(raw):]
    with open(os.path.join(data_dir, "audit.log"), "wb") as fh:
        fh.write(tampered + rest)
    with pytest.raises(LedgerError):
        AuditLog(data_dir)._read_all()


# -- HTTP / CLI surfaces -----------------------------------------------------


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
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
    handler = make_handler(store, policies, coordinator, op_store,
                           artifact_store)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    yield types.SimpleNamespace(data_dir=data_dir, base=base)
    httpd.shutdown()
    provider_mod.reset_for_tests()


def _call(stack, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-Operator-Id": "alice"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(stack.base + path, data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _corrupt_log(data_dir):
    path = os.path.join(data_dir, "audit.log")
    with open(path, "rb") as fh:
        raw = bytearray(fh.read())
    raw[len(raw) // 2] ^= 0x01
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


_KEY_FILE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$"
)


def _key_files(data_dir):
    return sorted(n for n in os.listdir(data_dir) if _KEY_FILE_RE.match(n))


def test_http_ledger_failure_is_fixed_500(stack):
    status, body = _call(stack, "POST", "/v1/keys",
                         {"tenant_id": "t1", "algorithm": "AES256",
                          "label": "k"})
    assert status == 201
    _corrupt_log(stack.data_dir)
    before = _key_files(stack.data_dir)

    status, body = _call(stack, "GET", "/v1/audit?tenant_id=t1")
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}

    status, body = _call(stack, "POST", "/v1/keys",
                         {"tenant_id": "t1", "algorithm": "AES256",
                          "label": "k2"})
    assert status == 500
    assert body == {"error": "audit ledger is unavailable"}
    # Zero side effects: no new key file, log and anchor untouched.
    assert _key_files(stack.data_dir) == before


def _run_cli(data_dir, *args):
    env = dict(os.environ)
    env.pop("KEYMGR_PROVIDER", None)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", data_dir]
        + [str(a) for a in args],
        capture_output=True, text=True, env=env, timeout=60,
    )


def _cli_json(proc):
    for stream in (proc.stdout, proc.stderr):
        text = stream.strip()
        if text.startswith("{"):
            return json.loads(text)
    raise AssertionError("no JSON body: rc=%d out=%r err=%r"
                         % (proc.returncode, proc.stdout, proc.stderr))


def test_cli_ledger_failure_is_fixed_body_exit_1(tmp_path):
    data_dir = str(tmp_path)
    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k",
                    "--operator", "alice")
    assert proc.returncode == 0, proc.stderr
    _corrupt_log(data_dir)
    before = _key_files(data_dir)

    proc = _run_cli(data_dir, "audit", "--tenant-id", "t1",
                    "--operator", "alice")
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}

    proc = _run_cli(data_dir, "gen", "--tenant-id", "t1",
                    "--algorithm", "AES256", "--label", "k2",
                    "--operator", "alice")
    assert proc.returncode == 1
    assert _cli_json(proc) == {"error": "audit ledger is unavailable"}
    assert _key_files(data_dir) == before
