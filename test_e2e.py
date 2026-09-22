"""End-to-end HTTP + CLI smoke test for batch-rotate contracts."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DATA = tempfile.mkdtemp(prefix="keymgr-e2e-")


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


PORT = free_port()
BASE = "http://127.0.0.1:%d" % PORT
ENV = dict(os.environ, KEYMGR_DATA_DIR=DATA)


def req(method, path, body=None, headers=None, expect=None):
    r = urllib.request.Request(BASE + path, method=method)
    r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(r, data=data) as resp:
            status, payload = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status, payload = e.code, json.loads(e.read())
    if expect is not None:
        assert status == expect, (method, path, status, payload)
    return status, payload


def cli(*args, expect=0):
    out = subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", DATA] + list(args),
        capture_output=True, text=True, env=ENV)
    assert out.returncode == expect, (args, out.returncode, out.stderr)
    return json.loads(out.stdout) if out.stdout.strip() else None


def main():
    from keymgr.server import serve
    threading.Thread(
        target=serve, kwargs={"host": "127.0.0.1", "port": PORT,
                              "data_dir": DATA}, daemon=True).start()
    import time
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/v1/audit?tenant_id=x",
                                   timeout=1)
            break
        except Exception:
            time.sleep(0.1)

    H = {"X-Operator-Id": "alice", "X-Tenant-Id": "t"}
    _, k1 = req("POST", "/v1/keys",
                {"tenant_id": "t", "algorithm": "AES256", "label": "a"},
                H, expect=201)
    _, k2 = req("POST", "/v1/keys",
                {"tenant_id": "t", "algorithm": "RSA2048", "label": "b"},
                H, expect=201)
    items = [{"key_id": k1["key_id"], "algorithm": "AES256"},
             {"key_id": k2["key_id"], "algorithm": "RSA2048"}]

    # Batch-rotate 201, items in request order.
    s, body = req("POST", "/v1/keys/batch-rotate",
                  {"tenant_id": "t", "items": items},
                  dict(H, **{"Idempotency-Key": "batch-1"}), expect=201)
    op_id = body["operation_id"]
    assert [i["key_id"] for i in body["items"]] == [k1["key_id"],
                                                    k2["key_id"]]
    assert all(i["version"] == 2 for i in body["items"])

    # Same key + same binding replays verbatim, no second event.
    s2, body2 = req("POST", "/v1/keys/batch-rotate",
                    {"tenant_id": "t", "items": items},
                    dict(H, **{"Idempotency-Key": "batch-1"}), expect=201)
    assert body2 == body
    # Same key, different binding -> 409 naming the operation.
    s3, body3 = req("POST", "/v1/keys/batch-rotate",
                    {"tenant_id": "t", "items": [items[0]]},
                    dict(H, **{"Idempotency-Key": "batch-1"}), expect=409)
    assert body3["operation_id"] == op_id

    # GET operation replays the terminal state.
    _, op = req("GET", "/v1/operations/" + op_id, None, H, expect=200)
    assert op["status"] == "succeeded" and op["http_status"] == 201
    assert op["response"]["items"] == body["items"]

    # Exactly one batch_rotate audit event, key_id null.
    _, aud = req("GET", "/v1/audit?action=batch_rotate", None, H, expect=200)
    assert len(aud["events"]) == 1, aud
    assert aud["events"][0]["key_id"] is None
    assert aud["events"][0]["event_id"] == op_id

    # Reads show committed versions.
    _, cur = req("GET", "/v1/keys/%s/current" % k1["key_id"], None, H,
                 expect=200)
    assert cur["version"] == 2

    # CLI batch-rotate works and shares the records.
    out = cli("batch-rotate", "--tenant-id", "t", "--operator", "alice",
              "--idempotency-key", "batch-2",
              "--items", json.dumps(items))
    assert all(i["version"] == 3 for i in out["items"]), out
    # CLI replay with the same key.
    out2 = cli("batch-rotate", "--tenant-id", "t", "--operator", "alice",
               "--idempotency-key", "batch-2",
               "--items", json.dumps(items))
    assert out2 == out
    _, aud = req("GET", "/v1/audit?action=batch_rotate", None, H, expect=200)
    assert len(aud["events"]) == 2, aud
    print("e2e HTTP + CLI batch-rotate contracts OK")

    shutil.rmtree(DATA)


if __name__ == "__main__":
    main()
