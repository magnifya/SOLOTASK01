"""End-to-end checks for idempotent rotate/import/restore."""
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import uuid
from http.server import ThreadingHTTPServer

from keymgr.audit import AuditLog
from keymgr import operations as ops_mod
from keymgr.operations import (
    OperationStore, OperationRecord, STATUS_SUCCEEDED, STATUS_FAILED,
    STATUS_CONFLICT, STATUS_PENDING,
)
from keymgr.policy import PolicyStore
from keymgr import restore as restore_mod
from keymgr.server import make_handler
from keymgr.store import KeyStore
from keymgr.crypto import SUPPORTED_ALGORITHMS

ROOT = "/tmp/keymgr_idem_test"
ROOT_B = "/tmp/keymgr_idem_test_b"
ROOT_C = "/tmp/keymgr_idem_test_c"
ROOT_D = "/tmp/keymgr_idem_test_d"
PORT = 18099
PORT_B = 18100
PORT_C = 18101
PORT_D = 18102

failures = []


def check(name, cond, detail=""):
    if cond:
        print("PASS", name)
    else:
        print("FAIL", name, detail)
        failures.append(name)


def http(method, path, body=None, headers=None, raw=None):
    return http_to(PORT, method, path, body, headers, raw)


def http_dup_header(path, header, values, body):
    """Send a request with a genuinely duplicated header via raw socket."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    conn.putrequest("POST", path)
    conn.putheader("Content-Type", "application/json")
    raw = json.dumps(body).encode()
    conn.putheader("Content-Length", str(len(raw)))
    conn.putheader("X-Operator-Id", "alice")
    for v in values:
        conn.putheader(header, v)
    conn.endheaders()
    conn.send(raw)
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


def http_b(method, path, body=None, headers=None):
    return http_to(PORT_B, method, path, body, headers)


def http_c(method, path, body=None, headers=None):
    return http_to(PORT_C, method, path, body, headers)


def wait_for_port(port, timeout=10.0):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server on port %d did not start" % port)


def http_to(port, method, path, body=None, headers=None, raw=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    data = raw if raw is not None else (
        json.dumps(body).encode() if body is not None else None
    )
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Operator-Id", "alice")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    shutil.rmtree(ROOT, ignore_errors=True)
    shutil.rmtree(ROOT_B, ignore_errors=True)
    shutil.rmtree(ROOT_C, ignore_errors=True)
    shutil.rmtree(ROOT_D, ignore_errors=True)
    shutil.rmtree(ROOT_D + "-restore", ignore_errors=True)
    audit_log = AuditLog(ROOT)
    store = KeyStore(ROOT, audit_log)
    policies = PolicyStore(ROOT, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    operations = OperationStore(ROOT, store, policies, coordinator)
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", PORT),
        make_handler(store, policies, coordinator, operations),
    )
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    # Second deployment runs in a real separate process (the actual
    # disaster-recovery shape): the local provider singleton is per-process,
    # so two data dirs must never share one.
    server_b = subprocess.Popen(
        [sys.executable, "-m", "keymgr", "--data-dir", ROOT_B,
         "serve", "--host", "127.0.0.1", "--port", str(PORT_B)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_port(PORT_B)
    # A third clean deployment for tenant restore (the import test already
    # populated B, and a restore must not collide with those keys).
    server_c = subprocess.Popen(
        [sys.executable, "-m", "keymgr", "--data-dir", ROOT_C,
         "serve", "--host", "127.0.0.1", "--port", str(PORT_C)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_port(PORT_C)
    time.sleep(0.2)

    tenant = "tenant-e2e"
    # Create an AES key (non-idempotent endpoint).
    s, r = http("POST", "/v1/keys",
                {"tenant_id": tenant, "algorithm": "AES256", "label": "k"})
    check("create 201", s == 201, (s, r))
    key_id = r["key_id"]

    # --- header validation: missing / illegal / duplicate, no side effects
    events_before = count_rotate_events(tenant, key_id)
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "AES256"})
    check("missing Idempotency-Key -> 400", s == 400 and "error" in r
          and "operation_id" not in r, (s, r))
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "AES256"},
                {"Idempotency-Key": "bad key!"})
    check("illegal Idempotency-Key -> 400", s == 400, (s, r))
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "AES256"},
                {"Idempotency-Key": ""})
    check("empty Idempotency-Key -> 400", s == 400, (s, r))
    s, r = http_dup_header("/v1/keys/%s/rotate" % key_id, "Idempotency-Key",
                           ["k1", "k2"],
                           {"tenant_id": tenant, "algorithm": "AES256"})
    check("duplicate Idempotency-Key -> 400", s == 400, (s, r))
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "AES256"},
                {"Idempotency-Key": "x" * 129})
    check("129-char Idempotency-Key -> 400", s == 400, (s, r))
    check("validation failures have no side effects",
          count_rotate_events(tenant, key_id) == events_before)

    # --- successful rotate + replay
    idem = "rotate-1"
    body = {"tenant_id": tenant, "algorithm": "AES256"}
    s, r1 = http("POST", "/v1/keys/%s/rotate" % key_id, body,
                 {"Idempotency-Key": idem})
    check("rotate 201 with operation_id",
          s == 201 and r1.get("version") == 2
          and is_uuid(r1.get("operation_id")), (s, r1))
    op_id = r1["operation_id"]
    check("success body has no extra keys",
          set(r1) == {"key_id", "version", "algorithm", "public_key",
                      "operation_id"}, sorted(r1))
    s, r2 = http("POST", "/v1/keys/%s/rotate" % key_id, body,
                 {"Idempotency-Key": idem})
    check("replay same binding -> same 201",
          s == 201 and r2 == r1, (r1, r2))
    s, cur = http("GET", "/v1/keys/%s/current?tenant_id=%s" % (key_id, tenant))
    check("replay did not add a version", cur["version"] == 2, cur)
    check("replay reuses one audit event",
          count_events(tenant) and
          sum(1 for e in read_events()
              if e["tenant_id"] == tenant and e["action"] == "rotate"
              and e["event_id"] == op_id) == 1)

    # --- same binding, different body -> 409 naming existing operation
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "RSA2048"},
                {"Idempotency-Key": idem})
    check("same key different body -> 409",
          s == 409 and r.get("operation_id") == op_id
          and set(r) == {"error", "operation_id"}, (s, r))
    s, cur = http("GET", "/v1/keys/%s/current?tenant_id=%s" % (key_id, tenant))
    check("409 changed nothing", cur["version"] == 2, cur)

    # --- GET operation status and tenant/operator isolation
    s, r = http("GET", "/v1/operations/%s?tenant_id=%s" % (op_id, tenant))
    check("GET operation 200",
          s == 200 and r["status"] == STATUS_SUCCEEDED
          and r["http_status"] == 201 and r["response"] == r1
          and r["tenant_id"] == tenant and r["operation_id"] == op_id, (s, r))
    s, r = http("GET", "/v1/operations/%s?tenant_id=other" % op_id)
    check("cross-tenant GET -> 404", s == 404, (s, r))
    s, r = http("GET", "/v1/operations/%s?tenant_id=%s" % (op_id, tenant),
                headers={"X-Operator-Id": "bob"})
    check("cross-operator GET -> 404", s == 404, (s, r))
    s, r = http("GET", "/v1/operations/%s?tenant_id=%s"
                % (str(uuid.uuid4()), tenant))
    check("unknown operation -> 404", s == 404, (s, r))
    s, r = http("GET", "/v1/operations/not-a-uuid?tenant_id=%s" % tenant)
    check("malformed operation id -> 404", s == 404, (s, r))
    s, r = http("GET", "/v1/operations/%s" % op_id)
    check("GET operation requires tenant -> 400", s == 400, (s, r))

    # --- policy denial is a stored 403 and replays with the same event
    from keymgr.policy import Rule
    policies.put(tenant, [Rule(subject="alice", actions=["rotate"],
                               effect="deny")])
    idem2 = "rotate-denied"
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "AES256"},
                {"Idempotency-Key": idem2})
    check("denied rotate -> 403 stored as failed with operation_id",
          s == 403 and set(r) == {"error", "operation_id"}, (s, r))
    deny_op = r["operation_id"]
    s, r2 = http("POST", "/v1/keys/%s/rotate" % key_id,
                 {"tenant_id": tenant, "algorithm": "AES256"},
                 {"Idempotency-Key": idem2})
    check("denied rotate replays 403", s == 403 and r2 == r, (r, r2))
    check("denial reuses one rejected event",
          sum(1 for e in read_events()
              if e["event_id"] == deny_op) == 1)
    s, st = http("GET", "/v1/operations/%s?tenant_id=%s" % (deny_op, tenant))
    check("GET shows failed/403",
          st["status"] == STATUS_FAILED and st["http_status"] == 403, st)
    policies.delete(tenant)

    # --- unknown key rotate -> stored 404 (CLI exit 4), replay identical
    unknown = str(uuid.uuid4())
    idem3 = "rotate-unknown"
    s, r = http("POST", "/v1/keys/%s/rotate" % unknown,
                {"tenant_id": tenant, "algorithm": "AES256"},
                {"Idempotency-Key": idem3})
    check("unknown key -> 404 + operation_id",
          s == 404 and set(r) == {"error", "operation_id"}, (s, r))
    unknown_op = r["operation_id"]
    s, r2 = http("POST", "/v1/keys/%s/rotate" % unknown,
                 {"tenant_id": tenant, "algorithm": "AES256"},
                 {"Idempotency-Key": idem3})
    check("unknown-key 404 replays", s == 404 and r2 == r, (r, r2))

    # --- pending record shape via GET (fabricated pending file)
    pend_id = str(uuid.uuid4())
    pend = OperationRecord(
        operation_id=pend_id, idempotency_key="x", tenant_id=tenant,
        operator="alice", path="/v1/restore",
        request_fingerprint="0" * 64,
    )
    operations._persist(pend)
    s, r = http("GET", "/v1/operations/%s?tenant_id=%s" % (pend_id, tenant))
    check("pending GET has null http_status/response",
          s == 200 and r["status"] == STATUS_PENDING
          and r["http_status"] is None and r["response"] is None, r)
    os.unlink(operations._op_path(pend_id))

    # --- import idempotency: export then import into the DR deployment.
    # A bundle carries its original key_id and belongs to one tenant, so the
    # import requests that same tenant (in the second deployment's dir).
    s, exp = http("POST", "/v1/keys/%s/export" % key_id,
                  {"tenant_id": tenant, "passphrase": "pw"})
    check("export 200", s == 200, (s, exp))
    ibody = {"tenant_id": tenant, "passphrase": "pw", "bundle": exp["bundle"]}
    s, r = http_b("POST", "/v1/keys/import", ibody,
                  {"Idempotency-Key": "imp-1"})
    check("import 201 + operation_id",
          s == 201 and r["key_id"] == key_id and is_uuid(r["operation_id"]),
          (s, r))
    imp_op = r["operation_id"]
    imp_resp = dict(r)
    s, r = http_b("POST", "/v1/keys/import", ibody,
                  {"Idempotency-Key": "imp-1"})
    check("import replay identical", s == 201 and r == imp_resp, (r, imp_resp))
    # same key, tampered bundle with same binding -> 409 (binding mismatch),
    # even though the tampered bundle would independently be a 400.
    s, r = http_b("POST", "/v1/keys/import",
                  {"tenant_id": tenant, "passphrase": "pw",
                   "bundle": exp["bundle"][:-2] + "AA"},
                  {"Idempotency-Key": "imp-1"})
    check("import same key different body -> 409",
          s == 409 and r["operation_id"] == imp_op, (s, r))
    # fresh key against the same tenant -> same-tenant conflict 409 stored
    s, r = http_b("POST", "/v1/keys/import", ibody,
                  {"Idempotency-Key": "imp-2"})
    check("same-tenant re-import -> 409 conflict",
          s == 409 and r["operation_id"] != imp_op, (s, r))
    s, st = http_b("GET", "/v1/operations/%s?tenant_id=%s"
                   % (r["operation_id"], tenant))
    check("409 stored as conflict",
          st["status"] == STATUS_CONFLICT and st["http_status"] == 409, st)

    # --- tenant backup/restore idempotency into a fresh DR deployment.
    s, bk = http("POST", "/v1/backup",
                 {"tenant_id": tenant, "passphrase": "pw"})
    check("backup 200", s == 200, (s, bk))
    rbody = {"tenant_id": tenant, "passphrase": "pw", "bundle": bk["bundle"]}
    s, r = http_c("POST", "/v1/restore", rbody,
                  {"Idempotency-Key": "res-1"})
    check("restore 201 + operation_id",
          s == 201 and r["tenant_id"] == tenant
          and key_id in r["key_ids"] and is_uuid(r["operation_id"]), (s, r))
    res_resp = dict(r)
    res_op = r["operation_id"]
    s, r = http_c("POST", "/v1/restore", rbody,
                  {"Idempotency-Key": "res-1"})
    check("restore replay identical", s == 201 and r == res_resp, (r, res_resp))
    check("restore committed exactly one import event",
          sum(1 for e in read_events(ROOT_C)
              if e["tenant_id"] == tenant and e["action"] == "import"
              and e["event_id"] == res_op) == 1)
    # restoring again with a different binding -> same-tenant 409
    s, r = http_c("POST", "/v1/restore", rbody,
                  {"Idempotency-Key": "res-2"})
    check("second restore -> 409", s == 409 and is_uuid(r["operation_id"]),
          (s, r))

    # empty bundle restore (the bundle names its own tenant)
    from keymgr import tenantbundle
    empty_bundle = tenantbundle.encode_bundle(
        {"format": tenantbundle.FORMAT, "tenant_id": "tenant-empty",
         "keys": [], "policy": None}, "pw")
    s, r = http_c("POST", "/v1/restore",
                  {"tenant_id": "tenant-empty", "passphrase": "pw",
                   "bundle": empty_bundle},
                  {"Idempotency-Key": "res-empty"})
    check("empty restore 201",
          s == 201 and r["key_ids"] == [] and r["policy_restored"] is False,
          (s, r))

    # --- concurrency: same binding, only one submission; waiter times out
    concurrency_check(operations)

        # --- CLI interop: CLI replay of an HTTP-created operation and vice versa
    cli_replay_checks()

    # --- crash recovery checks
    crash_recovery_checks()

    httpd.shutdown()
    server_b.terminate()
    server_c.terminate()
    for proc in (server_b, server_c):
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if failures:
        print("\n%d FAILURES: %s" % (len(failures), failures))
        sys.exit(1)
    print("\nALL E2E PASS")


def read_events(data_dir=ROOT):
    with open(os.path.join(data_dir, "audit.log")) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def count_events(tenant):
    return sum(1 for e in read_events() if e["tenant_id"] == tenant)


def count_rotate_events(tenant, key_id):
    return sum(1 for e in read_events()
               if e["tenant_id"] == tenant and e["action"] == "rotate")


def read_events_b():
    with open(os.path.join(ROOT_B, "audit.log")) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def is_uuid(v):
    try:
        return uuid.UUID(v).version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def concurrency_check(operations):
    tenant = "tenant-conc"
    s, r = http("POST", "/v1/keys",
                {"tenant_id": tenant, "algorithm": "AES256", "label": "c"})
    key_id = r["key_id"]
    # Make the provider slow (> the 5s lock budget) for one generate call.
    from keymgr import provider as provider_mod
    local = provider_mod.get_local_provider()
    orig_rotate = local.rotate
    state = {"slept": False}

    def slow_rotate(algorithm):
        if not state["slept"]:
            state["slept"] = True
            time.sleep(6.0)
        return orig_rotate(algorithm)

    local.rotate = slow_rotate
    results = {}

    def call(name, key):
        try:
            results[name] = operations.run_rotate(
                tenant_id=tenant, operator="alice", idempotency_key=key,
                key_id=key_id, payload={"tenant_id": tenant,
                                        "algorithm": "AES256"})
        except ops_mod.BindingTimeout as exc:
            results[name] = operations.get_operation(
                exc.operation_id, tenant, "alice")

    t1 = threading.Thread(target=call, args=("holder", "same"))
    t2 = threading.Thread(target=call, args=("waiter", "same"))
    t1.start()
    time.sleep(0.5)
    t2.start()
    t2.join(timeout=10)
    t1.join(timeout=10)
    local.rotate = orig_rotate
    waiter = results.get("waiter")
    holder = results.get("holder")
    check("waiter timed_out 503",
        waiter is not None and waiter.http_status == 503
        and waiter.status == "timed_out",
        {k: (v.http_status if v else None) for k, v in results.items()})
    check("holder succeeded 201",
        holder is not None and holder.http_status == 201)
    # The waiter wrote no key version, no audit event of its own.
    s, cur = http("GET", "/v1/keys/%s/current?tenant_id=%s" % (key_id, tenant))
    check("timeout produced no extra version", cur["version"] == 2, cur)
    check("timeout wrote no audit event",
          waiter is not None
          and not any(e["event_id"] == waiter.operation_id
                      for e in read_events()))
    # After the holder finishes, a genuine retry with the waiter-style
    # re-submission is unnecessary: the holder's binding is the only one, and
    # replaying its key returns the holder's 201.
    time.sleep(1.5)
    again = operations.run_rotate(
        tenant_id=tenant, operator="alice", idempotency_key="same",
        key_id=key_id, payload={"tenant_id": tenant, "algorithm": "AES256"})
    check("post-timeout binding replays holder 201",
          again.operation_id == holder.operation_id
          and again.http_status == 201, again)

    # A maximum-length (128) key is legal and succeeds.
    s, r = http("POST", "/v1/keys/%s/rotate" % key_id,
                {"tenant_id": tenant, "algorithm": "AES256"},
                {"Idempotency-Key": "a" * 128})
    check("128-char Idempotency-Key accepted", s == 201, (s, r))

    # Distinct idempotency keys (distinct bindings) both submit, even when
    # fired concurrently on the same key; neither waits on the other's
    # binding (the per-key lock only serializes the file write).
    out = {}

    def call(name, key):
        out[name] = operations.run_rotate(
            tenant_id=tenant, operator="alice", idempotency_key=key,
            key_id=key_id, payload={"tenant_id": tenant,
                                    "algorithm": "AES256"})

    t1 = threading.Thread(target=call, args=("a", "distinct-a"))
    t2 = threading.Thread(target=call, args=("b", "distinct-b"))
    t1.start(); t2.start(); t1.join(10); t2.join(10)
    check("distinct concurrent keys both 201",
          out["a"].http_status == 201 and out["b"].http_status == 201
          and out["a"].operation_id != out["b"].operation_id,
          {k: v.http_status for k, v in out.items()})
    s, cur = http("GET", "/v1/keys/%s/current?tenant_id=%s" % (key_id, tenant))
    check("distinct concurrent keys produced two versions",
          cur["version"] == 5, cur)


def cli(args, data_dir=ROOT):
    p = subprocess.run(
        [sys.executable, "-m", "keymgr", "--data-dir", data_dir] + args,
        capture_output=True, text=True,
    )
    out = p.stdout.strip()
    err = p.stderr.strip()

    def loads(text):
        try:
            return json.loads(text) if text else None
        except ValueError:
            return {"_raw": text}

    return p.returncode, loads(out), loads(err)


def start_server(data_dir, port):
    proc = subprocess.Popen(
        [sys.executable, "-m", "keymgr", "--data-dir", data_dir,
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_port(port)
    time.sleep(0.2)
    return proc


def cli_replay_checks():
    """CLI/HTTP interop using short-lived dedicated deployments.

    The built-in local provider keeps an in-process handle-registry cache;
    a long-running server and a CLI invocation must therefore never *mint*
    material in the same data dir concurrently (a pre-existing property).
    Replays, binding conflicts and policy denials never touch the provider,
    so they interleave freely; material-minting steps are ordered so each
    deployment's running process sees a registry that already contains every
    handle it needs.
    """
    dir_d = ROOT_D
    dir_e = ROOT_D + "-restore"
    shutil.rmtree(dir_d, ignore_errors=True)
    shutil.rmtree(dir_e, ignore_errors=True)
    tenant = "tenant-cli"

    # 1) CLI mints the key before any server runs on dir_d.
    rc, r, err = cli(["gen", "--tenant-id", tenant, "--algorithm", "AES256",
                     "--label", "c", "--operator", "alice"], data_dir=dir_d)
    check("CLI gen 0", rc == 0, (rc, r, err))
    key_id = r["key_id"]

    # 2) Start the server; it loads the registry (including CLI's handle).
    proc_d = start_server(dir_d, PORT_D)
    try:
        # HTTP creates the idempotent rotate operation...
        s, hr = http_to(PORT_D, "POST", "/v1/keys/%s/rotate" % key_id,
                        {"tenant_id": tenant, "algorithm": "AES256"},
                        {"Idempotency-Key": "cli-http-1"})
        check("HTTP rotate for CLI replay 201", s == 201, (s, hr))
        rotate_op = hr["operation_id"]
        # ...CLI replays the same binding/body: terminal replay, no mint.
        rc, r, err = cli(["rotate", "--tenant-id", tenant, "--key-id", key_id,
                          "--algorithm", "AES256", "--operator", "alice",
                          "--idempotency-key", "cli-http-1"], data_dir=dir_d)
        check("CLI replays HTTP operation identically",
              rc == 0 and r == hr, (rc, r, hr))
        # HTTP backup (server owns all handles in its loaded registry).
        s, bk = http_to(PORT_D, "POST", "/v1/backup",
                        {"tenant_id": tenant, "passphrase": "pw"})
        check("HTTP backup 200", s == 200 and "bundle" in bk, (s, bk))
        # CLI missing idempotency key -> argparse exit 2
        rc, out, err = cli(["rotate", "--tenant-id", tenant, "--key-id",
                            key_id, "--algorithm", "AES256",
                            "--operator", "alice"], data_dir=dir_d)
        check("CLI without --idempotency-key exits 2", rc == 2, (rc, err))
        # CLI illegal key -> exit 2
        rc, out, err = cli(["rotate", "--tenant-id", tenant, "--key-id",
                            key_id, "--algorithm", "AES256",
                            "--operator", "alice",
                            "--idempotency-key", "bad key"], data_dir=dir_d)
        check("CLI illegal key exits 2", rc == 2 and "error" in err,
              (rc, err))
        # CLI same key different body -> exit 3 naming the existing op
        rc, out, err = cli(["rotate", "--tenant-id", tenant, "--key-id",
                            key_id, "--algorithm", "RSA2048",
                            "--operator", "alice",
                            "--idempotency-key", "cli-http-1"],
                           data_dir=dir_d)
        check("CLI binding conflict exits 3 with existing operation_id",
              rc == 3 and err.get("operation_id") == rotate_op, (rc, err))
        # Policy denial via HTTP PUT, then CLI denied rotate (exit 3).
        rules = json.dumps([{"subject": "alice", "actions": ["rotate"],
                             "effect": "deny"}])
        req = urllib.request.Request(
            "http://127.0.0.1:%d/v1/policy" % PORT_D,
            json.dumps({"tenant_id": tenant, "rules": json.loads(rules)})
            .encode(), method="PUT")
        req.add_header("X-Operator-Id", "alice")
        with urllib.request.urlopen(req) as resp:
            check("PUT policy 200", resp.status == 200)
        rc1, _, e1 = cli(["rotate", "--tenant-id", tenant, "--key-id", key_id,
                          "--algorithm", "AES256", "--operator", "alice",
                          "--idempotency-key", "cli-deny"], data_dir=dir_d)
        rc2, _, e2 = cli(["rotate", "--tenant-id", tenant, "--key-id", key_id,
                          "--algorithm", "AES256", "--operator", "alice",
                          "--idempotency-key", "cli-deny"], data_dir=dir_d)
        check("CLI denied rotate exit 3 and replays identically",
              rc1 == 3 and rc2 == 3 and e1 == e2 and "operation_id" in e1,
              (rc1, rc2, e1, e2))
    finally:
        proc_d.terminate()
        try:
            proc_d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_d.kill()

    # 3) CLI restore into a clean deployment (mints handles in CLI process).
    rc, r, err = cli(["restore", "--tenant-id", tenant, "--passphrase", "pw",
                      "--bundle", bk["bundle"], "--operator", "alice",
                      "--idempotency-key", "http-cli-1"], data_dir=dir_e)
    check("CLI restore 0", rc == 0 and r and r["operation_id"], (rc, r, err))
    cli_op = r["operation_id"]
    cli_key_ids = r["key_ids"]
    # 4) Only now start a server there; HTTP replay is a terminal read.
    proc_e = start_server(dir_e, PORT_D + 1)
    try:
        s, hr2 = http_to(PORT_D + 1, "POST", "/v1/restore",
                         {"tenant_id": tenant, "passphrase": "pw",
                          "bundle": bk["bundle"]},
                         {"Idempotency-Key": "http-cli-1"})
        check("HTTP replays CLI restore identically",
              s == 201 and hr2["operation_id"] == cli_op
              and hr2["key_ids"] == cli_key_ids, (s, hr2, r))
    finally:
        proc_e.terminate()
        try:
            proc_e.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_e.kill()


def crash_recovery_checks():
    """A pending op whose event committed is finalized on restart."""
    data_dir = os.path.join(ROOT, "crash")
    os.makedirs(data_dir, exist_ok=True)
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    rec = store.create("tenant-crash", "AES256", "k")
    key_id = rec.key_id
    op_id = str(uuid.uuid4())
    # Simulate: rotate committed outbox (event op_id in ledger), but the
    # operation record is still pending when the process died.
    rotated = store.rotate(key_id, "tenant-crash", "AES256", event_id=op_id)
    version = rotated.current.version
    operations = OperationStore(data_dir, store, policies, coordinator)
    pend = OperationRecord(
        operation_id=op_id, idempotency_key="crash-1",
        tenant_id="tenant-crash", operator="alice",
        path="/v1/keys/%s/rotate" % key_id,
        request_fingerprint="0" * 64,
        intent={"kind": "rotate", "key_id": key_id},
    )
    operations._persist(pend)
    # Rebuild a fresh process: key/policy/restore recovery runs, then the
    # operation store finalizes the pending record from the ledger.
    store2 = KeyStore(data_dir, AuditLog(data_dir))
    policies2 = PolicyStore(data_dir, AuditLog(data_dir))
    coord2 = restore_mod.RestoreCoordinator(store2, policies2)
    ops2 = OperationStore(data_dir, store2, policies2, coord2)
    got = ops2.get_operation(op_id, "tenant-crash", "alice")
    check("crash: committed pending op finalized succeeded",
          got is not None and got.status == STATUS_SUCCEEDED
          and got.http_status == 201 and got.response["version"] == version
          and got.response["operation_id"] == op_id, got)

    # An orphan pending record (file landed, binding pointer never did) with
    # no committed event is unaddressable by any client and is finalized
    # failed on the next open; it changed nothing.
    orphan = str(uuid.uuid4())
    orphan_rec = OperationRecord(
        operation_id=orphan, idempotency_key="crash-orphan",
        tenant_id="tenant-crash", operator="alice",
        path="/v1/keys/%s/rotate" % key_id,
        request_fingerprint="0" * 64,
        intent={"kind": "rotate", "key_id": key_id},
    )
    ops2._persist(orphan_rec)
    ops3 = OperationStore(data_dir, store2, policies2, coord2)
    gone = ops3.get_operation(orphan, "tenant-crash", "alice")
    check("crash: orphan pending op finalized failed",
          gone is not None and gone.status == STATUS_FAILED
          and gone.http_status == 500, gone)
    versions_after_orphan = len(store2.read_raw(key_id).versions)

    # The pointer-present, not-yet-committed case stays pending and a
    # same-binding live retry re-executes under the SAME operation_id.
    op2 = str(uuid.uuid4())
    bh = ops3._binding_hash("tenant-crash", "alice", "crash-2")
    fp = ops_mod.canonical_fingerprint(
        "/v1/keys/%s/rotate" % key_id,
        {"tenant_id": "tenant-crash", "algorithm": "AES256"})
    pend2 = OperationRecord(
        operation_id=op2, idempotency_key="crash-2",
        tenant_id="tenant-crash", operator="alice",
        path="/v1/keys/%s/rotate" % key_id,
        request_fingerprint=fp,
        intent={"kind": "rotate", "key_id": key_id},
    )
    ops3._persist(pend2)
    assert ops3._create_pointer(bh, op2) is None
    ops4 = OperationStore(data_dir, store2, policies2, coord2)
    still = ops4.get_operation(op2, "tenant-crash", "alice")
    check("crash: pointer-bound uncommitted op stays pending",
          still is not None and still.status == STATUS_PENDING, still)
    rec2 = ops4.run_rotate(
        tenant_id="tenant-crash", operator="alice",
        idempotency_key="crash-2", key_id=key_id,
        payload={"tenant_id": "tenant-crash", "algorithm": "AES256"})
    check("crash: live retry under same op id commits",
          rec2.operation_id == op2 and rec2.http_status == 201, rec2)
    # And the orphan path added no version of its own.
    check("crash: orphan produced no version",
          len(store2.read_raw(key_id).versions) == versions_after_orphan + 1)

    # A terminal rejection carrying an outbox marker whose event never
    # reached the ledger: on the next open the event is appended exactly
    # once (idempotent on operation_id) and the marker is cleared.
    rej_id = str(uuid.uuid4())
    rej = OperationRecord(
        operation_id=rej_id, idempotency_key="crash-rej",
        tenant_id="tenant-crash", operator="alice",
        path="/v1/keys/%s/rotate" % key_id,
        request_fingerprint="1" * 64,
        intent={"kind": "rotate", "key_id": key_id},
    )
    rej.status = STATUS_FAILED
    rej.http_status = 404
    rej.response = {"error": "key not found", "operation_id": rej_id}
    rej.pending_event = {
        "event_id": rej_id, "tenant_id": "tenant-crash",
        "action": "rotate", "key_id": key_id, "outcome": "rejected",
        "timestamp": "2026-01-01T00:00:00+00:00", "seq": 0,
    }
    ops4._persist(rej)
    assert ops4.audit.get_event(rej_id) is None
    ops5 = OperationStore(data_dir, store2, policies2, coord2)
    fixed = ops5.get_operation(rej_id, "tenant-crash", "alice")
    check("crash: rejection marker committed on reopen",
          fixed is not None and fixed.http_status == 404
          and fixed.pending_event is None
          and ops5.audit.get_event(rej_id) is not None, fixed)
    # Reopening again must not duplicate the event.
    ops6 = OperationStore(data_dir, store2, policies2, coord2)
    check("crash: rejection event not duplicated",
          sum(1 for e in read_events(data_dir)
              if e["event_id"] == rej_id) == 1)


if __name__ == "__main__":
    main()
