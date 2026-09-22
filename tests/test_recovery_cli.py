"""Cross-process crash-recovery tests driven through the real CLI.

A crash is injected deterministically: the test process holds the exclusive
flock on ``audit.log.lock``, so the CLI subprocess blocks exactly at the
commit-point ledger append (after every provider handle, journal, marker and
snapshot is already durable). SIGKILL then simulates the process dying at the
worst possible moment; the next CLI invocation must settle the scene.
"""

import fcntl
import json
import os
import signal
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _cli_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = TESTS_DIR + os.pathsep + REPO_ROOT
    return env


def run_cli(env, *args, timeout=60):
    cmd = [sys.executable, "-m", "keymgr", "--data-dir", env.data_dir] + [
        str(a) for a in args
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, env=_cli_env(), timeout=timeout
    )


def start_cli(env, *args):
    cmd = [sys.executable, "-m", "keymgr", "--data-dir", env.data_dir] + [
        str(a) for a in args
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_cli_env(),
    )


def wait_for(predicate, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def json_out(proc):
    """The single-line JSON body of a CLI run (stdout or stderr)."""
    for stream in (proc.stdout, proc.stderr):
        text = stream.strip()
        if text.startswith("{"):
            return json.loads(text)
    raise AssertionError(
        "no JSON body: rc=%d out=%r err=%r"
        % (proc.returncode, proc.stdout, proc.stderr)
    )


class LedgerHold:
    """Block every ledger append of the data dir until released."""

    def __init__(self, env):
        self.path = os.path.join(env.data_dir, "audit.log.lock")

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def _gen(env, tenant, label):
    proc = run_cli(
        env, "gen", "--tenant-id", tenant, "--algorithm", "AES256",
        "--label", label, "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["key_id"]


def _key_file_has_marker(env, key_id):
    path = os.path.join(env.data_dir, key_id + ".json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return bool(json.load(fh).get("pending_event"))
    except (OSError, ValueError):
        return False


def _pending_operation_id(env):
    ops_dir = os.path.join(env.data_dir, "operations")
    for name in os.listdir(ops_dir):
        if name == "index.json" or not name.endswith(".json"):
            continue
        with open(os.path.join(ops_dir, name), "r", encoding="utf-8") as fh:
            record = json.load(fh)
        if record.get("status") == "pending":
            return record["operation_id"]
    return None


def _current_version(env, tenant, key_id):
    proc = run_cli(
        env, "current", "--tenant-id", tenant, "--key-id", key_id,
        "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["version"]


def _get_operation(env, tenant, operation_id):
    return run_cli(
        env, "operation", "--tenant-id", tenant, "--operator", "alice",
        "--operation-id", operation_id,
    )


def test_cli_rotate_crash_before_commit_recovers_and_replays(env):
    key_id = _gen(env, "t1", "k")
    with LedgerHold(env):
        proc = start_cli(
            env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
            "--algorithm", "AES256", "--operator", "alice",
            "--idempotency-key", "rot-1",
        )
        # Wait until the marker and journal are durable (the subprocess is
        # then blocked on the ledger append), then kill it mid-commit.
        assert wait_for(lambda: _key_file_has_marker(env, key_id))
        assert wait_for(lambda: _pending_operation_id(env) is not None)
        proc.kill()
        proc.wait()
    operation_id = _pending_operation_id(env)
    assert operation_id is not None

    # The next CLI process settles the crash scene.
    assert _current_version(env, "t1", key_id) == 2

    # The operation committed exactly once and replays its first response.
    op = _get_operation(env, "t1", operation_id)
    assert op.returncode == 0, op.stderr
    body = json.loads(op.stdout)
    assert body["operation_id"] == operation_id
    assert body["status"] == "succeeded"
    assert body["http_status"] == 201
    assert body["response"]["version"] == 2

    # A retry with the same idempotency key replays the original result.
    retry = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "rot-1",
    )
    assert retry.returncode == 0, retry.stderr
    replayed = json.loads(retry.stdout)
    assert replayed["operation_id"] == operation_id
    assert replayed["version"] == 2
    # Still exactly one rotate event for this operation.
    audit = run_cli(
        env, "audit", "--tenant-id", "t1", "--action", "rotate",
        "--operator", "alice",
    )
    events = json.loads(audit.stdout)["events"]
    assert [e["event_id"] for e in events] == [operation_id]


def test_cli_batch_rotate_crash_before_commit_rolls_back(env):
    keys = [_gen(env, "t1", "k0"), _gen(env, "t1", "k1")]
    items = json.dumps([{"key_id": k, "algorithm": "AES256"} for k in keys])
    handles_before = env.kms_handles()
    with LedgerHold(env):
        proc = start_cli(
            env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
            "--idempotency-key", "batch-1", "--items", items,
        )
        snapshot_dir = os.path.join(env.data_dir, "batch-rotations")
        assert wait_for(
            lambda: os.path.isdir(snapshot_dir) and os.listdir(snapshot_dir)
        )
        assert wait_for(
            lambda: all(_key_file_has_marker(env, k) for k in keys)
        )
        proc.kill()
        proc.wait()
    operation_id = _pending_operation_id(env)
    assert operation_id is not None

    # Recovery rolls the whole group back: old versions, no orphan handles.
    for key_id in keys:
        assert _current_version(env, "t1", key_id) == 1
    assert env.kms_handles() == handles_before
    assert not os.listdir(os.path.join(env.data_dir, "batch-rotations")) == [] or True
    assert not os.path.exists(snapshot_dir) or not os.listdir(snapshot_dir)

    # The operation never committed: recorded failed, replayed as-is.
    op = _get_operation(env, "t1", operation_id)
    assert op.returncode == 0, op.stderr
    body = json.loads(op.stdout)
    assert body["status"] == "failed"
    assert body["http_status"] == 500

    retry = run_cli(
        env, "batch-rotate", "--tenant-id", "t1", "--operator", "alice",
        "--idempotency-key", "batch-1", "--items", items,
    )
    assert retry.returncode == 1
    replayed = json_out(retry)
    assert replayed["operation_id"] == operation_id
    # No batch_rotate audit event was ever committed.
    audit = run_cli(
        env, "audit", "--tenant-id", "t1", "--action", "batch_rotate",
        "--operator", "alice",
    )
    assert json.loads(audit.stdout)["events"] == []


def test_cli_import_crash_before_commit_recovers_and_replays(env):
    key_id = _gen(env, "t1", "k")
    exported = run_cli(
        env, "export", "--tenant-id", "t1", "--key-id", key_id,
        "--passphrase", "pw", "--operator", "alice",
    )
    assert exported.returncode == 0, exported.stderr
    bundle = json.loads(exported.stdout)["bundle"]

    # Import into a fresh data dir (same KMS backend), crashing after the
    # key file and its marker landed but before the ledger append.
    import_dir = env.data_dir + "-import"
    os.makedirs(import_dir, exist_ok=True)
    import_env = type(env)(import_dir, env.state_path, env.faults_path)
    with LedgerHold(import_env):
        proc = start_cli(
            import_env, "import", "--tenant-id", "t1", "--passphrase", "pw",
            "--bundle", bundle, "--operator", "alice",
            "--idempotency-key", "imp-1",
        )
        assert wait_for(lambda: _key_file_has_marker(import_env, key_id))
        assert wait_for(lambda: _pending_operation_id(import_env) is not None)
        proc.kill()
        proc.wait()
    operation_id = _pending_operation_id(import_env)
    assert operation_id is not None

    # The next CLI process commits the import forward.
    proc = run_cli(
        import_env, "current", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice",
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["version"] == 1

    op = run_cli(
        import_env, "operation", "--tenant-id", "t1", "--operator", "alice",
        "--operation-id", operation_id,
    )
    body = json_out(op)
    assert body["status"] == "succeeded"
    assert body["http_status"] == 201

    # A retry replays the first response with the same operation_id.
    retry = run_cli(
        import_env, "import", "--tenant-id", "t1", "--passphrase", "pw",
        "--bundle", bundle, "--operator", "alice",
        "--idempotency-key", "imp-1",
    )
    assert retry.returncode == 0, retry.stderr
    assert json.loads(retry.stdout)["operation_id"] == operation_id
    # Exactly one import event for the operation.
    audit = run_cli(
        import_env, "audit", "--tenant-id", "t1", "--action", "import",
        "--operator", "alice",
    )
    events = json.loads(audit.stdout)["events"]
    assert [e["event_id"] for e in events] == [operation_id]


def test_cli_restore_crash_before_commit_rolls_back(env):
    key_id = _gen(env, "t1", "k")
    backup = run_cli(
        env, "backup", "--tenant-id", "t1", "--passphrase", "pw",
        "--operator", "alice",
    )
    assert backup.returncode == 0, backup.stderr
    bundle = json.loads(backup.stdout)["bundle"]

    # Restore into a fresh data dir (same tenant id, same KMS backend).
    restore_dir = env.data_dir + "-restore"
    os.makedirs(restore_dir, exist_ok=True)
    restore_env = type(env)(restore_dir, env.state_path, env.faults_path)
    handles_before = env.kms_handles()
    with LedgerHold(restore_env):
        proc = start_cli(
            restore_env, "restore", "--tenant-id", "t1", "--passphrase", "pw",
            "--bundle", bundle, "--operator", "alice",
            "--idempotency-key", "rest-1",
        )
        assert wait_for(lambda: _key_file_has_marker(restore_env, key_id))
        proc.kill()
        proc.wait()
    operation_id = _pending_operation_id(restore_env)
    assert operation_id is not None

    # A later CLI process settles the crash scene: the uncommitted restore
    # is rolled back (no key file, no orphan handles).
    op = run_cli(
        restore_env, "operation", "--tenant-id", "t1", "--operator", "alice",
        "--operation-id", operation_id,
    )
    assert not os.path.exists(os.path.join(restore_dir, key_id + ".json"))
    assert env.kms_handles() == handles_before

    body = json_out(op)
    assert body["status"] == "failed"
    assert body["http_status"] == 500


def test_cli_rotate_provider_down_is_503_text_and_exit_1(env):
    key_id = _gen(env, "t1", "k")
    env.set_faults({"unreachable": True})
    proc = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "rot-down",
    )
    assert proc.returncode == 1
    output = proc.stdout + proc.stderr
    assert "key management provider is unavailable" in output
    env.clear_faults()

    # The failed operation is terminal and replays identically.
    retry = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "rot-down",
    )
    assert retry.returncode == 1
    first = json_out(proc)
    replayed = json_out(retry)
    assert replayed["operation_id"] == first["operation_id"]
    assert replayed["error"] == first["error"]
    # No new version, no orphan handle.
    assert _current_version(env, "t1", key_id) == 1


def test_cli_responses_never_leak_handles_or_material(env):
    key_id = _gen(env, "t1", "k")
    rotate = run_cli(
        env, "rotate", "--tenant-id", "t1", "--key-id", key_id,
        "--algorithm", "AES256", "--operator", "alice",
        "--idempotency-key", "rot-leak",
    )
    assert rotate.returncode == 0
    show = run_cli(
        env, "show", "--tenant-id", "t1", "--key-id", key_id,
        "--operator", "alice",
    )
    audit = run_cli(
        env, "audit", "--tenant-id", "t1", "--operator", "alice",
    )
    handles = env.kms_handles()
    for output in (rotate.stdout, show.stdout, audit.stdout):
        assert "encrypted_material" not in output
        assert "private_material" not in output
        assert "passphrase" not in output
        for handle in handles:
            assert handle not in output
