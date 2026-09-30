"""CLI idempotent body tenant_id vs --tenant-id disagreement.

When the request body the CLI idempotent machinery would send carries a
tenant_id that is missing, empty or different from the --tenant-id source,
the outcome mirrors HTTP: exit 2 naming tenant_id and one invisible
tenant_conflict event, before any idempotency-key binding takes place.
"""

from keymgr.artifacts import ArtifactStore
from keymgr.audit import AuditLog
from keymgr import cli
from keymgr.operations import OperationStore
from keymgr.policy import PolicyStore
from keymgr.store import KeyStore


def _wiring(tmp_path):
    data_dir = str(tmp_path)
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    op_store = OperationStore(data_dir, audit_log)
    artifacts = ArtifactStore(data_dir, store, audit_log)
    return store, policies, op_store, artifacts, audit_log


def _run(tmp_path, body, capfd):
    store, policies, op_store, artifacts, audit_log = _wiring(tmp_path)

    def executor(operation, mirror=None):
        raise AssertionError("executor must never run")

    code = cli.idempotent_run(
        op_store, store, "/v1/restore", "t", "alice", body,
        "idem-1", lambda: None, executor, artifact_store=artifacts,
    )
    return code, audit_log, capfd.readouterr()


def test_body_tenant_mismatch_is_exit_2_and_records_conflict(
    tmp_path, capfd
):
    code, audit_log, captured = _run(
        tmp_path,
        {"tenant_id": "other", "passphrase": "p", "bundle": "b"},
        capfd,
    )
    assert code == 2
    assert "tenant_id" in captured.err
    events = audit_log._read_all()
    assert [e.action for e in events] == ["tenant_conflict"]
    assert events[0].tenant_id is None


def test_body_tenant_missing_is_exit_2_and_records_conflict(
    tmp_path, capfd
):
    code, audit_log, captured = _run(
        tmp_path,
        {"passphrase": "p", "bundle": "b"},
        capfd,
    )
    assert code == 2
    assert "tenant_id" in captured.err
    assert [e.action for e in audit_log._read_all()] == [
        "tenant_conflict"
    ]
