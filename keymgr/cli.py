"""Command-line interface: `gen` and `show` subcommands."""

import argparse
import json
import os
import re
import sys
from typing import List, Optional

from . import audit as audit_mod
from . import keybundle
from . import operations as operations_mod
from . import restore as restore_mod
from . import tenantbundle
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .operations import OperationStore
from .policy import PolicyError, PolicyStore, validate_rules
from .provider import ProviderInvalidMaterial, ProviderUnavailable
from .server import _resolve_committed_operation, serve
from .store import IMPORT_CONFLICT, KeyStore, LockTimeout, is_valid_key_id, validate_batch_items

DEFAULT_DATA_DIR = os.environ.get("KEYMGR_DATA_DIR", "keymgr_data")


def _positive_int(value: str) -> int:
    """argparse type: a positive integer version (ASCII digits only)."""
    if not re.fullmatch(r"[0-9]+", value):
        raise argparse.ArgumentTypeError(
            "field version must be a positive integer"
        )
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(
            "field version must be a positive integer"
        )
    return ivalue


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="keymgr", description="Multi-tenant key management backend."
    )
    parser.add_argument(
        "--data-dir", default=DEFAULT_DATA_DIR,
        help="directory for key material (default: %(default)s)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def tenant_parser(name, **kwargs):
        p = sub.add_parser(name, **kwargs)
        p.add_argument("--tenant-id", required=True)
        p.add_argument(
            "--operator", required=True,
            help="non-empty X-Operator-Id of the caller",
        )
        return p

    p_gen = tenant_parser("gen", help="generate a new key")
    p_gen.add_argument("--algorithm", required=True,
                       help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))
    p_gen.add_argument("--label", required=True)

    p_show = tenant_parser("show", help="show an existing key")
    p_show.add_argument("--key-id", required=True)

    p_rotate = tenant_parser("rotate", help="rotate a key to a new version")
    p_rotate.add_argument("--key-id", required=True)
    p_rotate.add_argument("--algorithm", required=True,
                          help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))
    p_rotate.add_argument(
        "--idempotency-key", required=True,
        help="1-128 chars A-Za-z0-9._~- ; retries reuse the result",
    )

    p_batch_rotate = tenant_parser(
        "batch-rotate",
        help="atomically rotate 1-100 keys in one idempotent batch",
    )
    p_batch_rotate.add_argument(
        "--items", required=True,
        help='JSON array of {"key_id","algorithm"} items (1-100, unique ids)',
    )
    p_batch_rotate.add_argument(
        "--idempotency-key", required=True,
        help="1-128 chars A-Za-z0-9._~- ; retries reuse the result",
    )

    p_version = tenant_parser("version", help="show a specific key version")
    p_version.add_argument("--key-id", required=True)
    p_version.add_argument("--version", required=True, type=_positive_int)

    p_current = tenant_parser("current", help="show the current key version")
    p_current.add_argument("--key-id", required=True)

    p_revoke = tenant_parser("revoke", help="revoke a key")
    p_revoke.add_argument("--key-id", required=True)
    p_revoke.add_argument("--reason", required=True)

    p_status = tenant_parser("status", help="show a key's revocation status")
    p_status.add_argument("--key-id", required=True)

    p_export = tenant_parser("export", help="export a key as an encrypted bundle")
    p_export.add_argument("--key-id", required=True)
    p_export.add_argument("--passphrase", required=True)

    p_import = tenant_parser("import", help="import a key from an encrypted bundle")
    p_import.add_argument("--passphrase", required=True)
    p_import.add_argument("--bundle", required=True)
    p_import.add_argument(
        "--idempotency-key", required=True,
        help="1-128 chars A-Za-z0-9._~- ; retries reuse the result",
    )

    p_backup = tenant_parser(
        "backup", help="back up all of a tenant's keys and policy"
    )
    p_backup.add_argument("--passphrase", required=True)

    p_restore = tenant_parser(
        "restore", help="restore a tenant from an encrypted backup bundle"
    )
    p_restore.add_argument("--passphrase", required=True)
    p_restore.add_argument("--bundle", required=True)
    p_restore.add_argument(
        "--idempotency-key", required=True,
        help="1-128 chars A-Za-z0-9._~- ; retries reuse the result",
    )

    p_operation = tenant_parser(
        "operation", help="show one idempotent operation's status"
    )
    p_operation.add_argument(
        "--operation-id", required=True,
        help="UUID4 operation_id returned by rotate/import/restore",
    )

    p_audit = tenant_parser("audit", help="list a tenant's audit events")
    p_audit.add_argument("--key-id", default=None,
                         help="filter to one key_id (must be a UUID4)")
    p_audit.add_argument("--action", default=None,
                         help="one of: %s" % ", ".join(audit_mod.ACTIONS))
    p_audit.add_argument("--limit", type=int, default=100,
                         help="page size, 1-1000 (default: %(default)s)")
    p_audit.add_argument("--cursor", default=None,
                         help="pagination cursor from a previous response")

    p_policy = sub.add_parser("policy", help="manage a tenant's action policy")
    p_policy.add_argument(
        "--operator", required=True,
        help="non-empty X-Operator-Id of the caller",
    )
    policy_sub = p_policy.add_subparsers(
        dest="policy_command", required=True
    )
    p_policy_show = policy_sub.add_parser(
        "show", help="show a tenant's policy"
    )
    p_policy_show.add_argument("--tenant-id", required=True)
    p_policy_set = policy_sub.add_parser(
        "set", help="replace a tenant's policy"
    )
    p_policy_set.add_argument("--tenant-id", required=True)
    p_policy_set.add_argument(
        "--rules", required=True,
        help='JSON array of {"subject","actions","effect"} rules',
    )
    p_policy_delete = policy_sub.add_parser(
        "delete", help="delete a tenant's policy"
    )
    p_policy_delete.add_argument("--tenant-id", required=True)

    p_serve = sub.add_parser("serve", help="run the HTTP server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)

    return parser


def _print(obj: dict) -> None:
    """Print a single-line JSON object."""
    print(json.dumps(obj, separators=(",", ":")))


def _fail(message: str, exit_code: int) -> int:
    print(json.dumps({"error": message}, separators=(",", ":")),
          file=sys.stderr)
    return exit_code


def _ledger_fail(exc: Exception) -> int:
    return _fail("audit ledger failure: %s" % exc, 1)


def _attempt(store, tenant_id, key_id, action, outcome) -> bool:
    """Record one attempt; False means a ledger failure was reported."""
    try:
        store.audit_attempt(tenant_id, key_id, action, outcome)
    except LedgerError as exc:
        _ledger_fail(exc)
        return False
    return True


def _conflict(store) -> bool:
    """Record an invisible tenant_conflict; False on ledger failure."""
    try:
        store.audit_conflict()
    except LedgerError as exc:
        _ledger_fail(exc)
        return False
    return True


def _identifiers_ok(tenant_id, key_id) -> bool:
    """Whether both identifiers are usable for a tenant-visible event."""
    return bool(tenant_id) and (key_id is None or is_valid_key_id(key_id))


def _deny(store, tenant_id, key_id, action) -> int:
    """Audit and report a policy rejection (HTTP 403 -> exit code 3)."""
    if not _identifiers_ok(tenant_id, key_id):
        if not _conflict(store):
            return 1
    elif not _attempt(store, tenant_id, key_id, action,
                      audit_mod.OUTCOME_REJECTED):
        return 1
    return _fail("action not permitted by policy", 3)


def _http_to_cli(http_status: int) -> int:
    return {201: 0, 200: 0, 400: 2, 403: 3, 409: 3, 404: 4}.get(
        http_status, 1
    )


def _terminal_rejection(
    op_store, store, operation, tenant_id, key_id, action,
    http_status, message,
):
    """Durably persist a bound op's terminal rejection and append it.

    CLI counterpart of the HTTP handler: the operation kind, the exact key_id
    rule, the terminal status, the complete error response and the audit
    descriptor are merged into the durable context *before* the one rejected
    event (named after the operation_id, deduped on event_id) is appended, so a
    crash and startup recovery replay this exact 403/404/409 verbatim instead
    of re-evaluating the policy or re-reading the object. Returns
    ``(http_status, body)`` for idempotent_run.
    """
    op_id = operation.operation_id
    body = {"error": message, "operation_id": op_id}
    kind = (operation.details or {}).get("kind")
    audit_key_id = (
        None if kind in ("restore", "batch_rotate")
        else (key_id if is_valid_key_id(key_id) else None)
    )
    op_store.stage_terminal(
        operation,
        http_status,
        body,
        audit={
            "action": action,
            "outcome": audit_mod.OUTCOME_REJECTED,
            "tenant_id": tenant_id,
            "key_id": audit_key_id,
        },
    )
    store.audit_attempt(
        tenant_id, audit_key_id, action, audit_mod.OUTCOME_REJECTED,
        event_id=op_id,
    )
    return http_status, body


def _provider_terminal(
    op_store, store, operation, http_status, message
):
    """Persist a bound op's provider-failure terminal and append it.

    CLI counterpart of the HTTP handler: after the Idempotency-Key is bound,
    a KMS/HSM load/contract/call/handle-delete failure (503) or a refusal of
    imported material (400) is a durable terminal -- the safe response is
    staged, one rejected event named after the operation_id is appended
    (rotate projects the request key_id, import the in-bundle key_id, restore
    null), and the op is finished, so an HTTP/CLI cross-retry replays exactly
    this result and the event is never duplicated. Raises OSError/LedgerError
    if that persistence itself fails (the caller finalizes failed(500)).
    """
    op_id = operation.operation_id
    body = {"error": message, "operation_id": op_id}
    details = operation.details or {}
    kind = details.get("kind")
    if kind == "batch_rotate":
        action = audit_mod.ACTION_BATCH_ROTATE
    elif kind == "rotate":
        action = audit_mod.ACTION_ROTATE
    else:
        action = audit_mod.ACTION_IMPORT
    audit_key_id = (
        None if kind in ("restore", "batch_rotate")
        else (
            details.get("key_id")
            if is_valid_key_id(details.get("key_id"))
            else None
        )
    )
    op_store.stage_terminal(
        operation,
        http_status,
        body,
        audit={
            "action": action,
            "outcome": audit_mod.OUTCOME_REJECTED,
            "tenant_id": operation.tenant_id,
            "key_id": audit_key_id,
        },
    )
    store.audit_attempt(
        operation.tenant_id, audit_key_id, action,
        audit_mod.OUTCOME_REJECTED, event_id=op_id,
    )
    op_store.finish(operation, operations_mod.STATUS_FAILED, http_status, body)
    return http_status, body


def _idem_key_error(key) -> bool:
    """Validate an --idempotency-key; report exit 2 when malformed."""
    if not operations_mod.is_valid_idempotency_key(key):
        _fail(
            "field idempotency_key must be 1-128 characters from "
            "A-Za-z0-9._~-", 2
        )
        return True
    return False


def _emit_operation_result(http_status: int, body: dict) -> int:
    """Print a terminal operation's body and return the CLI exit code."""
    if 200 <= http_status < 300:
        _print(body)
    else:
        # Errors contain only error and operation_id.
        print(
            json.dumps(
                {
                    "error": body.get("error", "request failed"),
                    "operation_id": body.get("operation_id"),
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
    return _http_to_cli(http_status)


def _idem_serve_existing(op_store, kind, record) -> "Optional[int]":
    """Replay/conflict/wait for a bound key; None means the key is unbound."""
    if kind == "new":
        return None
    if kind == "conflict":
        return _emit_operation_result(
            409,
            {
                "error": "Idempotency-Key is already bound to a different "
                "request",
                "operation_id": record.operation_id,
            },
        )
    if not record.is_terminal():
        record = op_store.await_terminal(record)
    if record.is_terminal():
        return _emit_operation_result(record.http_status, record.response)
    # Waiter outlived the 5 s budget: timed_out without mutating the owner.
    return _emit_operation_result(
        503,
        {
            "error": "operation timed out waiting for a lock",
            "operation_id": record.operation_id,
        },
    )


def idempotent_run(op_store, store, path, tenant_id, operator, body, key,
                   validator, executor, decoder=None):
    """CLI counterpart of the HTTP idempotency guard.

    Returns a process exit code. ``validator()`` runs cheap side-effect-free
    request checks *before* the binding lookup and returns None on success or
    an ``(exit_code, message)`` refusal (a refusal is never audited and never
    consumes the key). ``decoder`` (when given) performs the side-effect-free
    but expensive validation -- bundle decryption -- *after* an already-bound
    key has been replayed/conflicted but *before* a new key is bound, so a
    wrong passphrase neither masks a replay nor consumes the key.
    ``executor(operation) -> (http_status, body)`` runs once for a new binding
    and may raise ProviderInvalidMaterial / ProviderUnavailable /
    LedgerError / LockTimeout.
    """
    if _idem_key_error(key):
        return 2
    normalized = operations_mod.normalize_body(body)

    refusal = validator()
    if refusal is not None:
        code, message = refusal
        return _fail(message, code)

    # An already-bound key replays/conflicts before the expensive decoder
    # (bundle decryption), so a bad passphrase on a retry never masks a
    # replay or consumes the key.
    peek = op_store.peek(tenant_id, operator, path, normalized, key)
    existing = _idem_serve_existing(op_store, peek.kind, peek.record)
    if existing is not None:
        return existing

    if decoder is not None:
        refusal = decoder()
        if refusal is not None:
            code, message = refusal
            return _fail(message, code)

    # begin() is authoritative for the bind (another process may have won
    # between the peek and here).
    begin = op_store.begin(tenant_id, operator, path, normalized, key)
    existing = _idem_serve_existing(op_store, begin.kind, begin.record)
    if existing is not None:
        return existing

    operation = begin.record
    op_id = operation.operation_id
    try:
        http_status, resp = executor(operation)
    except LockTimeout:
        body_err = {
            "error": "operation timed out waiting for a lock",
            "operation_id": op_id,
        }
        op_store.finish(
            operation, operations_mod.STATUS_TIMED_OUT, 503, body_err
        )
        return _emit_operation_result(503, body_err)
    except ProviderInvalidMaterial as exc:
        try:
            http_status, body_err = _provider_terminal(
                op_store, store, operation, 400, str(exc)
            )
            return _emit_operation_result(http_status, body_err)
        except (OSError, LedgerError) as persist_exc:
            body_err = {
                "error": "audit ledger failure: %s" % persist_exc,
                "operation_id": op_id,
            }
            op_store.finish(
                operation, operations_mod.STATUS_FAILED, 500, body_err
            )
            return _emit_operation_result(500, body_err)
    except ProviderUnavailable:
        try:
            http_status, body_err = _provider_terminal(
                op_store, store, operation, 503,
                "key management provider is unavailable",
            )
            return _emit_operation_result(http_status, body_err)
        except (OSError, LedgerError) as persist_exc:
            body_err = {
                "error": "audit ledger failure: %s" % persist_exc,
                "operation_id": op_id,
            }
            op_store.finish(
                operation, operations_mod.STATUS_FAILED, 500, body_err
            )
            return _emit_operation_result(500, body_err)
    except OSError as exc:
        # A pre-commit staging/write failure happened before the commit-point
        # append: file and handles were rolled back, nothing committed.
        # Finalize failed(500).
        body_err = {
            "error": "audit ledger failure: %s" % exc,
            "operation_id": op_id,
        }
        op_store.finish(operation, operations_mod.STATUS_FAILED, 500, body_err)
        return _emit_operation_result(500, body_err)
    except LedgerError as exc:
        body_err = {
            "error": "audit ledger failure: %s" % exc,
            "operation_id": op_id,
        }
        op_store.finish(operation, operations_mod.STATUS_FAILED, 500, body_err)
        return _emit_operation_result(500, body_err)
    resp = dict(resp)
    resp["operation_id"] = op_id
    state = operations_mod.state_for_http_status(http_status)
    op_store.finish(operation, state, http_status, resp)
    return _emit_operation_result(http_status, resp)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns a process exit code.

    A KMS/HSM backend failure maps to exit code 1 (HTTP 503) with a generic
    message; malformed imported material maps to exit code 2 (HTTP 400).
    """
    try:
        return _run(argv)
    except ProviderInvalidMaterial as exc:
        return _fail(str(exc), 2)
    except ProviderUnavailable:
        # Generic wording: never print a handle or material in the error.
        return _fail("key management provider is unavailable", 1)


def _run(argv: Optional[List[str]] = None) -> int:
    """Parse and execute one CLI command."""
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        serve(args.host, args.port, args.data_dir)
        return 0

    audit_log = AuditLog(args.data_dir)
    store = KeyStore(args.data_dir, audit_log)
    policies = PolicyStore(args.data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policies)
    # Resolve any operations left pending by a crashed CLI/server run, after
    # the key/restore outbox recovery above has settled the mutation.
    op_store = OperationStore(args.data_dir, audit_log)
    register_artifacts, handle_cb, group_cb, rollback_uncommitted = (
        operations_mod.make_artifact_callbacks(op_store, store)
    )
    op_store.recover_pending(
        lambda record, event: _resolve_committed_operation(
            store, policies, record, event
        ),
        rollback_uncommitted=rollback_uncommitted,
    )

    if not getattr(args, "operator", None):
        return _fail(
            "field operator must be a non-empty string", 2
        )

    def allowed(action, key_id=None) -> bool:
        """Policy gate; on denial the response/audit was already handled."""
        if policies.is_allowed(args.tenant_id, action, args.operator):
            return True
        return False  # caller returns _deny(...)

    if args.command == "gen":
        if not args.tenant_id or args.algorithm not in SUPPORTED_ALGORITHMS:
            if not _identifiers_ok(args.tenant_id, None):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_CREATE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if not args.tenant_id:
                return _fail("field tenant_id must be a non-empty string", 2)
            return _fail(
                "unsupported value for field algorithm: %r (supported: %s)"
                % (args.algorithm, ", ".join(SUPPORTED_ALGORITHMS)),
                2,
            )
        if not allowed(audit_mod.ACTION_CREATE):
            return _deny(store, args.tenant_id, None, audit_mod.ACTION_CREATE)
        try:
            record = store.create(args.tenant_id, args.algorithm, args.label)
        except LedgerError as exc:
            return _ledger_fail(exc)
        _print(record.to_create_response())
        return 0

    if args.command in ("show", "current"):
        if not is_valid_key_id(args.key_id):
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            return _fail("field key_id must be a UUID4", 2)
        if not allowed(audit_mod.ACTION_READ):
            return _deny(store, args.tenant_id, args.key_id,
                         audit_mod.ACTION_READ)
        record = store.get(args.key_id, args.tenant_id)
        if record is None:
            if not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_READ, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("key not found", 4)
        if not _attempt(
            store, args.tenant_id, args.key_id,
            audit_mod.ACTION_READ, audit_mod.OUTCOME_SUCCESS,
        ):
            return 1
        if args.command == "show":
            _print(record.to_get_response())
        else:
            _print(record.current.to_version_response(args.key_id))
        return 0

    if args.command == "rotate":
        # The Idempotency-Key is validated before any other parameter (and
        # before the binding/execution): a malformed key is an exit-2 error
        # with no audit event, operation record, key change or provider
        # handle -- exactly like the HTTP endpoint.
        if _idem_key_error(args.idempotency_key):
            return 2
        if not args.tenant_id:
            return _fail("field tenant_id must be a non-empty string", 2)
        if not is_valid_key_id(args.key_id):
            return _fail("field key_id must be a UUID4", 2)
        if args.algorithm not in SUPPORTED_ALGORITHMS:
            return _fail(
                "unsupported value for field algorithm: %r (supported: %s)"
                % (args.algorithm, ", ".join(SUPPORTED_ALGORITHMS)),
                2,
            )

        body = {
            "tenant_id": args.tenant_id,
            "algorithm": args.algorithm,
        }
        path = "/v1/keys/%s/rotate" % args.key_id

        def execute(operation):
            # Kind/exact key_id are durable before the authorization check so
            # a 403 terminal replays from context alone after a crash.
            op_store.update_details(
                operation,
                {"kind": "rotate", "key_id": args.key_id,
                 "algorithm": args.algorithm},
            )
            register_artifacts(
                operation,
                journal=operation.operation_id,
                write_set=[args.key_id],
                marker="key:" + args.key_id,
            )
            if not policies.is_allowed(
                args.tenant_id, audit_mod.ACTION_ROTATE, args.operator
            ):
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, args.key_id,
                    audit_mod.ACTION_ROTATE, 403,
                    "action not permitted by policy",
                )

            def stage_success(committed_record):
                body = committed_record.to_rotate_response()
                body["operation_id"] = operation.operation_id
                op_store.stage_terminal(operation, 201, body)

            record = store.rotate(
                args.key_id, args.tenant_id, args.algorithm,
                event_id=operation.operation_id,
                lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                pre_commit=stage_success,
                on_handle=handle_cb(operation),
            )
            if record is None:
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, args.key_id,
                    audit_mod.ACTION_ROTATE, 404, "key not found",
                )
            return 201, record.to_rotate_response()

        return idempotent_run(
            op_store, store, path, args.tenant_id, args.operator, body,
            args.idempotency_key, lambda: None, execute,
        )

    if args.command == "batch-rotate":
        # The Idempotency-Key is validated before anything else; a malformed
        # key exits 2 with no audit event, operation record, key change or
        # provider handle -- exactly like the HTTP endpoint.
        if _idem_key_error(args.idempotency_key):
            return 2
        if not args.tenant_id:
            return _fail("field tenant_id must be a non-empty string", 2)
        # Parse/validate the items array before the binding lookup. These
        # checks are side-effect free (the HTTP endpoint does the same before
        # its idempotent guard): a refusal exits 2 with no audit event and
        # never consumes the key.
        try:
            raw_items = json.loads(args.items)
        except ValueError:
            return _fail("field items must be valid JSON", 2)
        items, message = validate_batch_items(raw_items)
        if message is not None:
            return _fail(message, 2)

        body = {"tenant_id": args.tenant_id, "items": raw_items}
        path = "/v1/keys/batch-rotate"

        def execute(operation):
            # Kind/exact request-order item set durable before any business
            # check, so a 403/404 terminal replays from context alone.
            op_store.update_details(
                operation,
                {
                    "kind": "batch_rotate",
                    "items": [
                        {"key_id": key_id, "algorithm": algorithm}
                        for key_id, algorithm in items
                    ],
                },
            )
            register_artifacts(
                operation,
                write_set=[key_id for key_id, _ in items],
                marker="batch_rotate",
            )
            # Authorization follows rotate; the rejection event is a single
            # batch_rotate with key_id null.
            if not policies.is_allowed(
                args.tenant_id, audit_mod.ACTION_ROTATE, args.operator
            ):
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, None,
                    audit_mod.ACTION_BATCH_ROTATE, 403,
                    "action not permitted by policy",
                )

            def stage_success(records_by_id):
                op_store.stage_terminal(
                    operation,
                    201,
                    {
                        "items": [
                            {
                                "key_id": key_id,
                                "version": records_by_id[key_id].current.version,
                                "algorithm": records_by_id[key_id].current.algorithm,
                                "public_key": records_by_id[key_id].current.public_key,
                            }
                            for key_id, _ in items
                        ],
                        "operation_id": operation.operation_id,
                    },
                )

            status, result = store.batch_rotate(
                args.tenant_id, items,
                event_id=operation.operation_id,
                lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                pre_commit=stage_success,
                on_handle=handle_cb(operation),
                on_group=group_cb(operation),
            )
            if status == store.BATCH_NOT_FOUND:
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, None,
                    audit_mod.ACTION_BATCH_ROTATE, 404, "key not found",
                )
            return (
                201,
                {
                    "items": [
                        {
                            "key_id": key_id,
                            "version": record.current.version,
                            "algorithm": record.current.algorithm,
                            "public_key": record.current.public_key,
                        }
                        for key_id, record in result
                    ]
                },
            )

        return idempotent_run(
            op_store, store, path, args.tenant_id, args.operator, body,
            args.idempotency_key, lambda: None, execute,
        )

    if args.command == "version":
        if not is_valid_key_id(args.key_id):
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            return _fail("field key_id must be a UUID4", 2)
        if not allowed(audit_mod.ACTION_READ):
            return _deny(store, args.tenant_id, args.key_id,
                         audit_mod.ACTION_READ)
        result = store.get_version(
            args.key_id, args.tenant_id, args.version
        )
        if result is None:
            if not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_READ, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("version not found", 4)
        if not _attempt(
            store, args.tenant_id, args.key_id,
            audit_mod.ACTION_READ, audit_mod.OUTCOME_SUCCESS,
        ):
            return 1
        _record, ver = result
        _print(ver.to_version_response(args.key_id))
        return 0

    if args.command == "revoke":
        if not args.tenant_id or not args.reason:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_REVOKE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if not args.tenant_id:
                return _fail("field tenant_id must be a non-empty string", 2)
            return _fail("field reason must be a non-empty string", 2)
        if not is_valid_key_id(args.key_id):
            if not _conflict(store):
                return 1
            return _fail("field key_id must be a UUID4", 2)
        if not allowed(audit_mod.ACTION_REVOKE):
            return _deny(store, args.tenant_id, args.key_id,
                         audit_mod.ACTION_REVOKE)
        try:
            record = store.revoke(
                args.key_id, args.tenant_id, args.reason, args.operator
            )
        except LedgerError as exc:
            return _ledger_fail(exc)
        if record is None:
            if not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_REVOKE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("key not found", 4)
        _print(record.to_status_response())
        return 0

    if args.command == "status":
        if not is_valid_key_id(args.key_id):
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            return _fail("field key_id must be a UUID4", 2)
        if not allowed(audit_mod.ACTION_READ):
            return _deny(store, args.tenant_id, args.key_id,
                         audit_mod.ACTION_READ)
        record = store.get(args.key_id, args.tenant_id)
        if record is None:
            if not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_READ, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("key not found", 4)
        if not _attempt(
            store, args.tenant_id, args.key_id,
            audit_mod.ACTION_READ, audit_mod.OUTCOME_SUCCESS,
        ):
            return 1
        _print(record.to_status_response())
        return 0

    if args.command == "export":
        if not args.tenant_id or not args.passphrase:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_EXPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail(
                "field passphrase must be a non-empty string", 2
            )
        if not is_valid_key_id(args.key_id):
            if not _conflict(store):
                return 1
            return _fail("field key_id must be a UUID4", 2)
        if not allowed(audit_mod.ACTION_EXPORT):
            return _deny(store, args.tenant_id, args.key_id,
                         audit_mod.ACTION_EXPORT)
        try:
            bundle = store.export_bundle(
                args.key_id, args.tenant_id, args.passphrase
            )
        except LedgerError as exc:
            return _ledger_fail(exc)
        if bundle is None:
            if not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_EXPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("key not found", 4)
        if not _attempt(
            store, args.tenant_id, args.key_id,
            audit_mod.ACTION_EXPORT, audit_mod.OUTCOME_SUCCESS,
        ):
            return 1
        _print({"format": keybundle.FORMAT, "bundle": bundle})
        return 0

    if args.command == "import":
        # The Idempotency-Key is validated first: a malformed key exits 2
        # with no side effect.
        if _idem_key_error(args.idempotency_key):
            return 2
        body = {
            "tenant_id": args.tenant_id,
            "passphrase": args.passphrase,
            "bundle": args.bundle,
        }
        path = "/v1/keys/import"
        decoded = {}

        def validator():
            # Cheap request-field checks, before the binding lookup. A
            # refusal is a plain exit-2 error with no audit event and never
            # consumes the key (mirrors the HTTP endpoint).
            if not args.tenant_id:
                return (2, "field tenant_id must be a non-empty string")
            if not args.passphrase:
                return (2, "field passphrase must be a non-empty string")
            if not args.bundle:
                return (2, "field bundle must be a non-empty string")
            return None

        def decoder():
            # Side-effect-free decryption after the replay precheck but
            # before the key is bound: a wrong passphrase/tampered bundle
            # exits 2 without an audit event and without consuming the key.
            try:
                payload = keybundle.decode_bundle(
                    args.bundle, args.passphrase
                )
            except keybundle.BundleError as exc:
                return (2, str(exc))
            decoded.update(payload)
            return None

        def execute(operation):
            key_id = decoded["key_id"]
            # Kind/exact key_id durable before any business check.
            op_store.update_details(
                operation,
                {"kind": "import", "key_id": key_id},
            )
            register_artifacts(
                operation,
                journal=operation.operation_id,
                write_set=[key_id],
                marker="key:" + key_id,
            )
            if not policies.is_allowed(
                args.tenant_id, audit_mod.ACTION_IMPORT, args.operator
            ):
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, key_id,
                    audit_mod.ACTION_IMPORT, 403,
                    "action not permitted by policy",
                )

            def stage_success(committed_record):
                body = committed_record.to_create_response()
                body["operation_id"] = operation.operation_id
                op_store.stage_terminal(operation, 201, body)

            status, record = store.import_bundle(
                args.tenant_id, decoded,
                event_id=operation.operation_id,
                lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                pre_commit=stage_success,
                on_handle=handle_cb(operation),
            )
            if status == IMPORT_CONFLICT:
                if record.tenant_id == args.tenant_id:
                    return _terminal_rejection(
                        op_store, store, operation,
                        args.tenant_id, record.key_id,
                        audit_mod.ACTION_IMPORT, 409,
                        "key_id already exists for this tenant",
                    )
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, record.key_id,
                    audit_mod.ACTION_IMPORT, 404, "key not found",
                )
            return 201, record.to_create_response()

        return idempotent_run(
            op_store, store, path, args.tenant_id, args.operator, body,
            args.idempotency_key, validator, execute, decoder,
        )

    if args.command == "backup":
        if not args.tenant_id or not args.passphrase:
            if not _identifiers_ok(args.tenant_id, None):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_EXPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if not args.tenant_id:
                return _fail("field tenant_id must be a non-empty string", 2)
            return _fail(
                "field passphrase must be a non-empty string", 2
            )
        if not allowed(audit_mod.ACTION_EXPORT):
            return _deny(store, args.tenant_id, None,
                         audit_mod.ACTION_EXPORT)
        try:
            bundle = coordinator.backup_bundle(
                args.tenant_id, args.passphrase
            )
        except LedgerError as exc:
            return _ledger_fail(exc)
        if not _attempt(
            store, args.tenant_id, None,
            audit_mod.ACTION_EXPORT, audit_mod.OUTCOME_SUCCESS,
        ):
            return 1
        _print({"format": tenantbundle.FORMAT, "bundle": bundle})
        return 0

    if args.command == "restore":
        # The Idempotency-Key is validated first: a malformed key exits 2
        # with no side effect.
        if _idem_key_error(args.idempotency_key):
            return 2
        body = {
            "tenant_id": args.tenant_id,
            "passphrase": args.passphrase,
            "bundle": args.bundle,
        }
        path = "/v1/restore"
        decoded = {}

        def validator():
            # Cheap request-field checks, before the binding lookup; a
            # refusal is an exit-2 error with no audit event and never
            # consumes the key.
            if not args.tenant_id:
                return (2, "field tenant_id must be a non-empty string")
            if not args.passphrase:
                return (2, "field passphrase must be a non-empty string")
            if not args.bundle:
                return (2, "field bundle must be a non-empty string")
            return None

        def decoder():
            # Side-effect-free decryption after the replay precheck but
            # before the key is bound; failures exit 2 without an audit
            # event and without consuming the key.
            try:
                payload = tenantbundle.decode_bundle(
                    args.bundle, args.passphrase
                )
            except tenantbundle.TenantBundleError as exc:
                return (2, str(exc))
            decoded.update(payload)
            return None

        def execute(operation):
            key_ids = sorted(k["key_id"] for k in decoded["keys"])
            writes_policy = decoded["policy"] is not None
            # Kind/write-set durable before any business check; restore
            # events project key_id null via the rejection helper.
            op_store.update_details(
                operation,
                {
                    "kind": "restore",
                    "key_ids": key_ids,
                    "policy_restored": writes_policy,
                },
            )
            register_artifacts(
                operation,
                write_set=list(key_ids),
                marker="restore",
            )
            if not policies.is_allowed(
                args.tenant_id, audit_mod.ACTION_IMPORT, args.operator
            ):
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, None,
                    audit_mod.ACTION_IMPORT, 403,
                    "action not permitted by policy",
                )
            if decoded["tenant_id"] != args.tenant_id:
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, None,
                    audit_mod.ACTION_IMPORT, 404,
                    "tenant backup not found",
                )

            def stage_success():
                body = {
                    "tenant_id": args.tenant_id,
                    "key_ids": key_ids,
                    "policy_restored": writes_policy,
                    "operation_id": operation.operation_id,
                }
                op_store.stage_terminal(operation, 201, body)

            result = coordinator.restore(
                args.tenant_id, decoded,
                event_id=operation.operation_id,
                lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                pre_commit=stage_success,
                on_handle=handle_cb(operation),
                on_group=group_cb(operation),
            )
            if result.status == restore_mod.RESTORE_CREATED:
                return (
                    201,
                    {
                        "tenant_id": result.tenant_id,
                        "key_ids": result.key_ids,
                        "policy_restored": result.policy_restored,
                    },
                )
            if result.status == restore_mod.RESTORE_SAME_TENANT_CONFLICT:
                return _terminal_rejection(
                    op_store, store, operation,
                    args.tenant_id, None,
                    audit_mod.ACTION_IMPORT, 409,
                    "backup target already contains this data",
                )
            return _terminal_rejection(
                op_store, store, operation,
                args.tenant_id, None,
                audit_mod.ACTION_IMPORT, 404,
                "tenant backup not found",
            )

        return idempotent_run(
            op_store, store, path, args.tenant_id, args.operator, body,
            args.idempotency_key, validator, execute, decoder,
        )

    if args.command == "operation":
        if not args.tenant_id:
            return _fail("field tenant_id must be a non-empty string", 2)
        record = op_store.get(
            args.operation_id, args.tenant_id, args.operator
        )
        if record is None:
            # Unknown, malformed, another tenant's or another operator's
            # operation all look identical: never leak existence.
            return _fail("operation not found", 4)
        _print(record.to_status_response())
        return 0

    if args.command == "audit":
        if not args.tenant_id:
            return _fail("field tenant_id must be a non-empty string", 2)
        if args.key_id is not None and not is_valid_key_id(args.key_id):
            return _fail("field key_id must be a UUID4", 2)
        if args.action is not None and args.action not in audit_mod.ACTIONS:
            return _fail(
                "field action must be one of: %s"
                % ", ".join(audit_mod.ACTIONS),
                2,
            )
        if not 1 <= args.limit <= 1000:
            return _fail(
                "field limit must be an integer between 1 and 1000", 2
            )
        if not allowed(audit_mod.ACTION_AUDIT):
            if not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_AUDIT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("action not permitted by policy", 3)
        try:
            page = store.audit.query(
                args.tenant_id,
                key_id=args.key_id,
                action=args.action,
                limit=args.limit,
                cursor=args.cursor,
            )
        except InvalidCursor:
            return _fail("invalid or expired cursor", 2)
        except LedgerError as exc:
            return _ledger_fail(exc)
        _print(
            {
                "events": [e.to_response() for e in page.events],
                "next_cursor": page.next_cursor,
            }
        )
        return 0

    if args.command == "policy":
        return _policy_command(args, policies)

    return 2  # pragma: no cover - argparse enforces choices


def _policy_command(args, policies: PolicyStore) -> int:
    """Handle `policy show|set|delete`; management is exempt from policy."""
    tenant_id = args.tenant_id
    if not tenant_id:
        return _fail("field tenant_id must be a non-empty string", 2)

    if args.policy_command == "show":
        rules = policies.get(tenant_id)
        if rules is None:
            return _fail("policy not found", 4)
        try:
            policies.audit_read(tenant_id)
        except LedgerError as exc:
            return _ledger_fail(exc)
        _print(
            {"tenant_id": tenant_id,
             "rules": [r.to_json() for r in rules]}
        )
        return 0

    if args.policy_command == "set":
        try:
            raw = json.loads(args.rules)
        except ValueError:
            return _fail("field rules must be valid JSON", 2)
        try:
            rules = validate_rules(raw)
        except PolicyError as exc:
            return _fail(str(exc), 2)
        try:
            policies.put(tenant_id, rules)
        except LedgerError as exc:
            return _ledger_fail(exc)
        _print(
            {"tenant_id": tenant_id,
             "rules": [r.to_json() for r in rules]}
        )
        return 0

    # policy delete
    try:
        policies.delete(tenant_id)
    except LedgerError as exc:
        return _ledger_fail(exc)
    _print({"tenant_id": tenant_id, "deleted": True})
    return 0

