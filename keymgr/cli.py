"""Command-line interface: `gen` and `show` subcommands."""

import argparse
import json
import os
import re
import sys
from typing import List, Optional

from . import audit as audit_mod
from . import keybundle
from . import restore as restore_mod
from . import tenantbundle
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .policy import PolicyError, PolicyStore, validate_rules
from .provider import ProviderInvalidMaterial, ProviderUnavailable
from .server import serve
from .store import IMPORT_CONFLICT, KeyStore, is_valid_key_id

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

    p_backup = tenant_parser(
        "backup", help="back up all of a tenant's keys and policy"
    )
    p_backup.add_argument("--passphrase", required=True)

    p_restore = tenant_parser(
        "restore", help="restore a tenant from an encrypted backup bundle"
    )
    p_restore.add_argument("--passphrase", required=True)
    p_restore.add_argument("--bundle", required=True)

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
        if not args.tenant_id or args.algorithm not in SUPPORTED_ALGORITHMS:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_ROTATE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if not args.tenant_id:
                return _fail("field tenant_id must be a non-empty string", 2)
            return _fail(
                "unsupported value for field algorithm: %r (supported: %s)"
                % (args.algorithm, ", ".join(SUPPORTED_ALGORITHMS)),
                2,
            )
        if not is_valid_key_id(args.key_id):
            if not _conflict(store):
                return 1
            return _fail("field key_id must be a UUID4", 2)
        if not allowed(audit_mod.ACTION_ROTATE):
            return _deny(store, args.tenant_id, args.key_id,
                         audit_mod.ACTION_ROTATE)
        try:
            record = store.rotate(
                args.key_id, args.tenant_id, args.algorithm
            )
        except LedgerError as exc:
            return _ledger_fail(exc)
        if record is None:
            if not _attempt(
                store, args.tenant_id, args.key_id,
                audit_mod.ACTION_ROTATE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("key not found", 4)
        _print(record.to_rotate_response())
        return 0

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
        if not args.tenant_id or not args.passphrase or not args.bundle:
            # Until the bundle decrypts the key_id is unknown, so a rejected
            # import carries a null key_id and is visible to this tenant.
            if not _identifiers_ok(args.tenant_id, None):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if not args.tenant_id:
                return _fail("field tenant_id must be a non-empty string", 2)
            field = "passphrase" if not args.passphrase else "bundle"
            return _fail(
                "field %s must be a non-empty string" % field, 2
            )
        try:
            payload = keybundle.decode_bundle(
                args.bundle, args.passphrase
            )
        except keybundle.BundleError as exc:
            if not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail(str(exc), 2)
        if not allowed(audit_mod.ACTION_IMPORT):
            return _deny(store, args.tenant_id, payload["key_id"],
                         audit_mod.ACTION_IMPORT)
        try:
            status, record = store.import_bundle(args.tenant_id, payload)
        except ProviderInvalidMaterial as exc:
            # Authentic bundle, malformed material: a rejected import.
            if not _attempt(
                store, args.tenant_id, payload["key_id"],
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail(str(exc), 2)
        except LedgerError as exc:
            return _ledger_fail(exc)
        if status == IMPORT_CONFLICT:
            if not _attempt(
                store, args.tenant_id, record.key_id,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if record.tenant_id == args.tenant_id:
                return _fail(
                    "key_id already exists for this tenant", 3
                )
            return _fail("key not found", 4)
        # The success event committed together with the imported key file.
        _print(record.to_create_response())
        return 0

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
        if not args.tenant_id or not args.passphrase or not args.bundle:
            if not _identifiers_ok(args.tenant_id, None):
                if not _conflict(store):
                    return 1
            elif not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            if not args.tenant_id:
                return _fail("field tenant_id must be a non-empty string", 2)
            field = "passphrase" if not args.passphrase else "bundle"
            return _fail(
                "field %s must be a non-empty string" % field, 2
            )
        try:
            payload = tenantbundle.decode_bundle(
                args.bundle, args.passphrase
            )
        except tenantbundle.TenantBundleError as exc:
            if not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail(str(exc), 2)
        if not allowed(audit_mod.ACTION_IMPORT):
            return _deny(store, args.tenant_id, None,
                         audit_mod.ACTION_IMPORT)
        if payload["tenant_id"] != args.tenant_id:
            if not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("tenant backup not found", 4)
        try:
            result = coordinator.restore(args.tenant_id, payload)
        except ProviderInvalidMaterial as exc:
            # Authentic bundle, malformed material: a rejected import
            # (key_id null, like every restore event).
            if not _attempt(
                store, args.tenant_id, None,
                audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail(str(exc), 2)
        except LedgerError as exc:
            return _ledger_fail(exc)
        if result.status == restore_mod.RESTORE_CREATED:
            _print(
                {
                    "tenant_id": result.tenant_id,
                    "key_ids": result.key_ids,
                    "policy_restored": result.policy_restored,
                }
            )
            return 0
        if not _attempt(
            store, args.tenant_id, None,
            audit_mod.ACTION_IMPORT, audit_mod.OUTCOME_REJECTED,
        ):
            return 1
        if result.status == restore_mod.RESTORE_SAME_TENANT_CONFLICT:
            return _fail("backup target already contains this data", 3)
        return _fail("tenant backup not found", 4)

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

