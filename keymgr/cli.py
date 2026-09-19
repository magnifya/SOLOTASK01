"""Command-line interface: `gen` and `show` subcommands."""

import argparse
import json
import os
import re
import sys
from typing import List, Optional

from . import audit as audit_mod
from . import keybundle
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .policy import InvalidPolicy, PolicyStore, validate_rules
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

    p_gen = sub.add_parser("gen", help="generate a new key")
    p_gen.add_argument("--tenant-id", required=True)
    p_gen.add_argument("--algorithm", required=True,
                       help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))
    p_gen.add_argument("--label", required=True)

    p_show = sub.add_parser("show", help="show an existing key")
    p_show.add_argument("--tenant-id", required=True)
    p_show.add_argument("--key-id", required=True)

    p_rotate = sub.add_parser("rotate", help="rotate a key to a new version")
    p_rotate.add_argument("--tenant-id", required=True)
    p_rotate.add_argument("--key-id", required=True)
    p_rotate.add_argument("--algorithm", required=True,
                          help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))

    p_version = sub.add_parser("version", help="show a specific key version")
    p_version.add_argument("--tenant-id", required=True)
    p_version.add_argument("--key-id", required=True)
    p_version.add_argument("--version", required=True, type=_positive_int)

    p_current = sub.add_parser("current", help="show the current key version")
    p_current.add_argument("--tenant-id", required=True)
    p_current.add_argument("--key-id", required=True)

    p_revoke = sub.add_parser("revoke", help="revoke a key")
    p_revoke.add_argument("--tenant-id", required=True)
    p_revoke.add_argument("--key-id", required=True)
    p_revoke.add_argument("--reason", required=True)
    p_revoke.add_argument("--operator", required=True)

    p_status = sub.add_parser("status", help="show a key's revocation status")
    p_status.add_argument("--tenant-id", required=True)
    p_status.add_argument("--key-id", required=True)

    p_export = sub.add_parser("export", help="export a key as an encrypted bundle")
    p_export.add_argument("--tenant-id", required=True)
    p_export.add_argument("--key-id", required=True)
    p_export.add_argument("--passphrase", required=True)

    p_import = sub.add_parser("import", help="import a key from an encrypted bundle")
    p_import.add_argument("--tenant-id", required=True)
    p_import.add_argument("--passphrase", required=True)
    p_import.add_argument("--bundle", required=True)

    p_audit = sub.add_parser("audit", help="list a tenant's audit events")
    p_audit.add_argument("--tenant-id", required=True)
    p_audit.add_argument("--key-id", default=None,
                         help="filter to one key_id (must be a UUID4)")
    p_audit.add_argument("--action", default=None,
                         help="one of: %s" % ", ".join(audit_mod.ACTIONS))
    p_audit.add_argument("--limit", type=int, default=100,
                         help="page size, 1-1000 (default: %(default)s)")
    p_audit.add_argument("--cursor", default=None,
                         help="pagination cursor from a previous response")

    p_policy = sub.add_parser("policy", help="manage a tenant's action policy")
    pol_sub = p_policy.add_subparsers(dest="policy_command", required=True)

    p_pol_show = pol_sub.add_parser("show", help="show a tenant's policy")
    p_pol_show.add_argument("--tenant-id", required=True)
    p_pol_show.add_argument("--operator", required=True)

    p_pol_set = pol_sub.add_parser("set", help="create or replace a policy")
    p_pol_set.add_argument("--tenant-id", required=True)
    p_pol_set.add_argument("--operator", required=True)
    p_pol_set.add_argument("--rules", required=True,
                           help="JSON array of rules, e.g. "
                                '\'[{"subject":"alice","actions":["read"],'
                                '"effect":"allow"}]\'')

    p_pol_del = pol_sub.add_parser("delete", help="delete a tenant's policy")
    p_pol_del.add_argument("--tenant-id", required=True)
    p_pol_del.add_argument("--operator", required=True)

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


def _run_policy(args, store, policies) -> int:
    """Handle `policy show|set|delete`; returns a process exit code.

    Exit codes mirror the HTTP layer: 2 for bad parameters/rules, 4 when no
    policy exists (show/delete), and 1 for a ledger failure. Output is a
    single-line JSON object identical in shape to the HTTP responses.
    """
    tenant_id = args.tenant_id
    operator = args.operator
    sub = args.policy_command

    if sub == "show":
        record = policies.get(tenant_id)
        if record is None:
            if not _attempt(
                store, tenant_id, None,
                audit_mod.ACTION_POLICY_READ, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("policy not found", 4)
        if not _attempt(
            store, tenant_id, None,
            audit_mod.ACTION_POLICY_READ, audit_mod.OUTCOME_SUCCESS,
        ):
            return 1
        _print(record.to_response())
        return 0

    if sub == "set":
        try:
            raw_rules = json.loads(args.rules)
        except ValueError:
            if not _attempt(
                store, tenant_id, None,
                audit_mod.ACTION_POLICY_UPDATE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail("field rules must be valid JSON", 2)
        try:
            rules = validate_rules(raw_rules)
        except InvalidPolicy as exc:
            if not _attempt(
                store, tenant_id, None,
                audit_mod.ACTION_POLICY_UPDATE, audit_mod.OUTCOME_REJECTED,
            ):
                return 1
            return _fail(str(exc), 2)
        try:
            record = policies.set(tenant_id, rules, operator)
        except LedgerError as exc:
            return _ledger_fail(exc)
        _print(record.to_response())
        return 0

    # delete
    try:
        deleted = policies.delete(tenant_id, operator)
    except LedgerError as exc:
        return _ledger_fail(exc)
    if not deleted:
        if not _attempt(
            store, tenant_id, None,
            audit_mod.ACTION_POLICY_DELETE, audit_mod.OUTCOME_REJECTED,
        ):
            return 1
        return _fail("policy not found", 4)
    _print({"tenant_id": tenant_id, "deleted": True})
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns a process exit code."""
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        serve(args.host, args.port, args.data_dir)
        return 0

    store = KeyStore(args.data_dir)

    if args.command == "policy":
        policies = PolicyStore(args.data_dir, store.audit)
        return _run_policy(args, store, policies)

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
        try:
            record = store.create(args.tenant_id, args.algorithm, args.label)
        except LedgerError as exc:
            return _ledger_fail(exc)
        _print(record.to_create_response())
        return 0

    if args.command in ("show", "current"):
        record = store.get(args.key_id, args.tenant_id)
        if record is None:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
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
        result = store.get_version(
            args.key_id, args.tenant_id, args.version
        )
        if result is None:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
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
        if not args.tenant_id or not args.reason or not args.operator:
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
            field = "reason" if not args.reason else "operator"
            return _fail(
                "field %s must be a non-empty string" % field, 2
            )
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
        record = store.get(args.key_id, args.tenant_id)
        if record is None:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
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
        try:
            bundle = store.export_bundle(
                args.key_id, args.tenant_id, args.passphrase
            )
        except LedgerError as exc:
            return _ledger_fail(exc)
        if bundle is None:
            if not _identifiers_ok(args.tenant_id, args.key_id):
                if not _conflict(store):
                    return 1
            elif not _attempt(
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
        try:
            status, record = store.import_bundle(args.tenant_id, payload)
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

    return 2  # pragma: no cover - argparse enforces choices
