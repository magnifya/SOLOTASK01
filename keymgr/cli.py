"""Command-line interface: `gen` and `show` subcommands."""

import argparse
import json
import os
import re
import sys
from typing import List, Optional

from . import audit as audit_mod
from .audit import InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .server import serve
from .store import KeyStore, is_valid_key_id

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


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns a process exit code."""
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        serve(args.host, args.port, args.data_dir)
        return 0

    store = KeyStore(args.data_dir)

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
