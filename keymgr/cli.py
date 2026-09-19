"""Command-line interface: gen/show/rotate/version/current subcommands."""

import argparse
import json
import os
import re
import sys
from typing import List, Optional

from .crypto import SUPPORTED_ALGORITHMS
from .server import serve
from .store import KeyStore

DEFAULT_DATA_DIR = os.environ.get("KEYMGR_DATA_DIR", "keymgr_data")


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

    p_gen = sub.add_parser("gen", help="generate a new key (version 1)")
    p_gen.add_argument("--tenant-id", required=True)
    p_gen.add_argument("--algorithm", required=True,
                       help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))
    p_gen.add_argument("--label", required=True)

    p_show = sub.add_parser("show", help="show the current version of a key")
    p_show.add_argument("--tenant-id", required=True)
    p_show.add_argument("--key-id", required=True)

    p_rotate = sub.add_parser("rotate", help="rotate a key to a new version")
    p_rotate.add_argument("--tenant-id", required=True)
    p_rotate.add_argument("--key-id", required=True)
    p_rotate.add_argument("--algorithm", required=True,
                          help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))

    p_version = sub.add_parser("version", help="show a specific version")
    p_version.add_argument("--tenant-id", required=True)
    p_version.add_argument("--key-id", required=True)
    p_version.add_argument("--version", required=True)

    p_current = sub.add_parser("current", help="show the current version")
    p_current.add_argument("--tenant-id", required=True)
    p_current.add_argument("--key-id", required=True)

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


def _unsupported_algorithm(algorithm: str) -> int:
    return _fail(
        "unsupported value for field algorithm: %r (supported: %s)"
        % (algorithm, ", ".join(SUPPORTED_ALGORITHMS)),
        2,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns a process exit code."""
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        serve(args.host, args.port, args.data_dir)
        return 0

    store = KeyStore(args.data_dir)

    if args.command == "gen":
        if args.algorithm not in SUPPORTED_ALGORITHMS:
            return _unsupported_algorithm(args.algorithm)
        record = store.create(args.tenant_id, args.algorithm, args.label)
        _print(record.to_create_response())
        return 0

    if args.command == "show":
        record = store.get(args.key_id, args.tenant_id)
        if record is None:
            return _fail("key not found", 4)
        _print(record.to_get_response())
        return 0

    if args.command == "rotate":
        if args.algorithm not in SUPPORTED_ALGORITHMS:
            return _unsupported_algorithm(args.algorithm)
        record = store.rotate(args.key_id, args.tenant_id, args.algorithm)
        if record is None:
            return _fail("key not found", 4)
        _print(record.to_rotate_response())
        return 0

    if args.command == "version":
        # Same strict rule as the HTTP path: digits only, no sign, no zero.
        if not re.fullmatch(r"[1-9][0-9]*", args.version):
            return _fail(
                "field version must be a positive integer: %r" % args.version,
                2,
            )
        version_number = int(args.version)
        record = store.get_version(
            args.key_id, args.tenant_id, version_number
        )
        if record is None:
            return _fail("key not found", 4)
        _print(record.to_version_response(version_number))
        return 0

    if args.command == "current":
        record = store.get_current(args.key_id, args.tenant_id)
        if record is None:
            return _fail("key not found", 4)
        _print(record.to_current_response())
        return 0

    return 2  # pragma: no cover - argparse enforces choices
