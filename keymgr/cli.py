"""Command-line interface: `gen` and `show` subcommands."""

import argparse
import json
import os
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

    p_gen = sub.add_parser("gen", help="generate a new key")
    p_gen.add_argument("--tenant-id", required=True)
    p_gen.add_argument("--algorithm", required=True,
                       help="one of: %s" % ", ".join(SUPPORTED_ALGORITHMS))
    p_gen.add_argument("--label", required=True)

    p_show = sub.add_parser("show", help="show an existing key")
    p_show.add_argument("--tenant-id", required=True)
    p_show.add_argument("--key-id", required=True)

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


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns a process exit code."""
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        serve(args.host, args.port, args.data_dir)
        return 0

    store = KeyStore(args.data_dir)

    if args.command == "gen":
        if args.algorithm not in SUPPORTED_ALGORITHMS:
            return _fail(
                "unsupported value for field algorithm: %r (supported: %s)"
                % (args.algorithm, ", ".join(SUPPORTED_ALGORITHMS)),
                2,
            )
        record = store.create(args.tenant_id, args.algorithm, args.label)
        _print(record.to_create_response())
        return 0

    if args.command == "show":
        record = store.get(args.key_id, args.tenant_id)
        if record is None:
            return _fail("key not found", 4)
        _print(record.to_get_response())
        return 0

    return 2  # pragma: no cover - argparse enforces choices
