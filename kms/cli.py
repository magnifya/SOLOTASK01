"""命令行入口：gen 与 show 子命令。"""

from __future__ import annotations

import argparse
import json
import sys

from .service import KeyService, ValidationError
from .store import KeyStore, DEFAULT_DATA_DIR


def build_parser() -> argparse.ArgumentParser:
    """构造命令行参数解析器。"""
    parser = argparse.ArgumentParser(prog="kms", description="多租户密钥管理工具")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                        help="密钥数据目录（默认：./kms_data）")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen", help="生成密钥（对应 POST /v1/keys）")
    gen.add_argument("--tenant-id", required=True)
    gen.add_argument("--algorithm", required=True)
    gen.add_argument("--label", required=True)

    show = sub.add_parser("show", help="查询密钥（对应 GET /v1/keys/{key_id}）")
    show.add_argument("--tenant-id", required=True)
    show.add_argument("--key-id", required=True)

    serve = sub.add_parser("serve", help="启动 HTTP 服务")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False))


def main(argv=None) -> int:
    """CLI 主入口，返回进程退出码。"""
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        from .server import run
        run(host=args.host, port=args.port, data_dir=args.data_dir)
        return 0

    service = KeyService(KeyStore(args.data_dir))

    if args.command == "gen":
        try:
            view = service.generate(args.tenant_id, args.algorithm, args.label)
        except ValidationError as exc:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
            return 2
        _print_json(view)
        return 0

    if args.command == "show":
        view = service.get(args.tenant_id, args.key_id)
        if view is None:
            print(json.dumps({"error": "key not found"}), file=sys.stderr)
            return 1
        _print_json({
            "algorithm": view["algorithm"],
            "label": view["label"],
            "created_at": view["created_at"],
            "public_key": view["public_key"],
        })
        return 0

    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
