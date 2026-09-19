"""基于标准库 http.server 的 HTTP 服务。"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .service import KeyService, ValidationError, validate_generate_request
from .store import KeyStore, DEFAULT_DATA_DIR

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080

_KEY_PATH = re.compile(r"^/v1/keys/([^/]+)$")


def make_handler(service: KeyService) -> type:
    """构造绑定指定 service 的请求处理类。"""

    class KeyHandler(BaseHTTPRequestHandler):
        server_version = "kms/0.1"

        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, message: str) -> None:
            self._send_json(status, {"error": message})

        def do_POST(self) -> None:  # noqa: N802（标准库命名）
            if urlparse(self.path).path != "/v1/keys":
                return self._error(404, "not found")
            try:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"")
            except (ValueError, json.JSONDecodeError):
                return self._error(400, "request body must be valid JSON")
            try:
                tenant_id, algorithm, label = validate_generate_request(payload)
            except ValidationError as exc:
                return self._error(400, str(exc))
            view = service.generate(tenant_id, algorithm, label)
            self._send_json(201, view)

        def do_GET(self) -> None:  # noqa: N802（标准库命名）
            parsed = urlparse(self.path)
            match = _KEY_PATH.match(parsed.path)
            if not match:
                return self._error(404, "not found")
            tenant_id = parse_qs(parsed.query).get("tenant_id", [None])[0]
            if not tenant_id:
                return self._error(400, "missing required field: tenant_id")
            view = service.get(tenant_id, match.group(1))
            if view is None:
                return self._error(404, "key not found")
            self._send_json(200, {
                "algorithm": view["algorithm"],
                "label": view["label"],
                "created_at": view["created_at"],
                "public_key": view["public_key"],
            })

        def log_message(self, fmt, *args) -> None:  # 保持静默，便于测试
            pass

    return KeyHandler


def run(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
        data_dir: str = None) -> None:
    """启动 HTTP 服务。"""
    service = KeyService(KeyStore(data_dir or DEFAULT_DATA_DIR))
    httpd = ThreadingHTTPServer((host, port), make_handler(service))
    print(f"kms listening on http://{host}:{port} (data: {httpd and service.store.data_dir})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
