"""HTTP service exposing POST/GET /v1/keys."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .crypto import SUPPORTED_ALGORITHMS
from .store import KeyStore

_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_REQUIRED_FIELDS = ("tenant_id", "algorithm", "label")


def make_handler(store: KeyStore) -> type:
    """Build a BaseHTTPRequestHandler subclass bound to the store."""

    class KeyHandler(BaseHTTPRequestHandler):
        server_version = "KeyMgr/1.0"

        # -- helpers ------------------------------------------------------
        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _bad_request(self, message: str) -> None:
            self._send_json(400, {"error": message})

        def log_message(self, fmt, *args):  # silence default stderr logging
            return

        # -- routes -------------------------------------------------------
        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/v1/keys":
                self._send_json(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self._bad_request("invalid Content-Length")
                return
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._bad_request("request body must be valid JSON")
                return
            if not isinstance(payload, dict):
                self._bad_request("request body must be a JSON object")
                return

            for field in _REQUIRED_FIELDS:
                if field not in payload:
                    self._bad_request("missing required field: %s" % field)
                    return
                if not isinstance(payload[field], str):
                    self._bad_request("field %s must be a string" % field)
                    return

            algorithm = payload["algorithm"]
            if algorithm not in SUPPORTED_ALGORITHMS:
                self._bad_request(
                    "unsupported value for field algorithm: %r (supported: %s)"
                    % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
                )
                return

            record = store.create(
                tenant_id=payload["tenant_id"],
                algorithm=algorithm,
                label=payload["label"],
            )
            self._send_json(201, record.to_create_response())

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            match = _KEY_PATH_RE.match(parts.path)
            if match is None:
                self._send_json(404, {"error": "not found"})
                return

            key_id = match.group(1)
            tenant_id = self.headers.get("X-Tenant-Id")
            if tenant_id is None:
                query = parse_qs(parts.query).get("tenant_id")
                tenant_id = query[0] if query else None
            if not tenant_id:
                self._bad_request("missing required field: tenant_id")
                return

            record = store.get(key_id, tenant_id)
            if record is None:
                # Same status whether the key is missing or owned by another
                # tenant: never confirm the existence of another tenant's key.
                self._send_json(404, {"error": "key not found"})
                return

            self._send_json(200, record.to_get_response())

    return KeyHandler


def serve(host: str, port: int, data_dir: str) -> None:
    """Run the HTTP server until interrupted."""
    store = KeyStore(data_dir)
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
