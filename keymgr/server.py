"""HTTP service exposing key generation, lookup, rotation and versions."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .crypto import SUPPORTED_ALGORITHMS
from .store import KeyStore

_CREATE_REQUIRED_FIELDS = ("tenant_id", "algorithm", "label")
_ROTATE_REQUIRED_FIELDS = ("tenant_id", "algorithm")

_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_VERSIONS_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
# A version number in the path must be a positive integer (no sign, no
# leading zero tricks); anything else is a 400 on field "version".
_POSITIVE_INT_RE = re.compile(r"^[1-9][0-9]*$")


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

        def _not_found(self) -> None:
            # Same status whether the key/version is missing or owned by
            # another tenant: never confirm the existence of foreign data.
            self._send_json(404, {"error": "key not found"})

        def log_message(self, fmt, *args):  # silence default stderr logging
            return

        def _read_json_object(self):
            """Return the request body dict, or send 400 and return None."""
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self._bad_request("invalid Content-Length")
                return None
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._bad_request("request body must be valid JSON")
                return None
            if not isinstance(payload, dict):
                self._bad_request("request body must be a JSON object")
                return None
            return payload

        def _resolve_tenant(self, parts, body_tenant=None):
            """Resolve the tenant from header/query/body.

            Returns tenant_id, or None after sending 400. Multiple supplied
            values must agree; otherwise it is a conflicting field error.
            """
            candidates = []
            header_tenant = self.headers.get("X-Tenant-Id")
            if header_tenant:
                candidates.append(header_tenant)
            query_tenant = parse_qs(parts.query).get("tenant_id")
            if query_tenant:
                candidates.append(query_tenant[0])
            if body_tenant:
                candidates.append(body_tenant)
            if not candidates:
                self._bad_request("missing required field: tenant_id")
                return None
            if len(set(candidates)) > 1:
                self._bad_request(
                    "conflicting values for field tenant_id"
                )
                return None
            return candidates[0]

        # -- routes -------------------------------------------------------
        def do_POST(self) -> None:
            parts = urlsplit(self.path)

            if parts.path == "/v1/keys":
                payload = self._read_json_object()
                if payload is None:
                    return
                self._handle_create(payload, parts)
                return

            rotate_match = _ROTATE_PATH_RE.match(parts.path)
            if rotate_match is not None:
                payload = self._read_json_object()
                if payload is None:
                    return
                self._handle_rotate(rotate_match.group(1), parts, payload)
                return

            self._send_json(404, {"error": "not found"})

        def _handle_create(self, payload: dict, parts) -> None:
            for field in _CREATE_REQUIRED_FIELDS:
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

            # A header/query tenant, if supplied, must agree with the body.
            tenant_id = self._resolve_tenant(
                parts, body_tenant=payload["tenant_id"]
            )
            if tenant_id is None:
                return

            record = store.create(
                tenant_id=tenant_id,
                algorithm=algorithm,
                label=payload["label"],
            )
            self._send_json(201, record.to_create_response())

        def _handle_rotate(self, key_id: str, parts, payload: dict) -> None:
            for field in _ROTATE_REQUIRED_FIELDS:
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

            tenant_id = self._resolve_tenant(
                parts, body_tenant=payload["tenant_id"]
            )
            if tenant_id is None:
                return

            record = store.rotate(key_id, tenant_id, algorithm)
            if record is None:
                self._not_found()
                return
            self._send_json(201, record.to_rotate_response())

        def do_GET(self) -> None:
            parts = urlsplit(self.path)

            match = _VERSIONS_PATH_RE.match(parts.path)
            if match is not None:
                self._handle_version(match.group(1), match.group(2), parts)
                return

            match = _CURRENT_PATH_RE.match(parts.path)
            if match is not None:
                self._handle_current(match.group(1), parts)
                return

            match = _KEY_PATH_RE.match(parts.path)
            if match is not None:
                self._handle_get(match.group(1), parts)
                return

            self._send_json(404, {"error": "not found"})

        def _handle_get(self, key_id: str, parts) -> None:
            tenant_id = self._resolve_tenant(parts)
            if tenant_id is None:
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                self._not_found()
                return
            self._send_json(200, record.to_get_response())

        def _handle_current(self, key_id: str, parts) -> None:
            tenant_id = self._resolve_tenant(parts)
            if tenant_id is None:
                return
            record = store.get_current(key_id, tenant_id)
            if record is None:
                self._not_found()
                return
            self._send_json(200, record.to_current_response())

        def _handle_version(self, key_id: str, version_text: str, parts) -> None:
            tenant_id = self._resolve_tenant(parts)
            if tenant_id is None:
                return
            if not _POSITIVE_INT_RE.fullmatch(version_text):
                self._bad_request(
                    "field version must be a positive integer: %r"
                    % version_text
                )
                return
            version_number = int(version_text)
            record = store.get_version(key_id, tenant_id, version_number)
            if record is None:
                self._not_found()
                return
            self._send_json(
                200, record.to_version_response(version_number)
            )

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
