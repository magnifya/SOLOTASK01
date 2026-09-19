"""HTTP service exposing POST/GET /v1/keys."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .crypto import SUPPORTED_ALGORITHMS
from .store import KeyStore

_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
_VERSION_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_POSITIVE_INT_RE = re.compile(r"[0-9]+")
_REQUIRED_FIELDS = ("tenant_id", "algorithm", "label")
_ROTATE_FIELDS = ("tenant_id", "algorithm")
_MISSING = object()


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

        # -- parsing helpers ---------------------------------------------
        def _read_json_object(self):
            """Return the request body as a dict, or None after sending 400."""
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

        def _require_fields(self, payload, fields):
            """Validate required string fields; False means a 400 was sent."""
            for field in fields:
                if field not in payload:
                    self._bad_request("missing required field: %s" % field)
                    return False
                if not isinstance(payload[field], str):
                    self._bad_request("field %s must be a string" % field)
                    return False
            return True

        def _tenant(self, parts, body=_MISSING):
            """Resolve tenant from X-Tenant-Id / query / JSON body.

            Returns the tenant id, or None after sending 400. Two different
            supplied tenant identifiers are a conflicting-parameter 400.
            """
            candidates = []
            header = self.headers.get("X-Tenant-Id")
            if header is not None:
                candidates.append(header)
            query = parse_qs(parts.query).get("tenant_id")
            if query:
                candidates.append(query[0])
            if body is not _MISSING:
                body_tenant = body.get("tenant_id")
                if body_tenant is not None:
                    if not isinstance(body_tenant, str) or not body_tenant:
                        self._bad_request("field tenant_id must be a non-empty string")
                        return None
                    candidates.append(body_tenant)
            distinct = set(candidates)
            if len(distinct) > 1:
                self._bad_request(
                    "conflicting tenant_id parameters (header, query and body must agree)"
                )
                return None
            if not distinct:
                self._bad_request("missing required field: tenant_id")
                return None
            tenant = next(iter(distinct))
            if not tenant:
                self._bad_request("field tenant_id must be a non-empty string")
                return None
            return tenant

        def _parse_version(self, raw):
            """Parse a positive integer version from the URL, else 400."""
            if not _POSITIVE_INT_RE.fullmatch(raw):
                self._bad_request("field version must be a positive integer")
                return None
            value = int(raw)
            if value < 1:
                self._bad_request("field version must be a positive integer")
                return None
            return value

        # -- POST ---------------------------------------------------------
        def do_POST(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            if path == "/v1/keys":
                self._create_key()
                return

            rotate_match = _ROTATE_PATH_RE.match(path)
            if rotate_match is not None:
                self._rotate_key(rotate_match.group(1), parts)
                return

            self._send_json(404, {"error": "not found"})

        def _create_key(self) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            if not self._require_fields(payload, _REQUIRED_FIELDS):
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

        def _rotate_key(self, key_id: str, parts) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            # The JSON body must carry tenant_id and algorithm.
            if not self._require_fields(payload, _ROTATE_FIELDS):
                return
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return
            algorithm = payload["algorithm"]
            if algorithm not in SUPPORTED_ALGORITHMS:
                self._bad_request(
                    "unsupported value for field algorithm: %r (supported: %s)"
                    % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
                )
                return
            record = store.rotate(key_id, tenant_id, algorithm)
            if record is None:
                # Unknown key or another tenant's key look identical.
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(201, record.to_rotate_response())

        # -- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            version_match = _VERSION_PATH_RE.match(path)
            if version_match is not None:
                self._get_version(
                    version_match.group(1), version_match.group(2), parts
                )
                return

            current_match = _CURRENT_PATH_RE.match(path)
            if current_match is not None:
                self._get_current(current_match.group(1), parts)
                return

            key_match = _KEY_PATH_RE.match(path)
            if key_match is not None:
                self._get_key(key_match.group(1), parts)
                return

            self._send_json(404, {"error": "not found"})

        def _get_key(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                # Same status whether the key is missing or owned by another
                # tenant: never confirm the existence of another tenant's key.
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.to_get_response())

        def _get_version(self, key_id: str, raw_version: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            version = self._parse_version(raw_version)
            if version is None:
                return
            result = store.get_version(key_id, tenant_id, version)
            if result is None:
                # Unknown key, unknown version and cross-tenant access are
                # indistinguishable, all 404.
                self._send_json(404, {"error": "version not found"})
                return
            _record, ver = result
            self._send_json(200, ver.to_version_response(key_id))

        def _get_current(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.current.to_version_response(key_id))

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
