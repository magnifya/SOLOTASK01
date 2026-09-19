"""HTTP service exposing POST/GET /v1/keys."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .audit import ACTIONS, AuditError, CursorError
from .crypto import SUPPORTED_ALGORITHMS
from .store import KeyStore

_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
_REVOKE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/revoke$")
_STATUS_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/status$")
_VERSION_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_POSITIVE_INT_RE = re.compile(r"[0-9]+")
_UUID4_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_REQUIRED_FIELDS = ("tenant_id", "algorithm", "label")
_ROTATE_FIELDS = ("tenant_id", "algorithm")
_REVOKE_FIELDS = ("tenant_id", "reason", "operator")
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

        def _audit_failure(self) -> None:
            self._send_json(500, {"error": "audit log failure"})

        def _record_tenant_conflict(self) -> bool:
            """Audit a tenant_conflict event; False means a 500 was sent."""
            try:
                store.record_tenant_conflict()
            except AuditError:
                self._audit_failure()
                return False
            return True

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

        def _require_non_empty(self, payload, fields):
            """Validate required non-empty string fields; False = 400 sent."""
            for field in fields:
                if field not in payload:
                    self._bad_request("missing required field: %s" % field)
                    return False
                if not isinstance(payload[field], str) or not payload[field]:
                    self._bad_request(
                        "field %s must be a non-empty string" % field
                    )
                    return False
            return True

        def _tenant(self, parts, body=_MISSING, audit_conflict=False):
            """Resolve tenant from X-Tenant-Id / query / JSON body.

            Returns the tenant id, or None after sending 400. Two different
            supplied tenant identifiers are a conflicting-parameter 400.
            With audit_conflict=True, every failure is also written to the
            audit log as a tenant_conflict event (both identifiers null).
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
                        if audit_conflict and not self._record_tenant_conflict():
                            return None
                        self._bad_request("field tenant_id must be a non-empty string")
                        return None
                    candidates.append(body_tenant)
            distinct = set(candidates)
            if len(distinct) > 1:
                if audit_conflict and not self._record_tenant_conflict():
                    return None
                self._bad_request(
                    "conflicting tenant_id parameters (header, query and body must agree)"
                )
                return None
            if not distinct:
                if audit_conflict and not self._record_tenant_conflict():
                    return None
                self._bad_request("missing required field: tenant_id")
                return None
            tenant = next(iter(distinct))
            if not tenant:
                if audit_conflict and not self._record_tenant_conflict():
                    return None
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

            revoke_match = _REVOKE_PATH_RE.match(path)
            if revoke_match is not None:
                self._revoke_key(revoke_match.group(1), parts)
                return

            self._send_json(404, {"error": "not found"})

        def _create_key(self) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            # A missing or non-string tenant is audited as tenant_conflict.
            if not isinstance(payload.get("tenant_id"), str):
                if not self._record_tenant_conflict():
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
            try:
                record = store.create(
                    tenant_id=payload["tenant_id"],
                    algorithm=algorithm,
                    label=payload["label"],
                )
            except AuditError:
                self._audit_failure()
                return
            self._send_json(201, record.to_create_response())

        def _rotate_key(self, key_id: str, parts) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            # A missing or non-string body tenant is a tenant_conflict.
            if not isinstance(payload.get("tenant_id"), str):
                if not self._record_tenant_conflict():
                    return
            # The JSON body must carry tenant_id and algorithm.
            if not self._require_fields(payload, _ROTATE_FIELDS):
                return
            tenant_id = self._tenant(parts, payload, audit_conflict=True)
            if tenant_id is None:
                return
            algorithm = payload["algorithm"]
            if algorithm not in SUPPORTED_ALGORITHMS:
                self._bad_request(
                    "unsupported value for field algorithm: %r (supported: %s)"
                    % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
                )
                return
            try:
                record = store.rotate(key_id, tenant_id, algorithm)
            except AuditError:
                self._audit_failure()
                return
            if record is None:
                # Unknown key or another tenant's key look identical.
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(201, record.to_rotate_response())

        def _revoke_key(self, key_id: str, parts) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            # A missing or non-string body tenant is a tenant_conflict.
            if not isinstance(payload.get("tenant_id"), str):
                if not self._record_tenant_conflict():
                    return
            # The JSON body must carry non-empty tenant_id, reason, operator.
            if not self._require_non_empty(payload, _REVOKE_FIELDS):
                return
            # Optional X-Tenant-Id / ?tenant_id= must agree with the body.
            tenant_id = self._tenant(parts, payload, audit_conflict=True)
            if tenant_id is None:
                return
            try:
                record = store.revoke(
                    key_id, tenant_id, payload["reason"], payload["operator"]
                )
            except AuditError:
                self._audit_failure()
                return
            if record is None:
                # Unknown key or another tenant's key look identical.
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.to_status_response())

        # -- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            if path == "/v1/audit":
                self._get_audit(parts)
                return

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

            status_match = _STATUS_PATH_RE.match(path)
            if status_match is not None:
                self._get_status(status_match.group(1), parts)
                return

            key_match = _KEY_PATH_RE.match(path)
            if key_match is not None:
                self._get_key(key_match.group(1), parts)
                return

            self._send_json(404, {"error": "not found"})

        def _get_key(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts, audit_conflict=True)
            if tenant_id is None:
                return
            try:
                record = store.get(key_id, tenant_id, audit=True)
            except AuditError:
                self._audit_failure()
                return
            if record is None:
                # Same status whether the key is missing or owned by another
                # tenant: never confirm the existence of another tenant's key.
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.to_get_response())

        def _get_version(self, key_id: str, raw_version: str, parts) -> None:
            tenant_id = self._tenant(parts, audit_conflict=True)
            if tenant_id is None:
                return
            version = self._parse_version(raw_version)
            if version is None:
                return
            try:
                result = store.get_version(key_id, tenant_id, version, audit=True)
            except AuditError:
                self._audit_failure()
                return
            if result is None:
                # Unknown key, unknown version and cross-tenant access are
                # indistinguishable, all 404.
                self._send_json(404, {"error": "version not found"})
                return
            _record, ver = result
            self._send_json(200, ver.to_version_response(key_id))

        def _get_current(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts, audit_conflict=True)
            if tenant_id is None:
                return
            try:
                record = store.get(key_id, tenant_id, audit=True)
            except AuditError:
                self._audit_failure()
                return
            if record is None:
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.current.to_version_response(key_id))

        def _get_status(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.to_status_response())

        # -- audit ---------------------------------------------------------
        def _get_audit(self, parts) -> None:
            """GET /v1/audit: query this tenant's audit events.

            The tenant comes from exactly one of X-Tenant-Id or the
            tenant_id query parameter. Querying never writes audit events.
            """
            params = parse_qs(parts.query, keep_blank_values=True)
            header = self.headers.get("X-Tenant-Id")
            query_values = params.get("tenant_id", [])
            if header is not None and query_values:
                self._bad_request(
                    "tenant_id must come from exactly one of "
                    "X-Tenant-Id header or tenant_id query parameter"
                )
                return
            if len(query_values) > 1:
                self._bad_request("duplicate tenant_id query parameter")
                return
            if header is None and not query_values:
                self._bad_request("missing required parameter: tenant_id")
                return
            tenant_id = header if header is not None else query_values[0]
            if not tenant_id:
                self._bad_request("field tenant_id must be a non-empty string")
                return

            key_id = None
            if "key_id" in params:
                values = params["key_id"]
                if len(values) != 1 or not _UUID4_RE.fullmatch(values[0]):
                    self._bad_request("field key_id must be a UUID4")
                    return
                key_id = values[0]

            action = None
            if "action" in params:
                values = params["action"]
                if len(values) != 1 or values[0] not in ACTIONS:
                    self._bad_request(
                        "unsupported value for field action: %r (supported: %s)"
                        % (values[0] if values else None, ", ".join(ACTIONS))
                    )
                    return
                action = values[0]

            limit = 100
            if "limit" in params:
                values = params["limit"]
                raw = values[0] if len(values) == 1 else ""
                if not _POSITIVE_INT_RE.fullmatch(raw):
                    self._bad_request(
                        "field limit must be an integer between 1 and 1000"
                    )
                    return
                limit = int(raw)
                if not 1 <= limit <= 1000:
                    self._bad_request(
                        "field limit must be an integer between 1 and 1000"
                    )
                    return

            cursor = None
            if "cursor" in params:
                values = params["cursor"]
                if len(values) != 1 or not values[0]:
                    self._bad_request("invalid cursor")
                    return
                cursor = values[0]

            try:
                result = store.audit.query(
                    tenant_id,
                    key_id=key_id,
                    action=action,
                    limit=limit,
                    cursor=cursor,
                )
            except CursorError as exc:
                self._bad_request(str(exc))
                return
            except AuditError:
                self._audit_failure()
                return
            self._send_json(200, result)

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
