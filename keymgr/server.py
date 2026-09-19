"""HTTP service exposing the key and audit APIs."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import audit as audit_mod
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .store import KeyStore, is_valid_key_id

_AUDIT_PATH = "/v1/audit"
_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
_REVOKE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/revoke$")
_STATUS_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/status$")
_VERSION_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_POSITIVE_INT_RE = re.compile(r"[0-9]+")
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

        def _server_error(self, exc: Exception) -> None:
            # A ledger write failure aborts the request with 500; mutations
            # have already rolled back their key-file change by this point.
            self._send_json(500, {"error": "audit ledger failure: %s" % exc})

        def log_message(self, fmt, *args):  # silence default stderr logging
            return

        def _record_conflict(self) -> bool:
            """Write the invisible tenant_conflict event. False = 500 sent."""
            try:
                store.audit_conflict()
            except LedgerError as exc:
                self._server_error(exc)
                return False
            return True

        def _record_attempt(self, tenant_id, key_id, action, outcome) -> bool:
            """Write one attempt event. False means a 500 was already sent."""
            try:
                store.audit_attempt(tenant_id, key_id, action, outcome)
            except LedgerError as exc:
                self._server_error(exc)
                return False
            return True

        # -- parsing helpers ---------------------------------------------
        def _read_json_object(self):
            """Return the request body as a dict, or None after responding.

            A body that cannot be parsed carries no usable tenant, so an
            invisible tenant_conflict is written before the 400; if that
            ledger write fails the 400 is skipped and a 500 is sent instead.
            """
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                if self._record_conflict():
                    self._bad_request("invalid Content-Length")
                return None
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                if self._record_conflict():
                    self._bad_request("request body must be valid JSON")
                return None
            if not isinstance(payload, dict):
                if self._record_conflict():
                    self._bad_request("request body must be a JSON object")
                return None
            return payload

        def _tenant(self, parts, body=_MISSING):
            """Resolve tenant from X-Tenant-Id / query / JSON body.

            Returns the tenant id, or None after sending 400. Two different
            supplied tenant identifiers are a conflicting-parameter 400. Any
            missing/empty/conflicting tenant is written to the ledger as an
            invisible tenant_conflict event.
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
                        if not self._record_conflict():
                            return None
                        self._bad_request(
                            "field tenant_id must be a non-empty string"
                        )
                        return None
                    candidates.append(body_tenant)
            distinct = set(candidates)
            if len(distinct) > 1:
                if not self._record_conflict():
                    return None
                self._bad_request(
                    "conflicting tenant_id parameters (header, query and body must agree)"
                )
                return None
            if not distinct:
                if not self._record_conflict():
                    return None
                self._bad_request("missing required field: tenant_id")
                return None
            tenant = next(iter(distinct))
            if not tenant:
                if not self._record_conflict():
                    return None
                self._bad_request("field tenant_id must be a non-empty string")
                return None
            return tenant

        def _audit_tenant(self, parts):
            """Resolve the single-source tenant for GET /v1/audit.

            Exactly one of a single X-Tenant-Id header or a single
            ?tenant_id= parameter must supply it. Any missing/duplicate/
            empty/conflicting value is a 400 naming tenant_id; the audit
            endpoint itself is never written to the ledger.
            """
            headers = self.headers.get_all("X-Tenant-Id") or []
            if len(headers) > 1:
                self._bad_request(
                    "duplicate tenant_id (provide a single X-Tenant-Id header)"
                )
                return None
            query_values = parse_qs(parts.query, keep_blank_values=True).get(
                "tenant_id", []
            )
            if len(query_values) > 1:
                self._bad_request(
                    "duplicate tenant_id (provide a single tenant_id parameter)"
                )
                return None
            if headers and query_values:
                self._bad_request(
                    "conflicting tenant_id parameters (use header or query, not both)"
                )
                return None
            tenant = headers[0] if headers else (
                query_values[0] if query_values else None
            )
            if tenant is None:
                self._bad_request("missing required field: tenant_id")
                return None
            if not tenant:
                self._bad_request("field tenant_id must be a non-empty string")
                return None
            return tenant

        def _parse_version(self, raw):
            """Parse a positive integer version from the URL, else 400."""
            if not _POSITIVE_INT_RE.fullmatch(raw) or int(raw) < 1:
                self._bad_request("field version must be a positive integer")
                return None
            return int(raw)

        def _bad_key_id(self, key_id) -> bool:
            """Record an invisible conflict for an illegal key_id."""
            if is_valid_key_id(key_id):
                return False
            if not self._record_conflict():
                return True
            self._send_json(404, {"error": "key not found"})
            return True

        # -- POST ---------------------------------------------------------
        def do_POST(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path
            try:
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
            except LedgerError as exc:
                self._server_error(exc)
                return

            self._send_json(404, {"error": "not found"})

        def _create_key(self) -> None:
            payload = self._read_json_object()
            if payload is None:
                # Conflict (if any) was already recorded by the body parser.
                return
            # tenant_id comes from the body for create; validate it first so
            # later field errors are tenant-visible rejections.
            tenant_id = payload.get("tenant_id")
            if not isinstance(tenant_id, str) or not tenant_id:
                if not self._record_conflict():
                    return
                self._bad_request("field tenant_id must be a non-empty string")
                return
            for field in ("algorithm", "label"):
                if field not in payload or not isinstance(
                    payload[field], str
                ):
                    if not self._record_attempt(
                        tenant_id, None, audit_mod.ACTION_CREATE,
                        audit_mod.OUTCOME_REJECTED,
                    ):
                        return
                    self._bad_request(
                        "field %s must be a string" % field
                        if field in payload
                        else "missing required field: %s" % field
                    )
                    return
            algorithm = payload["algorithm"]
            if algorithm not in SUPPORTED_ALGORITHMS:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_CREATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(
                    "unsupported value for field algorithm: %r (supported: %s)"
                    % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
                )
                return
            record = store.create(
                tenant_id=tenant_id,
                algorithm=algorithm,
                label=payload["label"],
            )
            self._send_json(201, record.to_create_response())

        def _rotate_key(self, key_id: str, parts) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                # The body must itself carry a non-empty tenant_id.
                if not self._record_conflict():
                    return
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            if not isinstance(payload.get("algorithm"), str):
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_ROTATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request("missing required field: algorithm")
                return
            algorithm = payload["algorithm"]
            if algorithm not in SUPPORTED_ALGORITHMS:
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_ROTATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(
                    "unsupported value for field algorithm: %r (supported: %s)"
                    % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
                )
                return
            record = store.rotate(key_id, tenant_id, algorithm)
            if record is None:
                # Unknown key or another tenant's key look identical; the
                # rejection is visible only to the requesting tenant.
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_ROTATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(201, record.to_rotate_response())

        def _revoke_key(self, key_id: str, parts) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                # The body must itself carry a non-empty tenant_id.
                if not self._record_conflict():
                    return
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            for field in ("reason", "operator"):
                value = payload.get(field)
                if not isinstance(value, str) or not value:
                    if not self._record_attempt(
                        tenant_id, key_id, audit_mod.ACTION_REVOKE,
                        audit_mod.OUTCOME_REJECTED,
                    ):
                        return
                    self._bad_request(
                        "field %s must be a non-empty string" % field
                        if value is not None
                        else "missing required field: %s" % field
                    )
                    return
            record = store.revoke(
                key_id, tenant_id, payload["reason"], payload["operator"]
            )
            if record is None:
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_REVOKE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            self._send_json(200, record.to_status_response())

        # -- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            if path == _AUDIT_PATH:
                # Audit failures are 500, not audited themselves.
                try:
                    self._get_audit(parts)
                except LedgerError as exc:
                    self._server_error(exc)
                return

            try:
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
            except LedgerError as exc:
                self._server_error(exc)
                return

            self._send_json(404, {"error": "not found"})

        def _reject_read(self, tenant_id, key_id, status, message) -> None:
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_READ,
                audit_mod.OUTCOME_REJECTED,
            ):
                return
            self._send_json(status, {"error": message})

        def _get_key(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                # Same status whether the key is missing or owned by another
                # tenant: never confirm the existence of another tenant's key.
                self._reject_read(tenant_id, key_id, 404, "key not found")
                return
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_READ,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            self._send_json(200, record.to_get_response())

        def _get_version(self, key_id: str, raw_version: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            version = self._parse_version(raw_version)
            if version is None:
                # Bad version parameter: tenant and key are known, so the
                # rejection is visible to them.
                self._reject_read(
                    tenant_id, key_id, 400,
                    "field version must be a positive integer",
                )
                return
            result = store.get_version(key_id, tenant_id, version)
            if result is None:
                # Unknown key, unknown version and cross-tenant access are
                # indistinguishable, all 404.
                self._reject_read(
                    tenant_id, key_id, 404, "version not found"
                )
                return
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_READ,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            _record, ver = result
            self._send_json(200, ver.to_version_response(key_id))

        def _get_current(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                self._reject_read(tenant_id, key_id, 404, "key not found")
                return
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_READ,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            self._send_json(200, record.current.to_version_response(key_id))

        def _get_status(self, key_id: str, parts) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            record = store.get(key_id, tenant_id)
            if record is None:
                self._reject_read(tenant_id, key_id, 404, "key not found")
                return
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_READ,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            self._send_json(200, record.to_status_response())

        # -- audit ---------------------------------------------------------
        def _single_param(self, qs, name):
            """Return (values, error_sent). Exactly one value or 400."""
            values = qs.get(name, [])
            if len(values) > 1:
                self._bad_request("duplicate %s parameter" % name)
                return None, True
            return values, False

        def _get_audit(self, parts) -> None:
            tenant_id = self._audit_tenant(parts)
            if tenant_id is None:
                return
            qs = parse_qs(parts.query, keep_blank_values=True)

            values, errored = self._single_param(qs, "key_id")
            if errored:
                return
            key_id = values[0] if values else None
            if key_id is not None and not is_valid_key_id(key_id):
                self._bad_request("field key_id must be a UUID4")
                return

            values, errored = self._single_param(qs, "action")
            if errored:
                return
            action = values[0] if values else None
            if action is not None and action not in audit_mod.ACTIONS:
                self._bad_request(
                    "field action must be one of: %s"
                    % ", ".join(audit_mod.ACTIONS)
                )
                return

            limit = 100
            values, errored = self._single_param(qs, "limit")
            if errored:
                return
            if values:
                raw_limit = values[0]
                if not _POSITIVE_INT_RE.fullmatch(raw_limit):
                    self._bad_request(
                        "field limit must be an integer between 1 and 1000"
                    )
                    return
                limit = int(raw_limit)
                if not 1 <= limit <= 1000:
                    self._bad_request(
                        "field limit must be an integer between 1 and 1000"
                    )
                    return

            values, errored = self._single_param(qs, "cursor")
            if errored:
                return
            cursor = values[0] if values else None

            try:
                page = store.audit.query(
                    tenant_id,
                    key_id=key_id,
                    action=action,
                    limit=limit,
                    cursor=cursor,
                )
            except InvalidCursor:
                self._bad_request("invalid or expired cursor")
                return
            self._send_json(
                200,
                {
                    "events": [e.to_response() for e in page.events],
                    "next_cursor": page.next_cursor,
                },
            )

    return KeyHandler


def serve(host: str, port: int, data_dir: str) -> None:
    """Run the HTTP server until interrupted."""
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
