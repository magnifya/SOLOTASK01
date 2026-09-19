"""HTTP service exposing the key and audit APIs."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import audit as audit_mod
from . import keybundle
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .policy import InvalidPolicy, PolicyStore, validate_rules
from .store import IMPORT_CONFLICT, KeyStore, is_valid_key_id

_AUDIT_PATH = "/v1/audit"
_POLICY_PATH = "/v1/policy"
_IMPORT_PATH = "/v1/keys/import"
_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
_REVOKE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/revoke$")
_EXPORT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/export$")
_STATUS_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/status$")
_VERSION_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_POSITIVE_INT_RE = re.compile(r"[0-9]+")
_MISSING = object()


def make_handler(store: KeyStore, policies: PolicyStore) -> type:
    """Build a BaseHTTPRequestHandler subclass bound to the stores."""

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

        def _operator_header(self):
            """The X-Operator-Id for a governed request, possibly absent.

            Only policy management requires the header (400 when missing); on
            governed endpoints an absent/empty header simply matches no
            subject, so a tenant with a policy fails closed (403) while a
            tenant without one is unaffected.
            """
            return self.headers.get("X-Operator-Id")

        def _enforce(self, tenant_id, operator, action, key_id) -> bool:
            """Apply the tenant policy for one governed action.

            Returns True when the request may proceed. A denial is recorded
            under the *original* action with outcome=rejected and the key_id
            (null for create/import/audit) and answered with 403; policy
            management endpoints never reach this method. Callers run the
            unknown/cross-tenant 404 check first, so those still win.
            """
            if policies.allowed(tenant_id, operator, action):
                return True
            if not self._record_attempt(
                tenant_id, key_id, action, audit_mod.OUTCOME_REJECTED
            ):
                return False
            self._send_json(
                403,
                {
                    "error": "policy denies action %s for operator %s"
                    % (action, operator)
                },
            )
            return False

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

        def _single_source_tenant(self, parts):
            """Resolve a tenant supplied by exactly one source.

            Used by GET /v1/audit and by GET/PUT/DELETE /v1/policy. Exactly
            one of a single X-Tenant-Id header or a single ?tenant_id=
            parameter must supply it. Any missing/duplicate/empty/conflicting
            value is a 400 naming tenant_id and is written to the ledger as an
            invisible tenant_conflict (parameter errors are audited). A
            successful audit query itself still writes nothing.
            """
            headers = self.headers.get_all("X-Tenant-Id") or []
            if len(headers) > 1:
                if not self._record_conflict():
                    return None
                self._bad_request(
                    "duplicate tenant_id (provide a single X-Tenant-Id header)"
                )
                return None
            query_values = parse_qs(parts.query, keep_blank_values=True).get(
                "tenant_id", []
            )
            if len(query_values) > 1:
                if not self._record_conflict():
                    return None
                self._bad_request(
                    "duplicate tenant_id (provide a single tenant_id parameter)"
                )
                return None
            if headers and query_values:
                if not self._record_conflict():
                    return None
                self._bad_request(
                    "conflicting tenant_id parameters (use header or query, not both)"
                )
                return None
            tenant = headers[0] if headers else (
                query_values[0] if query_values else None
            )
            if tenant is None:
                if not self._record_conflict():
                    return None
                self._bad_request("missing required field: tenant_id")
                return None
            if not tenant:
                if not self._record_conflict():
                    return None
                self._bad_request("field tenant_id must be a non-empty string")
                return None
            return tenant

        def _operator(self, tenant_id, action):
            """Resolve a non-empty X-Operator-Id, else record and 400.

            Returns the operator, or None after responding. When the tenant is
            known the rejection is an attempt on the given management action
            visible to them.
            """
            operator = self.headers.get("X-Operator-Id")
            if not operator:
                if tenant_id is not None:
                    if not self._record_attempt(
                        tenant_id, None, action, audit_mod.OUTCOME_REJECTED,
                    ):
                        return None
                self._bad_request(
                    "missing required header: X-Operator-Id"
                    if operator is None
                    else "field X-Operator-Id must be a non-empty string"
                )
                return None
            return operator

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

        # -- PUT / DELETE --------------------------------------------------
        def do_PUT(self) -> None:
            parts = urlsplit(self.path)
            if parts.path == _POLICY_PATH:
                try:
                    self._put_policy(parts)
                except LedgerError as exc:
                    self._server_error(exc)
                return
            self._send_json(404, {"error": "not found"})

        def do_DELETE(self) -> None:
            parts = urlsplit(self.path)
            if parts.path == _POLICY_PATH:
                try:
                    self._delete_policy(parts)
                except LedgerError as exc:
                    self._server_error(exc)
                return
            self._send_json(404, {"error": "not found"})

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

                export_match = _EXPORT_PATH_RE.match(path)
                if export_match is not None:
                    self._export_key(export_match.group(1), parts)
                    return

                if path == _IMPORT_PATH:
                    self._import_key(parts)
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
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_CREATE, None,
            ):
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
            # Unknown/cross-tenant must answer 404 even when the policy would
            # also deny, so existence is resolved before enforcement.
            if store.get(key_id, tenant_id) is None:
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_ROTATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_ROTATE, key_id,
            ):
                return
            record = store.rotate(key_id, tenant_id, algorithm)
            if record is None:
                # Lost a concurrent race to delete/relocate; treat as 404.
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
            # Resolve existence (404) before policy (403).
            if store.get(key_id, tenant_id) is None:
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_REVOKE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_REVOKE, key_id,
            ):
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

        def _export_key(self, key_id: str, parts) -> None:
            """POST /v1/keys/{key_id}/export.

            The body must carry a non-empty tenant_id and passphrase; an
            X-Tenant-Id header or ?tenant_id= may supplement the body but
            must agree with it. The full record (including private material)
            is only ever returned sealed inside the opaque bundle.
            """
            payload = self._read_json_object()
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                if not self._record_conflict():
                    return
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            passphrase = payload.get("passphrase")
            if not isinstance(passphrase, str) or not passphrase:
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_EXPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(
                    "field passphrase must be a non-empty string"
                )
                return
            # Resolve existence (404) before policy (403), and avoid doing
            # the expensive bundle sealing work for a denied request.
            if store.get(key_id, tenant_id) is None:
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_EXPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_EXPORT, key_id,
            ):
                return
            # The record is read before the success event, but nothing is
            # persisted by an export, so a ledger failure after this point
            # simply fails the request with 500.
            bundle = store.export_bundle(key_id, tenant_id, passphrase)
            if bundle is None:
                # Unknown key and another tenant's key look identical.
                if not self._record_attempt(
                    tenant_id, key_id, audit_mod.ACTION_EXPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_EXPORT,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            self._send_json(
                200, {"format": keybundle.FORMAT, "bundle": bundle}
            )

        def _import_key(self, parts) -> None:
            """POST /v1/keys/import.

            Decryption/tamper/format errors are 400s naming passphrase or
            bundle and never touch disk. A key_id the tenant already owns is
            a 409 that leaves the original record untouched; the same key_id
            owned by another tenant answers 404 so existence never leaks
            across tenants.
            """
            payload = self._read_json_object()
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                if not self._record_conflict():
                    return
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return
            passphrase = payload.get("passphrase")
            if not isinstance(passphrase, str) or not passphrase:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(
                    "field passphrase must be a non-empty string"
                )
                return
            bundle = payload.get("bundle")
            if not isinstance(bundle, str) or not bundle:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request("field bundle must be a non-empty string")
                return
            try:
                decoded = keybundle.decode_bundle(bundle, passphrase)
            except keybundle.WrongPassphrase as exc:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(str(exc))
                return
            except keybundle.InvalidBundle as exc:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(str(exc))
                return
            # The bundle authenticated; its key_id is a validated UUID4.
            # A key owned by another tenant still answers 404 before policy,
            # so existence across tenants never leaks.
            existing_owner = store.owner(decoded["key_id"])
            if existing_owner is not None and existing_owner != tenant_id:
                if not self._record_attempt(
                    tenant_id, decoded["key_id"], audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "key not found"})
                return
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_IMPORT, decoded["key_id"],
            ):
                return
            # The existence re-check and the create happen atomically in the
            # store (a concurrent import can still land first).
            status, record = store.import_bundle(tenant_id, decoded)
            if status == IMPORT_CONFLICT:
                if not self._record_attempt(
                    tenant_id, record.key_id, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                if record.tenant_id == tenant_id:
                    self._send_json(
                        409, {"error": "key_id already exists for this tenant"}
                    )
                else:
                    # Same answer as a missing key: never confirm another
                    # tenant owns this key_id.
                    self._send_json(404, {"error": "key not found"})
                return
            # The success event committed in the same transaction as the file.
            self._send_json(201, record.to_create_response())

        # -- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            if path == _POLICY_PATH:
                try:
                    self._get_policy(parts)
                except LedgerError as exc:
                    self._server_error(exc)
                return

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
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_READ, key_id,
            ):
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
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_READ, key_id,
            ):
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
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_READ, key_id,
            ):
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
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_READ, key_id,
            ):
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
            tenant_id = self._single_source_tenant(parts)
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

            # Querying the ledger is itself governed by the 'audit' action.
            # A denial is recorded (key_id null) and answers 403; an allowed
            # query still writes nothing ("查询不记").
            if not self._enforce(
                tenant_id, self._operator_header(),
                audit_mod.ACTION_AUDIT, None,
            ):
                return

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

        # -- policy management ---------------------------------------------
        def _get_policy(self, parts) -> None:
            tenant_id = self._single_source_tenant(parts)
            if tenant_id is None:
                return
            operator = self._operator(tenant_id, audit_mod.ACTION_POLICY_READ)
            if operator is None:
                return
            record = policies.get(tenant_id)
            if record is None:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_POLICY_READ,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "policy not found"})
                return
            # A policy read is non-mutating; its success event is appended
            # alongside the response, like a key read/export.
            if not self._record_attempt(
                tenant_id, None, audit_mod.ACTION_POLICY_READ,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            self._send_json(200, record.to_response())

        def _put_policy(self, parts) -> None:
            tenant_id = self._single_source_tenant(parts)
            if tenant_id is None:
                return
            operator = self._operator(
                tenant_id, audit_mod.ACTION_POLICY_UPDATE
            )
            if operator is None:
                return
            payload = self._read_json_object()
            if payload is None:
                # A malformed body already recorded an invisible conflict.
                return
            # The body must carry a non-empty tenant_id, agreeing with the
            # single header/query source ("头/参一项一致").
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                if not self._record_conflict():
                    return
                self._bad_request("field tenant_id must be a non-empty string")
                return
            if body_tenant != tenant_id:
                if not self._record_conflict():
                    return
                self._bad_request(
                    "conflicting tenant_id parameters "
                    "(header, query and body must agree)"
                )
                return
            if "rules" not in payload:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_POLICY_UPDATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request("missing required field: rules")
                return
            try:
                rules = validate_rules(payload["rules"])
            except InvalidPolicy as exc:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_POLICY_UPDATE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(str(exc))
                return
            # The success event commits in the same outbox transaction as the
            # policy file, so there is no separate attempt write here.
            record = policies.set(tenant_id, rules, operator)
            self._send_json(200, record.to_response())

        def _delete_policy(self, parts) -> None:
            tenant_id = self._single_source_tenant(parts)
            if tenant_id is None:
                return
            operator = self._operator(
                tenant_id, audit_mod.ACTION_POLICY_DELETE
            )
            if operator is None:
                return
            # The delete event commits together with the file removal.
            deleted = policies.delete(tenant_id, operator)
            if not deleted:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_POLICY_DELETE,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "policy not found"})
                return
            self._send_json(200, {"tenant_id": tenant_id, "deleted": True})

    return KeyHandler


def serve(host: str, port: int, data_dir: str) -> None:
    """Run the HTTP server until interrupted."""
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policies = PolicyStore(data_dir, audit_log)
    httpd = ThreadingHTTPServer((host, port), make_handler(store, policies))
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
