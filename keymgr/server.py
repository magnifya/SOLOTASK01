"""HTTP service exposing the key and audit APIs."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import audit as audit_mod
from . import keybundle
from . import restore as restore_mod
from . import tenantbundle
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .policy import PolicyError, PolicyStore, validate_rules
from .store import IMPORT_CONFLICT, KeyStore, is_valid_key_id

_AUDIT_PATH = "/v1/audit"
_POLICY_PATH = "/v1/policy"
_IMPORT_PATH = "/v1/keys/import"
_BACKUP_PATH = "/v1/backup"
_RESTORE_PATH = "/v1/restore"
_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
_REVOKE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/revoke$")
_EXPORT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/export$")
_STATUS_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/status$")
_VERSION_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_POSITIVE_INT_RE = re.compile(r"[0-9]+")
_MISSING = object()


def make_handler(
    store: KeyStore,
    policy_store: PolicyStore,
    coordinator: "restore_mod.RestoreCoordinator",
) -> type:
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

        # -- operator / policy -------------------------------------------
        def _operator(self):
            """Return the single non-empty X-Operator-Id, else send 400.

            Duplicate headers are a 400 as well. A missing/empty operator is
            rejected before any tenant-scoped work happens.
            """
            values = self.headers.get_all("X-Operator-Id") or []
            if len(values) > 1:
                self._bad_request(
                    "duplicate X-Operator-Id (provide a single header)"
                )
                return None
            operator = values[0] if values else None
            if not operator:
                self._bad_request(
                    "missing required header: X-Operator-Id"
                    if operator is None
                    else "header X-Operator-Id must be a non-empty string"
                )
                return None
            return operator

        def _enforce(self, tenant_id, key_id, action, operator) -> bool:
            """Enforce the tenant policy. True to proceed; else response sent.

            A rejection is a 403 carrying a rejected audit event that records
            the original action and key_id; unknown/cross-tenant keys remain
            404 and are handled by callers after enforcement.
            """
            if policy_store.is_allowed(tenant_id, action, operator):
                return True
            if not self._record_attempt(
                tenant_id, key_id, action, audit_mod.OUTCOME_REJECTED
            ):
                return False
            self._send_json(403, {"error": "action not permitted by policy"})
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
            operator = self._operator()
            if operator is None:
                return
            try:
                if path == "/v1/keys":
                    self._create_key(operator)
                    return

                rotate_match = _ROTATE_PATH_RE.match(path)
                if rotate_match is not None:
                    self._rotate_key(rotate_match.group(1), parts, operator)
                    return

                revoke_match = _REVOKE_PATH_RE.match(path)
                if revoke_match is not None:
                    self._revoke_key(revoke_match.group(1), parts, operator)
                    return

                export_match = _EXPORT_PATH_RE.match(path)
                if export_match is not None:
                    self._export_key(export_match.group(1), parts, operator)
                    return

                if path == _IMPORT_PATH:
                    self._import_key(parts, operator)
                    return

                if path == _BACKUP_PATH:
                    self._backup_tenant(parts, operator)
                    return

                if path == _RESTORE_PATH:
                    self._restore_tenant(parts, operator)
                    return
            except LedgerError as exc:
                self._server_error(exc)
                return

            self._send_json(404, {"error": "not found"})

        def _create_key(self, operator: str) -> None:
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
                tenant_id, None, audit_mod.ACTION_CREATE, operator
            ):
                return
            record = store.create(
                tenant_id=tenant_id,
                algorithm=algorithm,
                label=payload["label"],
            )
            self._send_json(201, record.to_create_response())

        def _rotate_key(self, key_id: str, parts, operator: str) -> None:
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
            # Authorization follows request validation (400) and precedes the
            # existence check, so a denial is a 403 even for an unknown key.
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_ROTATE, operator
            ):
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

        def _revoke_key(self, key_id: str, parts, operator: str) -> None:
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
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_REVOKE, operator
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

        def _export_key(self, key_id: str, parts, operator: str) -> None:
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
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_EXPORT, operator
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

        def _import_key(self, parts, operator: str) -> None:
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
            # The bundle authenticated; authorization now, before the
            # existence conflict check (deny is a 403 even when the key_id
            # already exists for another tenant).
            if not self._enforce(
                tenant_id, decoded["key_id"], audit_mod.ACTION_IMPORT, operator
            ):
                return
            # The bundle authenticated; its key_id is a validated UUID4. The
            # existence check and the create happen atomically in the store.
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

        # -- tenant backup / restore --------------------------------------
        def _backup_tenant(self, parts, operator: str) -> None:
            """POST /v1/backup.

            The whole tenant (every key with all versions and private
            material, plus its policy) is returned only sealed inside the
            opaque tenant bundle. A tenant with no data backs up as an empty
            bundle (keys [], policy null).
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
                    tenant_id, None, audit_mod.ACTION_EXPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(
                    "field passphrase must be a non-empty string"
                )
                return
            if not self._enforce(
                tenant_id, None, audit_mod.ACTION_EXPORT, operator
            ):
                return
            try:
                bundle = coordinator.backup_bundle(tenant_id, passphrase)
            except LedgerError as exc:
                self._server_error(exc)
                return
            # A backup reads but never mutates; its event rides with the
            # successful response like a single-key export.
            if not self._record_attempt(
                tenant_id, None, audit_mod.ACTION_EXPORT,
                audit_mod.OUTCOME_SUCCESS,
            ):
                return
            self._send_json(
                200, {"format": tenantbundle.FORMAT, "bundle": bundle}
            )

        def _restore_tenant(self, parts, operator: str) -> None:
            """POST /v1/restore.

            Decryption/tamper/format errors are 400s naming passphrase or
            bundle and never touch disk. Authorization (import) follows
            validation and precedes the in-bundle tenant check: a bundle
            naming another tenant answers 404. A key_id or policy already
            present for this tenant is a 409 that changes nothing; an id
            occupied by another tenant answers 404. Every audit event for a
            restore carries key_id null.
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
                decoded = tenantbundle.decode_bundle(bundle, passphrase)
            except tenantbundle.TenantBundleError as exc:
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._bad_request(str(exc))
                return
            # Validation (400) precedes authorization; the policy decision
            # uses the requesting tenant and a null key_id.
            if not self._enforce(
                tenant_id, None, audit_mod.ACTION_IMPORT, operator
            ):
                return
            if decoded["tenant_id"] != tenant_id:
                # The sealed bundle belongs to another tenant: answer exactly
                # like a missing object so existence never leaks.
                if not self._record_attempt(
                    tenant_id, None, audit_mod.ACTION_IMPORT,
                    audit_mod.OUTCOME_REJECTED,
                ):
                    return
                self._send_json(404, {"error": "tenant backup not found"})
                return
            try:
                result = coordinator.restore(tenant_id, decoded)
            except LedgerError as exc:
                # The coordinator has already removed every written file.
                self._server_error(exc)
                return
            if result.status == restore_mod.RESTORE_CREATED:
                # The success event committed in the same transaction as the
                # restored files.
                self._send_json(
                    201,
                    {
                        "tenant_id": result.tenant_id,
                        "key_ids": result.key_ids,
                        "policy_restored": result.policy_restored,
                    },
                )
                return
            if not self._record_attempt(
                tenant_id, None, audit_mod.ACTION_IMPORT,
                audit_mod.OUTCOME_REJECTED,
            ):
                return
            if result.status == restore_mod.RESTORE_SAME_TENANT_CONFLICT:
                self._send_json(
                    409,
                    {"error": "backup target already contains this data"},
                )
            else:
                self._send_json(404, {"error": "tenant backup not found"})

        # -- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            operator = self._operator()
            if operator is None:
                return

            if path == _AUDIT_PATH:
                # Audit failures are 500, not audited themselves.
                try:
                    self._get_audit(parts, operator)
                except LedgerError as exc:
                    self._server_error(exc)
                return

            if path == _POLICY_PATH:
                try:
                    self._get_policy(parts)
                except LedgerError as exc:
                    self._server_error(exc)
                return

            try:
                version_match = _VERSION_PATH_RE.match(path)
                if version_match is not None:
                    self._get_version(
                        version_match.group(1), version_match.group(2),
                        parts, operator,
                    )
                    return

                current_match = _CURRENT_PATH_RE.match(path)
                if current_match is not None:
                    self._get_current(
                        current_match.group(1), parts, operator
                    )
                    return

                status_match = _STATUS_PATH_RE.match(path)
                if status_match is not None:
                    self._get_status(
                        status_match.group(1), parts, operator
                    )
                    return

                key_match = _KEY_PATH_RE.match(path)
                if key_match is not None:
                    self._get_key(key_match.group(1), parts, operator)
                    return
            except LedgerError as exc:
                self._server_error(exc)
                return

            self._send_json(404, {"error": "not found" })

        def _reject_read(self, tenant_id, key_id, status, message) -> None:
            if not self._record_attempt(
                tenant_id, key_id, audit_mod.ACTION_READ,
                audit_mod.OUTCOME_REJECTED,
            ):
                return
            self._send_json(status, {"error": message})

        def _get_key(self, key_id: str, parts, operator: str) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_READ, operator
            ):
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

        def _get_version(self, key_id: str, raw_version: str, parts,
                         operator: str) -> None:
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
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_READ, operator
            ):
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

        def _get_current(self, key_id: str, parts, operator: str) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_READ, operator
            ):
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

        def _get_status(self, key_id: str, parts, operator: str) -> None:
            tenant_id = self._tenant(parts)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id):
                return
            if not self._enforce(
                tenant_id, key_id, audit_mod.ACTION_READ, operator
            ):
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

        def _get_audit(self, parts, operator: str) -> None:
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

            # Parameter validation (400) precedes authorization; a policy
            # rejection of an audit query is recorded with the original
            # action ("audit") and outcome rejected, key_id null.
            if not self._enforce(
                tenant_id, None, audit_mod.ACTION_AUDIT, operator
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

        # -- policy management --------------------------------------------
        def _strict_tenant(self, parts):
            """Single header or single query tenant, with conflict auditing.

            Same rules as _audit_tenant (simultaneous/duplicate/empty/missing
            is a 400 naming tenant_id), but the failure is also written to the
            ledger as an invisible tenant_conflict event. Used by the policy
            management endpoints.
            """
            headers = self.headers.get_all("X-Tenant-Id") or []
            query_values = parse_qs(
                parts.query, keep_blank_values=True
            ).get("tenant_id", [])

            def fail(message: str) -> None:
                if self._record_conflict():
                    self._bad_request(message)

            if len(headers) > 1:
                fail("duplicate tenant_id (provide a single X-Tenant-Id header)")
                return None
            if len(query_values) > 1:
                fail("duplicate tenant_id (provide a single tenant_id parameter)")
                return None
            if headers and query_values:
                fail(
                    "conflicting tenant_id parameters (use header or query, not both)"
                )
                return None
            tenant = headers[0] if headers else (
                query_values[0] if query_values else None
            )
            if tenant is None:
                fail("missing required field: tenant_id")
                return None
            if not tenant:
                fail("field tenant_id must be a non-empty string")
                return None
            return tenant

        def do_PUT(self) -> None:
            parts = urlsplit(self.path)
            if parts.path != _POLICY_PATH:
                self._send_json(404, {"error": "not found"})
                return
            operator = self._operator()
            if operator is None:
                return
            try:
                self._put_policy(parts)
            except LedgerError as exc:
                self._server_error(exc)

        def do_DELETE(self) -> None:
            parts = urlsplit(self.path)
            if parts.path != _POLICY_PATH:
                self._send_json(404, {"error": "not found"})
                return
            operator = self._operator()
            if operator is None:
                return
            try:
                self._delete_policy(parts)
            except LedgerError as exc:
                self._server_error(exc)

        def _get_policy(self, parts) -> None:
            tenant_id = self._strict_tenant(parts)
            if tenant_id is None:
                return
            rules = policy_store.get(tenant_id)
            if rules is None:
                self._send_json(404, {"error": "policy not found"})
                return
            policy_store.audit_read(tenant_id)
            self._send_json(
                200,
                {
                    "tenant_id": tenant_id,
                    "rules": [r.to_json() for r in rules],
                },
            )

        def _put_policy(self, parts) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                if self._record_conflict():
                    self._bad_request(
                        "field tenant_id must be a non-empty string"
                    )
                return
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return
            if "rules" not in payload:
                self._bad_request("missing required field: rules")
                return
            try:
                rules = validate_rules(payload["rules"])
            except PolicyError as exc:
                self._bad_request(str(exc))
                return
            policy_store.put(tenant_id, rules)
            self._send_json(
                200,
                {
                    "tenant_id": tenant_id,
                    "rules": [r.to_json() for r in rules],
                },
            )

        def _delete_policy(self, parts) -> None:
            tenant_id = self._strict_tenant(parts)
            if tenant_id is None:
                return
            policy_store.delete(tenant_id)
            self._send_json(200, {"tenant_id": tenant_id, "deleted": True})

    return KeyHandler


def serve(host: str, port: int, data_dir: str) -> None:
    """Run the HTTP server until interrupted."""
    audit_log = AuditLog(data_dir)
    store = KeyStore(data_dir, audit_log)
    policy_store = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policy_store)
    httpd = ThreadingHTTPServer(
        (host, port),
        make_handler(store, policy_store, coordinator),
    )
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
