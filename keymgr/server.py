"""HTTP service exposing the key and audit APIs."""

import hashlib
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import audit as audit_mod
from . import envelope
from . import keybundle
from . import operations as operations_mod
from . import restore as restore_mod
from . import tenantbundle
from .artifacts import (
    ArtifactAlreadyTerminal,
    ArtifactStrandUnavailable,
)
from .audit import AuditLog, InvalidCursor, LedgerError
from .crypto import SUPPORTED_ALGORITHMS
from .operations import OperationStore
from .policy import PolicyError, PolicyStore, validate_rules
from .provider import ProviderInvalidMaterial, ProviderUnavailable
from .store import IMPORT_CONFLICT, KeyStore, LockTimeout, is_valid_key_id, validate_batch_items

_AUDIT_PATH = "/v1/audit"
_POLICY_PATH = "/v1/policy"
_OPERATIONS_PATH_RE = re.compile(r"^/v1/operations/([^/]+)$")
_IMPORT_PATH = "/v1/keys/import"
_BATCH_ROTATE_PATH = "/v1/keys/batch-rotate"
_BACKUP_PATH = "/v1/backup"
_RESTORE_PATH = "/v1/restore"
_KEY_PATH_RE = re.compile(r"^/v1/keys/([^/]+)$")
_ROTATE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/rotate$")
_REVOKE_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/revoke$")
_EXPORT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/export$")
_ENCRYPT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/encrypt$")
_DECRYPT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/decrypt$")
_STATUS_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/status$")
_VERSION_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/versions/([^/]+)$")
_CURRENT_PATH_RE = re.compile(r"^/v1/keys/([^/]+)/current$")
_POSITIVE_INT_RE = re.compile(r"[0-9]+")
_MISSING = object()


def make_handler(
    store: KeyStore,
    policy_store: PolicyStore,
    coordinator: "restore_mod.RestoreCoordinator",
    operation_store: "OperationStore",
    artifact_store=None,
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

        def _provider_unavailable(self, exc: Exception) -> None:
            # A KMS/HSM backend failure is a 503 with a generic message: the
            # detail (which may mention handles) is kept server-side and never
            # put in a response.
            self._send_json(
                503, {"error": "key management provider is unavailable"}
            )

        def _provider_invalid_material(self, exc: Exception) -> None:
            # Malformed imported material is a 400. The provider message names
            # a field but never embeds the material itself.
            self._send_json(400, {"error": str(exc)})

        # -- idempotency ---------------------------------------------------
        def _idempotency_key(self):
            """Return a valid Idempotency-Key, else send 400 (no side effect).

            The header is required on rotate/import/restore: exactly one
            header whose value is 1-128 unreserved ASCII characters. A
            missing, empty, duplicated or illegal value is a 400 that happens
            before any tenant work, audit event or provider call.
            """
            values = self.headers.get_all("Idempotency-Key") or []
            if len(values) > 1:
                self._bad_request(
                    "duplicate Idempotency-Key (provide a single header)"
                )
                return None
            value = values[0] if values else None
            if value is None:
                self._bad_request("missing required header: Idempotency-Key")
                return None
            if not operations_mod.is_valid_idempotency_key(value):
                self._bad_request(
                    "field Idempotency-Key must be 1-128 characters from "
                    "A-Za-z0-9._~-"
                )
                return None
            return value

        def _serve_conflict(self, record) -> None:
            self._send_json(
                409,
                {
                    "error": "Idempotency-Key is already bound to a "
                    "different request",
                    "operation_id": record.operation_id,
                },
            )

        def _replay_terminal(self, record) -> None:
            self._send_json(record.http_status, record.response)

        def _serve_pending_wait(self, record) -> bool:
            """Wait for a live owner's terminal, then replay/503.

            Returns True when a response was sent. The waiter writes nothing:
            on timeout the owner's still-pending record is left untouched.
            """
            record = operation_store.await_terminal(record)
            if record.is_terminal():
                self._replay_terminal(record)
                return True
            self._send_json(503, self._timed_out_body(record.operation_id))
            return True

        def _idempotent_precheck(self, path, tenant_id, operator, payload,
                                key) -> bool:
            """Resolve an already-bound key before expensive/decrypt work.

            Returns True when the response was sent (a conflict or a terminal
            replay); False when the caller should proceed with side-effect-free
            validation. A still-PENDING binding is deliberately left open: the
            idempotent guard is the single place that decides whether a live
            owner is running (wait) or a dead owner left a restartable strand
            (take over under the same operation_id). This keeps a failed
            bundle decrypt from consuming an Idempotency-Key, and makes a
            same-key/different-binding request answer 409 even when its bundle
            would not decrypt.
            """
            normalized = operations_mod.normalize_body(payload)
            peek = operation_store.peek(
                tenant_id, operator, path, normalized, key
            )
            if peek.kind == "new":
                return False
            if peek.kind == "conflict":
                self._serve_conflict(peek.record)
                return True
            if peek.record.is_terminal():
                self._replay_terminal(peek.record)
                return True
            return False

        def _op_state_for_status(self, http_status: int) -> str:
            # 201 is the only success; an explicit request conflict is the
            # "conflict" state. Every other terminal refusal (400/403/404) or
            # backend failure (500/503) records as "failed"; a lock-wait
            # timeout is recorded separately as "timed_out".
            return operations_mod.state_for_http_status(http_status)

        def _idempotent_rejection(
            self, operation, tenant_id, key_id, action, http_status, message
        ):
            """Durably persist a bound op's terminal rejection and append it.

            The operation kind, the exact key_id rule, the terminal status,
            the complete error response and the audit descriptor (action,
            outcome, tenant_id and the projection key_id) are merged into the
            durable operation context *before* the single rejection event is
            appended, so on a crash between the two: if the event is not
            durable the op recovers as an uncommitted failure (no key, file or
            handle was written by a refusal), and once it is durable startup
            recovery replays this exact 403/404/409 response verbatim instead
            of re-evaluating the policy or re-reading the object. The ledger
            dedupes on event_id, so a retry never writes the event twice. The
            error body contains only error and operation_id. Returns
            ``(http_status, body)`` for the idempotent guard.
            """
            op_id = operation.operation_id
            body = {"error": message, "operation_id": op_id}
            # The accurate key_id rule: a restore's and a batch rotation's
            # events are always key_id null; rotate/import carry the (already
            # validated) key_id.
            kind = (operation.details or {}).get("kind")
            audit_key_id = (
                None if kind in ("restore", "batch_rotate")
                else (key_id if is_valid_key_id(key_id) else None)
            )
            audit_desc = {
                "action": action,
                "outcome": audit_mod.OUTCOME_REJECTED,
                "tenant_id": tenant_id,
                "key_id": audit_key_id,
            }
            operation_store.stage_terminal(
                operation, http_status, body, audit=audit_desc
            )
            store.audit_attempt(
                tenant_id, audit_key_id, action, audit_mod.OUTCOME_REJECTED,
                event_id=op_id,
            )
            return http_status, body

        def _idempotent_provider_terminal(
            self, operation, http_status, message
        ):
            """Persist a bound op's provider-failure terminal and append it.

            A KMS/HSM load/contract/call/handle-delete failure (503) or a
            refusal of imported material (400) that happens *after* the
            Idempotency-Key is bound is a durable terminal state, exactly like
            a 403/404/409 refusal: the safe response is staged first, then a
            single ``rejected`` event named after the operation_id is appended
            (rotate projects the request key_id, import the in-bundle key_id,
            restore null), so HTTP/CLI retries and GET operation replay the
            same status/body byte-for-byte and the event is never duplicated.
            The body never carries the backend detail, a handle, material or
            a passphrase. A failure of the stage write or the ledger append
            propagates (the guard finalizes failed(500)); nothing committed.
            """
            op_id = operation.operation_id
            body = {"error": message, "operation_id": op_id}
            details = operation.details or {}
            kind = details.get("kind")
            if kind == "batch_rotate":
                action = audit_mod.ACTION_BATCH_ROTATE
            elif kind == "rotate":
                action = audit_mod.ACTION_ROTATE
            else:
                action = audit_mod.ACTION_IMPORT
            audit_key_id = (
                None if kind in ("restore", "batch_rotate")
                else (
                    details.get("key_id")
                    if is_valid_key_id(details.get("key_id"))
                    else None
                )
            )
            operation_store.stage_terminal(
                operation,
                http_status,
                body,
                audit={
                    "action": action,
                    "outcome": audit_mod.OUTCOME_REJECTED,
                    "tenant_id": operation.tenant_id,
                    "key_id": audit_key_id,
                },
            )
            store.audit_attempt(
                operation.tenant_id, audit_key_id, action,
                audit_mod.OUTCOME_REJECTED, event_id=op_id,
            )
            operation_store.finish(
                operation, operations_mod.STATUS_FAILED, http_status, body
            )
            self._send_json(http_status, body)

        def _timed_out_body(self, operation_id: str) -> dict:
            return {
                "error": "operation timed out waiting for a lock",
                "operation_id": operation_id,
            }

        def _strand_unavailable_body(self, operation_id: str) -> dict:
            # Material-safe: no handle, material, passphrase or path detail.
            return {
                "error": "temporary storage failure, please retry",
                "operation_id": operation_id,
            }

        def _send_strand_unavailable(self, operation_id, status: int) -> None:
            # The operation stays PENDING (no provider/key/handle/audit was
            # touched); the client retries with the same Idempotency-Key and
            # reuses this operation_id.
            self._send_json(status, self._strand_unavailable_body(operation_id))

        def _idempotent_guard(self, path, tenant_id, operator, payload, key,
                              executor) -> None:
            """Bind the Idempotency-Key and run an idempotent mutation.

            ``key`` is the already-validated Idempotency-Key. ``executor`` is
            ``executor(operation, mirror) -> (http_status, response_body)``
            and performs the mutation once; it may raise
            ProviderUnavailable / ProviderInvalidMaterial / LedgerError /
            LockTimeout. On a new binding the operation is persisted pending,
            its 0600/fsynced artifact mirror is created BEFORE any provider
            call, the mutation is executed once and the operation is recorded
            with its terminal status/response; an identical retry replays the
            stored result (no new audit event); a same-key/different-binding
            request gets 409 naming the original operation; waiting on an
            in-flight owner beyond 5 s answers timed_out (503) without
            writing anything.

            If the 0600 mirror cannot be created (an OSError making the
            directory, temp file or rename) AFTER the key bound but BEFORE the
            first provider call, the bound operation is left pending and the
            request answers a material-safe 500/503: no provider, key, handle
            or audit is written, and a later identical HTTP/CLI request
            rebuilds the mirror and runs the attempt under the SAME
            operation_id.
            """
            normalized = operations_mod.normalize_body(payload)
            begin = operation_store.begin(
                tenant_id, operator, path, normalized, key
            )
            if begin.kind == "conflict":
                self._serve_conflict(begin.record)
                return
            if begin.kind == "replay":
                self._serve_replay_or_takeover(begin.record, executor)
                return
            self._run_owned_attempt(
                begin.record, executor, blocking=True, takeover=False
            )

        def _serve_replay_or_takeover(self, record, executor) -> None:
            """Resolve an identical binding: replay a terminal, wait for a live
            owner, or take a dead owner's clean pre-provider strand over."""
            if record.is_terminal():
                self._replay_terminal(record)
                return
            if artifact_store is None:
                self._serve_pending_wait(record)
                return
            # Still pending. First try to claim the attempt immediately: if a
            # live owner (thread or process) holds it, fall back to the 5 s
            # wait. A dead owner with a clean, never-committed strand hands it
            # over under the same operation_id.
            try:
                self._run_owned_attempt(
                    record, executor, blocking=False, takeover=True
                )
            except BlockingIOError:
                self._serve_pending_wait(record)

        def _run_owned_attempt(self, operation, executor, blocking,
                              takeover) -> None:
            """Run the attempt once, owning its mirror + claim for the window.

            Used both by the binding winner (``takeover=False``) and by a
            retried identical request taking a stranded pending attempt over
            (``takeover=True``).
            """
            op_id = operation.operation_id
            if artifact_store is None:
                # Mirrors disabled (tests/legacy wiring): run directly.
                self._idempotent_run_body(operation, op_id, executor, None)
                return
            attempt_cm = artifact_store.attempt(
                operation, blocking, takeover=takeover,
                operation_store=operation_store if takeover else None,
            )
            try:
                mirror = attempt_cm.__enter__()
            except ArtifactAlreadyTerminal as already:
                # The owner reached a terminal while the claim was taken:
                # replay its fresh stored result verbatim, execute nothing.
                self._replay_terminal(already.record)
                return
            except ArtifactStrandUnavailable as exc:
                # Mirror claim/creation failed with the op still bound and
                # pending: surface 500/503 without finalizing it.
                self._send_strand_unavailable(op_id, exc.http_status)
                return
            except BlockingIOError:
                # A live owner holds the attempt; the caller waits.
                raise
            try:
                self._idempotent_run_body(
                    operation, op_id, executor, mirror
                )
            finally:
                # Committed: verified ownership then dropped; uncommitted:
                # dropped only once every rollback artifact is gone. A
                # mirror that cannot be verified survives for startup.
                try:
                    artifact_store.after_terminal(mirror)
                finally:
                    attempt_cm.__exit__(None, None, None)

        def _idempotent_run_body(self, operation, op_id, executor, mirror):
            try:
                http_status, body = executor(operation, mirror)
            except ArtifactStrandUnavailable as exc:
                # The mirror could not be described/tied in before the first
                # provider call, or a clean strand could not be taken over.
                # Nothing committed: leave the operation PENDING and answer
                # 500/503. A same-key HTTP/CLI retry reuses the operation_id.
                self._send_strand_unavailable(op_id, exc.http_status)
                return
            except LockTimeout:
                # Lock wait exceeded 5 s: no key, audit event or handle was
                # written. Record and answer timed_out (503).
                body = self._timed_out_body(op_id)
                operation_store.finish(
                    operation, operations_mod.STATUS_TIMED_OUT, 503, body
                )
                self._send_json(503, body)
                return
            except ProviderInvalidMaterial as exc:
                # A bound refusal of imported material is a terminal 400:
                # stage the field-naming error, append its single rejected
                # event and finish. A failure of that persistence itself
                # becomes failed(500) below; nothing committed.
                try:
                    self._idempotent_provider_terminal(
                        operation, 400, str(exc)
                    )
                    return
                except (OSError, LedgerError) as persist_exc:
                    body = {
                        "error": "audit ledger failure: %s" % persist_exc,
                        "operation_id": op_id,
                    }
                    operation_store.finish(
                        operation, operations_mod.STATUS_FAILED, 500, body
                    )
                    self._send_json(500, body)
                    return
            except ProviderUnavailable:
                # A bound KMS/HSM fault (load/contract/call/handle-delete) is
                # a durable terminal 503 with the fixed safe message and one
                # rejected event named after the operation_id; retries replay
                # it verbatim. Persistence failure becomes failed(500).
                try:
                    self._idempotent_provider_terminal(
                        operation, 503,
                        "key management provider is unavailable",
                    )
                    return
                except (OSError, LedgerError) as persist_exc:
                    body = {
                        "error": "audit ledger failure: %s" % persist_exc,
                        "operation_id": op_id,
                    }
                    operation_store.finish(
                        operation, operations_mod.STATUS_FAILED, 500, body
                    )
                    self._send_json(500, body)
                    return
            except OSError as exc:
                # Persisting the staged result (or another pre-commit write)
                # failed before the commit-point append: the store already
                # rolled back the file and minted handles, so nothing
                # committed. Finalize failed(500).
                body = {
                    "error": "audit ledger failure: %s" % exc,
                    "operation_id": op_id,
                }
                operation_store.finish(
                    operation, operations_mod.STATUS_FAILED, 500, body
                )
                self._send_json(500, body)
                return
            except LedgerError as exc:
                body = {
                    "error": "audit ledger failure: %s" % exc,
                    "operation_id": op_id,
                }
                operation_store.finish(
                    operation, operations_mod.STATUS_FAILED, 500, body
                )
                self._send_json(500, body)
                return
            body = dict(body)
            body["operation_id"] = op_id
            state = self._op_state_for_status(http_status)
            operation_store.finish(operation, state, http_status, body)
            self._send_json(http_status, body)

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
        def _read_json_object(self, audit: bool = True):
            """Return the request body as a dict, or None after responding.

            A body that cannot be parsed carries no usable tenant. By default
            an invisible tenant_conflict is written before the 400 (and a
            ledger failure turns the answer into 500). The idempotent
            mutation endpoints pass ``audit=False``: an Idempotency-Key has
            already been validated on them, but no operation is bound yet, so
            a parse/parameter failure must leave no audit event, operation
            record, key or provider handle behind.
            """
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                if not audit or self._record_conflict():
                    self._bad_request("invalid Content-Length")
                return None
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                if not audit or self._record_conflict():
                    self._bad_request("request body must be valid JSON")
                return None
            if not isinstance(payload, dict):
                if not audit or self._record_conflict():
                    self._bad_request("request body must be a JSON object")
                return None
            return payload

        def _tenant(self, parts, body=_MISSING, audit: bool = True):
            """Resolve tenant from X-Tenant-Id / query / JSON body.

            Returns the tenant id, or None after sending 400. A duplicated
            X-Tenant-Id header or a duplicated tenant_id query parameter is a
            400 naming tenant_id, as is any disagreement between the sources;
            several sources carrying the *same* value are accepted. Every
            failure is written to the ledger as an invisible tenant_conflict
            event, except on the idempotent endpoints before their key is
            bound (``audit=False``): such a parameter failure must leave no
            audit event behind.
            """
            def fail(message: str) -> None:
                if not audit or self._record_conflict():
                    self._bad_request(message)

            headers = self.headers.get_all("X-Tenant-Id") or []
            if len(headers) > 1:
                fail("duplicate tenant_id (provide a single X-Tenant-Id header)")
                return None
            query_values = parse_qs(
                parts.query, keep_blank_values=True
            ).get("tenant_id", [])
            if len(query_values) > 1:
                fail("duplicate tenant_id (provide a single tenant_id parameter)")
                return None

            candidates = []
            if headers:
                candidates.append(headers[0])
            if query_values:
                candidates.append(query_values[0])
            if body is not _MISSING:
                body_tenant = body.get("tenant_id")
                if body_tenant is not None:
                    if not isinstance(body_tenant, str) or not body_tenant:
                        fail("field tenant_id must be a non-empty string")
                        return None
                    candidates.append(body_tenant)
            distinct = set(candidates)
            if len(distinct) > 1:
                fail(
                    "conflicting tenant_id parameters (header, query and body must agree)"
                )
                return None
            if not distinct:
                fail("missing required field: tenant_id")
                return None
            tenant = next(iter(distinct))
            if not tenant:
                fail("field tenant_id must be a non-empty string")
                return None
            return tenant

        def _audit_tenant(self, parts):
            """Resolve the single-source tenant for GET /v1/audit.

            Exactly one of a single X-Tenant-Id header or a single
            ?tenant_id= parameter must supply it. Any missing/duplicate/
            empty/conflicting value is a 400 naming tenant_id and is written
            to the ledger as an invisible tenant_conflict event, like every
            other tenant-parameter failure.
            """
            def fail(message: str) -> None:
                if self._record_conflict():
                    self._bad_request(message)

            headers = self.headers.get_all("X-Tenant-Id") or []
            if len(headers) > 1:
                fail(
                    "duplicate tenant_id (provide a single X-Tenant-Id header)"
                )
                return None
            query_values = parse_qs(parts.query, keep_blank_values=True).get(
                "tenant_id", []
            )
            if len(query_values) > 1:
                fail(
                    "duplicate tenant_id (provide a single tenant_id parameter)"
                )
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

        def _parse_version(self, raw):
            """Parse a positive integer version from the URL, else 400."""
            if not _POSITIVE_INT_RE.fullmatch(raw) or int(raw) < 1:
                self._bad_request("field version must be a positive integer")
                return None
            return int(raw)

        def _bad_key_id(self, key_id, audit: bool = True) -> bool:
            """Reject a malformed key_id as a 400 naming the field.

            Only a strict RFC 4122 UUID4 passes; anything else is a parameter
            error (never a 404, so an invalid id cannot probe existence). By
            default the rejection is recorded as an invisible
            tenant_conflict event; the idempotent endpoints pass ``audit=False``
            before their key is bound so the 400 has no side effect.
            """
            if is_valid_key_id(key_id):
                return False
            if not audit or self._record_conflict():
                self._bad_request("field key_id must be a UUID4")
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

                encrypt_match = _ENCRYPT_PATH_RE.match(path)
                if encrypt_match is not None:
                    self._encrypt_key(encrypt_match.group(1), parts, operator)
                    return

                decrypt_match = _DECRYPT_PATH_RE.match(path)
                if decrypt_match is not None:
                    self._decrypt_key(decrypt_match.group(1), parts, operator)
                    return

                if path == _IMPORT_PATH:
                    self._import_key(parts, operator)
                    return

                if path == _BATCH_ROTATE_PATH:
                    self._batch_rotate_keys(parts, operator)
                    return

                if path == _BACKUP_PATH:
                    self._backup_tenant(parts, operator)
                    return

                if path == _RESTORE_PATH:
                    self._restore_tenant(parts, operator)
                    return
            except ProviderInvalidMaterial as exc:
                self._provider_invalid_material(exc)
                return
            except ProviderUnavailable as exc:
                self._provider_unavailable(exc)
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
            # Validate the Idempotency-Key before reading or parsing the body
            # (and before any tenant resolution, audit write or provider
            # call): a missing/duplicate/illegal header is a side-effect-free
            # 400, and so is every later parse/parameter failure on this
            # endpoint until the key is actually bound.
            idem_key = self._idempotency_key()
            if idem_key is None:
                return
            payload = self._read_json_object(audit=False)
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                # The body must itself carry a non-empty tenant_id.
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload, audit=False)
            if tenant_id is None:
                return
            if self._bad_key_id(key_id, audit=False):
                return
            if not isinstance(payload.get("algorithm"), str):
                self._bad_request("missing required field: algorithm")
                return
            algorithm = payload["algorithm"]
            if algorithm not in SUPPORTED_ALGORITHMS:
                self._bad_request(
                    "unsupported value for field algorithm: %r (supported: %s)"
                    % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
                )
                return

            def execute(operation, mirror=None):
                # The operation kind and the exact key_id rule are durable
                # before the authorization check, so even a 403 terminal can
                # be replayed verbatim after a crash from context alone.
                operation_store.update_details(
                    operation,
                    {"kind": "rotate", "key_id": key_id,
                     "algorithm": algorithm},
                )
                if mirror is not None:
                    # Kind/action/write set land in the mirror BEFORE the
                    # policy check and provider call.
                    mirror.describe(
                        {"kind": "rotate", "write_set": [key_id]}
                    )
                # Authorization follows validation and precedes existence; a
                # denial is a bound terminal 403 whose single rejection event
                # is named after the operation_id.
                if not policy_store.is_allowed(
                    tenant_id, audit_mod.ACTION_ROTATE, operator
                ):
                    return self._idempotent_rejection(
                        operation, tenant_id, key_id,
                        audit_mod.ACTION_ROTATE, 403,
                        "action not permitted by policy",
                    )

                def stage_success(committed_record):
                    # Runs after the key file landed, before the commit-point
                    # ledger append: the exact 201 body is durable with the
                    # event, independent of later policy/object state.
                    body = committed_record.to_rotate_response()
                    body["operation_id"] = operation.operation_id
                    operation_store.stage_terminal(operation, 201, body)

                record = store.rotate(
                    key_id, tenant_id, algorithm,
                    event_id=operation.operation_id,
                    lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                    pre_commit=stage_success,
                    mirror=mirror,
                )
                if record is None:
                    return self._idempotent_rejection(
                        operation, tenant_id, key_id,
                        audit_mod.ACTION_ROTATE, 404, "key not found",
                    )
                # The success event committed in the same outbox transaction.
                return 201, record.to_rotate_response()

            self._idempotent_guard(
                parts.path, tenant_id, operator, payload, idem_key, execute
            )

        def _parse_batch_items(self, raw):
            """Validate a batch-rotate items array before the key is bound.

            Thin HTTP wrapper over the shared, side-effect-free validator so
            the CLI and the service accept exactly the same items shape.
            """
            return validate_batch_items(raw)

        def _batch_rotate_keys(self, parts, operator: str) -> None:
            """POST /v1/keys/batch-rotate.

            The Idempotency-Key is checked before the body is read. Every
            parse/parameter/items failure is a side-effect-free 400 (no audit
            event, operation record, key change or provider handle) and never
            consumes the key. After binding, authorization follows the
            ``rotate`` action (a denial is a terminal 403 whose single
            rejected ``batch_rotate`` event has key_id null); any unknown or
            foreign key_id makes the whole batch a terminal 404 with zero
            changes. On success every key gains one fresh version under the
            rotate semantics, the batch commits atomically, and the response
            items are in request order.
            """
            idem_key = self._idempotency_key()
            if idem_key is None:
                return
            payload = self._read_json_object(audit=False)
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload, audit=False)
            if tenant_id is None:
                return
            items, error = self._parse_batch_items(payload.get("items"))
            if error is not None:
                self._bad_request(error)
                return

            def execute(operation, mirror=None):
                # Kind and the exact request-order item set are durable before
                # any business check, so a 403/404 terminal replays from
                # context alone after a crash.
                operation_store.update_details(
                    operation,
                    {
                        "kind": "batch_rotate",
                        "items": [
                            {"key_id": key_id, "algorithm": algorithm}
                            for key_id, algorithm in items
                        ],
                    },
                )
                if mirror is not None:
                    # The whole batch's write set is mirrored before the
                    # authorization check / any provider call.
                    mirror.describe(
                        {
                            "kind": "batch_rotate",
                            "write_set": [key_id for key_id, _ in items],
                        }
                    )
                # Authorization follows rotate and precedes existence; a
                # denial is a bound terminal 403 with one rejected
                # batch_rotate event (key_id null).
                if not policy_store.is_allowed(
                    tenant_id, audit_mod.ACTION_ROTATE, operator
                ):
                    return self._idempotent_rejection(
                        operation, tenant_id, None,
                        audit_mod.ACTION_BATCH_ROTATE, 403,
                        "action not permitted by policy",
                    )

                def stage_success(records_by_id):
                    # After every key file landed, before the single
                    # commit-point append: stage the exact 201 body verbatim,
                    # with items in REQUEST order.
                    result_items = [
                        {
                            "key_id": key_id,
                            "version": records_by_id[key_id].current.version,
                            "algorithm": records_by_id[key_id].current.algorithm,
                            "public_key": records_by_id[key_id].current.public_key,
                        }
                        for key_id, _ in items
                    ]
                    operation_store.stage_terminal(
                        operation,
                        201,
                        {
                            "items": result_items,
                            "operation_id": operation.operation_id,
                        },
                    )

                status, result = store.batch_rotate(
                    tenant_id, items,
                    event_id=operation.operation_id,
                    lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                    pre_commit=stage_success,
                    mirror=mirror,
                )
                if status == store.BATCH_NOT_FOUND:
                    # Any unknown/foreign key_id fails the whole batch with no
                    # change; the answer is identical to a missing key so
                    # cross-tenant existence never leaks.
                    return self._idempotent_rejection(
                        operation, tenant_id, None,
                        audit_mod.ACTION_BATCH_ROTATE, 404, "key not found",
                    )
                result_items = [
                    {
                        "key_id": key_id,
                        "version": record.current.version,
                        "algorithm": record.current.algorithm,
                        "public_key": record.current.public_key,
                    }
                    for key_id, record in result
                ]
                # The single success event committed with the files.
                return 201, {"items": result_items}

            self._idempotent_guard(
                parts.path, tenant_id, operator, payload, idem_key, execute
            )

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

        def _reject_crypto(self, tenant_id, key_id, action, status,
                           message) -> None:
            """Audit a rejected encrypt/decrypt attempt, then answer."""
            if not self._record_attempt(
                tenant_id, key_id, action, audit_mod.OUTCOME_REJECTED
            ):
                return
            self._send_json(status, {"error": message})

        def _crypto_request_base(self, key_id, parts, action):
            """Shared parse/validate prelude for encrypt and decrypt.

            Returns ``(tenant_id, payload)`` or None after the response was
            sent. Follows the export endpoint's rules: body/tenant failures
            are invisible tenant_conflict events, and field errors after the
            tenant is known are tenant-visible rejected attempts.
            """
            payload = self._read_json_object()
            if payload is None:
                return None
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                if not self._record_conflict():
                    return None
                self._bad_request("field tenant_id must be a non-empty string")
                return None
            tenant_id = self._tenant(parts, payload)
            if tenant_id is None:
                return None
            if self._bad_key_id(key_id):
                return None
            return tenant_id, payload

        def _request_aad(self, tenant_id, key_id, action, payload):
            """Decode the optional aad field; None means 400 was sent."""
            aad = payload.get("aad")
            if aad is None:
                return b""
            try:
                return envelope.b64_decode_field(aad, "aad")
            except envelope.EnvelopeError as exc:
                self._reject_crypto(
                    tenant_id, key_id, action, 400, str(exc)
                )
                return None

        def _encrypt_key(self, key_id: str, parts, operator: str) -> None:
            """POST /v1/keys/{key_id}/encrypt.

            Body ``{tenant_id, version?, plaintext, aad?}``; plaintext and aad
            are base64, version defaults to the current version. The answer
            carries only the opaque envelope token -- never the data key, the
            KEK or any backend material.
            """
            action = audit_mod.ACTION_ENCRYPT
            base = self._crypto_request_base(key_id, parts, action)
            if base is None:
                return
            tenant_id, payload = base
            version = payload.get("version")
            if version is not None and (
                not isinstance(version, int)
                or isinstance(version, bool)
                or version < 1
            ):
                self._reject_crypto(
                    tenant_id, key_id, action, 400,
                    "field version must be a positive integer",
                )
                return
            plaintext = payload.get("plaintext")
            if not isinstance(plaintext, str):
                self._reject_crypto(
                    tenant_id, key_id, action, 400,
                    "field plaintext must be a base64 string"
                    if "plaintext" in payload
                    else "missing required field: plaintext",
                )
                return
            try:
                raw_plaintext = envelope.b64_decode_field(
                    plaintext, "plaintext"
                )
            except envelope.EnvelopeError as exc:
                self._reject_crypto(
                    tenant_id, key_id, action, 400, str(exc)
                )
                return
            aad = self._request_aad(tenant_id, key_id, action, payload)
            if aad is None:
                return
            if not self._enforce(tenant_id, key_id, action, operator):
                return
            status, record, ver, kek = store.crypto_material(
                key_id, tenant_id, version
            )
            if status == store.CRYPTO_NOT_FOUND:
                # Unknown key, unknown version and cross-tenant access are
                # indistinguishable, all 404.
                self._reject_crypto(
                    tenant_id, key_id, action, 404, "key not found"
                )
                return
            if status == store.CRYPTO_REVOKED:
                self._reject_crypto(
                    tenant_id, key_id, action, 409, "key is revoked"
                )
                return
            token = envelope.encode_envelope(
                key_id=key_id,
                version=ver.version,
                algorithm=ver.algorithm,
                kek=kek,
                plaintext=raw_plaintext,
                aad=aad,
            )
            if not self._record_attempt(
                tenant_id, key_id, action, audit_mod.OUTCOME_SUCCESS
            ):
                return
            self._send_json(
                200, {"format": envelope.FORMAT, "envelope": token}
            )

        def _decrypt_key(self, key_id: str, parts, operator: str) -> None:
            """POST /v1/keys/{key_id}/decrypt.

            Body ``{tenant_id, envelope, aad?}``. The envelope names its own
            key_id and version; both must match the request, the AAD must
            match the sealed one, and any tampering is a 400 naming the
            field. The plaintext leaves only inside the response body.
            """
            action = audit_mod.ACTION_DECRYPT
            base = self._crypto_request_base(key_id, parts, action)
            if base is None:
                return
            tenant_id, payload = base
            token = payload.get("envelope")
            if not isinstance(token, str) or not token:
                self._reject_crypto(
                    tenant_id, key_id, action, 400,
                    "field envelope must be a non-empty string",
                )
                return
            aad = self._request_aad(tenant_id, key_id, action, payload)
            if aad is None:
                return
            # Structural validation is parameter validation: it runs before
            # authorization, exactly like the other request fields.
            try:
                opened = envelope.decode_envelope(token)
            except envelope.EnvelopeError as exc:
                self._reject_crypto(
                    tenant_id, key_id, action, 400, str(exc)
                )
                return
            if opened.key_id != key_id:
                self._reject_crypto(
                    tenant_id, key_id, action, 400,
                    "field envelope key_id does not match the request key_id",
                )
                return
            if not self._enforce(tenant_id, key_id, action, operator):
                return
            status, record, ver, kek = store.crypto_material(
                key_id, tenant_id, opened.version
            )
            if status == store.CRYPTO_NOT_FOUND:
                self._reject_crypto(
                    tenant_id, key_id, action, 404, "key not found"
                )
                return
            if status == store.CRYPTO_REVOKED:
                self._reject_crypto(
                    tenant_id, key_id, action, 409, "key is revoked"
                )
                return
            if opened.algorithm != ver.algorithm:
                self._reject_crypto(
                    tenant_id, key_id, action, 400,
                    "field envelope algorithm does not match the key version",
                )
                return
            if opened.aad != aad:
                self._reject_crypto(
                    tenant_id, key_id, action, 400,
                    "field aad does not match the envelope",
                )
                return
            try:
                plaintext = envelope.open_envelope(opened, kek)
            except envelope.EnvelopeError as exc:
                self._reject_crypto(
                    tenant_id, key_id, action, 400, str(exc)
                )
                return
            if not self._record_attempt(
                tenant_id, key_id, action, audit_mod.OUTCOME_SUCCESS
            ):
                return
            self._send_json(
                200, {"plaintext": envelope.b64_encode(plaintext)}
            )

        def _import_key(self, parts, operator: str) -> None:
            """POST /v1/keys/import.

            The Idempotency-Key is checked before the body is even read.
            Every subsequent parse/decrypt/parameter failure is a
            side-effect-free 400 (no audit event, no operation record, no
            provider handle) and never consumes the key. Once the key is
            bound, a policy denial / unknown key / conflict is a terminal
            state whose single rejection event is named after the
            operation_id. A key_id the tenant already owns is a 409 that
            leaves the original record untouched; the same key_id owned by
            another tenant answers 404 so existence never leaks across
            tenants.
            """
            idem_key = self._idempotency_key()
            if idem_key is None:
                return
            payload = self._read_json_object(audit=False)
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload, audit=False)
            if tenant_id is None:
                return
            passphrase = payload.get("passphrase")
            if not isinstance(passphrase, str) or not passphrase:
                self._bad_request(
                    "field passphrase must be a non-empty string"
                )
                return
            bundle = payload.get("bundle")
            if not isinstance(bundle, str) or not bundle:
                self._bad_request("field bundle must be a non-empty string")
                return
            # An already-bound key replays/conflicts before we decrypt, so a
            # wrong passphrase on a retry neither masks a replay nor consumes
            # the key.
            if self._idempotent_precheck(
                parts.path, tenant_id, operator, payload, idem_key
            ):
                return
            # Decrypting/authenticating the bundle is side-effect free, so it
            # stays outside the idempotent binding: a wrong passphrase or a
            # tampered bundle is a plain 400 with no audit event and never
            # consumes the key.
            try:
                decoded = keybundle.decode_bundle(bundle, passphrase)
            except keybundle.BundleError as exc:
                self._bad_request(str(exc))
                return

            def execute(operation, mirror=None):
                key_id = decoded["key_id"]
                # Kind and exact key_id rule are durable before any business
                # check, so a 403/404/409 terminal replays from context alone.
                operation_store.update_details(
                    operation,
                    {"kind": "import", "key_id": key_id},
                )
                if mirror is not None:
                    mirror.describe(
                        {"kind": "import", "write_set": [key_id]}
                    )
                # Authorization precedes the conflict check: a denial is a
                # bound terminal 403 even when the key_id already exists for
                # another tenant.
                if not policy_store.is_allowed(
                    tenant_id, audit_mod.ACTION_IMPORT, operator
                ):
                    return self._idempotent_rejection(
                        operation, tenant_id, key_id,
                        audit_mod.ACTION_IMPORT, 403,
                        "action not permitted by policy",
                    )

                def stage_success(committed_record):
                    # After the new key file landed, before the commit-point
                    # append: stage the exact 201 body verbatim.
                    body = committed_record.to_create_response()
                    body["operation_id"] = operation.operation_id
                    operation_store.stage_terminal(operation, 201, body)

                # ProviderInvalidMaterial propagates to the guard (400). The
                # existence check and the create are atomic in the store.
                status, record = store.import_bundle(
                    tenant_id, decoded,
                    event_id=operation.operation_id,
                    lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                    pre_commit=stage_success,
                    mirror=mirror,
                )
                if status == IMPORT_CONFLICT:
                    if record.tenant_id == tenant_id:
                        return self._idempotent_rejection(
                            operation, tenant_id, record.key_id,
                            audit_mod.ACTION_IMPORT, 409,
                            "key_id already exists for this tenant",
                        )
                    # Same answer as a missing key: never confirm another
                    # tenant owns this key_id.
                    return self._idempotent_rejection(
                        operation, tenant_id, record.key_id,
                        audit_mod.ACTION_IMPORT, 404, "key not found",
                    )
                # The success event committed in the same transaction as file.
                return 201, record.to_create_response()

            self._idempotent_guard(
                parts.path, tenant_id, operator, payload, idem_key, execute
            )

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

            The Idempotency-Key is checked before the body is read. Parse,
            parameter and decryption failures are side-effect-free 400s (no
            audit event, no operation record, no provider handle) and never
            consume the key. After the key is bound, authorization (import)
            precedes the in-bundle tenant check: a bundle naming another
            tenant answers 404. A key_id or policy already present for this
            tenant is a terminal 409 that changes nothing; an id occupied by
            another tenant answers 404. Every audit event for a restore
            carries key_id null and is named after the operation_id.
            """
            idem_key = self._idempotency_key()
            if idem_key is None:
                return
            payload = self._read_json_object(audit=False)
            if payload is None:
                return
            body_tenant = payload.get("tenant_id")
            if not isinstance(body_tenant, str) or not body_tenant:
                self._bad_request("field tenant_id must be a non-empty string")
                return
            tenant_id = self._tenant(parts, payload, audit=False)
            if tenant_id is None:
                return
            passphrase = payload.get("passphrase")
            if not isinstance(passphrase, str) or not passphrase:
                self._bad_request(
                    "field passphrase must be a non-empty string"
                )
                return
            bundle = payload.get("bundle")
            if not isinstance(bundle, str) or not bundle:
                self._bad_request("field bundle must be a non-empty string")
                return
            # An already-bound key replays/conflicts before we decrypt, so a
            # wrong passphrase on a retry never masks a replay.
            if self._idempotent_precheck(
                parts.path, tenant_id, operator, payload, idem_key
            ):
                return
            # Decrypting/authenticating the bundle is side-effect free, so it
            # stays outside the idempotent binding; a failure is a 400 with no
            # audit event and never consumes the key.
            try:
                decoded = tenantbundle.decode_bundle(bundle, passphrase)
            except tenantbundle.TenantBundleError as exc:
                self._bad_request(str(exc))
                return

            def execute(operation, mirror=None):
                key_ids = sorted(k["key_id"] for k in decoded["keys"])
                writes_policy = decoded["policy"] is not None
                # Kind and write-set facts are durable before any business
                # check. Restore events always project key_id null, enforced
                # by the rejection helper from kind == "restore".
                operation_store.update_details(
                    operation,
                    {
                        "kind": "restore",
                        "key_ids": key_ids,
                        "policy_restored": writes_policy,
                    },
                )
                if mirror is not None:
                    mirror.describe(
                        {
                            "kind": "restore",
                            "write_set": key_ids,
                            "policy": writes_policy,
                        }
                    )
                # Authorization (import) precedes the in-bundle tenant check.
                if not policy_store.is_allowed(
                    tenant_id, audit_mod.ACTION_IMPORT, operator
                ):
                    return self._idempotent_rejection(
                        operation, tenant_id, None,
                        audit_mod.ACTION_IMPORT, 403,
                        "action not permitted by policy",
                    )
                if decoded["tenant_id"] != tenant_id:
                    # The sealed bundle belongs to another tenant: answer like
                    # a missing object so existence never leaks.
                    return self._idempotent_rejection(
                        operation, tenant_id, None,
                        audit_mod.ACTION_IMPORT, 404,
                        "tenant backup not found",
                    )

                def stage_success():
                    # After the write set landed, before the single
                    # commit-point append: stage the exact 201 body verbatim.
                    body = {
                        "tenant_id": tenant_id,
                        "key_ids": key_ids,
                        "policy_restored": writes_policy,
                        "operation_id": operation.operation_id,
                    }
                    operation_store.stage_terminal(operation, 201, body)

                # ProviderInvalidMaterial (400) and LedgerError (500)
                # propagate to the guard; the coordinator has already removed
                # every written file on a ledger failure.
                result = coordinator.restore(
                    tenant_id, decoded,
                    event_id=operation.operation_id,
                    lock_timeout=operations_mod.LOCK_WAIT_SECONDS,
                    pre_commit=stage_success,
                    mirror=mirror,
                )
                if result.status == restore_mod.RESTORE_CREATED:
                    # The single success event committed with the files.
                    return (
                        201,
                        {
                            "tenant_id": result.tenant_id,
                            "key_ids": result.key_ids,
                            "policy_restored": result.policy_restored,
                        },
                    )
                if result.status == restore_mod.RESTORE_SAME_TENANT_CONFLICT:
                    return self._idempotent_rejection(
                        operation, tenant_id, None,
                        audit_mod.ACTION_IMPORT, 409,
                        "backup target already contains this data",
                    )
                return self._idempotent_rejection(
                    operation, tenant_id, None,
                    audit_mod.ACTION_IMPORT, 404,
                    "tenant backup not found",
                )

            self._idempotent_guard(
                parts.path, tenant_id, operator, payload, idem_key, execute
            )

        # -- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path

            operator = self._operator()
            if operator is None:
                return

            operation_match = _OPERATIONS_PATH_RE.match(path)
            if operation_match is not None:
                self._get_operation(
                    operation_match.group(1), parts, operator
                )
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

        # -- operations ----------------------------------------------------
        def _get_operation(self, operation_id: str, parts, operator: str) -> None:
            """GET /v1/operations/{operation_id}.

            Scoped to exactly one tenant (single header or single query
            parameter) and the single operator. An unknown id, a malformed id,
            an operation owned by another tenant or by another operator all
            answer 404 so existence never leaks.
            """
            tenant_id = self._audit_tenant(parts)
            if tenant_id is None:
                return
            record = operation_store.get(operation_id, tenant_id, operator)
            if record is None:
                self._send_json(404, {"error": "operation not found"})
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
                # An illegal identifier is a tenant_conflict event, like any
                # other malformed tenant/key parameter.
                if self._record_conflict():
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


def _resolve_committed_operation(store, policy_store, record, event):
    """Rebuild the terminal response of a committed-but-unfinished operation.

    Runs during startup recovery after the key/restore outbox recovery has
    made the mutation durable. The audit event named after the operation_id
    is the durable fact: a ``success`` event rebuilds the original 201
    response, while a ``rejected`` event rebuilds the exact 403/404/409
    terminal (its state, error body and audit projection) from the recorded
    action/key_id and the current tenant state. Returns
    ``(http_status, response)``.
    """
    op_id = record.operation_id
    details = record.details or {}
    kind = details.get("kind")
    tenant_id = record.tenant_id
    operator_id = record.operator_id

    def error(status: int, message: str):
        return status, {"error": message, "operation_id": op_id}

    if event.outcome == audit_mod.OUTCOME_REJECTED:
        action = event.action
        terminal = details.get("terminal")
        # A batch rotation is AUTHORIZED as rotate even though its audit
        # action is batch_rotate; map back for the legacy no-terminal policy
        # reconstruction below.
        policy_action = (
            audit_mod.ACTION_ROTATE
            if action == audit_mod.ACTION_BATCH_ROTATE
            else action
        )

        def message_for(status: int) -> str:
            if status == 403:
                return "action not permitted by policy"
            if status == 409:
                if kind == "restore":
                    return "backup target already contains this data"
                return "key_id already exists for this tenant"
            if kind == "restore":
                return "tenant backup not found"
            return "key not found"

        # The original terminal status is persisted with the event: replay it
        # verbatim, so a policy change or a state change after the crash can
        # never turn a 403 into a 404/409 or vice versa.
        if terminal in (403, 404, 409):
            return error(terminal, message_for(terminal))

        # Older records without the stashed terminal: infer once from the
        # durable action and the current state.
        # A policy denial outranks existence: it is reconstructed whenever the
        # tenant's policy currently rejects this operator/action.
        if not policy_store.is_allowed(tenant_id, policy_action, operator_id):
            return error(403, message_for(403))
        if kind == "restore":
            # A same-tenant conflict is reconstructed when any key from the
            # write set now belongs to the tenant, a restored policy exists,
            # or (empty bundle) the persistent empty-restore marker is on
            # disk. Every other rejection (in-bundle tenant mismatch, foreign
            # occupation) replays as 404. Restore events always carry
            # key_id null.
            for key_id in details.get("key_ids", []):
                raw = store.read_raw(key_id)
                if raw is not None and raw.tenant_id == tenant_id:
                    return error(409, message_for(409))
            if details.get("policy_restored") and policy_store.get(
                tenant_id
            ) is not None:
                return error(409, message_for(409))
            digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
            marker = os.path.join(
                store.data_dir, "restore-empty-" + digest + ".json"
            )
            if os.path.exists(marker):
                return error(409, message_for(409))
            return error(404, message_for(404))
        if kind == "import":
            key_id = event.key_id or details.get("key_id")
            raw = store.read_raw(key_id) if is_valid_key_id(key_id) else None
            if raw is not None and raw.tenant_id == tenant_id:
                return error(409, message_for(409))
            return error(404, message_for(404))
        # rotate (and any unknown shape): a rejected rotate means the key was
        # unknown or foreign at commit time and no version was appended.
        return error(404, message_for(404))

    if kind == "rotate":
        key_id = event.key_id or details.get("key_id")
        key = store.get(key_id, tenant_id)
        if key is not None:
            # The committed version is the one whose creation time equals the
            # event timestamp; fall back to the current pointer.
            ver = None
            for candidate in key.versions:
                if candidate.created_at == event.timestamp:
                    ver = candidate
                    break
            if ver is None:
                ver = key.current
            return (
                201,
                {
                    "key_id": key_id,
                    "version": ver.version,
                    "algorithm": ver.algorithm,
                    "public_key": ver.public_key,
                    "operation_id": op_id,
                },
            )
    if kind == "batch_rotate":
        # The batch's single event carries key_id null; the request-order
        # item set is durable in details. Rebuild each item's committed
        # version (the one minted at the event timestamp, else the current
        # pointer). A key that is no longer readable makes the projection fall
        # back to operation_id-only rather than fabricating a version.
        result_items = []
        complete = True
        for one in details.get("items", []):
            key_id = one.get("key_id")
            key = (
                store.get(key_id, tenant_id)
                if is_valid_key_id(key_id)
                else None
            )
            if key is None:
                complete = False
                break
            ver = None
            for candidate in key.versions:
                if candidate.created_at == event.timestamp:
                    ver = candidate
                    break
            if ver is None:
                ver = key.current
            result_items.append(
                {
                    "key_id": key_id,
                    "version": ver.version,
                    "algorithm": ver.algorithm,
                    "public_key": ver.public_key,
                }
            )
        if complete:
            return 201, {"items": result_items, "operation_id": op_id}
    if kind == "import":
        key_id = event.key_id or details.get("key_id")
        key = store.get(key_id, tenant_id)
        if key is not None:
            body = key.to_create_response()
            body["operation_id"] = op_id
            return 201, body
    if kind == "restore":
        return (
            201,
            {
                "tenant_id": tenant_id,
                "key_ids": details.get("key_ids", []),
                "policy_restored": details.get("policy_restored", False),
                "operation_id": op_id,
            },
        )
    # Cannot rebuild the projection; the mutation did commit, so keep it
    # succeeded with an operation_id-only body rather than pending forever.
    return 201, {"operation_id": op_id}


def serve(host: str, port: int, data_dir: str) -> None:
    """Run the HTTP server until interrupted."""
    audit_log = AuditLog(data_dir)
    # Key-store and restore outbox recovery run first (constructors), so a
    # half-committed mutation's files/handles are settled before the
    # operation store resolves the pending operation that wrapped it.
    store = KeyStore(data_dir, audit_log)
    policy_store = PolicyStore(data_dir, audit_log)
    coordinator = restore_mod.RestoreCoordinator(store, policy_store)
    operation_store = OperationStore(data_dir, audit_log)
    # The artifact mirrors settle next (after the outbox recovery): a
    # consistent mirror is cleaned, a fully rolled-back attempt's mirror is
    # dropped, and an unprovable scene keeps both its evidence and its
    # operation pending for a later open.
    from .artifacts import ArtifactStore

    artifact_store = ArtifactStore(data_dir, store, audit_log)
    artifact_store.settle_pending(operation_store)
    operation_store.recover_pending(
        lambda record, event: _resolve_committed_operation(
            store, policy_store, record, event
        ),
        is_parked=artifact_store.is_parked,
    )
    httpd = ThreadingHTTPServer(
        (host, port),
        make_handler(
            store, policy_store, coordinator, operation_store, artifact_store
        ),
    )
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
