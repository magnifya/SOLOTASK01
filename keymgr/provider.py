"""KMS/HSM provider abstraction.

Every private key is owned by a *provider*: a local software key store by
default, or an external KMS/HSM reached through the ``module:factory`` entry
point named by ``KEYMGR_PROVIDER``. The rest of the package never touches raw
key material when a provider is in use: it only persists the opaque
``provider_id`` / ``handle`` / ``encrypted_material`` triple a provider
returns, and asks the provider to turn a handle back into exportable material.

Provider contract
-----------------
A provider instance exposes:

* ``provider_id``: a non-empty string;
* ``capabilities``: ``{"algorithms": ["AES256", "RSA2048"],
  "operations": ["generate", "rotate", "import_material",
  "export_material", "delete"]}``;
* ``generate(algorithm)`` / ``rotate(algorithm)`` ->
  ``{"handle", "public_key", "encrypted_material"}``;
* ``import_material(algorithm, public_key, material)`` -> the same triple;
* ``export_material(handle)`` -> ``{"public_key", "encrypted_material"}``;
* ``delete(handle)`` -> ``None``, idempotent;
* ``health()`` -> a plain ``bool`` (optional): a missing method is treated as
  healthy, while a non-bool result or a raised exception means the backend is
  unavailable. Health probing never returns the backend's text to a client.

The factory named by ``KEYMGR_PROVIDER=module:factory`` is imported lazily on
first use and called with no arguments. A missing module/factory, a factory
raising, or a returned object failing the contract all raise
:class:`ProviderUnavailable`; the service answers ``503`` (CLI exit ``1``) and
never falls back to the local provider.

A live provider is never replaced while one of its calls is in flight:
:func:`reconnect` builds and validates the replacement first (the old instance
keeps serving), and the swap waits up to :data:`SWITCH_WAIT_SECONDS` for
in-flight calls to drain. New calls arriving during that window wait for the
fresh instance; when the drain deadline passes the reconnect fails with
:class:`ProviderSwitchTimeout`, the old instance stays installed and nothing
was visibly changed.
"""

import base64
import importlib
import json
import os
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from typing import NamedTuple, Optional

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import SUPPORTED_ALGORITHMS, generate_key

#: Default provider id and the id of the built-in software provider.
LOCAL_PROVIDER_ID = "local"

OP_GENERATE = "generate"
OP_ROTATE = "rotate"
OP_IMPORT_MATERIAL = "import_material"
OP_EXPORT_MATERIAL = "export_material"
OP_DELETE = "delete"
OPERATIONS = (
    OP_GENERATE,
    OP_ROTATE,
    OP_IMPORT_MATERIAL,
    OP_EXPORT_MATERIAL,
    OP_DELETE,
)

_DEK_NAME = "local.dek"
_REGISTRY_NAME = "local-registry.json"
# Prefix for material wrapped by the local DEK; never reused for another
# encoding so wrapped blobs are self-describing on disk.
_WRAP_PREFIX = "pev1."
_NONCE_LEN = 12


class ProviderError(Exception):
    """Base class for provider failures."""


class ProviderUnavailable(ProviderError):
    """The provider cannot service the request (load/backend/handle failure).

    Surfaced as HTTP ``503`` / CLI exit code ``1``. The message is logged
    server-side; clients only ever see a generic status (handles and material
    never leave the boundary).
    """


class ProviderInvalidMaterial(ProviderError):
    """Material handed to the provider is malformed for the algorithm.

    Surfaced as HTTP ``400`` / CLI exit code ``2``; the message names the
    offending field but never embeds the material itself.
    """


class ProviderSwitchTimeout(ProviderUnavailable):
    """A provider reconnect could not drain in-flight calls in time.

    Subclasses :class:`ProviderUnavailable` so every ordinary caller still
    answers ``503`` with the fixed generic message; the idempotent operation
    wrappers handle it specifically, leaving the operation PENDING (the
    request made no provider call and wrote no event). The old provider
    instance is still installed and no state was visibly changed.
    """


class ProviderMismatch(ProviderUnavailable):
    """A pending operation is bound to a provider that is not active.

    The bound operation is kept PENDING and answered ``503``; reconnecting a
    provider with the same ``provider_id`` lets the identical retry continue
    under the same operation_id. No audit event is written, so the event_id
    is never duplicated.
    """


#: Reconnect and ordinary provider calls share one gate: a switch waits at
#: most this long for in-flight calls on the old instance to finish, and a new
#: call arriving while a switch runs waits at most this long for the fresh
#: instance. Beyond it the request answers 503 with zero side effects.
SWITCH_WAIT_SECONDS = 5.0
_SWITCH_POLL_SECONDS = 0.02


class MaterialTriple(NamedTuple):
    """The provider-owned result of generate/rotate/import_material."""

    handle: str
    public_key: Optional[str]
    encrypted_material: str


class ExportedMaterial(NamedTuple):
    """Result of export_material: material plus its public component."""

    public_key: Optional[str]
    encrypted_material: str


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _require_triple(result, operation: str) -> MaterialTriple:
    """Validate a generate/rotate/import result has a handle and material."""
    if not isinstance(result, dict):
        raise ProviderUnavailable(
            "provider %s returned a non-object from %s"
            % ("external", operation)
        )
    handle = result.get("handle")
    material = result.get("encrypted_material")
    if not isinstance(handle, str) or not handle:
        raise ProviderUnavailable(
            "provider returned an empty handle from %s" % operation
        )
    if not isinstance(material, str) or not material:
        raise ProviderUnavailable(
            "provider returned empty encrypted_material from %s" % operation
        )
    public_key = result.get("public_key")
    if public_key is not None and not isinstance(public_key, str):
        raise ProviderUnavailable(
            "provider returned an invalid public_key from %s" % operation
        )
    return MaterialTriple(
        handle=handle, public_key=public_key, encrypted_material=material
    )


class KeyProvider:
    """Abstract provider; concrete providers implement the five operations."""

    provider_id = ""
    capabilities = {"algorithms": (), "operations": ()}

    def configure(self, data_dir: str) -> None:
        """Bind any persistent state to the data directory (optional)."""

    def generate(self, algorithm: str) -> MaterialTriple:
        raise NotImplementedError

    def rotate(self, algorithm: str) -> MaterialTriple:
        raise NotImplementedError

    def import_material(
        self,
        algorithm: str,
        public_key: Optional[str],
        material: str,
    ) -> MaterialTriple:
        raise NotImplementedError

    def export_material(self, handle: str) -> ExportedMaterial:
        raise NotImplementedError

    def delete(self, handle: str) -> None:
        raise NotImplementedError

    def supports(self, algorithm: str, operation: str) -> bool:
        caps = getattr(self, "capabilities", {}) or {}
        return (
            algorithm in caps.get("algorithms", ())
            and operation in caps.get("operations", ())
        )


def _validate_external(obj) -> None:
    """Check a factory-built object satisfies the provider contract."""
    provider_id = getattr(obj, "provider_id", None)
    if not isinstance(provider_id, str) or not provider_id:
        raise ProviderUnavailable(
            "provider factory returned an object without a non-empty provider_id"
        )
    caps = getattr(obj, "capabilities", None)
    if not isinstance(caps, dict):
        raise ProviderUnavailable(
            "provider %r has no capabilities mapping" % provider_id
        )
    algorithms = caps.get("algorithms")
    operations = caps.get("operations")
    if not isinstance(algorithms, (list, tuple)) or not isinstance(
        operations, (list, tuple)
    ):
        raise ProviderUnavailable(
            "provider %r capabilities must list algorithms and operations"
            % provider_id
        )
    missing = [a for a in SUPPORTED_ALGORITHMS if a not in algorithms]
    if missing:
        raise ProviderUnavailable(
            "provider %r lacks required algorithms: %s"
            % (provider_id, ", ".join(missing))
        )
    missing_ops = [op for op in OPERATIONS if op not in operations]
    if missing_ops:
        raise ProviderUnavailable(
            "provider %r lacks required operations: %s"
            % (provider_id, ", ".join(missing_ops))
        )
    for name in OPERATIONS:
        if not callable(getattr(obj, name, None)):
            raise ProviderUnavailable(
                "provider %r is missing a callable %s() operation"
                % (provider_id, name)
            )
    configure = getattr(obj, "configure", None)
    if configure is not None and not callable(configure):
        raise ProviderUnavailable(
            "provider %r has a non-callable configure attribute" % provider_id
        )


class _SafeProvider:
    """Adapter around an external provider enforcing the error contract.

    ProviderError subtypes pass through unchanged; any other exception the
    external module raises is normalized to ProviderUnavailable so a backend
    fault always surfaces as 503 and never as a 500 or a fallback.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.provider_id = inner.provider_id
        self.capabilities = inner.capabilities

    def configure(self, data_dir: str) -> None:
        try:
            configure = getattr(self._inner, "configure", None)
            if configure is not None:
                configure(data_dir)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderUnavailable(
                "provider %r failed to initialize" % self.provider_id
            ) from exc

    def _call(self, name: str, *args):
        method = getattr(self._inner, name)
        try:
            return method(*args)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderUnavailable(
                "provider %r operation %s failed" % (self.provider_id, name)
            ) from exc

    def generate(self, algorithm: str) -> MaterialTriple:
        return _require_triple(self._call("generate", algorithm), "generate")

    def rotate(self, algorithm: str) -> MaterialTriple:
        return _require_triple(self._call("rotate", algorithm), "rotate")

    def import_material(self, algorithm, public_key, material) -> MaterialTriple:
        return _require_triple(
            self._call("import_material", algorithm, public_key, material),
            "import_material",
        )

    def export_material(self, handle: str) -> ExportedMaterial:
        result = self._call("export_material", handle)
        if not isinstance(result, dict):
            raise ProviderUnavailable(
                "provider returned a non-object from export_material"
            )
        material = result.get("encrypted_material")
        if not isinstance(material, str) or not material:
            raise ProviderUnavailable(
                "provider returned empty encrypted_material from export_material"
            )
        public_key = result.get("public_key")
        if public_key is not None and not isinstance(public_key, str):
            raise ProviderUnavailable(
                "provider returned an invalid public_key from export_material"
            )
        return ExportedMaterial(
            public_key=public_key, encrypted_material=material
        )

    def delete(self, handle: str) -> None:
        # Idempotent by contract; even so, a backend fault on delete is a 503
        # (the caller may retry, and delete must remain idempotent).
        self._call("delete", handle)

    def health(self) -> bool:
        # Optional contract: a missing method means healthy; a non-bool result
        # or any backend exception means unavailable. Text never escapes.
        method = getattr(self._inner, "health", None)
        if method is None or not callable(method):
            return True
        try:
            result = method()
        except Exception:
            return False
        return isinstance(result, bool) and result


class LocalProvider(KeyProvider):
    """Built-in software provider.

    Raw material never lands in a key file: each generated/imported key is
    wrapped with AES-256-GCM under a data-encryption key kept in
    ``local.dek`` (0600), and only the wrapped blob plus an opaque handle is
    persisted. A small registry (``local-registry.json``, 0600) maps each
    handle to its algorithm and wrapped blob, so ``export_material(handle)``
    can re-derive the raw material and ``delete`` stays idempotent. The
    registry stores only DEK-wrapped material, never plaintext.
    """

    provider_id = LOCAL_PROVIDER_ID
    capabilities = {
        "algorithms": tuple(SUPPORTED_ALGORITHMS),
        "operations": OPERATIONS,
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data_dir: Optional[str] = None
        self._dek: Optional[bytes] = None
        self._registry: dict = {}
        self._configured = False

    # -- state -------------------------------------------------------------
    def configure(self, data_dir: str) -> None:
        with self._lock:
            if self._configured and self._data_dir == data_dir:
                return
            os.makedirs(data_dir, exist_ok=True)
            self._data_dir = data_dir
            self._dek = self._load_or_create_dek(data_dir)
            self._registry = self._load_registry(data_dir)
            self._configured = True

    @staticmethod
    def _load_or_create_dek(data_dir: str) -> bytes:
        path = os.path.join(data_dir, _DEK_NAME)
        try:
            with open(path, "rb") as fh:
                dek = fh.read()
            if len(dek) == 32:
                return dek
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ProviderUnavailable("cannot read local DEK: %s" % exc) from exc
        dek = os.urandom(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, dek)
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            with open(path, "rb") as fh:
                dek = fh.read()
        except OSError as exc:
            raise ProviderUnavailable("cannot write local DEK: %s" % exc) from exc
        if len(dek) != 32:
            raise ProviderUnavailable("local DEK file is corrupt")
        return dek

    @staticmethod
    def _load_registry(data_dir: str) -> dict:
        path = os.path.join(data_dir, _REGISTRY_NAME)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise ProviderUnavailable(
                "cannot read local handle registry: %s" % exc
            ) from exc
        if not isinstance(data, dict):
            raise ProviderUnavailable("local handle registry is corrupt")
        return data

    def _persist_registry_locked(self) -> None:
        path = os.path.join(self._data_dir, _REGISTRY_NAME)
        fd, tmp_path = tempfile.mkstemp(dir=self._data_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._registry, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _require_configured(self) -> None:
        if not self._configured:
            raise ProviderUnavailable("local provider is not configured")

    # -- wrapping ----------------------------------------------------------
    def _wrap_locked(self, raw_material: str) -> str:
        nonce = os.urandom(_NONCE_LEN)
        ct = AESGCM(self._dek).encrypt(
            nonce, raw_material.encode("utf-8"), None
        )
        return _WRAP_PREFIX + _b64e(nonce) + "." + _b64e(ct)

    def _unwrap_locked(self, blob: str) -> str:
        if not isinstance(blob, str) or not blob.startswith(_WRAP_PREFIX):
            raise ProviderUnavailable("stored material is not a local blob")
        try:
            nonce_b, ct_b = blob[len(_WRAP_PREFIX):].split(".", 1)
            nonce = _b64d(nonce_b)
            ct = _b64d(ct_b)
            raw = AESGCM(self._dek).decrypt(nonce, ct, None)
            return raw.decode("utf-8")
        except Exception as exc:
            raise ProviderUnavailable(
                "cannot unwrap local material"
            ) from exc

    # -- material validation ----------------------------------------------
    @staticmethod
    def _validate_material(
        algorithm: str, public_key, material
    ):
        """Validate raw (legacy-shaped) material for an algorithm.

        AES material is base64 of exactly 32 bytes and has no public part;
        RSA material is a PEM private key of exactly 2048 bits, and the
        supplied public key (when present) must match it. Returns the parsed
        RSA private key (None for AES).
        """
        if not isinstance(material, str) or not material:
            raise ProviderInvalidMaterial(
                "field encrypted_material must be a non-empty string"
            )
        if algorithm == "AES256":
            if public_key is not None:
                raise ProviderInvalidMaterial(
                    "field public_key must be null for AES256"
                )
            try:
                raw = base64.b64decode(material, validate=True)
            except (ValueError, TypeError) as exc:
                raise ProviderInvalidMaterial(
                    "field encrypted_material must be valid base64 for AES256"
                ) from exc
            if len(raw) != 32:
                raise ProviderInvalidMaterial(
                    "field encrypted_material must decode to 32 bytes for AES256"
                )
            return None
        if algorithm == "RSA2048":
            try:
                private_key = serialization.load_pem_private_key(
                    material.encode("utf-8"), password=None
                )
            except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
                raise ProviderInvalidMaterial(
                    "field encrypted_material must be a PEM private key for RSA2048"
                ) from exc
            if not isinstance(private_key, rsa.RSAPrivateKey) or (
                private_key.key_size != 2048
            ):
                raise ProviderInvalidMaterial(
                    "field encrypted_material must be a 2048-bit RSA private key"
                )
            if public_key is not None:
                if not isinstance(public_key, str) or not public_key:
                    raise ProviderInvalidMaterial(
                        "field public_key must be a PEM string for RSA2048"
                    )
                try:
                    supplied = serialization.load_pem_public_key(
                        public_key.encode("utf-8")
                    )
                    if not isinstance(supplied, rsa.RSAPublicKey):
                        raise ValueError("not an RSA public key")
                except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
                    raise ProviderInvalidMaterial(
                        "field public_key must be a PEM RSA public key"
                    ) from exc
                expected = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                actual = supplied.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if expected != actual:
                    raise ProviderInvalidMaterial(
                        "field public_key does not match the private key"
                    )
            return private_key
        raise ProviderInvalidMaterial(
            "unsupported value for field algorithm: %r (supported: %s)"
            % (algorithm, ", ".join(SUPPORTED_ALGORITHMS))
        )

    @staticmethod
    def _public_pem(private_key) -> str:
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def _adopt(
        self,
        algorithm: str,
        public_key,
        raw_material: str,
    ) -> MaterialTriple:
        """Validate raw material, wrap it under the DEK, mint a handle."""
        self._require_configured()
        private_key = self._validate_material(algorithm, public_key, raw_material)
        if algorithm == "RSA2048" and public_key is None:
            public_key = self._public_pem(private_key)
        handle = uuid.uuid4().hex
        with self._lock:
            wrapped = self._wrap_locked(raw_material)
            self._registry[handle] = {
                "algorithm": algorithm,
                "wrapped": wrapped,
            }
            self._persist_registry_locked()
        return MaterialTriple(
            handle=handle,
            public_key=public_key,
            encrypted_material=wrapped,
        )

    # -- KeyProvider operations -------------------------------------------
    def generate(self, algorithm: str) -> MaterialTriple:
        generated = generate_key(algorithm)
        return self._adopt(
            algorithm, generated.public_material, generated.private_material
        )

    def rotate(self, algorithm: str) -> MaterialTriple:
        # A rotated version is brand-new material owned by the same provider.
        return self.generate(algorithm)

    def import_material(
        self,
        algorithm: str,
        public_key,
        material: str,
    ) -> MaterialTriple:
        return self._adopt(algorithm, public_key, material)

    def export_material(self, handle: str) -> ExportedMaterial:
        """Return the raw bundle-shaped material for a registered handle.

        The registry keeps the DEK-wrapped blob, which is unwrapped here. The
        returned material is only ever sealed inside a passphrase-encrypted
        export bundle; an unknown handle is ProviderUnavailable.
        """
        self._require_configured()
        if not isinstance(handle, str) or not handle:
            raise ProviderUnavailable("export_material requires a handle")
        with self._lock:
            meta = self._registry.get(handle)
            if meta is None:
                raise ProviderUnavailable("unknown handle")
            algorithm = meta.get("algorithm")
            blob = meta.get("wrapped")
            try:
                raw = self._unwrap_locked(blob)
            except ProviderUnavailable:
                raise
        if algorithm == "AES256":
            return ExportedMaterial(public_key=None, encrypted_material=raw)
        try:
            private_key = serialization.load_pem_private_key(
                raw.encode("utf-8"), password=None
            )
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise ProviderUnavailable("stored local material is corrupt") from exc
        return ExportedMaterial(
            public_key=self._public_pem(private_key),
            encrypted_material=raw,
        )

    def delete(self, handle: str) -> None:
        """Drop a handle from the registry. Idempotent and never fails 404."""
        self._require_configured()
        with self._lock:
            if handle in self._registry:
                del self._registry[handle]
                self._persist_registry_locked()

    def health(self) -> bool:
        # The built-in provider is healthy whenever it is installed; its
        # state is local disk and a failure surfaces from the operation that
        # hits it, never from this probe's text.
        return True


def _is_healthy(provider) -> bool:
    """Apply the optional ``health()`` contract to one instance.

    A missing/non-callable method means healthy (the pre-health contract is
    unchanged). A non-bool result or any raised exception means unavailable;
    the backend's text is deliberately ignored.
    """
    method = getattr(provider, "health", None)
    if method is None or not callable(method):
        return True
    try:
        result = method()
    except Exception:
        return False
    return isinstance(result, bool) and result


def _check_health(provider) -> None:
    """Health gate used by reconnect: fail the swap when not plainly healthy."""
    method = getattr(provider, "health", None)
    if method is None or not callable(method):
        return
    try:
        result = method()
    except Exception as exc:
        raise ProviderUnavailable("provider health check failed") from exc
    if not isinstance(result, bool):
        raise ProviderUnavailable("provider health() returned a non-bool")
    if not result:
        raise ProviderUnavailable("provider reported itself unavailable")


# -- module:factory loading -------------------------------------------------
_configured_dir: Optional[str] = None
_LOCAL_SINGLETON = LocalProvider()


def _spec() -> str:
    return os.environ.get("KEYMGR_PROVIDER", "") or LOCAL_PROVIDER_ID


def active_is_local() -> bool:
    """Whether the configured active provider is the built-in local one.

    Reads the ``KEYMGR_PROVIDER`` spec without importing anything: the local
    provider is active only for an empty value or an explicit ``local``. This
    is used for the provider-selection gates (legacy-record adoption, legacy
    bundle import) that must never trigger an import of a module:factory
    provider from a plain read.
    """
    return _spec() == LOCAL_PROVIDER_ID


def _load_external(spec: str):
    module_name, sep, factory_name = spec.partition(":")
    if not sep or not module_name or not factory_name:
        raise ProviderUnavailable(
            "KEYMGR_PROVIDER must be 'local' or 'module:factory', got %r" % spec
        )
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise ProviderUnavailable(
            "cannot import provider module %r: %s" % (module_name, exc)
        ) from exc
    target = module
    for part in factory_name.split("."):
        try:
            target = getattr(target, part)
        except AttributeError as exc:
            raise ProviderUnavailable(
                "provider module %r has no factory %r"
                % (module_name, factory_name)
            ) from exc
    if not callable(target):
        raise ProviderUnavailable(
            "provider factory %r is not callable" % factory_name
        )
    try:
        obj = target()
    except Exception as exc:
        raise ProviderUnavailable(
            "provider factory %r failed: %s" % (factory_name, exc)
        ) from exc
    _validate_external(obj)
    return _SafeProvider(obj)


def _build_configured_provider():
    """Build a FRESH provider for the current ``KEYMGR_PROVIDER`` config.

    The external factory is re-imported/re-invoked per call, so a reconnect
    rebuilds from current configuration even after the env var changed; the
    built-in local provider has durable on-disk state and is returned as its
    singleton (reconfigure is idempotent). Contract validation happens inside
    :func:`_load_external`; ``configure`` runs here as the second gate. The
    returned instance is not installed until the caller swaps it in.
    """
    spec = _spec()
    if spec == LOCAL_PROVIDER_ID:
        provider = _LOCAL_SINGLETON
    else:
        provider = _load_external(spec)
    if _configured_dir is not None:
        provider.configure(_configured_dir)
    return provider


class _ProviderRegistry:
    """Process-wide active provider plus the reconnect drain gate.

    A provider *activity* is one request-scoped provider operation (an
    idempotent executor or a create/export/decrypt/backup section). Each
    activity reserves a token on the currently installed instance: while any
    token is outstanding a reconnect cannot swap instances, so every call an
    operation makes goes to the instance it started on ("in-flight calls
    finish on the old instance"). When a switch is in progress, newly arriving
    activities wait (bounded by :data:`SWITCH_WAIT_SECONDS`) and then run on
    the fresh instance ("new calls wait"); if the switch does not settle in
    time they raise :class:`ProviderSwitchTimeout` without touching a
    provider or writing anything. The same flag serializes the lazy first
    load, so a request never runs against a half-built instance.
    """

    def __init__(self) -> None:
        # Reentrant so the lazy loader (entered under the gate) can re-enter
        # to publish its result or clear the flag on a failed build.
        self._cond = threading.Condition(threading.RLock())
        self._installed = None
        self._switching = False
        self._tokens: list = []
        self._generation = 0
        # Nested activities in the SAME thread are one logical operation: the
        # outermost block reserves the token and pins the instance; inner
        # blocks reuse it so a request that acquires the provider several
        # times (a batch rotation, an import) never straddles a switch.
        self._local = threading.local()

    # -- internals (caller holds/uses the condition) -----------------------
    def _wait_clear(self, deadline: float) -> None:
        """Wait for a load/switch in progress to finish.

        A new provider call shares the reconnect's five-second gate. If the
        switch is still running when its own budget expires it raises
        :class:`ProviderSwitchTimeout`; the deadline is re-checked AFTER the
        wait too, so a reconnect whose drain fails at the same instant the
        gate expires makes the waiter answer 503 rather than racing onto the
        retained old instance. A call that reaches a fully-cleared gate with
        budget left proceeds normally (on the new instance after a success or
        the retained old one after a failure it did not wait out).
        """
        while self._switching:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderSwitchTimeout(
                    "provider reconnect gate timed out"
                )
            self._cond.wait(min(_SWITCH_POLL_SECONDS, remaining))
        if time.monotonic() >= deadline:
            raise ProviderSwitchTimeout(
                "provider reconnect gate timed out"
            )

    def _load_locked(self) -> None:
        """Perform the lazy first load; caller holds the gate and saw None.

        Builds while holding the gate (so concurrent first-users wait on one
        factory call), publishes the instance, or clears the flag on failure
        so the next caller retries against then-current config.
        """
        self._switching = True
        try:
            provider = _build_configured_provider()
        except BaseException:
            self._switching = False
            self._cond.notify_all()
            raise
        if self._installed is None:
            self._installed = provider
            self._generation += 1
        self._switching = False
        self._cond.notify_all()

    def peek(self):
        with self._cond:
            return self._installed

    def ensure_loaded(self):
        """Return the active provider, performing the lazy first load.

        Raises ProviderUnavailable (never falls back) when the configured
        provider cannot be loaded or fails the contract. A failed first load
        installs nothing, so the next caller retries.
        """
        with self._cond:
            if self._installed is not None:
                return self._installed
            self._wait_clear(time.monotonic() + SWITCH_WAIT_SECONDS)
            if self._installed is not None:
                return self._installed
            self._load_locked()
            return self._installed

    @contextmanager
    def reserve(self, timeout: Optional[float] = None):
        """Lazily pin a provider for one (possibly multi-call) operation.

        Unlike :meth:`activity`, nothing is loaded or reserved until the
        yielded getter is first called: an idempotent request that is
        refused by policy or on existence (403/404) therefore never imports
        or health-touches a backend. On first use the getter waits out any
        switch (bounded by ``timeout``), performs the lazy load, pins THAT
        instance and reserves the drain token for the whole ``with`` block,
        so every later call in the operation (mint, commit, rollback delete)
        hits the same backend and a concurrent reconnect waits for all of
        them. A getter whose gate expires raises
        :class:`ProviderSwitchTimeout` before any provider is touched.
        """
        deadline_box = [None]
        token = object()
        pinned: list = []
        wait_for = SWITCH_WAIT_SECONDS if timeout is None else timeout

        def get():
            if pinned:
                return pinned[0]
            # The 5 s budget covers waiting for an in-progress switch, not the
            # request's policy/lock work that precedes its first provider use:
            # start the clock when the backend is actually first resolved.
            if deadline_box[0] is None:
                deadline_box[0] = time.monotonic() + wait_for
            deadline = deadline_box[0]
            with self._cond:
                self._wait_clear(deadline)
                if self._installed is None:
                    self._load_locked()
                # A switch may have started while the lazy load ran.
                self._wait_clear(deadline)
                provider = self._installed
                if provider is None:
                    raise ProviderUnavailable("provider could not be loaded")
                self._tokens.append(token)
                pinned.append(provider)
            return provider

        try:
            yield get
        finally:
            if pinned:
                with self._cond:
                    try:
                        self._tokens.remove(token)
                    except ValueError:
                        pass
                    self._cond.notify_all()

    @contextmanager
    def activity(self, timeout: float = SWITCH_WAIT_SECONDS):
        """Gate one request-scoped provider operation.

        Yields the installed instance, which is pinned for the whole
        operation by the reserved token: a concurrent reconnect waits for
        this block to finish before swapping, so multi-step work and its
        rollback always hit the same backend object. A switch in progress is
        awaited (bounded by ``timeout``); on timeout ProviderSwitchTimeout is
        raised before any provider is touched. Nested blocks in the same
        thread reuse the outermost block's instance and token.
        """
        stack = getattr(self._local, "stack", None)
        if stack is None:
            stack = []
            self._local.stack = stack
        if stack:
            # Inner block: reuse the pinned instance, reserve nothing.
            yield stack[-1]
            return
        deadline = time.monotonic() + timeout
        token = object()
        with self._cond:
            self._wait_clear(deadline)
            if self._installed is None:
                # First-ever use: build lazily while the others wait.
                self._load_locked()
            self._wait_clear(deadline)
            provider = self._installed
            if provider is None:
                # _load_locked raised; it already notified. Surface the load
                # failure to this caller.
                raise ProviderUnavailable("provider could not be loaded")
            self._tokens.append(token)
        stack.append(provider)
        try:
            yield provider
        finally:
            stack.pop()
            with self._cond:
                try:
                    self._tokens.remove(token)
                except ValueError:
                    pass
                self._cond.notify_all()

    def status(self) -> tuple:
        """Return ``(provider_id, ready)`` for GET /v1/provider/status.

        A never-loaded provider is built lazily here; a load failure reports
        ``(None, False)`` rather than raising. A cached instance is probed
        with its optional ``health()``; the probe's text is never returned.
        """
        with self._cond:
            provider = self._installed
        if provider is None:
            try:
                provider = self.ensure_loaded()
            except ProviderError:
                return None, False
        return provider.provider_id, _is_healthy(provider)

    def reconnect(self, timeout: Optional[float] = None):
        """Rebuild the provider from current config and swap it in safely.

        The replacement is built, contract-validated, configured and health
        checked BEFORE the gate, while the old instance keeps serving: any
        failure there raises ProviderUnavailable and installs nothing. The
        swap then serializes behind any other load/switch and waits for
        in-flight activities to drain (bounded by ``timeout``); on timeout
        the old instance is retained and ProviderSwitchTimeout is raised.
        Returns the fresh provider.
        """
        wait_for = SWITCH_WAIT_SECONDS if timeout is None else timeout
        candidate = _build_configured_provider()
        _check_health(candidate)
        deadline = time.monotonic() + wait_for
        with self._cond:
            self._wait_clear(deadline)
            old = self._installed
            if old is None:
                # First install: no in-flight activities can exist on None.
                self._installed = candidate
                self._generation += 1
                self._cond.notify_all()
                return candidate
            if candidate is old:
                # The built-in local singleton rebuilt from current config.
                return candidate
            self._switching = True
            try:
                while self._tokens:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProviderSwitchTimeout(
                            "provider reconnect drain timed out"
                        )
                    self._cond.wait(min(_SWITCH_POLL_SECONDS, remaining))
                self._installed = candidate
                self._generation += 1
            finally:
                self._switching = False
                self._cond.notify_all()
            return candidate


_registry = _ProviderRegistry()


def get_provider():
    """Return the configured provider, importing it lazily on first use.

    Raises ProviderUnavailable (never falls back) when the configured
    provider cannot be loaded or fails the contract.
    """
    return _registry.ensure_loaded()


def activity(timeout: float = SWITCH_WAIT_SECONDS):
    """Context manager gating one request-scoped provider operation."""
    return _registry.activity(timeout)


# -- request-thread gate/pin plumbing ---------------------------------------
# A provider-touching request runs inside exactly one thread-local *session*:
# the idempotent endpoints push an :class:`_OperationGate` (which also durably
# binds the pending operation to its provider id); every other provider
# endpoint pushes a plain :class:`_PlainPin`. Nested store sections (a batch
# rotation, an import, restore rollback) reuse the outermost session, so one
# logical request lazily reserves the drain token on its FIRST provider use --
# a 403/404 refusal never loads a backend -- and every later call, including a
# rollback delete, hits the same pinned instance while a concurrent reconnect
# waits for the whole request to finish.
_session_local = threading.local()


def _session_stack():
    stack = getattr(_session_local, "stack", None)
    if stack is None:
        stack = []
        _session_local.stack = stack
    return stack


def current_session():
    """The request-scoped gate/pin on this thread, if any."""
    stack = _session_stack()
    return stack[-1] if stack else None


class _PlainPin:
    """A lazy drain reserve for a non-idempotent provider endpoint."""

    def __init__(self, timeout: Optional[float]) -> None:
        self._timeout = timeout
        self._cm = None
        self._get = None

    def __enter__(self):
        self._cm = _registry.reserve(self._timeout)
        self._get = self._cm.__enter__()
        return self

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)

    def resolve(self, provider_id: str):
        instance = self._get()
        if instance.provider_id != provider_id:
            # A record owned by a provider that is not the active one: same
            # deterministic 503 as before the gate existed.
            raise ProviderUnavailable(
                "record provider %r is not the active provider" % provider_id
            )
        return instance

    def resolve_active(self):
        return self._get()

    def preflight(self, provider_ids) -> None:
        for provider_id in dict.fromkeys(
            pid for pid in provider_ids if pid
        ):
            self.resolve(provider_id)


class _OperationGate:
    """Gate for one idempotent attempt plus its durable provider binding.

    The bound operation's ``details["provider_id"]`` records the provider the
    attempt starts on BEFORE its first backend call. A retry/takeover whose
    active provider carries a different id raises :class:`ProviderMismatch`
    without calling the backend or writing an event, so the operation stays
    PENDING (answer 503) and an identical retry after a same-id reconnect
    continues under the same operation_id.
    """

    def __init__(self, operation, operation_store,
                 timeout: Optional[float] = None) -> None:
        self.operation = operation
        self.operation_store = operation_store
        self._timeout = timeout
        self._cm = None
        self._get = None

    def __enter__(self):
        self._cm = _registry.reserve(self._timeout)
        self._get = self._cm.__enter__()
        return self

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)

    def _bound_id(self):
        details = self.operation.details or {}
        bound = details.get("provider_id")
        return bound if isinstance(bound, str) and bound else None

    def _bind(self, provider_id: str) -> None:
        """Durably record the owning provider id before the first backend call."""
        bound = self._bound_id()
        if bound is not None:
            if bound != provider_id:
                # Two sections of one attempt named different providers: a
                # deterministic configuration fault; leave the original
                # binding untouched.
                raise ProviderUnavailable(
                    "an attempt cannot span two different providers"
                )
            return
        self.operation_store.update_details(
            self.operation, {"provider_id": provider_id}
        )

    def resolve(self, provider_id: str):
        bound = self._bound_id()
        if bound is not None and bound != provider_id:
            raise ProviderMismatch("pending operation is bound to another provider")
        instance = self._get()
        if instance.provider_id != provider_id:
            if bound is not None:
                # The operation already ran (partially) on provider_id, which
                # is no longer the active provider: keep it pending; a
                # same-id reconnect lets the retry continue.
                raise ProviderMismatch(
                    "pending operation's provider is not active"
                )
            raise ProviderUnavailable(
                "record provider %r is not the active provider" % provider_id
            )
        self._bind(provider_id)
        return instance

    def resolve_active(self):
        instance = self._get()
        bound = self._bound_id()
        if bound is not None and instance.provider_id != bound:
            raise ProviderMismatch(
                "pending operation's provider is not active"
            )
        self._bind(instance.provider_id)
        return instance

    def preflight(self, provider_ids) -> None:
        """Bind/check the expected owning provider ids before any artifact.

        Called by import/restore executors BEFORE the provision journal is
        created, so a provider mismatch or an expired reconnect gate is a
        clean 503 with no orphaned journal. Every bundled version must be
        adopted through the SAME active provider: a fresh attempt naming an
        inactive provider id is a plain ProviderUnavailable (a terminal 503,
        as before the gate existed); a RETRIED attempt whose durable binding
        names a provider that is no longer active is a ProviderMismatch that
        leaves the operation PENDING for a same-id reconnect.
        """
        ids = list(dict.fromkeys(pid for pid in provider_ids if pid))
        instance = self._get()
        active_id = instance.provider_id
        bound = self._bound_id()
        if bound is not None and bound != active_id:
            raise ProviderMismatch(
                "pending operation's provider is not active"
            )
        for provider_id in ids:
            if provider_id != active_id:
                if bound is not None:
                    raise ProviderMismatch(
                        "pending operation is bound to another provider"
                    )
                raise ProviderUnavailable(
                    "record provider %r is not the active provider"
                    % provider_id
                )
        self._bind(active_id)


@contextmanager
def operation_pin(timeout: Optional[float] = None):
    """Pin one (possibly multi-call) provider request to one instance.

    A surrounding gate/pin already owns the reserve and drain token, so
    nested store sections simply reuse it.
    """
    if current_session() is not None:
        yield
        return
    pin = _PlainPin(timeout)
    pin.__enter__()
    stack = _session_stack()
    stack.append(pin)
    try:
        yield
    finally:
        stack.pop()
        pin.__exit__(None, None, None)


@contextmanager
def operation_gate(operation, operation_store,
                   timeout: Optional[float] = None):
    """Push the idempotent attempt's provider gate onto this thread."""
    gate = _OperationGate(operation, operation_store, timeout)
    gate.__enter__()
    stack = _session_stack()
    stack.append(gate)
    try:
        yield gate
    finally:
        stack.pop()
        gate.__exit__(None, None, None)


def preflight(provider_ids) -> None:
    """Bind/check the expected owning provider ids before the first artifact.

    Runs against the current request session (an idempotent gate or a plain
    pin); outside a session it is a no-op (startup recovery resolves each
    provider itself).
    """
    session = current_session()
    if session is not None:
        session.preflight(provider_ids)


def provider_status() -> tuple:
    """``(provider_id, ready)``; provider_id is null when load fails."""
    return _registry.status()


def reconnect(timeout: Optional[float] = None):
    """Rebuild from current config, validate + health-check, swap safely."""
    return _registry.reconnect(timeout)


def configure(data_dir: str) -> KeyProvider:
    """Bind the data directory and load the provider.

    Records ``data_dir`` and configures the built-in local provider (needed
    to adopt pre-provider records), then returns the active provider —
    importing an external ``module:factory`` provider here if it has not been
    loaded yet.
    """
    global _configured_dir
    _configured_dir = data_dir
    _LOCAL_SINGLETON.configure(data_dir)
    provider = get_provider()
    provider.configure(data_dir)
    return provider


def configure_local(data_dir: str) -> "LocalProvider":
    """Bind state without importing an external provider.

    Used when the local provider is actually needed (local generation, lazy
    legacy adoption, local bundle import, startup cleanup of local handles):
    legacy records are owned by the local provider, never by whatever is
    configured now. The external factory stays unloaded until its first
    operation (lazy load).
    """
    global _configured_dir
    _configured_dir = data_dir
    _LOCAL_SINGLETON.configure(data_dir)
    return _LOCAL_SINGLETON


def bind_data_dir(data_dir: str) -> None:
    """Remember the data directory without loading any provider.

    Called at store open so the provider chosen lazily by
    :func:`get_provider` gets configured on first use, while startup itself
    neither imports a module:factory provider nor creates local provider
    state. Plain reads therefore load no provider.
    """
    global _configured_dir
    _configured_dir = data_dir


def get_local_provider() -> "LocalProvider":
    """Return the built-in local provider singleton, configured if a data
    directory has been bound (configure_local/bind_data_dir). Never imports a
    configured external provider."""
    if _configured_dir is not None and not _LOCAL_SINGLETON._configured:
        _LOCAL_SINGLETON.configure(_configured_dir)
    return _LOCAL_SINGLETON


def reset_for_tests() -> None:
    """Forget the cached provider (tests only)."""
    global _configured_dir, _registry
    with _registry._cond:
        _registry = _ProviderRegistry()
    _configured_dir = None
    _LOCAL_SINGLETON._configured = False
