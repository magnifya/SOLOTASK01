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
* ``health()`` -> ``bool``, *optional*. A missing method is treated as ready;
  a method that raises or returns anything but a real bool reports unavailable.
  The probe's own text never leaves the process.

The factory named by ``KEYMGR_PROVIDER=module:factory`` is imported lazily on
first use and called with no arguments. A missing module/factory, a factory
raising, or a returned object failing the contract all raise
:class:`ProviderUnavailable`; the service answers ``503`` (CLI exit ``1``) and
never falls back to the local provider.
"""

import base64
import errno
import importlib
import json
import os
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from typing import NamedTuple, Optional, Tuple

try:  # fcntl is POSIX-only; the cross-process gate degrades to in-process.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

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

    def health(self) -> bool:
        """Optional KMS/HSM readiness probe.

        Built-in providers are always ready. An external provider may omit
        this method (a missing probe means healthy); :class:`_SafeProvider`
        enforces the bool/exception contract on objects that supply one.
        """
        return True

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
    # health() is optional: no attribute means always healthy. A present but
    # non-callable health is a contract failure like any other method.
    health = getattr(obj, "health", None)
    if health is not None and not callable(health):
        raise ProviderUnavailable(
            "provider %r has a non-callable health attribute" % provider_id
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
        """Optional readiness probe normalized to a bool.

        A provider without a ``health`` method is treated as ready. A method
        that raises, returns a non-bool, or returns ``False`` reports
        unavailable; any backend text is swallowed here and never reaches a
        client.
        """
        method = getattr(self._inner, "health", None)
        if method is None:
            # Missing health() means healthy by contract.
            return True
        try:
            result = method()
        except Exception:
            return False
        # Only the exact bool True is healthy; a bool False, a truthy
        # non-bool (1, "yes", ...) and any other object mean unavailable.
        return result is True


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


# -- module:factory loading -------------------------------------------------
_provider_lock = threading.Lock()
_provider: Optional[KeyProvider] = None
_configured_dir: Optional[str] = None
_LOCAL_SINGLETON = LocalProvider()
# Every provider_id that has been the active instance (in this process, and
# historically in the data directory) is remembered. Lets a pending operation
# distinguish a reconnect that swapped in a different provider_id (keep the op
# pending) from a record owned by a provider that was never active here (the
# classic inactive-provider terminal 503).
_active_history: set = set()
_HISTORY_NAME = "provider-ids.json"


def _history_path() -> Optional[str]:
    if _configured_dir is None:
        return None
    return os.path.join(_configured_dir, _HISTORY_NAME)


def _load_history() -> None:
    path = _history_path()
    if path is None:
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return
    except (OSError, ValueError):
        return
    ids = data.get("ids") if isinstance(data, dict) else None
    if isinstance(ids, list):
        _active_history.update(i for i in ids if isinstance(i, str) and i)


def _remember(provider_id: str) -> None:
    if not provider_id or provider_id in _active_history:
        return
    _active_history.add(provider_id)
    path = _history_path()
    if path is None:
        return
    ids = sorted(_active_history)
    fd, tmp_path = tempfile.mkstemp(dir=_configured_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"ids": ids}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        # A history write failure never blocks provider selection; the set is
        # a best-effort hint, not an authority.


# -- non-disruptive reconnect gate -----------------------------------------
# Reconnect and ordinary provider calls share ONE five-second budget. While a
# reconnect is draining or installing a freshly built provider, every NEW
# provider operation waits at the gate; operations already in flight keep
# using the provider instance they started on, so they complete without
# interruption. A call that cannot be admitted within the budget fails with
# ProviderUnavailable (surfaced as 503) having made zero provider calls and
# therefore zero side effects.
CALL_GATE_SECONDS = 5.0


class ProviderReconnectPending(ProviderUnavailable):
    """A provider call blocked on the reconnect gate past the 5 s budget.

    Like every provider failure it answers 503 with the fixed generic body,
    but an idempotent operation bound when this is raised has made NO provider
    call: the guard leaves it PENDING (mirror and binding intact, no audit
    event), so a retry once reconnect settles continues under the same
    operation_id/event_id rather than being frozen as a terminal failure.
    """


class ProviderIdentityMismatch(ProviderReconnectPending):
    """A record/pending attempt is bound to a provider_id that is not active.

    Raised while a reconnect has installed a provider with a *different*
    ``provider_id`` and an idempotent operation still owed to the old id is
    being continued. The idempotent guard leaves the operation PENDING (never
    terminal) and answers 503, so that reconnecting a provider with the same
    id lets the same request/event continue exactly once.
    """


# -- committed cross-process provider state ---------------------------------
# ``provider-state.json`` (0600) is the single cross-process record of which
# provider is active in a data directory and which generation of it was last
# committed. It is written atomically (temp file, fsync, rename) by the first
# healthy activation and by every successful reconnect, as compact UTF-8 JSON
# with the fixed key order ``schema_version,provider_id,generation``, no
# ASCII escaping and no trailing newline. A missing file is created by the
# first healthy activation (generation 1); a corrupt or invalid file poisons
# provider calls and reconnect (fixed 503) and is never rewritten.
_STATE_NAME = "provider-state.json"
_STATE_LOCK_NAME = "provider-state.lock"
_STATE_SCHEMA_VERSION = 1

# The (provider_id, generation) this process's cached ``_provider`` instance
# was activated/adopted/committed with. Only ever set together with
# ``_provider``; a commit observed on disk that does not match this tuple
# forces a rebuild on the next provider call.
_active_state: Optional[Tuple[str, int]] = None
# Serializes state sync/activation/adoption within this process. Lock order:
# ``_state_sync_lock`` -> state lock file -> ``_provider_lock`` (never the
# reverse), so a thread upgrading to the exclusive file lease can never
# deadlock against one holding the provider lock.
_state_sync_lock = threading.Lock()


def _state_path() -> Optional[str]:
    if _configured_dir is None:
        return None
    return os.path.join(_configured_dir, _STATE_NAME)


def _read_committed_state() -> Optional[Tuple[str, int]]:
    """Return the committed ``(provider_id, generation)``, or None if absent.

    A corrupt or field-invalid ``provider-state.json`` raises
    :class:`ProviderUnavailable`: provider calls and reconnect then answer
    the fixed 503 text and the file is left byte-for-byte untouched.
    """
    path = _state_path()
    if path is None:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProviderUnavailable(
            "cannot read provider state: %s" % exc
        ) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProviderUnavailable("provider state file is corrupt") from exc
    valid = isinstance(data, dict) and set(data) == {
        "schema_version",
        "provider_id",
        "generation",
    }
    if valid:
        version = data["schema_version"]
        provider_id = data["provider_id"]
        generation = data["generation"]
        valid = (
            type(version) is int
            and version == _STATE_SCHEMA_VERSION
            and isinstance(provider_id, str)
            and bool(provider_id)
            and type(generation) is int
            and generation >= 1
        )
    if not valid:
        raise ProviderUnavailable("provider state file is corrupt")
    return (data["provider_id"], data["generation"])


def _write_committed_state(provider_id: str, generation: int) -> None:
    """Atomically commit ``provider-state.json`` (0600, fsync + rename).

    The payload is compact UTF-8 JSON with the fixed key order
    ``schema_version,provider_id,generation``, non-ASCII written as-is and
    no trailing newline. The rename is the commit point: a crash before it
    keeps the previous generation.
    """
    if _configured_dir is None:
        return
    payload = json.dumps(
        {
            "schema_version": _STATE_SCHEMA_VERSION,
            "provider_id": provider_id,
            "generation": generation,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        fd, tmp_path = tempfile.mkstemp(dir=_configured_dir, suffix=".tmp")
    except OSError as exc:
        raise ProviderUnavailable(
            "cannot write provider state: %s" % exc
        ) from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, os.path.join(_configured_dir, _STATE_NAME))
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise ProviderUnavailable(
            "cannot write provider state: %s" % exc
        ) from exc
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


class _FileLease:
    """A held shared/exclusive ``flock`` on ``provider-state.lock``.

    This is the cross-process half of the reconnect gate: provider calls
    hold a shared lease for their whole duration (in-flight calls in every
    process finish before a reconnect commits), while a reconnect commit or
    a first activation takes the exclusive lease. Acquisition polls with a
    non-blocking flock against the shared five-second deadline; a wait past
    it raises :class:`ProviderReconnectPending` with zero side effects. When
    no data directory is bound (or fcntl is unavailable) the lease is a
    no-op and the in-process gate alone applies.
    """

    def __init__(self) -> None:
        self._fd: Optional[int] = None

    def acquire(self, exclusive: bool, deadline: float) -> None:
        self.release()
        if _configured_dir is None or fcntl is None:
            return
        try:
            os.makedirs(_configured_dir, exist_ok=True)
            fd = os.open(
                os.path.join(_configured_dir, _STATE_LOCK_NAME),
                os.O_RDWR | os.O_CREAT,
                0o600,
            )
        except OSError as exc:
            raise ProviderUnavailable(
                "cannot open provider state lock: %s" % exc
            ) from exc
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        try:
            while True:
                try:
                    fcntl.flock(fd, operation | fcntl.LOCK_NB)
                    break
                except InterruptedError:
                    continue
                except OSError as exc:
                    if exc.errno not in (
                        errno.EACCES,
                        errno.EAGAIN,
                        errno.EWOULDBLOCK,
                    ):
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProviderReconnectPending(
                            "timed out waiting for the cross-process "
                            "provider gate"
                        )
                    time.sleep(min(0.05, remaining))
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


@contextmanager
def _exclusive_state_lease(deadline: float):
    """Hold the exclusive cross-process state lease for one commit."""
    lease = _FileLease()
    lease.acquire(True, deadline)
    try:
        yield
    finally:
        lease.release()


def _healthy_within(provider, deadline: float) -> bool:
    """Bounded health probe; False (never raises) when unhealthy/too slow."""
    return _health_with_deadline(provider, deadline)


def _activate_or_adopt(provider, deadline: float) -> None:
    """Reconcile a freshly built ``provider`` with the committed state.

    Called with ``_state_sync_lock`` held. A missing state file is created
    by this first healthy activation (generation 1, mutually exclusive with
    reconnect commits in every process). An existing committed state is
    adopted: the built provider must carry the committed ``provider_id``
    and be healthy, otherwise :class:`ProviderUnavailable` (503) is raised
    with zero side effects. A corrupt state file propagates the same error
    and is never rewritten.
    """
    global _active_state
    if _configured_dir is None:
        return
    state = _read_committed_state()
    if state is None:
        with _exclusive_state_lease(deadline):
            state = _read_committed_state()
            if state is None:
                if not _healthy_within(provider, deadline):
                    raise ProviderUnavailable("provider reported unhealthy")
                _write_committed_state(provider.provider_id, 1)
                _active_state = (provider.provider_id, 1)
                return
    if provider.provider_id != state[0]:
        raise ProviderUnavailable(
            "configured provider does not match the committed provider "
            "state"
        )
    if not _healthy_within(provider, deadline):
        raise ProviderUnavailable("provider reported unhealthy")
    _active_state = state


def _current_consistent(state: Tuple[str, int]) -> bool:
    """Whether the cached provider already matches the committed state."""
    return (
        _provider is not None
        and _active_state == state
        and _provider.provider_id == state[0]
    )


def _sync_committed_state(deadline: float, lease: "_FileLease") -> None:
    """Bring this process's cached provider in line with the committed state.

    Called from :func:`provider_call` with ``_state_sync_lock`` and the
    shared file lease held (the lease is released/re-acquired internally if
    a first activation needs the exclusive lease). After a commit by any
    process, the next call rebuilds the provider from the current
    configuration; a rebuilt instance whose ``provider_id`` disagrees with
    the committed state, or one that is not healthy, fails the call with
    :class:`ProviderUnavailable` before any provider operation, handle,
    audit event or state write happens.
    """
    global _provider, _active_state
    if _configured_dir is None:
        return
    while True:
        state = _read_committed_state()
        if state is None:
            # First activation is mutually exclusive with reconnect
            # commits in every process: drop the shared lease, take the
            # exclusive one and re-check under it.
            lease.release()
            try:
                with _exclusive_state_lease(deadline):
                    state = _read_committed_state()
                    if state is None:
                        provider = _provider
                        if provider is None:
                            provider = _build_current_provider()
                        if not _healthy_within(provider, deadline):
                            raise ProviderUnavailable(
                                "provider reported unhealthy"
                            )
                        _write_committed_state(provider.provider_id, 1)
                        with _provider_lock:
                            _provider = provider
                        _remember(provider.provider_id)
                        _active_state = (provider.provider_id, 1)
                        return
            finally:
                lease.acquire(False, deadline)
            # Another process activated meanwhile; adopt its commit.
            continue
        if _current_consistent(state):
            return
        candidate = _build_current_provider()
        if candidate.provider_id != state[0]:
            raise ProviderUnavailable(
                "configured provider does not match the committed "
                "provider state"
            )
        if not _healthy_within(candidate, deadline):
            raise ProviderUnavailable("provider reported unhealthy")
        with _provider_lock:
            _provider = candidate
        _remember(candidate.provider_id)
        _active_state = state


class _ReconnectGate:
    """Serialize non-disruptive provider replacement against provider calls.

    Reconnect marks the gate as *draining* and waits for every lease handed
    out before it began to be returned (calls in flight finish on the OLD
    instance), then builds/configures/health-checks the candidate and swaps it
    in. Provider operations take a shared lease: while draining they block and
    are admitted against the (new) current instance once reconnect completes.
    A wait beyond :data:`CALL_GATE_SECONDS` raises ProviderReconnectPending
    without invoking any provider.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._serialize = threading.Lock()
        self._draining = False
        self._leases = 0

    def _acquire_lease(self, deadline: float) -> None:
        with self._cond:
            while self._draining:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderReconnectPending(
                        "timed out waiting for provider reconnect to settle"
                    )
                self._cond.wait(timeout=min(0.05, remaining))
            self._leases += 1

    def _release_lease(self) -> None:
        with self._cond:
            self._leases -= 1
            if self._draining and self._leases == 0:
                self._cond.notify_all()

    @contextmanager
    def swapping(self, builder, timeout: Optional[float] = None):
        """Drain in-flight calls, run ``builder`` and let it swap the instance.

        Only one reconnect runs at a time. The shared budget (default
        :data:`CALL_GATE_SECONDS`, read at call time) bounds both the wait for
        in-flight leases and the overall settle (a builder that returns after
        the budget is refused). On any failure the previously active instance
        is retained untouched.
        """
        if timeout is None:
            timeout = CALL_GATE_SECONDS
        with self._serialize:
            deadline = time.monotonic() + timeout
            with self._cond:
                self._draining = True
                try:
                    while self._leases > 0:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ProviderReconnectPending(
                                "timed out draining provider calls before "
                                "reconnect"
                            )
                        self._cond.wait(timeout=min(0.05, remaining))
                except BaseException:
                    self._draining = False
                    self._cond.notify_all()
                    raise
            # The condition lock is released here (draining stays true, so no
            # new lease can be admitted, and the lease count cannot rise above
            # zero); the slow factory/configure/health work and the swap run
            # without holding it.
            try:
                builder(deadline)
            finally:
                with self._cond:
                    self._draining = False
                    self._cond.notify_all()


_gate = _ReconnectGate()

# A thread holding an active call lease is bound to the exact provider
# instance captured at admission: every nested get_provider() in that thread
# resolves to it, so one logical operation can never straddle a swap. Leases
# are reentrant per thread (an outer store operation may call helpers that
# take the gate too); only the outermost level acquires and releases.
_tls = threading.local()


@contextmanager
def provider_call(timeout: Optional[float] = None):
    """Bind one logical operation to one provider instance for its duration.

    Yields the provider instance captured at admission. Blocks behind an
    in-progress reconnect up to ``timeout`` (defaulting to
    :data:`CALL_GATE_SECONDS`, read at call time); on timeout raises
    :class:`ProviderReconnectPending` with zero provider side effects. Nested
    use on the same thread reuses the outer lease/instance.

    Admission also takes the shared cross-process state lease (so a
    reconnect in ANY process drains this call before committing) and
    reconciles the cached provider with the committed
    ``provider-state.json``: a commit by another process forces a rebuild
    here, and a corrupt state, an id mismatch or an unhealthy rebuild fails
    the call before any provider operation, handle, audit event or state
    write happens.
    """
    if timeout is None:
        timeout = CALL_GATE_SECONDS
    depth = getattr(_tls, "depth", 0)
    if depth:
        _tls.depth = depth + 1
        try:
            yield _tls.bound_provider
        finally:
            _tls.depth -= 1
        return

    deadline = time.monotonic() + timeout
    _gate._acquire_lease(deadline)
    lease = _FileLease()
    try:
        # Lock order: _state_sync_lock -> state lock file. The shared file
        # lease is only ever acquired under _state_sync_lock, so a thread
        # waiting for the exclusive lease (its own shared lease released)
        # can never be blocked by a holder that also needs the sync lock.
        with _state_sync_lock:
            lease.acquire(False, deadline)
            try:
                _sync_committed_state(deadline, lease)
            except BaseException:
                lease.release()
                raise
        # Capture the current instance AFTER admission, without holding the
        # gate condition: a lazy first import stays out of the condition
        # lock. If loading fails, the lease is released and nothing was
        # called.
        try:
            provider = get_provider()
        except BaseException:
            lease.release()
            raise
    except BaseException:
        _gate._release_lease()
        raise
    _tls.depth = 1
    _tls.bound_provider = provider
    try:
        yield provider
    finally:
        _tls.depth = 0
        _tls.bound_provider = None
        lease.release()
        _gate._release_lease()


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


def get_provider():
    """Return the configured provider, importing it lazily on first use.

    A thread already inside a :func:`provider_call` lease always gets the
    exact instance captured when that logical operation was admitted, so an
    in-flight operation is never moved onto a freshly reconnected instance
    mid-way. Every other caller gets the current cached provider, importing
    it lazily on first use. Raises ProviderUnavailable (never falls back)
    when the configured provider cannot be loaded or fails the contract.

    The first build in a process is reconciled with the committed
    ``provider-state.json``: a missing file is created by this first
    healthy activation, an existing one is adopted only if the built
    provider carries the committed ``provider_id`` and is healthy, and a
    corrupt file fails the call (503) without being rewritten.
    """
    global _provider
    bound = getattr(_tls, "bound_provider", None)
    if bound is not None and getattr(_tls, "depth", 0) > 0:
        return bound
    if _provider is not None:
        return _provider
    with _state_sync_lock:
        if _provider is not None:
            return _provider
        provider = _build_current_provider()
        _activate_or_adopt(
            provider, time.monotonic() + CALL_GATE_SECONDS
        )
        with _provider_lock:
            _provider = provider
        _remember(provider.provider_id)
        return _provider


def _build_current_provider():
    """Load (and configure) the provider named by the current configuration."""
    spec = _spec()
    if spec == LOCAL_PROVIDER_ID:
        provider = _LOCAL_SINGLETON
    else:
        provider = _load_external(spec)
    if _configured_dir is not None:
        provider.configure(_configured_dir)
    return provider


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
    _load_history()


def provider_was_active(provider_id: str) -> bool:
    """Whether ``provider_id`` has ever been an active provider in this data
    directory (current or any earlier load/reconnect). Used to tell a pending
    operation orphaned by a reconnect to a *different* provider_id apart from
    a record owned by a provider that was never active here."""
    return provider_id in _active_history


def get_local_provider() -> "LocalProvider":
    """Return the built-in local provider singleton, configured if a data
    directory has been bound (configure_local/bind_data_dir). Never imports a
    configured external provider."""
    if _configured_dir is not None and not _LOCAL_SINGLETON._configured:
        _LOCAL_SINGLETON.configure(_configured_dir)
    return _LOCAL_SINGLETON


def reset_for_tests() -> None:
    """Forget the cached provider (tests only)."""
    global _provider, _configured_dir, _active_state
    with _provider_lock:
        _provider = None
        _configured_dir = None
        _active_state = None
        _active_history.clear()
        _LOCAL_SINGLETON._configured = False


# -- health probe and non-disruptive reconnect -----------------------------
def provider_status() -> dict:
    """Return the status body for ``GET /v1/provider/status``.

    ``{"provider_id": <id>, "status": "ready"|"unavailable"}``. A provider
    that has never loaded is built here (lazy) purely to answer the probe; a
    load/contract/configuration failure reports ``provider_id`` null and
    status unavailable. A corrupt ``provider-state.json`` poisons every
    provider call, so it reports unavailable as well (the file is left
    untouched). The probe's own exception text is never returned.
    """
    if _configured_dir is not None:
        try:
            _read_committed_state()
        except ProviderUnavailable:
            return {"provider_id": None, "status": "unavailable"}
    provider = None
    if _provider is not None:
        provider = _provider
    else:
        try:
            provider = get_provider()
        except ProviderError:
            return {"provider_id": None, "status": "unavailable"}
        except Exception:
            # Never let an unexpected factory/load error leak text.
            return {"provider_id": None, "status": "unavailable"}
    return _status_for(provider)


def _status_for(provider) -> dict:
    """Health-check one instance and project its status without leaking text."""
    try:
        ready = provider.health() is True
    except ProviderError:
        ready = False
    except Exception:
        ready = False
    if ready:
        return {"provider_id": provider.provider_id, "status": "ready"}
    return {"provider_id": provider.provider_id, "status": "unavailable"}


def _install_provider(candidate) -> None:
    """Swap the active cached provider (caller holds the draining gate).

    A module-level setter is required because a ``global`` declaration does
    not propagate into the nested builder closure.
    """
    global _provider
    with _provider_lock:
        _provider = candidate
        _remember(candidate.provider_id)


def reconnect(timeout: float = CALL_GATE_SECONDS) -> dict:
    """Rebuild the provider from the current configuration without dropping
    in-flight calls.

    A fresh instance is built from the factory named by ``KEYMGR_PROVIDER``,
    contract-validated, configured against the bound data directory and health
    checked; only a healthy instance is swapped in, and the swap happens while
    the gate is still draining so every call admitted afterwards uses the new
    instance. In-flight calls finish on the OLD instance while new calls wait
    behind the shared five-second gate. On any failure (drain/build/configure/
    health timeout) the previously active instance is retained untouched and
    :class:`ProviderUnavailable` is raised. Returns the new status body.

    A successful reconnect atomically commits ``provider-state.json`` with
    the next generation under the exclusive cross-process state lease, so
    only a healthy candidate can increment the generation and a failure or
    crash before the commit keeps the old generation. Every other process
    observes the commit on its next provider call and rebuilds.
    """

    def builder(deadline: float) -> None:
        if deadline - time.monotonic() <= 0:
            raise ProviderReconnectPending(
                "reconnect exceeded the shared five-second budget"
            )
        global _active_state
        # The generation increment is mutually exclusive across processes:
        # the exclusive state lease is held from the committed-state read
        # through the atomic commit. A corrupt state file fails the
        # reconnect here and is never rewritten.
        with _state_sync_lock:
            with _exclusive_state_lease(deadline):
                state = _read_committed_state()
                # Build + contract validation + configure (factory work
                # happens while new calls are held at the gate but no gate
                # condition lock is held).
                candidate = _build_current_provider()
                # The health check shares the same five-second budget: a
                # slow/blocked probe is a failed reconnect; its text is
                # never surfaced.
                try:
                    ready = _health_with_deadline(candidate, deadline)
                except Exception:
                    raise ProviderUnavailable("provider health check failed")
                if not ready:
                    raise ProviderUnavailable("provider reported unhealthy")
                generation = 1 if state is None else state[1] + 1
                # The atomic rename is the commit point: a crash before it
                # keeps the old generation; afterwards every process's next
                # call rebuilds and adopts this generation.
                _write_committed_state(candidate.provider_id, generation)
                # Swap while still draining: leases are zero and no new
                # lease can be admitted, so the old instance is retained
                # only by calls already in flight (which captured it) and
                # every later call lands on candidate.
                _install_provider(candidate)
                _active_state = (candidate.provider_id, generation)

    _gate.swapping(builder, timeout=timeout)

    current = get_provider()
    return _status_for(current)


def _health_with_deadline(provider, deadline: float) -> bool:
    """Run health() bounded by the reconnect deadline.

    health() implementations are normally immediate; a probe that blocks past
    the shared budget is treated as unavailable without waiting longer.
    """
    result: dict = {}

    def probe() -> None:
        try:
            result["ready"] = provider.health() is True
        except Exception:
            result["ready"] = False

    thread = threading.Thread(target=probe, daemon=True)
    thread.start()
    thread.join(timeout=max(0.0, deadline - time.monotonic()))
    if thread.is_alive():
        return False
    return bool(result.get("ready"))
