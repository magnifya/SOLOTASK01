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
* ``delete(handle)`` -> ``None``, idempotent.

The factory named by ``KEYMGR_PROVIDER=module:factory`` is imported lazily on
first use and called with no arguments. A missing module/factory, a factory
raising, or a returned object failing the contract all raise
:class:`ProviderUnavailable`; the service answers ``503`` (CLI exit ``1``) and
never falls back to the local provider.
"""

import base64
import importlib
import json
import os
import tempfile
import threading
import uuid
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


def _spec() -> str:
    return os.environ.get("KEYMGR_PROVIDER", "") or LOCAL_PROVIDER_ID


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

    Raises ProviderUnavailable (never falls back) when the configured
    provider cannot be loaded or fails the contract.
    """
    global _provider
    if _provider is not None:
        return _provider
    with _provider_lock:
        if _provider is not None:
            return _provider
        spec = _spec()
        if spec == LOCAL_PROVIDER_ID:
            provider = _LOCAL_SINGLETON
        else:
            provider = _load_external(spec)
        if _configured_dir is not None:
            provider.configure(_configured_dir)
        _provider = provider
        return _provider


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

    Used at store startup to adopt pre-provider records (raw local material)
    even when the active provider is an external KMS/HSM: legacy records are
    owned by the local provider, never by whatever is configured now. The
    external factory stays unloaded until its first operation (lazy load).
    """
    global _configured_dir
    _configured_dir = data_dir
    _LOCAL_SINGLETON.configure(data_dir)
    return _LOCAL_SINGLETON


def get_local_provider() -> "LocalProvider":
    """Return the built-in local provider singleton (configured separately)."""
    return _LOCAL_SINGLETON


def reset_for_tests() -> None:
    """Forget the cached provider (tests only)."""
    global _provider, _configured_dir
    with _provider_lock:
        _provider = None
        _configured_dir = None
        _LOCAL_SINGLETON._configured = False
