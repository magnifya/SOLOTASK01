"""KMS/HSM provider abstraction.

Every private key is owned by a *provider*: a local software key store by
default, or an external KMS/HSM reached through the ``module:factory`` entry
point named by ``KEYMGR_PROVIDER``. The rest of the package never touches raw
key material when a provider is in use: it only persists the opaque
``provider_id`` / ``handle`` / ``encrypted_material`` triple a provider
returns, and asks the provider to turn a handle back into exportable material.

Primary/standby failover
------------------------
``KEYMGR_PROVIDER_CHAIN`` may name a comma-separated list of ``local`` /
``module:factory`` entries (entries and their built ``provider_id`` values
must be unique; an unset variable falls back to ``KEYMGR_PROVIDER``, while a
set-but-empty, empty-item or malformed chain is unusable). The first healthy
entry is activated. Every ordinary provider call then probes the active
instance first and the outcome feeds a persistent failure threshold
(``provider-health.json``, 0600): a healthy probe resets the consecutive
failure count to zero and the call proceeds, while an unhealthy one
(``False``, a non-bool or an exception) increments the active entry's count
(capped at 3) and answers the fixed 503. The first two consecutive failures
never switch; the third re-verifies the active entry inside the same
five-second cross-process intent/drain gate a reconnect uses -- if it
recovered the count is reset and the call proceeds, otherwise the service
switches exactly once to the first healthy standby and commits generation+1
(old calls finish on the instance they captured, later calls land on the new
generation, and concurrent failures trigger exactly one build/commit). No
healthy standby or an exhausted budget keeps the old generation. A recovered
primary is never re-selected automatically; only ``reconnect`` re-selects the
first healthy entry, while ``switchover`` moves the active provider to one
NAMED chain entry under the same gate (``switching`` then ``ready`` commits,
reason ``reconnect``). Pending idempotent operations stay bound to their
original ``provider_id`` and are never replayed on a standby.

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
from typing import List, NamedTuple, Optional, Tuple

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


class ProviderSwitchoverInvalid(ProviderError):
    """A switchover request names no usable chain target.

    Raised when no provider chain is configured or the requested
    ``provider_id`` is not one of the chain entries. Surfaced as HTTP
    ``400`` / CLI exit code ``2`` with the field named, and raised before
    any state write, provider swap or audit event (zero side effects).
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
# Reconnect and ordinary provider calls share ONE five-second budget, measured
# from the attempt's FIRST wait. The ordering the gate enforces is:
#
#   1. a reconnect first establishes a cross-process *intent* (an exclusive
#      flock on ``provider-reconnect.lock``), THEN drains the calls admitted
#      before it;
#   2. every LATER call waits -- in every process -- from the instant intent
#      is visible until the candidate is built, contract-validated, health
#      probed, ``provider-state.json`` is committed and the swap finished;
#   3. calls admitted before the intent was established keep running on the
#      OLD provider instance they captured and are simply drained.
#
# The extra intent file is required because a blocking exclusive flock alone
# is NOT a barrier on Linux: new shared-lock requests leapfrog a queued
# exclusive waiter (verified on the host kernel), so later calls would slip
# past a reconnect that had only *queued* for ``provider-state.lock`` and a
# steady call stream could starve it. Ordinary calls therefore never hold the
# intent lock for their duration; they only probe it with an instant
# non-blocking shared trylock, once before and once after taking their shared
# state lease, and fall back to waiting when the probe catches a reconnect.
CALL_GATE_SECONDS = 5.0
_POLL_SECONDS = 0.02


class _Budget:
    """The shared five-second budget for one call or reconnect attempt.

    The deadline starts lazily at the first blocking wait (``start`` is
    idempotent), so an attempt admitted without contention spends no budget on
    the gate; every later wait, poll and bounded probe shares one deadline.
    """

    def __init__(self, seconds: Optional[float] = None) -> None:
        self.seconds = CALL_GATE_SECONDS if seconds is None else seconds
        self._deadline: Optional[float] = None

    def start(self) -> float:
        if self._deadline is None:
            self._deadline = time.monotonic() + self.seconds
        return self._deadline

    @property
    def deadline(self) -> float:
        return self.start()

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0


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
# healthy activation, by every successful reconnect and by the two commits of
# every provider switch, as compact UTF-8 JSON with the fixed key order
# ``schema_version,provider_id,target_provider_id,generation,reason,phase``,
# no ASCII escaping and no trailing newline: schema_version is the fixed
# integer 2, provider_id a non-empty string, target_provider_id null or a
# non-empty string, generation a positive integer, reason one of
# ``initial``/``reconnect``/``failover`` and phase ``ready``/``switching``. A
# switch (a failover, or a reconnect that changes provider_id) first commits
# ``switching`` (old id, target id, the ORIGINAL generation) and only then
# ``ready`` (target id, null, generation+1), so a crash between the two
# commits never moves the generation. A process that reads ``switching``
# re-verifies the target: a healthy target completes the switch, anything
# else keeps the file byte-for-byte and answers the fixed 503. A legacy
# schema_version 1 file (no target/reason/phase) reads as ``ready``. A
# missing file is created by the first healthy activation (generation 1); a
# corrupt or invalid file poisons provider calls and reconnect (fixed 503)
# and is never rewritten.
_STATE_NAME = "provider-state.json"
_STATE_LOCK_NAME = "provider-state.lock"
# The reconnect-intent fence: a reconnect holds this lock exclusively for its
# whole drain/build/commit/swap window, while ordinary calls only ever touch
# it with an instant non-blocking shared trylock (never hold it across their
# work). A granted intent therefore becomes immediately visible to every later
# call in every process, regardless of flock's unfair read-leapfrog.
_INTENT_LOCK_NAME = "provider-reconnect.lock"
_STATE_SCHEMA_VERSION = 2
_STATE_LEGACY_SCHEMA_VERSION = 1
_REASON_INITIAL = "initial"
_REASON_RECONNECT = "reconnect"
_REASON_FAILOVER = "failover"
_REASONS = (_REASON_INITIAL, _REASON_RECONNECT, _REASON_FAILOVER)
_PHASE_READY = "ready"
_PHASE_SWITCHING = "switching"


class _CommittedState(NamedTuple):
    """A parsed ``provider-state.json`` record.

    ``reason`` is None only for a legacy schema_version 1 file (which has no
    target/reason/phase fields and is treated as ``ready``).
    """

    provider_id: str
    target_provider_id: Optional[str]
    generation: int
    reason: Optional[str]
    phase: str

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


def _read_committed_state() -> Optional[_CommittedState]:
    """Return the committed state, or None if the state file is absent.

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
    state = _parse_committed_state(data)
    if state is None:
        raise ProviderUnavailable("provider state file is corrupt")
    return state


def _parse_committed_state(data) -> Optional[_CommittedState]:
    """Validate a decoded state object; None when any field is invalid."""
    if not isinstance(data, dict):
        return None
    keys = set(data)
    if keys == {"schema_version", "provider_id", "generation"}:
        # Legacy schema_version 1: no target/reason/phase; treated as ready.
        version = data["schema_version"]
        provider_id = data["provider_id"]
        generation = data["generation"]
        if (
            type(version) is int
            and version == _STATE_LEGACY_SCHEMA_VERSION
            and isinstance(provider_id, str)
            and bool(provider_id)
            and type(generation) is int
            and generation >= 1
        ):
            return _CommittedState(
                provider_id=provider_id,
                target_provider_id=None,
                generation=generation,
                reason=None,
                phase=_PHASE_READY,
            )
        return None
    if keys != {
        "schema_version",
        "provider_id",
        "target_provider_id",
        "generation",
        "reason",
        "phase",
    }:
        return None
    version = data["schema_version"]
    provider_id = data["provider_id"]
    target = data["target_provider_id"]
    generation = data["generation"]
    reason = data["reason"]
    phase = data["phase"]
    if not (
        type(version) is int
        and version == _STATE_SCHEMA_VERSION
        and isinstance(provider_id, str)
        and bool(provider_id)
        and (target is None or (isinstance(target, str) and bool(target)))
        and type(generation) is int
        and generation >= 1
        and reason in _REASONS
        and phase in (_PHASE_READY, _PHASE_SWITCHING)
    ):
        return None
    # ready carries no target; switching always names its target.
    if phase == _PHASE_READY and target is not None:
        return None
    if phase == _PHASE_SWITCHING and not target:
        return None
    return _CommittedState(
        provider_id=provider_id,
        target_provider_id=target,
        generation=generation,
        reason=reason,
        phase=phase,
    )


def _write_committed_state(
    provider_id: str,
    generation: int,
    reason: str,
    target_provider_id: Optional[str] = None,
    phase: str = _PHASE_READY,
) -> None:
    """Atomically commit ``provider-state.json`` (0600, fsync + rename).

    The payload is compact UTF-8 JSON with the fixed key order
    ``schema_version,provider_id,target_provider_id,generation,reason,phase``,
    non-ASCII written as-is and no trailing newline. The rename is the commit
    point: a crash before it keeps the previous record.
    """
    if _configured_dir is None:
        return
    payload = json.dumps(
        {
            "schema_version": _STATE_SCHEMA_VERSION,
            "provider_id": provider_id,
            "target_provider_id": target_provider_id,
            "generation": generation,
            "reason": reason,
            "phase": phase,
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


# -- committed cross-process health threshold -------------------------------
# ``provider-health.json`` (0600) is the persistent consecutive-failure
# threshold of the primary/standby chain. It is written atomically (temp
# file, fsync, rename) as compact UTF-8 JSON with the fixed key order
# ``schema_version,provider_id,generation,status,consecutive_failures``, no
# ASCII escaping and no trailing newline: schema_version is the fixed
# integer 1, provider_id a non-empty string, generation a positive integer,
# status ``ready``/``unavailable`` and consecutive_failures an integer from
# 0 to 3. The record always belongs to the committed READY
# ``provider-state.json`` of the same provider_id and generation: a missing
# or generation-behind file is rebuilt from that state as ready/0, while a
# corrupt file, a generation ahead of the state or a same-generation
# different provider_id poisons ordinary provider calls with the fixed 503
# and is never rewritten. A failover switch commits provider-state first and
# only then writes the new generation's ready/0 record.
_HEALTH_NAME = "provider-health.json"
_HEALTH_SCHEMA_VERSION = 1
_STATUS_READY = "ready"
_STATUS_UNAVAILABLE = "unavailable"
#: Consecutive probe failures that trigger a gated failover; also the cap of
#: the persisted counter.
_MAX_CONSECUTIVE_FAILURES = 3


class _CommittedHealth(NamedTuple):
    """A parsed ``provider-health.json`` record."""

    provider_id: str
    generation: int
    status: str
    consecutive_failures: int


# Serializes the read-modify-write of the persisted failure counter within
# this process (the cross-process intent/drain gate serializes the switch
# itself). Never held while acquiring any other lock.
_health_lock = threading.Lock()


def _health_path() -> Optional[str]:
    if _configured_dir is None:
        return None
    return os.path.join(_configured_dir, _HEALTH_NAME)


def _read_committed_health() -> Optional[_CommittedHealth]:
    """Return the committed health record, or None if the file is absent.

    A corrupt or field-invalid ``provider-health.json`` raises
    :class:`ProviderUnavailable`: ordinary provider calls then answer the
    fixed 503 and the file is left byte-for-byte untouched.
    """
    path = _health_path()
    if path is None:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProviderUnavailable(
            "cannot read provider health: %s" % exc
        ) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProviderUnavailable("provider health file is corrupt") from exc
    health = _parse_committed_health(data)
    if health is None:
        raise ProviderUnavailable("provider health file is corrupt")
    return health


def _parse_committed_health(data) -> Optional[_CommittedHealth]:
    """Validate a decoded health object; None when any field is invalid."""
    if not isinstance(data, dict):
        return None
    if set(data) != {
        "schema_version",
        "provider_id",
        "generation",
        "status",
        "consecutive_failures",
    }:
        return None
    version = data["schema_version"]
    provider_id = data["provider_id"]
    generation = data["generation"]
    status = data["status"]
    failures = data["consecutive_failures"]
    if not (
        type(version) is int
        and version == _HEALTH_SCHEMA_VERSION
        and isinstance(provider_id, str)
        and bool(provider_id)
        and type(generation) is int
        and generation >= 1
        and status in (_STATUS_READY, _STATUS_UNAVAILABLE)
        and type(failures) is int
        and 0 <= failures <= _MAX_CONSECUTIVE_FAILURES
    ):
        return None
    return _CommittedHealth(
        provider_id=provider_id,
        generation=generation,
        status=status,
        consecutive_failures=failures,
    )


def _write_committed_health(
    provider_id: str,
    generation: int,
    status: str,
    consecutive_failures: int,
) -> None:
    """Atomically commit ``provider-health.json`` (0600, fsync + rename).

    The payload is compact UTF-8 JSON with the fixed key order
    ``schema_version,provider_id,generation,status,consecutive_failures``,
    non-ASCII written as-is and no trailing newline. The rename is the commit
    point: a crash before it keeps the previous record.
    """
    if _configured_dir is None:
        return
    payload = json.dumps(
        {
            "schema_version": _HEALTH_SCHEMA_VERSION,
            "provider_id": provider_id,
            "generation": generation,
            "status": status,
            "consecutive_failures": consecutive_failures,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        fd, tmp_path = tempfile.mkstemp(dir=_configured_dir, suffix=".tmp")
    except OSError as exc:
        raise ProviderUnavailable(
            "cannot write provider health: %s" % exc
        ) from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, os.path.join(_configured_dir, _HEALTH_NAME))
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise ProviderUnavailable(
            "cannot write provider health: %s" % exc
        ) from exc
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _reconcile_health(provider_id: str, generation: int) -> _CommittedHealth:
    """Match ``provider-health.json`` against a committed READY state.

    A missing file or one whose generation lags the state's is rebuilt from
    the state as ready/0. A corrupt file (raised by
    :func:`_read_committed_health`), a generation AHEAD of the state or a
    same-generation record naming a different provider_id raises
    :class:`ProviderUnavailable` -- the fixed 503 -- and the file is never
    rewritten in those cases.
    """
    health = _read_committed_health()
    if health is None or health.generation < generation:
        health = _CommittedHealth(
            provider_id=provider_id,
            generation=generation,
            status=_STATUS_READY,
            consecutive_failures=0,
        )
        _write_committed_health(
            health.provider_id,
            health.generation,
            health.status,
            health.consecutive_failures,
        )
        return health
    if health.generation > generation or health.provider_id != provider_id:
        raise ProviderUnavailable("provider health file is corrupt")
    return health


def _converge_health_ready(provider_id: str, generation: int) -> None:
    """Leave ``provider-health.json`` at ready/0 for a committed READY state.

    Used once a (re-)verified healthy active is known to serve the committed
    generation: a missing/behind file is rebuilt and any recorded failures
    are reset. The corrupt/ahead/wrong-id cases keep their fixed 503 and are
    never rewritten.
    """
    if _configured_dir is None:
        return
    health = _reconcile_health(provider_id, generation)
    if (
        health.status != _STATUS_READY
        or health.consecutive_failures != 0
    ):
        _write_committed_health(provider_id, generation, _STATUS_READY, 0)


def _health_gate(provider, budget: "_Budget") -> bool:
    """Probe the active instance and apply the persistent failure threshold.

    Chain mode only; called from :func:`provider_call` after admission.
    Returns True when the call may proceed on ``provider``: a healthy probe
    first resets any recorded consecutive failures to ready/0. Returns False
    when the THIRD consecutive unhealthy probe (``False``, a non-bool or an
    exception -- each persisted as an incremented ``consecutive_failures``)
    must re-verify inside the failover gate: the caller releases its leases
    and runs :func:`_failover`. The first and second consecutive failures
    raise :class:`ProviderUnavailable` (the fixed 503) without switching, as
    does a corrupt/ahead/mismatched ``provider-health.json`` (never
    rewritten).
    """
    if _configured_dir is None:
        # No persistence without a bound data directory: the plain probe
        # decides (an unhealthy active fails over immediately).
        return _healthy_within(provider, budget)
    healthy = _healthy_within(provider, budget)
    with _health_lock:
        state = _read_committed_state()
        if (
            state is None
            or state.phase != _PHASE_READY
            or state.provider_id != provider.provider_id
        ):
            # Defensive: the committed state cannot move while this call
            # holds its shared lease and gate admission, so these shapes are
            # impossible -- fall back to the plain probe outcome.
            return healthy
        health = _reconcile_health(state.provider_id, state.generation)
        if healthy:
            if (
                health.status != _STATUS_READY
                or health.consecutive_failures != 0
            ):
                _write_committed_health(
                    state.provider_id, state.generation, _STATUS_READY, 0
                )
            return True
        failures = min(
            health.consecutive_failures + 1, _MAX_CONSECUTIVE_FAILURES
        )
        _write_committed_health(
            state.provider_id,
            state.generation,
            _STATUS_UNAVAILABLE,
            failures,
        )
    if failures < _MAX_CONSECUTIVE_FAILURES:
        raise ProviderUnavailable("provider reported unhealthy")
    return False


class _FileLease:
    """A held shared/exclusive ``flock`` on a gate lock file.

    This is the cross-process half of the reconnect gate: provider calls
    hold a shared lease for their whole duration (in-flight calls in every
    process finish before a reconnect commits), while a reconnect commit or
    a first activation takes the exclusive lease. Acquisition polls with a
    non-blocking flock against the shared five-second deadline; a wait past
    it raises :class:`ProviderReconnectPending` with zero side effects. When
    no data directory is bound (or fcntl is unavailable) the lease is a
    no-op and the in-process gate alone applies.
    """

    def __init__(self, lock_name: str = _STATE_LOCK_NAME) -> None:
        self._lock_name = lock_name
        self._fd: Optional[int] = None

    def acquire(self, exclusive: bool, deadline: float) -> None:
        self.release()
        if _configured_dir is None or fcntl is None:
            return
        try:
            os.makedirs(_configured_dir, exist_ok=True)
            fd = os.open(
                os.path.join(_configured_dir, self._lock_name),
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


def _intent_probe_clear() -> bool:
    """Return whether no reconnect intent is currently held.

    The check is instantaneous and never BLOCKS on the lock and never retains
    the descriptor: an unheld exclusive lock always grants a shared trylock
    even while waiters are queued, so only a *held* reconnect intent reads as
    blocked. Ordinary calls use this to notice reconnect intent established
    after they began arriving; the descriptor (and its shared lock) is closed
    again immediately, so probing calls never queue behind -- and never
    leapfrog -- a reconnect waiting on the state lease.
    """
    if _configured_dir is None or fcntl is None:
        return True
    try:
        os.makedirs(_configured_dir, exist_ok=True)
        fd = os.open(
            os.path.join(_configured_dir, _INTENT_LOCK_NAME),
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
    except OSError as exc:
        raise ProviderUnavailable(
            "cannot open provider reconnect lock: %s" % exc
        ) from exc
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                return True
            except InterruptedError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    return False
                raise
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _intent_wait_clear(budget: "_Budget") -> None:
    """Wait until no reconnect intent is held, bounded by ``budget``.

    Polls with the instant shared trylock rather than queueing a blocking
    shared flock: a waiting call must not hold a queue entry that an
    exclusive requester has to drain, otherwise a stream of waiting calls
    could starve reconnects (flock grants new shared locks ahead of a queued
    exclusive waiter on Linux).
    """
    while not _intent_probe_clear():
        if budget.expired():
            raise ProviderReconnectPending(
                "timed out waiting for provider reconnect to settle"
            )
        time.sleep(min(_POLL_SECONDS, budget.remaining()))


def _intent_lease() -> "_FileLease":
    """A lease on the reconnect-intent fence (caller acquires/releases)."""
    return _FileLease(_INTENT_LOCK_NAME)


@contextmanager
def _exclusive_state_lease(deadline: float):
    """Hold the exclusive cross-process state lease for one commit."""
    lease = _FileLease()
    lease.acquire(True, deadline)
    try:
        yield
    finally:
        lease.release()


def _healthy_within(provider, deadline) -> bool:
    """Bounded health probe; False (never raises) when unhealthy/too slow."""
    if isinstance(deadline, _Budget):
        deadline = deadline.deadline
    return _health_with_deadline(provider, deadline)


def _first_healthy(candidates, deadline, exclude_id: Optional[str] = None):
    """The first candidate (in chain order) probing healthy, or None."""
    for candidate in candidates:
        if exclude_id is not None and candidate.provider_id == exclude_id:
            continue
        if _healthy_within(candidate, deadline):
            return candidate
    return None


def _select_initial(deadline):
    """Choose the provider for a first activation (generation 1).

    Chain mode picks the first healthy configured entry; single-spec mode
    builds the one configured provider. No healthy candidate is
    :class:`ProviderUnavailable` (the fixed 503) with zero side effects.
    """
    if _chain_configured():
        chosen = _first_healthy(_build_candidates(_specs()), deadline)
        if chosen is None:
            raise ProviderUnavailable(
                "no healthy provider in the configured provider chain"
            )
        return chosen
    provider = _provider if _provider is not None else _build_current_provider()
    if not _healthy_within(provider, deadline):
        raise ProviderUnavailable("provider reported unhealthy")
    return provider


def _complete_switch(state: _CommittedState, deadline) -> _CommittedState:
    """Finish an interrupted switch after re-verifying its target.

    Called with the exclusive state lease held. The target entry is rebuilt
    and health-probed; only a healthy target commits the ``ready`` record
    (target id, null target, generation+1, the original reason). Any other
    outcome keeps the ``switching`` file byte-for-byte and raises
    :class:`ProviderUnavailable` (the fixed 503).
    """
    if isinstance(deadline, _Budget):
        deadline = deadline.deadline
    target = None
    for candidate in _build_candidates(_specs()):
        if candidate.provider_id == state.target_provider_id:
            target = candidate
            break
    if target is None or not _healthy_within(target, deadline):
        raise ProviderUnavailable("provider switch target is unavailable")
    _write_committed_state(
        target.provider_id, state.generation + 1, state.reason
    )
    return _CommittedState(
        provider_id=target.provider_id,
        target_provider_id=None,
        generation=state.generation + 1,
        reason=state.reason,
        phase=_PHASE_READY,
    )


def _adopt_committed(state: _CommittedState, deadline) -> None:
    """Install the configured instance matching a committed ready state.

    Chain mode maps the committed ``provider_id`` back to a chain entry; a
    committed id no entry builds is a fixed 503. The instance's health is
    not probed here: the per-call health gate (:func:`_health_gate`) probes
    the active instance and applies the persistent failure threshold.
    """
    global _provider, _active_state
    if _chain_configured():
        chosen = None
        for candidate in _build_candidates(_specs()):
            if candidate.provider_id == state.provider_id:
                chosen = candidate
                break
        if chosen is None:
            raise ProviderUnavailable(
                "configured provider does not match the committed provider "
                "state"
            )
    else:
        chosen = _build_current_provider()
        if chosen.provider_id != state.provider_id:
            raise ProviderUnavailable(
                "configured provider does not match the committed provider "
                "state"
            )
        if not _healthy_within(chosen, deadline):
            raise ProviderUnavailable("provider reported unhealthy")
    with _provider_lock:
        _provider = chosen
    _remember(chosen.provider_id)
    _active_state = (chosen.provider_id, state.generation)


def _activate_or_adopt(deadline):
    """Reconcile a lazy first load with the committed state; return it.

    Called with ``_state_sync_lock`` held. A missing state file is created
    by this first healthy activation (generation 1, mutually exclusive with
    reconnect/failover commits in every process). An interrupted ``switching``
    record is completed only for a healthy target. An existing ready state is
    adopted: a configured entry must carry the committed ``provider_id`` and
    be healthy, otherwise :class:`ProviderUnavailable` (503) is raised with
    zero side effects. A corrupt state file propagates the same error and is
    never rewritten.
    """
    global _active_state
    if isinstance(deadline, _Budget):
        deadline = deadline.deadline
    if _configured_dir is None:
        return _select_initial(deadline)
    state = _read_committed_state()
    if state is None:
        with _exclusive_state_lease(deadline):
            state = _read_committed_state()
            if state is None:
                chosen = _select_initial(deadline)
                _write_committed_state(
                    chosen.provider_id, 1, _REASON_INITIAL
                )
                _active_state = (chosen.provider_id, 1)
                return chosen
    if state.phase == _PHASE_SWITCHING:
        with _exclusive_state_lease(deadline):
            state = _read_committed_state()
            if state.phase == _PHASE_SWITCHING:
                state = _complete_switch(state, deadline)
    if _chain_configured():
        chosen = None
        for candidate in _build_candidates(_specs()):
            if candidate.provider_id == state.provider_id:
                chosen = candidate
                break
        if chosen is None:
            raise ProviderUnavailable(
                "configured provider does not match the committed provider "
                "state"
            )
        if not _healthy_within(chosen, deadline):
            raise ProviderUnavailable("provider reported unhealthy")
    else:
        chosen = _build_current_provider()
        if chosen.provider_id != state.provider_id:
            raise ProviderUnavailable(
                "configured provider does not match the committed provider "
                "state"
            )
        if not _healthy_within(chosen, deadline):
            raise ProviderUnavailable("provider reported unhealthy")
    _active_state = (chosen.provider_id, state.generation)
    return chosen


def _current_consistent(state: _CommittedState) -> bool:
    """Whether the cached provider already matches the committed state."""
    return (
        _provider is not None
        and _active_state == (state.provider_id, state.generation)
        and _provider.provider_id == state.provider_id
    )


def _sync_committed_state(budget: "_Budget", lease: "_FileLease") -> None:
    """Bring this process's cached provider in line with the committed state.

    Called from :func:`provider_call` with ``_state_sync_lock`` and the
    shared file lease held (the lease is released/re-acquired internally if
    a first activation or a switch completion needs the exclusive lease).
    After a commit by any process, the next call rebuilds the provider from
    the current configuration; a committed ``provider_id`` no configured
    entry builds, corrupt state, or (single-spec mode) an unhealthy rebuild
    fails the call with :class:`ProviderUnavailable` before any provider
    operation, handle, audit event or state write happens. In chain mode the
    committed active is adopted without a probe: the per-call health gate
    (:func:`_health_gate`) applies the persistent failure threshold.
    """
    global _provider, _active_state
    deadline = budget.deadline
    if _configured_dir is None:
        return
    while True:
        state = _read_committed_state()
        if state is not None and state.phase == _PHASE_SWITCHING:
            # A crash interrupted a provider switch: re-verify the target
            # under the exclusive lease. A healthy target completes the
            # switch; anything else keeps the file byte-for-byte and fails
            # the call with the fixed 503.
            lease.release()
            try:
                with _exclusive_state_lease(deadline):
                    state = _read_committed_state()
                    if state is not None and state.phase == _PHASE_SWITCHING:
                        _complete_switch(state, deadline)
            finally:
                lease.acquire(False, deadline)
            continue
        if state is None:
            # First activation is mutually exclusive with reconnect/failover
            # commits in every process: drop the shared lease, take the
            # exclusive one and re-check under it.
            lease.release()
            try:
                with _exclusive_state_lease(deadline):
                    state = _read_committed_state()
                    if state is None:
                        chosen = _select_initial(deadline)
                        _write_committed_state(
                            chosen.provider_id, 1, _REASON_INITIAL
                        )
                        with _provider_lock:
                            _provider = chosen
                        _remember(chosen.provider_id)
                        _active_state = (chosen.provider_id, 1)
                        return
            finally:
                lease.acquire(False, deadline)
            # Another process activated meanwhile; adopt its commit.
            continue
        if _current_consistent(state):
            return
        _adopt_committed(state, deadline)
        return


class _ReconnectGate:
    """Serialize non-disruptive provider replacement against provider calls.

    The in-process half of the reconnect ordering. A reconnect first marks
    the gate as *draining* (only AFTER the cross-process intent fence is held)
    and waits for every lease handed out before it began to be returned:
    calls admitted earlier finish on the OLD instance they captured, and no
    new local lease is admitted while draining. Later calls wait on the
    condition and are admitted against the freshly installed instance once
    the swap finishes. A wait past the attempt's shared five-second budget
    raises ProviderReconnectPending without invoking any provider.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._serialize = threading.Lock()
        self._draining = False
        self._leases = 0

    def acquire_serialized(self, budget: "_Budget") -> None:
        """Become the single in-flight reconnect, bounded by ``budget``.

        Polled (never an unbounded blocking acquire) so a storm of concurrent
        reconnects serializes without a thread waiting past the shared
        five-second budget: a waiter that cannot get its turn answers 503 and
        leaves the old instance untouched instead of blocking indefinitely.
        """
        while not self._serialize.acquire(timeout=min(0.05, budget.remaining())):
            if budget.expired():
                raise ProviderReconnectPending(
                    "timed out waiting for an earlier reconnect to finish"
                )

    def release_serialized(self) -> None:
        self._serialize.release()

    def begin_draining(self) -> None:
        with self._cond:
            self._draining = True

    def wait_drained(self, budget: "_Budget") -> None:
        """Wait for all leases admitted before draining began to be returned."""
        with self._cond:
            while self._leases > 0:
                if budget.expired():
                    raise ProviderReconnectPending(
                        "timed out draining provider calls before reconnect"
                    )
                self._cond.wait(timeout=min(0.05, budget.remaining()))

    def end_draining(self) -> None:
        with self._cond:
            self._draining = False
            self._cond.notify_all()

    def acquire_lease(self, budget: "_Budget") -> None:
        with self._cond:
            while self._draining:
                if budget.expired():
                    raise ProviderReconnectPending(
                        "timed out waiting for provider reconnect to settle"
                    )
                self._cond.wait(timeout=min(0.05, budget.remaining()))
            self._leases += 1

    def release_lease(self) -> None:
        with self._cond:
            self._leases -= 1
            if self._draining and self._leases == 0:
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

    Yields the provider instance captured at admission. One shared five-second
    budget (``timeout``) covers EVERY wait of the attempt, starting at the
    first one: waiting behind a draining reconnect in this process, waiting
    for a reconnect INTENT held in another process, and taking the shared
    cross-process state lease. On timeout raises
    :class:`ProviderReconnectPending` before any provider is built, probed or
    called -- hence before any handle, audit event or state write. Nested use
    on the same thread reuses the outer lease/instance.

    Admission order, and the double intent check that closes the flock
    read-leapfrog race:

    1. take the in-process gate lease (wait while a local reconnect drains);
    2. probe the cross-process reconnect intent -- if held, release the gate
       lease and wait for the intent to clear;
    3. take the shared ``provider-state.lock`` lease;
    4. probe the intent AGAIN: a reconnect may have established it between
       the two probes (its exclusive intent is instant, while this call's
       shared state lease can be granted ahead of the reconnect's queued
       exclusive one). On a hit release both leases and go back to waiting;
    5. reconcile with the committed ``provider-state.json`` (a foreign commit
       forces a rebuild; corrupt state, id mismatch or an unhealthy rebuild
       fail the call with zero side effects), then capture the instance;
    6. with ``KEYMGR_PROVIDER_CHAIN`` configured, probe the captured active
       instance and apply the persistent failure threshold
       (``provider-health.json``): a healthy probe resets the consecutive
       failure count and the call proceeds; an unhealthy one increments the
       count (capped at 3) and the first two answer the fixed 503 without
       switching, while the third re-verifies inside the same intent/drain
       gate and either resets (recovered) or fails over to the first healthy
       standby (see :func:`_failover`), after which this attempt re-enters
       admission against the new generation.

    Calls admitted before intent existed are not kept out: they hold their
    shared lease, run on the instance they captured and are simply drained by
    the reconnect (which waits for that lease).
    """
    depth = getattr(_tls, "depth", 0)
    if depth:
        _tls.depth = depth + 1
        try:
            yield _tls.bound_provider
        finally:
            _tls.depth -= 1
        return

    budget = _Budget(timeout)
    lease = None
    gate_held = False
    admitted = False
    try:
        while True:
            # (1) In-process gate: wait out a locally draining reconnect.
            _gate.acquire_lease(budget)
            gate_held = True
            try:
                # (2) Intent BEFORE the shared state lease. A hit drops the
                # gate lease (this attempt is not yet admitted anywhere) and
                # waits for the intent to clear, all on the same budget.
                if not _intent_probe_clear():
                    _gate.release_lease()
                    gate_held = False
                    _intent_wait_clear(budget)
                    continue
                # (3)+(4) take the shared state lease strictly UNDER the
                # sync lock (lock order: _state_sync_lock -> state lock
                # file), then probe intent AGAIN: a reconnect may have
                # established intent between the two probes -- its exclusive
                # intent is instant while this call's shared state lease can
                # be granted ahead of its queued exclusive one. On a hit the
                # state lease is dropped at once and the call goes back to
                # waiting, so it never extends the reconnect's drain.
                intent_hit = False
                with _state_sync_lock:
                    lease = _FileLease()
                    lease.acquire(False, budget.deadline)
                    if not _intent_probe_clear():
                        lease.release()
                        lease = None
                        intent_hit = True
                    else:
                        # (5) Reconcile with the committed generation.
                        _sync_committed_state(budget, lease)
                if intent_hit:
                    _gate.release_lease()
                    gate_held = False
                    _intent_wait_clear(budget)
                    continue
                # Capture the current instance AFTER admission; a lazy first
                # import happens here, outside the gate/sync locks.
                provider = get_provider()
                # (6) Chain mode: probe the captured active instance and run
                # the persistent failure threshold. A healthy probe resets
                # the counter and the call proceeds; the first and second
                # consecutive failures answer the fixed 503 without
                # switching; the third re-verifies inside the failover gate
                # and either resets (recovered) or switches exactly once to
                # the first healthy standby, after which this attempt
                # re-enters admission against the new generation. There is no
                # automatic failback while the active entry stays healthy.
                if _chain_configured() and not _health_gate(provider, budget):
                    lease.release()
                    lease = None
                    _gate.release_lease()
                    gate_held = False
                    _failover(budget)
                    continue
                admitted = True
                break
            except BaseException:
                if lease is not None:
                    lease.release()
                    lease = None
                if gate_held:
                    _gate.release_lease()
                    gate_held = False
                raise
        _tls.depth = 1
        _tls.bound_provider = provider
        try:
            yield provider
        finally:
            _tls.depth = 0
            _tls.bound_provider = None
            lease.release()
            _gate.release_lease()
    finally:
        # Defensive: an unexpected escape between admission and binding must
        # not leak a lease.
        if not admitted:
            if lease is not None:
                lease.release()
            if gate_held:
                _gate.release_lease()


def _spec() -> str:
    return os.environ.get("KEYMGR_PROVIDER", "") or LOCAL_PROVIDER_ID


def _chain_configured() -> bool:
    """Whether ``KEYMGR_PROVIDER_CHAIN`` is set (even to an invalid value)."""
    return os.environ.get("KEYMGR_PROVIDER_CHAIN") is not None


def _chain_specs() -> Optional[List[str]]:
    """Parse ``KEYMGR_PROVIDER_CHAIN`` into an ordered list of specs.

    Returns ``None`` when the variable is unset (the single
    ``KEYMGR_PROVIDER`` spec applies). A set value must be a comma-separated
    list of ``local`` / ``module:factory`` items with no empty and no
    duplicate items; any violation raises :class:`ProviderUnavailable`, so a
    set-but-empty, empty-item or malformed chain is unusable (fixed 503) at
    every provider operation.
    """
    raw = os.environ.get("KEYMGR_PROVIDER_CHAIN")
    if raw is None:
        return None
    items = [item.strip() for item in raw.split(",")]
    seen = set()
    for item in items:
        if not item:
            raise ProviderUnavailable(
                "KEYMGR_PROVIDER_CHAIN must not contain empty items"
            )
        if item in seen:
            raise ProviderUnavailable(
                "KEYMGR_PROVIDER_CHAIN items must be unique"
            )
        seen.add(item)
        if item == LOCAL_PROVIDER_ID:
            continue
        module_name, sep, factory_name = item.partition(":")
        if not sep or not module_name or not factory_name:
            raise ProviderUnavailable(
                "KEYMGR_PROVIDER_CHAIN items must be 'local' or "
                "'module:factory', got %r" % item
            )
    return items


def _specs() -> List[str]:
    """The ordered provider specs to select from (chain or single spec)."""
    chain = _chain_specs()
    if chain is not None:
        return chain
    return [_spec()]


def active_is_local() -> bool:
    """Whether the configured active provider is the built-in local one.

    Without a chain this reads the ``KEYMGR_PROVIDER`` spec without importing
    anything: the local provider is active only for an empty value or an
    explicit ``local``. With ``KEYMGR_PROVIDER_CHAIN`` set, the active entry
    is whichever healthy entry was committed, so this consults the committed
    ``provider-state.json`` (still importing nothing): local is active only
    when the committed ``provider_id`` is ``local``. This is used for the
    provider-selection gates (legacy-record adoption, legacy bundle import)
    that must never trigger an import of a module:factory provider from a
    plain read.
    """
    if not _chain_configured():
        return _spec() == LOCAL_PROVIDER_ID
    try:
        state = _read_committed_state()
    except ProviderUnavailable:
        return False
    return state is not None and state.provider_id == LOCAL_PROVIDER_ID


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
    healthy activation (chain mode selects the first healthy entry), an
    interrupted ``switching`` record is completed only for a healthy
    target, an existing ready state is adopted only if a configured entry
    carries the committed ``provider_id`` and is healthy, and a corrupt
    file fails the call (503) without being rewritten.
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
        provider = _activate_or_adopt(
            time.monotonic() + CALL_GATE_SECONDS
        )
        with _provider_lock:
            _provider = provider
        _remember(provider.provider_id)
        return _provider


def _build_spec(spec: str):
    """Load (and configure) the provider named by one spec."""
    if spec == LOCAL_PROVIDER_ID:
        provider = _LOCAL_SINGLETON
    else:
        provider = _load_external(spec)
    if _configured_dir is not None:
        provider.configure(_configured_dir)
    return provider


def _build_candidates(specs) -> list:
    """Build every configured entry; the built provider_ids must be unique."""
    providers = [_build_spec(spec) for spec in specs]
    ids = [p.provider_id for p in providers]
    if len(set(ids)) != len(ids):
        raise ProviderUnavailable(
            "provider chain entries must build unique provider_id values"
        )
    return providers


def _build_current_provider():
    """Load (and configure) the provider named by the single-spec config."""
    return _build_spec(_spec())


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


def local_provider_displaced() -> bool:
    """Whether the built-in ``local`` provider is a previously-active, now
    displaced provider (so a bound op owned by it stays pending).

    True only when local is NOT the active entry, local WAS active earlier in
    this data directory, and a readable committed ``provider-state.json``
    names a different active ``provider_id`` (including a mid-switch record).
    A missing state file (nothing ever committed) and a corrupt/illegal one
    read as False: those scenes keep the plain inactive-provider 503 (the
    committed-state corruption contract) rather than the pending-displacement
    one. Imports no provider and configures nothing.
    """
    if active_is_local():
        return False
    if not provider_was_active(LOCAL_PROVIDER_ID):
        return False
    try:
        state = _read_committed_state()
    except ProviderUnavailable:
        return False
    return state is not None and state.provider_id != LOCAL_PROVIDER_ID


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


def _failover(budget: "_Budget") -> None:
    """Switch the active provider to the first healthy standby chain entry.

    Entered after the THIRD consecutive unhealthy probe of the active
    instance; the active entry is re-verified inside the gate and a recovered
    one simply resets the persisted failure count to ready/0 without any
    commit. Uses the same cross-process intent/drain gate as
    :func:`reconnect`: calls admitted earlier finish on the instance they
    captured, every later call waits from the moment intent is established,
    and the switch commits ``switching`` (old id, target id, the ORIGINAL
    generation) then ``ready`` (target id, null, generation+1) atomically,
    writing the new generation's ``provider-health.json`` as ready/0 only
    after the provider-state commit. Concurrent triggers serialize on the
    gate: only the first builds and commits, later ones adopt the committed
    generation. Any failure (no healthy standby, budget exceeded, commit
    failure) keeps the old generation byte-for-byte and raises
    :class:`ProviderUnavailable` -- the fixed 503 with no handle, audit
    event or backend text. There is no automatic failback: a recovered
    primary is never re-selected here, only by :func:`reconnect`.
    """
    global _active_state
    _gate.acquire_serialized(budget)
    intent = _intent_lease()
    state_lease = _FileLease()
    draining = False
    try:
        intent.acquire(True, budget.deadline)
        _gate.begin_draining()
        draining = True
        _gate.wait_drained(budget)
        if budget.expired():
            raise ProviderReconnectPending(
                "failover exceeded the shared five-second budget"
            )
        # Lock order: _state_sync_lock -> state lock file.
        with _state_sync_lock:
            state_lease.acquire(True, budget.deadline)
            if budget.expired():
                raise ProviderReconnectPending(
                    "failover exceeded the shared five-second budget"
                )
            state = _read_committed_state()
            if state is not None and state.phase == _PHASE_SWITCHING:
                # An interrupted switch is completed for a healthy target or
                # kept byte-for-byte (fixed 503); failover never overrides it.
                state = _complete_switch(state, budget.deadline)
            if state is None:
                # No committed generation (never activated, or no data
                # directory bound): pick the first healthy entry other than
                # the instance that just failed, if there is one.
                exclude = (
                    _provider.provider_id if _provider is not None else None
                )
                chosen = _first_healthy(
                    _build_candidates(_specs()),
                    budget.deadline,
                    exclude_id=exclude,
                )
                if chosen is None:
                    raise ProviderUnavailable(
                        "no healthy standby provider in the configured "
                        "provider chain"
                    )
                if _configured_dir is not None:
                    _write_committed_state(
                        chosen.provider_id, 1, _REASON_INITIAL
                    )
                    _converge_health_ready(chosen.provider_id, 1)
                _install_provider(chosen)
                _active_state = (chosen.provider_id, 1)
                return
            if _current_consistent(state) and _healthy_within(
                _provider, budget.deadline
            ):
                # A concurrent reconnect/failover already restored a healthy
                # active instance while this one waited (or the active entry
                # recovered): nothing to commit, just reset the persisted
                # failure count.
                _converge_health_ready(state.provider_id, state.generation)
                return
            candidates = _build_candidates(_specs())
            committed = None
            for candidate in candidates:
                if candidate.provider_id == state.provider_id:
                    committed = candidate
                    break
            if committed is None:
                raise ProviderUnavailable(
                    "configured provider does not match the committed "
                    "provider state"
                )
            if _healthy_within(committed, budget.deadline):
                # The committed active is healthy (a foreign reconnect or
                # failover committed while this one waited): adopt it
                # instead of committing a second generation.
                _install_provider(committed)
                _active_state = (committed.provider_id, state.generation)
                _converge_health_ready(state.provider_id, state.generation)
                return
            target = _first_healthy(
                candidates, budget.deadline, exclude_id=state.provider_id
            )
            if target is None:
                raise ProviderUnavailable(
                    "no healthy standby provider in the configured "
                    "provider chain"
                )
            generation = state.generation
            # Two atomic commits: switching(old id, target id, the original
            # generation), then ready(target id, null, generation+1). A
            # crash between them keeps the old generation and is completed
            # (healthy target) or kept (fixed 503) at the next read.
            _write_committed_state(
                state.provider_id,
                generation,
                _REASON_FAILOVER,
                target_provider_id=target.provider_id,
                phase=_PHASE_SWITCHING,
            )
            _write_committed_state(
                target.provider_id, generation + 1, _REASON_FAILOVER
            )
            # The new generation's health record is written only AFTER the
            # provider-state commit: ready/0 for the standby just activated.
            _write_committed_health(
                target.provider_id, generation + 1, _STATUS_READY, 0
            )
            _install_provider(target)
            _active_state = (target.provider_id, generation + 1)
    finally:
        # Always release in reverse order; failure or timeout leaves the
        # previously active instance and committed state untouched.
        state_lease.release()
        if draining:
            _gate.end_draining()
        intent.release()
        _gate.release_serialized()


def reconnect(timeout: float = CALL_GATE_SECONDS) -> dict:
    """Rebuild the provider from the current configuration without dropping
    in-flight calls.

    Ordering (within one data directory):

    1. serialize against concurrent reconnects in this process;
    2. establish the cross-process reconnect INTENT (exclusive
       ``provider-reconnect.lock``) -- only after this does any draining
       happen, and every LATER call in every process waits from now on;
    3. drain calls admitted earlier in this process (they finish on the
       instance they captured), then take the exclusive
       ``provider-state.lock`` which drains earlier calls in other processes;
    4. build, contract-validate, configure and health-probe the candidate --
       with ``KEYMGR_PROVIDER_CHAIN`` set this re-selects the FIRST healthy
       chain entry (the only operation that may move the active provider
       back to a recovered primary) --
       atomically commit ``provider-state.json`` with the next generation and
       only then swap the cached instance. A commit that changes
       ``provider_id`` first writes ``switching`` (old id, target id, the
       original generation) and then ``ready`` (target id, null,
       generation+1);
    5. release the drain/intent: later calls resume on the NEW generation.

    Every wait shares one five-second budget started at the first one. On any
    failure (serialization, intent/drain wait, build, configure, health,
    commit) the previously active instance and the old state are retained
    byte-for-byte and :class:`ProviderUnavailable` is raised. One successful
    reconnect increments ``generation`` by exactly one.
    """
    budget = _Budget(timeout)
    # (1) Single reconnect per process at a time, bounded by the budget.
    _gate.acquire_serialized(budget)
    intent = _intent_lease()
    state_lease = _FileLease()
    draining = False
    try:
        # (2) Cross-process intent FIRST. Held to the end of the swap, so a
        # call arriving after this point can never slip in via flock's
        # read-leapfrog: its intent probe blocks and it waits.
        intent.acquire(True, budget.deadline)
        # (3) Mark the local drain, wait out earlier in-process calls, then
        # take the exclusive state lease (which drains earlier cross-process
        # calls still holding their shared lease).
        _gate.begin_draining()
        draining = True
        _gate.wait_drained(budget)
        if budget.expired():
            raise ProviderReconnectPending(
                "reconnect exceeded the shared five-second budget"
            )
        # Lock order: _state_sync_lock -> state lock file.
        with _state_sync_lock:
            state_lease.acquire(True, budget.deadline)
            if budget.expired():
                raise ProviderReconnectPending(
                    "reconnect exceeded the shared five-second budget"
                )
            # A corrupt state file fails the reconnect and is never
            # rewritten; a missing file means generation 1.
            state = _read_committed_state()
            # (4) Build + contract validation + configure while every later
            # call is held behind intent/draining. Chain mode re-selects the
            # first healthy entry in chain order; single-spec mode rebuilds
            # the one configured provider. The health probe shares the same
            # deadline: a slow/blocked probe is a failed reconnect; its text
            # never surfaces.
            if _chain_configured():
                selected = _first_healthy(
                    _build_candidates(_specs()), budget.deadline
                )
                if selected is None:
                    raise ProviderUnavailable(
                        "no healthy provider in the configured provider chain"
                    )
            else:
                selected = _build_current_provider()
                if not _healthy_within(selected, budget.deadline):
                    raise ProviderUnavailable("provider reported unhealthy")
            if state is None:
                generation = 1
                _write_committed_state(
                    selected.provider_id, generation, _REASON_INITIAL
                )
            elif state.phase == _PHASE_SWITCHING and (
                selected.provider_id == state.target_provider_id
            ):
                # Finishing an interrupted switch with its original target:
                # complete it under the original reason.
                generation = state.generation + 1
                _write_committed_state(
                    selected.provider_id, generation, state.reason
                )
            else:
                generation = state.generation + 1
                if selected.provider_id == state.provider_id:
                    _write_committed_state(
                        selected.provider_id, generation, _REASON_RECONNECT
                    )
                else:
                    # A provider switch: switching(old id, target id, the
                    # original generation), then ready(target id, null,
                    # generation+1).
                    _write_committed_state(
                        state.provider_id,
                        state.generation,
                        _REASON_RECONNECT,
                        target_provider_id=selected.provider_id,
                        phase=_PHASE_SWITCHING,
                    )
                    _write_committed_state(
                        selected.provider_id, generation, _REASON_RECONNECT
                    )
            # Swap while still draining and holding intent: no call can be
            # admitted, so the old instance is retained only by calls
            # already in flight (which captured it) and every later call
            # lands on selected.
            global _active_state
            _install_provider(selected)
            _active_state = (selected.provider_id, generation)
    finally:
        # (5) Always release in reverse order; failure or timeout leaves the
        # previously active instance and committed state untouched.
        state_lease.release()
        if draining:
            _gate.end_draining()
        intent.release()
        _gate.release_serialized()

    current = get_provider()
    return _status_for(current)


def _build_unconfigured(spec: str):
    """Build one chain entry for a membership check WITHOUT configuring it.

    A factory/contract failure still raises :class:`ProviderUnavailable`,
    but no data-directory state (e.g. ``local.dek``) is created: the local
    entry is a fresh, unconfigured instance whose ``provider_id`` is
    ``local`` without touching the data directory.
    """
    if spec == LOCAL_PROVIDER_ID:
        return LocalProvider()
    return _load_external(spec)


def _chain_member(target_provider_id: str, specs: List[str]):
    """Return the spec building ``target_provider_id`` without configuring.

    Raises :class:`ProviderSwitchoverInvalid` when no entry builds that id
    (the HTTP layer turns this into a 400 naming provider_id). Built ids
    must be unique, like :func:`_build_candidates`; a duplicate is a
    malformed chain and raises :class:`ProviderUnavailable` (503). No entry
    is configured, so the check has zero data-directory side effects.
    """
    target_spec = None
    seen = set()
    for spec in specs:
        candidate = _build_unconfigured(spec)
        if candidate.provider_id in seen:
            raise ProviderUnavailable(
                "provider chain entries must build unique provider_id values"
            )
        seen.add(candidate.provider_id)
        if candidate.provider_id == target_provider_id:
            target_spec = spec
    if target_spec is None:
        raise ProviderSwitchoverInvalid(
            "field provider_id is not in the configured provider chain"
        )
    return target_spec


def switchover(
    target_provider_id: str, timeout: float = CALL_GATE_SECONDS
) -> dict:
    """Switch the active provider to the named chain entry, directed.

    Unlike :func:`reconnect` (which re-selects the FIRST healthy chain
    entry) this moves the active provider to exactly
    ``target_provider_id``. Requires ``KEYMGR_PROVIDER_CHAIN``: an unset
    chain, or a target no chain entry builds, is
    :class:`ProviderSwitchoverInvalid` (HTTP 400 / CLI exit 2). The
    membership check runs BEFORE the drain gate and configures nothing, so
    a 400 is strictly side-effect-free and never waits behind another
    switch: only the single target is ever configured.

    Ordering and failure semantics are the reconnect ones: serialize
    in-process, establish the cross-process intent, drain calls admitted
    earlier (they finish on the instance they captured; every later call
    waits on one shared five-second budget), then under the exclusive
    state lease:

    * an interrupted ``switching`` record is completed only for a healthy
      target, else kept byte-for-byte with the fixed 503;
    * a target that already IS the committed active entry answers 200
      with the generation unchanged when it probes healthy, else 503 with
      zero side effects;
    * otherwise the target is configured and health-probed (any failure or
      an exhausted budget: the fixed 503, old generation retained
      byte-for-byte), then committed as ``switching`` (old id, target id,
      the ORIGINAL generation, reason ``reconnect``) followed by ``ready``
      (target id, null, generation+1), and only then installed. Concurrent
      switchovers to the same target serialize on the gate: only the first
      commits, later ones adopt the committed generation.

    A missing state file (never activated) is created by this first
    healthy activation of the target at generation 1. Returns the
    ``provider_id,status`` body of the newly active target.
    """
    global _active_state
    if not isinstance(target_provider_id, str) or not target_provider_id:
        raise ProviderSwitchoverInvalid(
            "field provider_id must be a non-empty string"
        )
    if not _chain_configured():
        raise ProviderSwitchoverInvalid(
            "field provider_id cannot be switched over: no provider chain "
            "is configured"
        )
    # A set-but-malformed chain is unusable (fixed 503), as at every other
    # provider operation. Locate the target BEFORE touching the gate: this
    # neither waits nor configures any entry, so a "not in chain" 400 has
    # strictly zero side effects even while another switch is draining.
    specs = _chain_specs()
    target_spec = _chain_member(target_provider_id, specs)
    budget = _Budget(timeout)
    _gate.acquire_serialized(budget)
    intent = _intent_lease()
    state_lease = _FileLease()
    draining = False
    try:
        intent.acquire(True, budget.deadline)
        _gate.begin_draining()
        draining = True
        _gate.wait_drained(budget)
        if budget.expired():
            raise ProviderReconnectPending(
                "switchover exceeded the shared five-second budget"
            )
        # Lock order: _state_sync_lock -> state lock file.
        with _state_sync_lock:
            state_lease.acquire(True, budget.deadline)
            if budget.expired():
                raise ProviderReconnectPending(
                    "switchover exceeded the shared five-second budget"
                )
            # A corrupt state file fails the switchover and is never
            # rewritten; an interrupted switch is completed only for a
            # healthy target, else kept byte-for-byte (fixed 503).
            state = _read_committed_state()
            if state is not None and state.phase == _PHASE_SWITCHING:
                state = _complete_switch(state, budget.deadline)
            # Build/configure only the single target (membership was proven
            # pre-gate): a factory/contract/configure failure here is the
            # fixed 503 with the old generation retained byte-for-byte.
            target = _build_spec(target_spec)
            if state is not None and state.provider_id == target.provider_id:
                # Already the active entry (possibly committed by a
                # concurrent switchover to the same target while this one
                # waited): healthy -> 200 with the generation unchanged,
                # unhealthy -> the fixed 503. Nothing is committed.
                if not _healthy_within(target, budget.deadline):
                    raise ProviderUnavailable("provider reported unhealthy")
                _install_provider(target)
                _active_state = (target.provider_id, state.generation)
                return _status_for(target)
            if not _healthy_within(target, budget.deadline):
                raise ProviderUnavailable("provider reported unhealthy")
            if state is None:
                # First activation: the switchover target becomes the
                # committed active entry at generation 1.
                generation = 1
                _write_committed_state(
                    target.provider_id, generation, _REASON_INITIAL
                )
            else:
                generation = state.generation + 1
                # Two atomic commits: switching(old id, target id, the
                # original generation, reason reconnect), then
                # ready(target id, null, generation+1). A crash between
                # them keeps the old generation and is completed (healthy
                # target) or kept (fixed 503) at the next read.
                _write_committed_state(
                    state.provider_id,
                    state.generation,
                    _REASON_RECONNECT,
                    target_provider_id=target.provider_id,
                    phase=_PHASE_SWITCHING,
                )
                _write_committed_state(
                    target.provider_id, generation, _REASON_RECONNECT
                )
            _install_provider(target)
            _active_state = (target.provider_id, generation)
    finally:
        # Always release in reverse order; failure or timeout leaves the
        # previously active instance and committed state untouched.
        state_lease.release()
        if draining:
            _gate.end_draining()
        intent.release()
        _gate.release_serialized()

    return _status_for(get_provider())


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
