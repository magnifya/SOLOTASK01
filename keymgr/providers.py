"""Pluggable KMS/HSM key-provider layer.

Key material operations (generate, rotate, import, export, delete) are
delegated to a *provider*. The provider is selected by the ``KEYMGR_PROVIDER``
environment variable:

* unset, empty or ``local`` — the built-in local provider, which keeps the
  pre-KMS behaviour (material is wrapped by an opaque local encoding and
  stored in the key file);
* ``module:factory`` — the named module is imported and its zero-argument
  factory is called to build the provider (an HSM/KMS adapter).

The provider is loaded lazily on first use and cached per spec string. Any
loading or operation failure raises :class:`ProviderError`, surfaced as HTTP
503 / CLI exit code 1; there is never a silent fallback to the local
provider.

Provider contract:

* ``provider_id`` — non-empty string identifying the provider;
* ``capabilities`` — ``{"algorithms": [...], "operations": [...]}`` covering
  all of ``generate``, ``rotate``, ``import_material``, ``export_material``
  and ``delete``;
* ``generate(algorithm)`` / ``rotate(algorithm)`` /
  ``import_material(algorithm, public_key, material)`` return
  ``{"handle", "public_key", "encrypted_material"}`` with a non-empty handle
  and non-empty encrypted material;
* ``export_material(handle)`` returns ``{"public_key", "encrypted_material"}``;
* ``delete(handle)`` is idempotent.

Handles and encrypted material are opaque to the rest of the system and must
never appear in responses, audit events or error messages.
"""

import base64
import importlib
import os

from .crypto import SUPPORTED_ALGORITHMS, generate_key

LOCAL_PROVIDER_ID = "local"

REQUIRED_OPERATIONS = (
    "generate",
    "rotate",
    "import_material",
    "export_material",
    "delete",
)

_ENV_VAR = "KEYMGR_PROVIDER"


class ProviderError(Exception):
    """The configured key provider is unavailable or misbehaving.

    Surfaced as HTTP 503 / CLI exit code 1. Messages are static text: they
    never carry handles or key material.
    """


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class LocalProvider:
    """Built-in provider: material is wrapped locally, no external KMS.

    The handle is self-contained (it embeds the wrapped material), so the
    provider is stateless and works across restarts and data directories
    without any registry. ``encrypted_material`` is an opaque encoding of
    the private material; plaintext is never written under the KMS schema.
    """

    provider_id = LOCAL_PROVIDER_ID
    capabilities = {
        "algorithms": list(SUPPORTED_ALGORITHMS),
        "operations": list(REQUIRED_OPERATIONS),
    }

    _WRAP_PREFIX = "v1:"
    _HANDLE_PREFIX = "local:"

    @classmethod
    def _wrap(cls, raw_material: str) -> str:
        return cls._WRAP_PREFIX + _b64e(raw_material.encode("utf-8"))

    @classmethod
    def _unwrap(cls, encrypted_material: str) -> str:
        if not encrypted_material.startswith(cls._WRAP_PREFIX):
            raise ValueError("not a locally wrapped material")
        return _b64d(encrypted_material[len(cls._WRAP_PREFIX):]).decode("utf-8")

    @classmethod
    def _mint(cls, public_key, raw_material: str) -> dict:
        encrypted = cls._wrap(raw_material)
        return {
            "handle": cls._HANDLE_PREFIX + encrypted,
            "public_key": public_key,
            "encrypted_material": encrypted,
        }

    def generate(self, algorithm: str) -> dict:
        generated = generate_key(algorithm)
        return self._mint(generated.public_material, generated.private_material)

    def rotate(self, algorithm: str) -> dict:
        return self.generate(algorithm)

    def import_material(self, algorithm: str, public_key, material: str) -> dict:
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError("unsupported algorithm: %r" % (algorithm,))
        # Accept both locally wrapped material and raw legacy plaintext
        # (pre-KMS export bundles); the stored form is always wrapped.
        encrypted = (
            material
            if material.startswith(self._WRAP_PREFIX)
            else self._wrap(material)
        )
        return {
            "handle": self._HANDLE_PREFIX + encrypted,
            "public_key": public_key,
            "encrypted_material": encrypted,
        }

    def export_material(self, handle: str) -> dict:
        if not handle.startswith(self._HANDLE_PREFIX):
            raise ValueError("not a local handle")
        encrypted = handle[len(self._HANDLE_PREFIX):]
        raw = self._unwrap(encrypted)
        return {
            "public_key": _public_from_material(raw),
            "encrypted_material": encrypted,
        }

    def delete(self, handle: str) -> None:
        # Stateless: nothing to remove. Idempotent by construction.
        return None


def _public_from_material(raw_material: str):
    """Derive the public key from raw private material (RSA), else None."""
    if raw_material.startswith("-----BEGIN"):
        from cryptography.hazmat.primitives import serialization

        private_key = serialization.load_pem_private_key(
            raw_material.encode("utf-8"), password=None
        )
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    return None


# -- loading ---------------------------------------------------------------
_providers: dict = {}


def get_provider():
    """Return the configured provider, loading it lazily on first use.

    The spec comes from ``KEYMGR_PROVIDER`` (default/empty/"local" selects
    the built-in local provider; "module:factory" imports an external one).
    Providers are cached per spec string; load failures are not cached and
    raise ProviderError on every attempt — there is no fallback.
    """
    spec = (os.environ.get(_ENV_VAR) or "").strip() or LOCAL_PROVIDER_ID
    provider = _providers.get(spec)
    if provider is not None:
        return provider
    provider = _load_provider(spec)
    _providers[spec] = provider
    return provider


def _reset() -> None:
    """Drop the provider cache (test hook)."""
    _providers.clear()


def _load_provider(spec: str):
    if spec == LOCAL_PROVIDER_ID:
        return _validate(LocalProvider())
    module_name, sep, factory_name = spec.partition(":")
    if not sep or not module_name.strip() or not factory_name.strip():
        raise ProviderError(
            "invalid %s %r (expected 'local' or 'module:factory')"
            % (_ENV_VAR, spec)
        )
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise ProviderError(
            "cannot load key provider module %r: %s" % (module_name, exc)
        ) from exc
    factory = getattr(module, factory_name, None)
    if not callable(factory):
        raise ProviderError(
            "key provider factory %r not found in module %r"
            % (factory_name, module_name)
        )
    try:
        provider = factory()
    except Exception as exc:
        raise ProviderError(
            "key provider factory %r failed: %s" % (factory_name, exc)
        ) from exc
    return _validate(provider)


def _validate(provider):
    """Enforce the provider contract at load time."""
    provider_id = getattr(provider, "provider_id", None)
    if not isinstance(provider_id, str) or not provider_id:
        raise ProviderError("key provider must expose a non-empty provider_id")
    capabilities = getattr(provider, "capabilities", None)
    if not isinstance(capabilities, dict):
        raise ProviderError("key provider must expose capabilities")
    algorithms = capabilities.get("algorithms")
    if not isinstance(algorithms, (list, tuple)) or not algorithms:
        raise ProviderError(
            "key provider capabilities must list supported algorithms"
        )
    operations = capabilities.get("operations")
    if not isinstance(operations, (list, tuple)) or any(
        op not in operations for op in REQUIRED_OPERATIONS
    ):
        raise ProviderError(
            "key provider capabilities must list operations: %s"
            % ", ".join(REQUIRED_OPERATIONS)
        )
    for name in REQUIRED_OPERATIONS:
        if not callable(getattr(provider, name, None)):
            raise ProviderError("key provider is missing method %s" % name)
    return provider


# -- operation helpers -----------------------------------------------------
def check_algorithm(provider, algorithm: str) -> None:
    """Raise ProviderError if the provider does not support the algorithm."""
    capabilities = getattr(provider, "capabilities", None)
    algorithms = (
        capabilities.get("algorithms") if isinstance(capabilities, dict) else None
    )
    if isinstance(algorithms, (list, tuple)) and algorithm not in algorithms:
        raise ProviderError(
            "key provider does not support algorithm %r" % (algorithm,)
        )


def material_result(raw, operation: str) -> dict:
    """Validate a generate/rotate/import_material result."""
    if not isinstance(raw, dict):
        raise ProviderError(
            "key provider operation %s returned an invalid result" % operation
        )
    handle = raw.get("handle")
    encrypted = raw.get("encrypted_material")
    public_key = raw.get("public_key")
    if (
        not isinstance(handle, str)
        or not handle
        or not isinstance(encrypted, str)
        or not encrypted
    ):
        raise ProviderError(
            "key provider operation %s returned an invalid result" % operation
        )
    if public_key is not None and not isinstance(public_key, str):
        raise ProviderError(
            "key provider operation %s returned an invalid result" % operation
        )
    return {
        "handle": handle,
        "public_key": public_key,
        "encrypted_material": encrypted,
    }


def run(provider, operation: str, *args) -> dict:
    """Call a material-minting provider operation with error normalization.

    Provider exceptions are collapsed into a static ProviderError so handles
    or key material can never leak into an error message.
    """
    try:
        raw = getattr(provider, operation)(*args)
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError(
            "key provider operation %s failed" % operation
        ) from exc
    return material_result(raw, operation)


def discard(provider, handle) -> None:
    """Best-effort idempotent delete of a handle; never raises."""
    if not handle:
        return
    try:
        provider.delete(handle)
    except Exception:
        pass
