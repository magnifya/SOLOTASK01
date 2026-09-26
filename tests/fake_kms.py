"""A fake external KMS/HSM provider for recovery tests.

Loaded through the ``module:factory`` mechanism (``KEYMGR_PROVIDER``). State
lives in a JSON file named by ``FAKE_KMS_STATE`` so several *processes* (the
CLI, a server, a recovery sweep) share one backend, exactly like a real KMS.
Fault injection is driven by a JSON file named by ``FAKE_KMS_FAULTS``:

    {
      "unreachable": true,          # every call fails as a backend outage
      "fail": {"delete": true, ...} # per-operation failures
      "sleep": {"rotate": 5.0},     # per-operation pre-call delay (seconds)
      "health": false,              # health() returns False (unavailable)
      "health_raises": true,        # health() raises (treated as unavailable)
      "health_nonbool": "yes",      # health() returns a non-bool (unavailable)
      "health_sleep": 6.0,          # health() blocks past the reconnect budget
      "provider_id": "fakekms-alt"  # override the factory's provider_id
      "declare_sign": true,         # capabilities.operations gains "sign"
      "sign_not_callable": true,    # declare sign but break the method (contract)
      "sign_short": true,           # sign() returns a malformed short value
      "sign_tamper": true,          # sign() returns a flipped-byte signature
      "declare_unwrap_key": true,   # capabilities.operations gains "unwrap_key"
      "unwrap_not_callable": true,  # declare unwrap_key but break the method
      "unwrap_fail": true,          # unwrap_key() raises a backend fault
      "unwrap_short": true          # unwrap_key() returns a malformed short DEK
      "declare_wrap_key": true,     # capabilities.operations gains "wrap_key"
      "wrap_not_callable": true,    # declare wrap_key but break the method
      "wrap_fail": true,            # wrap_key() raises a backend fault
      "wrap_short": true            # wrap_key() returns a malformed short wrap
    }

Materials are stored base64-wrapped with a static prefix so nothing here ever
resembles plaintext, and handles are random UUIDs recorded in the state file.
Per-process per-operation call counts are exposed via ``call_count(op)`` so
tests can assert which provider operations a request actually used.
"""

import base64
import json
import os
import threading
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PROVIDER_ID = "fakekms"

_lock = threading.Lock()


def _state_path():
    return os.environ["FAKE_KMS_STATE"]


def _faults_path():
    return os.environ.get("FAKE_KMS_FAULTS", "")


def _load_state():
    try:
        with open(_state_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"handles": {}}


def _save_state(state):
    path = _state_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _faults():
    path = _faults_path()
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


_call_counts = {}


def reset():
    """Clear per-process fault counters (called by the test fixture)."""
    _call_counts.clear()


def call_count(op):
    """How many times operation ``op`` was entered in this process."""
    return _call_counts.get(op, 0)


def _check_fault(op):
    _call_counts[op] = _call_counts.get(op, 0) + 1
    faults = _faults()
    sleep = faults.get("sleep")
    if isinstance(sleep, dict) and op in sleep:
        time.sleep(float(sleep[op]))
    if faults.get("unreachable"):
        raise RuntimeError("backend is unreachable")
    fail = faults.get("fail")
    if isinstance(fail, dict) and fail.get(op):
        raise RuntimeError("backend failure in %s" % op)
    fail_after = faults.get("fail_after")
    if isinstance(fail_after, dict) and op in fail_after:
        if _call_counts[op] > int(fail_after[op]):
            raise RuntimeError("backend failure in %s" % op)


def _wrap(material):
    return "fk1." + base64.urlsafe_b64encode(material.encode("utf-8")).decode(
        "ascii"
    )


def _unwrap(blob):
    if not isinstance(blob, str) or not blob.startswith("fk1."):
        raise RuntimeError("not a fakekms blob")
    return base64.urlsafe_b64decode(blob[4:].encode("ascii")).decode("utf-8")


class FakeKmsProvider:
    def __init__(self):
        # The id can be overridden per process (FAKE_KMS_PROVIDER_ID) so a
        # reconnect can install a provider carrying a different provider_id,
        # exercising the pending-operation displacement rule.
        self.provider_id = os.environ.get("FAKE_KMS_PROVIDER_ID", PROVIDER_ID)
        if _faults().get("sign_not_callable"):
            # Contract-violation injection: the provider declares "sign" in
            # its capabilities but the attribute is not a callable method.
            self.sign = True
        if _faults().get("unwrap_not_callable"):
            # Contract-violation injection: declares "unwrap_key" without a
            # callable method.
            self.unwrap_key = True
        if _faults().get("wrap_not_callable"):
            # Contract-violation injection: declares "wrap_key" without a
            # callable method.
            self.wrap_key = True

    @property
    def capabilities(self):
        operations = [
            "generate",
            "rotate",
            "import_material",
            "export_material",
            "delete",
        ]
        if _faults().get("declare_sign"):
            operations.append("sign")
        if _faults().get("declare_unwrap_key"):
            operations.append("unwrap_key")
        if _faults().get("declare_wrap_key"):
            operations.append("wrap_key")
        return {
            "algorithms": ["AES256", "RSA2048"],
            "operations": operations,
        }

    def configure(self, data_dir):
        _check_fault("configure")

    def health(self):
        """Optional readiness probe driven by the faults file."""
        faults = _faults()
        if faults.get("health_raises"):
            raise RuntimeError("health endpoint is failing")
        if "health_nonbool" in faults:
            return faults.get("health_nonbool")
        if "health_sleep" in faults:
            time.sleep(float(faults["health_sleep"]))
        if "health" in faults:
            return bool(faults.get("health"))
        # Default: healthy unless the backend is globally unreachable.
        return not faults.get("unreachable")

    def _mint(self, algorithm, public_key, material):
        _check_fault("mint")
        handle = uuid.uuid4().hex
        with _lock:
            state = _load_state()
            state["handles"][handle] = {
                "algorithm": algorithm,
                "public_key": public_key,
                "material": _wrap(material),
            }
            _save_state(state)
        return {
            "handle": handle,
            "public_key": public_key,
            "encrypted_material": _wrap(material),
        }

    def generate(self, algorithm):
        _check_fault("generate")
        from keymgr.crypto import generate_key

        generated = generate_key(algorithm)
        return self._mint(
            algorithm, generated.public_material, generated.private_material
        )

    def rotate(self, algorithm):
        _check_fault("rotate")
        return self.generate(algorithm)

    def import_material(self, algorithm, public_key, material):
        _check_fault("import_material")
        if not isinstance(material, str) or not material:
            raise RuntimeError("empty material")
        return self._mint(algorithm, public_key, material)

    def export_material(self, handle):
        _check_fault("export_material")
        with _lock:
            state = _load_state()
            entry = state["handles"].get(handle)
            if entry is None:
                raise RuntimeError("unknown handle")
            return {
                "public_key": entry["public_key"],
                "encrypted_material": _unwrap(entry["material"]),
            }

    def sign(self, handle, message):
        """Optional native RSASSA-PKCS1-v1_5/SHA-256 signature (declared via
        the ``declare_sign`` fault key)."""
        if not isinstance(handle, str) or not handle:
            raise ValueError("sign requires a non-empty handle string")
        if not isinstance(message, bytes):
            raise TypeError("sign message must be bytes")
        _check_fault("sign")
        with _lock:
            state = _load_state()
            entry = state["handles"].get(handle)
        if entry is None:
            raise RuntimeError("unknown handle")
        if entry.get("algorithm") != "RSA2048":
            raise RuntimeError("handle is not an RSA2048 key")
        faults = _faults()
        if faults.get("sign_short"):
            # Contract-violation injection: a malformed, short signature.
            return b"short"
        private_key = serialization.load_pem_private_key(
            _unwrap(entry["material"]).encode("utf-8"), password=None
        )
        signature = private_key.sign(
            message, padding.PKCS1v15(), hashes.SHA256()
        )
        if faults.get("sign_tamper"):
            # Contract-violation injection: 256 bytes that do not verify.
            tampered = bytearray(signature)
            tampered[0] ^= 0x01
            return bytes(tampered)
        return signature

    def unwrap_key(self, handle, wrapped_key, wrap_nonce=None):
        """Optional native DEK unwrap (declared via ``declare_unwrap_key``).

        Implements the provider contract: argument ``ValueError``/
        ``TypeError`` rules, ``ProviderInvalidMaterial`` on an authentication
        failure, backend faults as plain exceptions (the service normalizes
        them to ProviderUnavailable).
        """
        if not isinstance(handle, str) or not handle:
            raise ValueError("unwrap_key requires a non-empty handle string")
        if not isinstance(wrapped_key, bytes):
            raise TypeError("unwrap_key wrapped_key must be bytes")
        if wrap_nonce is not None and not isinstance(wrap_nonce, bytes):
            raise TypeError("unwrap_key wrap_nonce must be bytes or None")
        if not wrapped_key:
            raise ValueError("unwrap_key wrapped_key must be non-empty")
        _check_fault("unwrap_key")
        if _faults().get("unwrap_fail"):
            raise RuntimeError("backend failure in unwrap_key")
        with _lock:
            state = _load_state()
            entry = state["handles"].get(handle)
        if entry is None:
            raise RuntimeError("unknown handle")
        if _faults().get("unwrap_short"):
            # Contract-violation injection: a malformed, short data key.
            return b"short"
        from keymgr.provider import ProviderInvalidMaterial

        algorithm = entry.get("algorithm")
        material = _unwrap(entry["material"])
        if algorithm == "AES256":
            if wrap_nonce is None or len(wrap_nonce) != 12:
                raise ValueError(
                    "unwrap_key wrap_nonce must be 12 bytes for AES256"
                )
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            kek = base64.b64decode(material.encode("ascii"), validate=True)
            try:
                dek = AESGCM(kek).decrypt(wrap_nonce, wrapped_key, None)
            except Exception as exc:
                raise ProviderInvalidMaterial(
                    "wrapped_key cannot be authenticated"
                ) from exc
        elif algorithm == "RSA2048":
            if wrap_nonce is not None:
                raise ValueError(
                    "unwrap_key wrap_nonce must be null for RSA2048"
                )
            private_key = serialization.load_pem_private_key(
                material.encode("utf-8"), password=None
            )
            oaep = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
            try:
                dek = private_key.decrypt(wrapped_key, oaep)
            except ValueError as exc:
                raise ProviderInvalidMaterial(
                    "wrapped_key cannot be authenticated"
                ) from exc
        else:
            raise RuntimeError("handle is not a supported algorithm")
        if len(dek) != 32:
            raise ProviderInvalidMaterial(
                "unwrapped data key must be 32 bytes"
            )
        return dek

    def wrap_key(self, handle, data_key):
        """Optional native DEK wrap (declared via ``declare_wrap_key``).

        Implements the provider contract: argument ``ValueError``/
        ``TypeError`` rules, ``(wrapped_key, wrap_nonce)`` in that order,
        backend faults as plain exceptions (the service normalizes them to
        ProviderUnavailable).
        """
        if not isinstance(handle, str) or not handle:
            raise ValueError("wrap_key requires a non-empty handle string")
        if not isinstance(data_key, bytes):
            raise TypeError("wrap_key data_key must be bytes")
        if len(data_key) != 32:
            raise ValueError("wrap_key data_key must be 32 bytes")
        _check_fault("wrap_key")
        if _faults().get("wrap_fail"):
            raise RuntimeError("backend failure in wrap_key")
        with _lock:
            state = _load_state()
            entry = state["handles"].get(handle)
        if entry is None:
            raise RuntimeError("unknown handle")
        if _faults().get("wrap_short"):
            # Contract-violation injection: a malformed, short wrapped key.
            return b"short", None
        algorithm = entry.get("algorithm")
        material = _unwrap(entry["material"])
        if algorithm == "AES256":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            kek = base64.b64decode(material.encode("ascii"), validate=True)
            wrap_nonce = os.urandom(12)
            return AESGCM(kek).encrypt(wrap_nonce, data_key, None), wrap_nonce
        if algorithm == "RSA2048":
            private_key = serialization.load_pem_private_key(
                material.encode("utf-8"), password=None
            )
            oaep = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
            return private_key.public_key().encrypt(data_key, oaep), None
        raise RuntimeError("handle is not a supported algorithm")

    def delete(self, handle):
        _check_fault("delete")
        with _lock:
            state = _load_state()
            if handle in state["handles"]:
                del state["handles"][handle]
                _save_state(state)


def make_provider():
    faults = _faults()
    if faults.get("factory_fails"):
        raise RuntimeError("fake factory is failing")
    if faults.get("factory_sleep"):
        time.sleep(float(faults["factory_sleep"]))
    return FakeKmsProvider()
