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
    }

Materials are stored base64-wrapped with a static prefix so nothing here ever
resembles plaintext, and handles are random UUIDs recorded in the state file.
"""

import base64
import json
import os
import threading
import time
import uuid

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


def _check_fault(op):
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
        count = _call_counts.get(op, 0) + 1
        _call_counts[op] = count
        if count > int(fail_after[op]):
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

    @property
    def capabilities(self):
        operations = [
            "generate",
            "rotate",
            "import_material",
            "export_material",
            "delete",
        ]
        # The optional native-signing operation is declared only when the
        # faults file asks for it, so both provider shapes can be exercised.
        if _faults().get("declare_sign"):
            operations.append("sign")
        return {"algorithms": ["AES256", "RSA2048"], "operations": operations}

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

    def delete(self, handle):
        _check_fault("delete")
        with _lock:
            state = _load_state()
            if handle in state["handles"]:
                del state["handles"][handle]
                _save_state(state)

    def sign(self, handle, message):
        """Optional native signing, declared via the declare_sign fault."""
        if not isinstance(handle, str) or not handle:
            raise ValueError("sign requires a non-empty handle")
        if not isinstance(message, bytes):
            raise TypeError("sign message must be bytes")
        _check_fault("sign")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        with _lock:
            state = _load_state()
            entry = state["handles"].get(handle)
        if entry is None:
            raise RuntimeError("unknown handle")
        if entry["algorithm"] != "RSA2048":
            raise RuntimeError("handle is not an RSA2048 key")
        private_key = serialization.load_pem_private_key(
            _unwrap(entry["material"]).encode("utf-8"), password=None
        )
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def make_provider():
    faults = _faults()
    if faults.get("factory_fails"):
        raise RuntimeError("fake factory is failing")
    if faults.get("factory_sleep"):
        time.sleep(float(faults["factory_sleep"]))
    return FakeKmsProvider()
