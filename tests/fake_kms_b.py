"""A second fake external KMS/HSM provider for chain failover tests.

Identical in shape to ``fake_kms`` but with its own ``provider_id``
(``fakekms-b``), its own backend state file (``FAKE_KMS_B_STATE``) and its
own fault-injection file (``FAKE_KMS_B_FAULTS``), so a
``KEYMGR_PROVIDER_CHAIN`` of ``fake_kms:make_provider,fake_kms_b:make_provider``
behaves like two independent KMS backends. The id can be overridden with
``FAKE_KMS_B_PROVIDER_ID`` (used to exercise the duplicate-provider_id
configuration error).
"""

import base64
import json
import os
import threading
import time
import uuid

PROVIDER_ID = "fakekms-b"

_lock = threading.Lock()


def _state_path():
    return os.environ["FAKE_KMS_B_STATE"]


def _faults_path():
    return os.environ.get("FAKE_KMS_B_FAULTS", "")


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


def _wrap(material):
    return "fk2." + base64.urlsafe_b64encode(material.encode("utf-8")).decode(
        "ascii"
    )


def _unwrap(blob):
    if not isinstance(blob, str) or not blob.startswith("fk2."):
        raise RuntimeError("not a fakekms-b blob")
    return base64.urlsafe_b64decode(blob[4:].encode("ascii")).decode("utf-8")


class FakeKmsBProvider:
    capabilities = {
        "algorithms": ["AES256", "RSA2048"],
        "operations": [
            "generate",
            "rotate",
            "import_material",
            "export_material",
            "delete",
        ],
    }

    def __init__(self):
        self.provider_id = os.environ.get(
            "FAKE_KMS_B_PROVIDER_ID", PROVIDER_ID
        )

    def configure(self, data_dir):
        _check_fault("configure")

    def health(self):
        faults = _faults()
        if faults.get("health_raises"):
            raise RuntimeError("health endpoint is failing")
        if "health_nonbool" in faults:
            return faults.get("health_nonbool")
        if "health_sleep" in faults:
            time.sleep(float(faults["health_sleep"]))
        if "health" in faults:
            return bool(faults.get("health"))
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


def make_provider():
    faults = _faults()
    if faults.get("factory_fails"):
        raise RuntimeError("fake factory is failing")
    if faults.get("factory_sleep"):
        time.sleep(float(faults["factory_sleep"]))
    return FakeKmsBProvider()
