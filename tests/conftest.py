"""Shared fixtures for the crash-recovery test suite."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keymgr import provider as provider_mod  # noqa: E402
from keymgr.audit import AuditLog  # noqa: E402
from keymgr.store import KeyStore  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """A data dir wired to the fake external KMS provider."""
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    state_path = str(tmp_path / "kms-state.json")
    faults_path = str(tmp_path / "kms-faults.json")
    monkeypatch.setenv("KEYMGR_PROVIDER", "fake_kms:make_provider")
    monkeypatch.setenv("FAKE_KMS_STATE", state_path)
    monkeypatch.setenv("FAKE_KMS_FAULTS", faults_path)
    provider_mod.reset_for_tests()
    import fake_kms

    fake_kms.reset()
    yield Env(data_dir, state_path, faults_path)
    provider_mod.reset_for_tests()


class Env:
    def __init__(self, data_dir, state_path, faults_path):
        self.data_dir = data_dir
        self.state_path = state_path
        self.faults_path = faults_path

    def open_store(self):
        """Open a fresh store (runs startup recovery), like a new process."""
        return KeyStore(self.data_dir, AuditLog(self.data_dir))

    def kms_handles(self):
        """Handle set currently registered in the fake KMS backend."""
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                return set(json.load(fh)["handles"])
        except (OSError, ValueError, KeyError):
            return set()

    def set_faults(self, faults):
        with open(self.faults_path, "w", encoding="utf-8") as fh:
            json.dump(faults, fh)

    def clear_faults(self):
        try:
            os.unlink(self.faults_path)
        except OSError:
            pass

    def audit_events(self):
        return AuditLog(self.data_dir)._read_all()
