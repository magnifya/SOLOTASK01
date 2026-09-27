"""Unit tests for the transfer_out/transfer_in provider contract.

Covers the all-or-nothing declaration rule, the ``_SafeProvider`` boundary
argument/return validation, and the built-in local provider's pair.
"""

import base64

import pytest

from keymgr import provider as p


_REQUIRED = [
    "generate",
    "rotate",
    "import_material",
    "export_material",
    "delete",
]


class _Stub:
    def __init__(self, operations, *, break_out=False, break_in=False):
        self.provider_id = "stub"
        self.capabilities = {
            "algorithms": ["AES256", "RSA2048"],
            "operations": operations,
        }
        # A non-callable attribute of the declared name is a contract
        # violation (mirrors the fake_kms *_not_callable fault injection).
        if break_out:
            self.transfer_out = True
        if break_in:
            self.transfer_in = "not-callable"

    def configure(self, data_dir):
        pass

    def generate(self, algorithm):
        raise NotImplementedError

    def rotate(self, algorithm):
        raise NotImplementedError

    def import_material(self, algorithm, public_key, material):
        raise NotImplementedError

    def export_material(self, handle):
        raise NotImplementedError

    def delete(self, handle):
        raise NotImplementedError

    def transfer_out(self, handle, target_provider_id):
        return b"blob"

    def transfer_in(self, source_provider_id, blob):
        return {
            "handle": "h",
            "public_key": None,
            "encrypted_material": "m",
        }


def _ops(*extra):
    return list(_REQUIRED) + list(extra)


def test_declaring_both_with_methods_is_valid():
    p._validate_external(_Stub(_ops("transfer_out", "transfer_in")))


@pytest.mark.parametrize(
    "operations",
    [
        _ops("transfer_out"),
        _ops("transfer_in"),
    ],
)
def test_declaring_only_one_transfer_op_fails_contract(operations):
    with pytest.raises(p.ProviderUnavailable):
        p._validate_external(_Stub(operations))


def test_declaring_pair_without_callable_methods_fails_contract():
    stub = _Stub(
        _ops("transfer_out", "transfer_in"), break_out=True, break_in=True
    )
    with pytest.raises(p.ProviderUnavailable):
        p._validate_external(stub)


def _safe():
    return p._SafeProvider(
        _Stub(_ops("transfer_out", "transfer_in"))
    )


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.transfer_out(1, "peer"),
        lambda s: s.transfer_out("", "peer"),
        lambda s: s.transfer_out("h", 2),
        lambda s: s.transfer_out("h", ""),
        lambda s: s.transfer_in(3, b"x"),
        lambda s: s.transfer_in("", b"x"),
        lambda s: s.transfer_in("p", "not bytes"),
        lambda s: s.transfer_in("p", b""),
    ],
)
def test_safe_provider_transfer_argument_rules(call):
    safe = _safe()
    with pytest.raises((TypeError, ValueError)):
        call(safe)


class _BadOut(_Stub):
    def transfer_out(self, handle, target_provider_id):
        return "not-bytes"


class _EmptyOut(_Stub):
    def transfer_out(self, handle, target_provider_id):
        return b""


class _BadInKeys(_Stub):
    def transfer_in(self, source_provider_id, blob):
        return {"handle": "h"}


class _BadInHandle(_Stub):
    def transfer_in(self, source_provider_id, blob):
        return {
            "handle": "",
            "public_key": None,
            "encrypted_material": "m",
        }


class _BadInPkType(_Stub):
    def transfer_in(self, source_provider_id, blob):
        return {
            "handle": "h",
            "public_key": 5,
            "encrypted_material": "m",
        }


@pytest.mark.parametrize(
    "stub,method,args",
    [
        (_BadOut(_ops("transfer_out", "transfer_in")), "transfer_out",
         ("h", "peer")),
        (_EmptyOut(_ops("transfer_out", "transfer_in")), "transfer_out",
         ("h", "peer")),
        (_BadInKeys(_ops("transfer_out", "transfer_in")), "transfer_in",
         ("peer", b"x")),
        (_BadInHandle(_ops("transfer_out", "transfer_in")), "transfer_in",
         ("peer", b"x")),
        (_BadInPkType(_ops("transfer_out", "transfer_in")), "transfer_in",
         ("peer", b"x")),
    ],
)
def test_safe_provider_malformed_transfer_results_are_unavailable(
    stub, method, args
):
    safe = p._SafeProvider(stub)
    with pytest.raises(p.ProviderUnavailable):
        getattr(safe, method)(*args)


def test_declares_transfer_pair_helper():
    local = p.LocalProvider()
    assert p.declares_transfer_pair(local)
    assert not p.declares_transfer_pair(_Stub(_REQUIRED))
    assert not p.declares_transfer_pair(_Stub(_ops("transfer_out")))


def test_local_transfer_roundtrip(tmp_path):
    data = str(tmp_path)
    local = p.configure_local(data)
    raw = base64.b64encode(b"k" * 32).decode("ascii")
    # An inbound blob a peer sealed FOR local (source "peer", target local).
    inbound = p._transfer_seal(data, "peer", "local", "AES256", None, raw)
    out = local.transfer_in("peer", inbound)
    # The built-in local provider returns the fixed-order triple dict
    # handle, public_key, encrypted_material (the same externally visible
    # shape an external provider's dict is normalized to).
    assert isinstance(out, dict)
    assert list(out.keys()) == [
        "handle", "public_key", "encrypted_material"
    ]
    assert out["public_key"] is None and out["handle"] and out[
        "encrypted_material"
    ]


def test_safe_provider_transfer_in_fixed_key_order():
    # An external provider's dict must arrive with the exact fixed order
    # handle, public_key, encrypted_material (the _Stub already does).
    safe = p._SafeProvider(_Stub(_ops("transfer_out", "transfer_in")))
    triple = safe.transfer_in("peer", b"x")
    assert isinstance(triple, p.MaterialTriple)
    assert triple.handle == "h"
    assert triple.public_key is None
    assert triple.encrypted_material == "m"


def test_transfer_blob_is_endpoint_bound(tmp_path):
    data = str(tmp_path)
    local = p.configure_local(data)
    triple = local.import_material(
        "AES256", None, base64.b64encode(b"k" * 32).decode("ascii")
    )
    blob = local.transfer_out(triple.handle, "fakekms")
    # Opening for different endpoints or after tampering fails authentication.
    with pytest.raises(p.ProviderInvalidMaterial):
        p._transfer_open(data, blob, "local", "other")
