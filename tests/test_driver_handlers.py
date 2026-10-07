"""
Kernel driver framework handlers (NDIS, WFP, WSK, KMDF) return what callers read.
"""

import uuid

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.kernelmode.fwpkclnt import FWP_E_SUBLAYER_NOT_FOUND, Fwpkclnt
from speakeasy.winenv.api.kernelmode.netio import Netio
from tests.handler_harness import alloc, call


def test_wsk_receive_from_accepts_all_parameters(driver_emu: Speakeasy) -> None:
    rv, _ = call(driver_emu, "netio", "callback_WskReceiveFrom", [1, 2, 3, 4, 5, 6, 7, 8])
    assert rv == 0


def test_wsk_get_local_address_pops_three_slots(driver_emu: Speakeasy) -> None:
    assert Netio.WskGetLocalAddress.__apihook__[2] == 3
    rv, _ = call(driver_emu, "netio", "callback_WskGetLocalAddress", [1, 2, 3])
    assert rv == 0


def test_wsk_capture_provider_npi_writes_every_capture(driver64_emu: Speakeasy) -> None:
    registration = alloc(driver64_emu, b"\x00" * 16)
    rv, _ = call(driver64_emu, "netio", "WskRegister", [alloc(driver64_emu, b"\x00" * 16), registration])
    assert rv == 0
    first = alloc(driver64_emu, b"\xcc" * 16)
    second = alloc(driver64_emu, b"\xcc" * 16)
    assert call(driver64_emu, "netio", "WskCaptureProviderNPI", [registration, 0, first])[0] == 0
    assert call(driver64_emu, "netio", "WskCaptureProviderNPI", [registration, 0, second])[0] == 0
    assert driver64_emu.mem_read(first, 16) != b"\xcc" * 16
    assert driver64_emu.mem_read(second, 16) == driver64_emu.mem_read(first, 16)


def test_fwpm_filter_add_accepts_a_null_id(driver_emu: Speakeasy) -> None:
    flt = alloc(driver_emu, b"\x00" * 0x200)
    rv, _ = call(driver_emu, "fwpkclnt", "FwpmFilterAdd0", [4, flt, 0, 0])
    assert rv == 0
    pid = alloc(driver_emu, b"\xcc" * 8)
    rv, _ = call(driver_emu, "fwpkclnt", "FwpmFilterAdd0", [4, flt, 0, pid])
    assert rv == 0
    assert 0 < int.from_bytes(driver_emu.mem_read(pid, 8), "little") < 0x10000


def test_fwpm_sublayer_delete_by_key_finds_an_added_sublayer(driver_emu: Speakeasy) -> None:
    key = uuid.UUID("6f1d2c3b-4a59-4e7f-8a9b-0c1d2e3f4a5b")
    sublayer = alloc(driver_emu, key.bytes_le + b"\x00" * 0xF0)
    rv, _ = call(driver_emu, "fwpkclnt", "FwpmSubLayerAdd0", [4, sublayer, 0])
    assert rv == 0
    key_addr = alloc(driver_emu, key.bytes_le)
    assert call(driver_emu, "fwpkclnt", "FwpmSubLayerDeleteByKey0", [4, key_addr])[0] == 0
    assert call(driver_emu, "fwpkclnt", "FwpmSubLayerDeleteByKey0", [4, key_addr])[0] == FWP_E_SUBLAYER_NOT_FOUND


def test_fwpm_filter_delete_by_id_pops_the_64_bit_id(driver_emu: Speakeasy) -> None:
    assert Fwpkclnt.FwpmFilterDeleteById0.__apihook__[2] == 3
    rv, _ = call(driver_emu, "fwpkclnt", "FwpmFilterDeleteById0", [4, 8, 0])
    assert rv == 0


@pytest.mark.parametrize(
    "api, argv",
    [
        ("NdisMRegisterMiniportDriver", [0, 0, 0, 0, "out"]),
        ("NdisRegisterProtocol", ["buf", "out", "buf", 0x40]),
        ("NdisIMRegisterLayeredMiniport", [0, "buf", 0x40, "out"]),
    ],
)
def test_ndis_handles_are_pointer_sized(driver64_emu: Speakeasy, api: str, argv: list[int | str]) -> None:
    out = alloc(driver64_emu, b"\xcc" * 8)
    slots = {"out": out, "buf": alloc(driver64_emu, b"\x00" * 0x40)}
    call(driver64_emu, "ndis", api, [slots[a] if isinstance(a, str) else a for a in argv])
    handle = int.from_bytes(driver64_emu.mem_read(out, 8), "little")
    assert 0 < handle < 0x10000
