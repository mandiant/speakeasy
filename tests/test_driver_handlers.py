"""
Kernel driver framework handlers (NDIS, WFP, WSK, KMDF) return what callers read.
"""

import struct
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.kernelmode.fwpkclnt import FWP_E_SUBLAYER_NOT_FOUND, Fwpkclnt
from speakeasy.winenv.api.kernelmode.netio import Netio
from speakeasy.winenv.defs import wdf
from speakeasy.winenv.defs.nt import ddk
from tests.handler_harness import alloc, call, load_emu

USBSAMP = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\usbsamp"


@pytest.fixture(params=["wdm_test_x86.sys.xz", "wdm_test_x64.sys.xz"], ids=["x86", "x64"])
def any_driver_emu(request: pytest.FixtureRequest, config: dict[str, Any], load_test_bin: Any) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin(request.param))


def _ptr_size(se: Speakeasy) -> int:
    assert se.emu is not None
    return se.emu.get_ptr_size()


def _read_ptr(se: Speakeasy, addr: int) -> int:
    return int.from_bytes(se.mem_read(addr, _ptr_size(se)), "little")


def _unicode_string(se: Speakeasy, text: str) -> int:
    buf = text.encode("utf-16le")
    buf_addr = alloc(se, buf + b"\x00\x00")
    pad = b"\x00" * (_ptr_size(se) - 4)
    return alloc(se, struct.pack("<HH", len(buf), len(buf) + 2) + pad + buf_addr.to_bytes(_ptr_size(se), "little"))


def _wdf_driver(se: Speakeasy) -> int:
    """Bind to KMDF, create the driver, and return the driver globals."""
    ps = _ptr_size(se)
    bind_info = wdf.WDF_BIND_INFO(ps)
    bind_info.FuncTable = alloc(se, b"\x00" * ps)
    globals_ptr = alloc(se, b"\x00" * ps)
    rv, _ = call(se, "wdfldr", "WdfVersionBind", [0, 0, alloc(se, bind_info.get_bytes()), globals_ptr])
    assert rv == ddk.STATUS_SUCCESS
    driver_globals = _read_ptr(se, globals_ptr)
    driver_object = alloc(se, b"\x00" * 0x200)
    rv, _ = call(
        se, "wdfldr", "WdfDriverCreate", [driver_globals, driver_object, _unicode_string(se, USBSAMP), 0, 0, 0]
    )
    assert rv == ddk.STATUS_SUCCESS
    return driver_globals


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


def test_wdf_parameters_key_is_null_when_missing(any_driver_emu: Speakeasy) -> None:
    driver_globals = _wdf_driver(any_driver_emu)
    key = alloc(any_driver_emu, b"\xcc" * 8)
    rv, _ = call(any_driver_emu, "wdfldr", "WdfDriverOpenParametersRegistryKey", [driver_globals, 0, 0x20019, 0, key])
    assert rv == ddk.STATUS_OBJECT_NAME_NOT_FOUND
    assert _read_ptr(any_driver_emu, key) == 0


def test_wdf_parameters_key_opens(config: dict[str, Any], load_test_bin: Any) -> None:
    config["registry"]["keys"].append(
        {"path": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\usbsamp\\Parameters"}
    )
    for se in load_emu(config, load_test_bin("wdm_test_x86.sys.xz")):
        driver_globals = _wdf_driver(se)
        key = alloc(se, b"\x00" * 4)
        rv, _ = call(se, "wdfldr", "WdfDriverOpenParametersRegistryKey", [driver_globals, 0, 0x20019, 0, key])
        assert rv == ddk.STATUS_SUCCESS
        assert _read_ptr(se, key) != 0


@pytest.mark.parametrize(
    "name, rv, value",
    [
        ("Start", ddk.STATUS_SUCCESS, struct.pack("<I", 3)),
        ("DisplayName", ddk.STATUS_OBJECT_TYPE_MISMATCH, b"\xcc" * 4),
        ("Missing", ddk.STATUS_OBJECT_NAME_NOT_FOUND, b"\xcc" * 4),
    ],
)
def test_wdf_registry_query_ulong(any_driver_emu: Speakeasy, name: str, rv: int, value: bytes) -> None:
    assert any_driver_emu.emu is not None
    key = any_driver_emu.emu.reg_open_key(USBSAMP)
    out = alloc(any_driver_emu, b"\xcc" * 4)
    args = [0, key, _unicode_string(any_driver_emu, name), out]
    assert call(any_driver_emu, "wdfldr", "WdfRegistryQueryULong", args)[0] == rv
    assert any_driver_emu.mem_read(out, 4) == value
