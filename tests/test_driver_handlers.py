"""
Kernel driver framework handlers (NDIS, WFP, WSK, KMDF) return what callers read.
"""

from speakeasy import Speakeasy
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
