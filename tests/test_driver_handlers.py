"""
Kernel driver framework handlers (NDIS, WFP, WSK, KMDF) return what callers read.
"""

from speakeasy import Speakeasy
from speakeasy.winenv.api.kernelmode.netio import Netio
from tests.handler_harness import call


def test_wsk_receive_from_accepts_all_parameters(driver_emu: Speakeasy) -> None:
    rv, _ = call(driver_emu, "netio", "callback_WskReceiveFrom", [1, 2, 3, 4, 5, 6, 7, 8])
    assert rv == 0


def test_wsk_get_local_address_pops_three_slots(driver_emu: Speakeasy) -> None:
    assert Netio.WskGetLocalAddress.__apihook__[2] == 3
    rv, _ = call(driver_emu, "netio", "callback_WskGetLocalAddress", [1, 2, 3])
    assert rv == 0
