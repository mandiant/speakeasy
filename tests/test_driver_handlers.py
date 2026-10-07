"""
Kernel driver framework handlers (NDIS, WFP, WSK, KMDF) return what callers read.
"""

from speakeasy import Speakeasy
from tests.handler_harness import call


def test_wsk_receive_from_accepts_all_parameters(driver_emu: Speakeasy) -> None:
    rv, _ = call(driver_emu, "netio", "callback_WskReceiveFrom", [1, 2, 3, 4, 5, 6, 7, 8])
    assert rv == 0
