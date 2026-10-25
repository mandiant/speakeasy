"""
winmm handlers return what Windows returns.
"""

from speakeasy import Speakeasy
from tests.handler_harness import call

DRV_LOAD = 1
DRV_INSTALL = 9


def test_def_driver_proc_accepts_load_and_ignores_other_messages(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "api-ms-win-mm-misc-l1-1-0", "DefDriverProc", [0, 0, DRV_LOAD, 0, 0])
    assert rv == 1
    rv, _ = call(dll_emu, "winmm", "DefDriverProc", [0, 0, DRV_INSTALL, 0, 0])
    assert rv == 1
    rv, _ = call(dll_emu, "winmm", "DefDriverProc", [0, 0, 0x2000, 0, 0])
    assert rv == 0
