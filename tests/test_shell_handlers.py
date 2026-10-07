"""
Shell, COM, and ntdll handlers return what Windows returns and write what
Windows writes.
"""

from speakeasy import Speakeasy
from tests.handler_harness import call


def test_sys_free_string_accepts_null(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysFreeString", [0])
    assert rv is None
