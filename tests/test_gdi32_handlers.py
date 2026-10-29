"""
Gdi32 handlers return values that drawing code can use.
"""

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, start_process


def test_select_object_returns_the_previous_object(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    dc = call(dll_emu, "gdi32", "CreateCompatibleDC", [0])[0]
    logfont = alloc(dll_emu, b"\x00" * 0x3C)
    first = call(dll_emu, "gdi32", "CreateFontIndirectA", [logfont])[0]
    second = call(dll_emu, "gdi32", "CreateFontIndirectA", [logfont])[0]

    default = call(dll_emu, "gdi32", "SelectObject", [dc, first])[0]
    previous = call(dll_emu, "gdi32", "SelectObject", [dc, second])[0]
    restored = call(dll_emu, "gdi32", "SelectObject", [dc, default])[0]

    assert default
    assert previous == first
    assert restored == second
    assert call(dll_emu, "gdi32", "SelectObject", [dc, 0])[0] == 0
