"""
Gdi32 handlers return values that drawing code can use.
"""

import pytest

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


def test_get_stock_object_gives_one_handle_per_index(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    white = call(dll_emu, "gdi32", "GetStockObject", [0])[0]
    black = call(dll_emu, "gdi32", "GetStockObject", [4])[0]

    assert white and black and white != black
    assert call(dll_emu, "gdi32", "GetStockObject", [0])[0] == white
    assert call(dll_emu, "gdi32", "GetStockObject", [100])[0] == 0


@pytest.mark.parametrize(
    "index, expected",
    [(8, 1920), (10, 1080), (12, 32), (14, 1), (88, 96), (90, 96), (24, -1 & 0xFFFFFFFF), (999, 0)],
)
def test_get_device_caps_describes_a_desktop_display(dll_emu: Speakeasy, index: int, expected: int) -> None:
    start_process(dll_emu)
    dc = call(dll_emu, "user32", "GetDC", [0])[0]

    assert call(dll_emu, "gdi32", "GetDeviceCaps", [dc, index])[0] == expected
