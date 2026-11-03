"""Gdi32 handlers return values that drawing code can use."""

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


def test_get_object_fails_for_a_handle_that_gdi32_did_not_give(dll_emu: Speakeasy) -> None:
    pv = 0x5FFF0010
    assert not dll_emu.emu.is_address_valid(pv)
    assert call(dll_emu, "gdi32", "GetObjectA", [0x1234, 24, pv])[0] == 0
    assert not dll_emu.emu.is_address_valid(pv)


def test_get_object_fills_the_buffer_for_a_stock_object(dll_emu: Speakeasy) -> None:
    system_font = call(dll_emu, "gdi32", "GetStockObject", [13])[0]
    buf = alloc(dll_emu, b"\xcc" * 24)
    assert call(dll_emu, "gdi32", "GetObjectA", [system_font, 24, buf])[0] == 24
    assert dll_emu.mem_read(buf, 24) == b"\x00" * 24
