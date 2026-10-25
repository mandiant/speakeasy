"""
Gdi32 handlers return values that drawing code can use.
"""

import struct

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


DXGI_ERROR_UNSUPPORTED = 0x887A0004


@pytest.mark.parametrize(
    ("dll", "name", "argv", "out_slots"),
    [
        ("dxgi", "CreateDXGIFactory", ["iid", "out"], [0]),
        ("dxgi", "CreateDXGIFactory1", ["iid", "out"], [0]),
        ("dxgi", "CreateDXGIFactory2", [0, "iid", "out"], [0]),
        ("d3d11", "D3D11CreateDevice", [0, 1, 0, 0, 0, 0, 7, "out", "out+8", "out+16"], [0, 1, 2]),
        (
            "d3d11",
            "D3D11CreateDeviceAndSwapChain",
            [0, 1, 0, 0, 0, 0, 7, 0, "out", "out+8", "out+16", "out+24"],
            [0, 1, 2, 3],
        ),
    ],
)
def test_dxgi_object_creation_reports_unsupported_and_clears_outputs(
    dll_emu: Speakeasy, dll: str, name: str, argv: list, out_slots: list[int]
) -> None:
    iid = alloc(dll_emu, b"\x11" * 16)
    out = alloc(dll_emu, struct.pack("<8I", *([0x1234] * 8)))
    values = {"iid": iid, "out": out, "out+8": out + 8, "out+16": out + 16, "out+24": out + 24}

    rv, _ = call(dll_emu, dll, name, [values.get(a, a) if isinstance(a, str) else a for a in argv])

    assert rv == DXGI_ERROR_UNSUPPORTED
    for slot in out_slots:
        assert struct.unpack("<I", dll_emu.mem_read(out + 8 * slot, 4))[0] == 0


def test_draw_dib_open_gives_a_handle_that_draw_and_close_accept(dll_emu: Speakeasy) -> None:
    first = call(dll_emu, "msvfw32", "DrawDibOpen", [])[0]
    second = call(dll_emu, "msvfw32", "DrawDibOpen", [])[0]
    bmi = alloc(dll_emu, struct.pack("<IiiHHI", 40, 4, 4, 1, 32, 0) + b"\x00" * 20)
    bits = alloc(dll_emu, b"\x00" * 64)

    assert first and second and first != second
    assert call(dll_emu, "msvfw32", "DrawDibDraw", [first, 0x1234, 0, 0, 4, 4, bmi, bits, 0, 0, 4, 4, 0])[0] == 1
    assert call(dll_emu, "msvfw32", "DrawDibClose", [first])[0] == 1
