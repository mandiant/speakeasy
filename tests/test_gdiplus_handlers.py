"""GDI+ starts, allocates memory, and reports that it cannot decode images."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.gdiplus import GENERIC_ERROR, INVALID_PARAMETER, OK
from tests.handler_harness import alloc, call


def test_gdiplus_startup_returns_a_token(dll_emu: Speakeasy) -> None:
    token = alloc(dll_emu, b"\x00" * 4)
    startup_input = alloc(dll_emu, struct.pack("<IIII", 1, 0, 0, 0))
    assert call(dll_emu, "gdiplus", "GdiplusStartup", [token, startup_input, 0])[0] == OK
    assert dll_emu.mem_read(token, 4) != b"\x00" * 4
    assert call(dll_emu, "gdiplus", "GdiplusStartup", [token, 0, 0])[0] == INVALID_PARAMETER


def test_gdip_alloc_returns_writable_memory(dll_emu: Speakeasy) -> None:
    p = call(dll_emu, "gdiplus", "GdipAlloc", [0x20])[0]
    dll_emu.mem_write(p, b"\x41" * 0x20)
    call(dll_emu, "gdiplus", "GdipFree", [p])


@pytest.mark.parametrize(
    "name",
    [
        "GdipCreateBitmapFromStream",
        "GdipCreateBitmapFromFile",
        "GdipLoadImageFromStream",
        "GdipLoadImageFromFile",
        "GdipCreateBitmapFromStreamICM",
        "GdipCreateBitmapFromFileICM",
        "GdipLoadImageFromStreamICM",
        "GdipLoadImageFromFileICM",
    ],
)
def test_gdip_image_decoding_fails_without_an_image(dll_emu: Speakeasy, name: str) -> None:
    image = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "gdiplus", name, [0x1234, image])[0] == GENERIC_ERROR
    assert dll_emu.mem_read(image, 4) == b"\x00" * 4


def test_gdip_dispose_image_rejects_null(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "gdiplus", "GdipDisposeImage", [0])[0] == INVALID_PARAMETER
