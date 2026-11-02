"""Handlers read and write integers in guest memory through ApiHandler."""

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, invalid_handle, start_process

PAGE_READWRITE = 0x04
FILE_MAP_ALL_ACCESS = 0xF001F


def test_write_dword_writes_a_negative_value_as_its_low_32_bits(dll_emu: Speakeasy) -> None:
    handler, _ = dll_emu.emu.get_api_handler("kernel32", "GetLastError")
    addr = alloc(dll_emu, b"\xaa" * 8)
    handler.write_dword(addr, -2)
    assert dll_emu.mem_read(addr, 8) == b"\xfe\xff\xff\xff\xaa\xaa\xaa\xaa"
    assert handler.read_dword(addr) == 0xFFFFFFFE


def test_write_ptr_writes_each_view_of_a_shared_mapping(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    hmap, _ = call(
        dll_emu, "kernel32", "CreateFileMappingA", [invalid_handle(dll_emu), 0, PAGE_READWRITE, 0, 0x1000, 0]
    )
    first, _ = call(dll_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 0])
    second, _ = call(dll_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 0])
    assert first != second
    handler, _ = dll_emu.emu.get_api_handler("kernel32", "MapViewOfFile")
    handler.write_ptr(first + 8, 0x11223344)
    assert dll_emu.mem_read(second + 8, 4) == b"\x44\x33\x22\x11"
    assert handler.read_ptr(second + 8) == 0x11223344
