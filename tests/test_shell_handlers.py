"""
Shell, COM, and ntdll handlers return what Windows returns and write what
Windows writes.
"""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ddk
from tests.handler_harness import alloc, call


def wstr(text: str, width: int) -> bytes:
    return (text + "\x00").encode("utf-16le" if width == 2 else "utf-8")


def read_wstr(se: Speakeasy, addr: int) -> str:
    data = b""
    while not data.endswith(b"\x00\x00") or len(data) % 2:
        data += se.mem_read(addr + len(data), 1)
    return data[:-2].decode("utf-16le")


def test_sys_free_string_accepts_null(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysFreeString", [0])
    assert rv is None


def test_ldr_access_resource_writes_address_and_ulong_size(dll64_emu: Speakeasy) -> None:
    base = 0x180000000
    entry = alloc(dll64_emu, struct.pack("<IIII", 0x1234, 0x56, 0, 0))
    resource = alloc(dll64_emu, b"\xcc" * 8)
    size = alloc(dll64_emu, b"\xcc" * 8)
    rv, _ = call(dll64_emu, "ntdll", "LdrAccessResource", [base, entry, resource, size])
    assert rv == ddk.STATUS_SUCCESS
    assert dll64_emu.mem_read(resource, 8) == struct.pack("<Q", base + 0x1234)
    assert dll64_emu.mem_read(size, 8) == struct.pack("<I", 0x56) + b"\xcc" * 4


@pytest.mark.parametrize("api", ["StrStrA", "StrStrW", "StrStrIA", "StrStrIW"])
def test_str_str_returns_the_match_address(dll_emu: Speakeasy, api: str) -> None:
    width = 2 if api.endswith("W") else 1
    hay = alloc(dll_emu, wstr("abCDef", width))
    needle = alloc(dll_emu, wstr("CD", width))
    rv, _ = call(dll_emu, "shlwapi", api, [hay, needle])
    assert rv == hay + 2 * width


@pytest.mark.parametrize("api", ["StrStrA", "StrStrW", "StrStrIA", "StrStrIW"])
def test_str_str_returns_null_for_null_args(dll_emu: Speakeasy, api: str) -> None:
    s = alloc(dll_emu, b"a\x00\x00\x00")
    assert call(dll_emu, "shlwapi", api, [0, s])[0] == 0
    assert call(dll_emu, "shlwapi", api, [s, 0])[0] == 0


@pytest.mark.parametrize(
    "api, path, index",
    [
        ("PathFindExtension", "C:\\dir\\file.txt", 11),
        ("PathFindExtension", "C:\\dir.d\\file", 13),
        ("PathFindFileName", "C:\\dir\\file.txt", 7),
        ("PathFindFileName", "file.txt", 0),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_find_returns_byte_address(dll_emu: Speakeasy, api: str, path: str, index: int, width: int) -> None:
    p = alloc(dll_emu, wstr(path, width))
    rv, _ = call(dll_emu, "shlwapi", api + ("W" if width == 2 else "A"), [p])
    assert rv == p + index * width


@pytest.mark.parametrize(
    "cmdline, expected",
    [
        ('C:\\dir\\a.exe "x y" a\\\\\\"b', ["C:\\dir\\a.exe", "x y", 'a\\"b']),
        ('"C:\\Program Files\\a.exe" b\\\\"c d" e\\f', ["C:\\Program Files\\a.exe", "b\\c d", "e\\f"]),
        ('C:\\a\\"b c\\\\', ['C:\\a\\"b', "c\\\\"]),
        ('a.exe "" \t x', ["a.exe", "", "x"]),
        ('a.exe "b c', ["a.exe", "b c"]),
    ],
)
def test_command_line_to_argv_uses_windows_rules(dll_emu: Speakeasy, cmdline: str, expected: list[str]) -> None:
    cl = alloc(dll_emu, wstr(cmdline, 2))
    nargs = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "CommandLineToArgvW", [cl, nargs])
    assert struct.unpack("<I", dll_emu.mem_read(nargs, 4))[0] == len(expected)
    ptrs = struct.unpack(f"<{len(expected)}I", dll_emu.mem_read(rv, 4 * len(expected)))
    assert [read_wstr(dll_emu, p) for p in ptrs] == expected
