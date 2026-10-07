"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process

PAGE_READWRITE = 0x04
FILE_MAP_READ = 0x04
FILE_MAP_ALL_ACCESS = 0xF001F
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3


@pytest.fixture
def file_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes], tmp_path: Path) -> Iterator[Speakeasy]:
    host = tmp_path / "data.bin"
    host.write_bytes(b"".join(struct.pack("<I", i) for i in range(0x8000)))
    config["filesystem"]["files"].insert(0, {"mode": "full_path", "emu_path": "c:\\data.bin", "path": str(host)})
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


def test_map_view_of_unknown_mapping_fails(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    rv, _ = call(dll_emu, "kernel32", "MapViewOfFile", [0x9999, FILE_MAP_READ, 0, 0, 0])
    assert rv == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


def test_map_view_of_pagefile_section_maps_the_whole_section(dll_emu: Speakeasy) -> None:
    hmap, _ = call(
        dll_emu, "kernel32", "CreateFileMappingA", [windefs.INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x10000, 0]
    )
    view, _ = call(dll_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 0])
    assert view
    dll_emu.mem_write(view + 0xF000, b"end")
    assert dll_emu.mem_read(view + 0xF000, 3) == b"end"


def test_map_view_of_file_starts_at_the_offset(file_emu: Speakeasy) -> None:
    name = alloc(file_emu, b"c:\\data.bin\x00")
    hfile, _ = call(file_emu, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0])
    hmap, _ = call(file_emu, "kernel32", "CreateFileMappingA", [hfile, 0, 0x02, 0, 0, 0])
    view, _ = call(file_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_READ, 0, 0x10000, 0])
    assert file_emu.mem_read(view, 4) == struct.pack("<I", 0x4000)


@pytest.mark.parametrize(
    "alloc_api, alloc_argv, realloc_api, realloc_argv",
    [
        ("HeapAlloc", lambda h: [h, 0, 0x3000], "HeapReAlloc", lambda h, p: [h, 0, p, 0x10]),
        ("LocalAlloc", lambda h: [0, 0x3000], "LocalReAlloc", lambda h, p: [p, 0x10, 0]),
    ],
)
def test_shrinking_realloc_copies_only_the_new_size(
    dll_emu: Speakeasy,
    alloc_api: str,
    alloc_argv: Callable[[int], list[int]],
    realloc_api: str,
    realloc_argv: Callable[[int, int], list[int]],
) -> None:
    heap, _ = call(dll_emu, "kernel32", "GetProcessHeap", [])
    old, _ = call(dll_emu, "kernel32", alloc_api, alloc_argv(heap))
    dll_emu.mem_write(old, bytes(range(256)) * 0x30)
    neighbor, _ = call(dll_emu, "kernel32", alloc_api, alloc_argv(heap))
    dll_emu.mem_write(neighbor, b"\xee" * 0x3000)
    new, _ = call(dll_emu, "kernel32", realloc_api, realloc_argv(heap, old))
    assert new
    assert dll_emu.mem_read(new, 0x10) == bytes(range(0x10))
    assert dll_emu.mem_read(neighbor, 0x3000) == b"\xee" * 0x3000


@pytest.mark.parametrize(
    "api, path, cw",
    [
        ("GetSystemDirectoryA", "C:\\Windows\\system32", 1),
        ("GetSystemDirectoryW", "C:\\Windows\\system32", 2),
        ("GetWindowsDirectoryA", "C:\\Windows", 1),
        ("GetWindowsDirectoryW", "C:\\Windows", 2),
    ],
)
def test_system_directory_returns_length_without_nul(dll_emu: Speakeasy, api: str, path: str, cw: int) -> None:
    encoding = "utf-16le" if cw == 2 else "latin-1"
    rv, _ = call(dll_emu, "kernel32", api, [0, 0])
    assert rv == len(path) + 1
    buf = alloc(dll_emu, b"\xcc" * 520)
    rv, _ = call(dll_emu, "kernel32", api, [buf, 260])
    assert rv == len(path)
    assert dll_emu.mem_read(buf, (len(path) + 1) * cw) == (path + "\0").encode(encoding)


CP_UTF8 = 65001


@pytest.mark.parametrize("text", ["abc", "café"])
def test_wide_char_to_multi_byte_returns_bytes_written(dll_emu: Speakeasy, text: str) -> None:
    start_process(dll_emu)
    expected = (text + "\0").encode("utf-8")
    src = alloc(dll_emu, (text + "\0").encode("utf-16le"))
    need, _ = call(dll_emu, "kernel32", "WideCharToMultiByte", [CP_UTF8, 0, src, 0xFFFFFFFF, 0, 0, 0, 0])
    assert need == len(expected)
    dst = alloc(dll_emu, b"\xcc" * 260)
    rv, _ = call(dll_emu, "kernel32", "WideCharToMultiByte", [CP_UTF8, 0, src, 0xFFFFFFFF, dst, 260, 0, 0])
    assert rv == len(expected)
    assert dll_emu.mem_read(dst, len(expected) + 1) == expected + b"\xcc"


def test_wide_char_to_multi_byte_checks_the_buffer_size(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    src = alloc(dll_emu, "abc\0".encode("utf-16le"))
    dst = alloc(dll_emu, b"\xcc" * 8)
    rv, _ = call(dll_emu, "kernel32", "WideCharToMultiByte", [CP_UTF8, 0, src, 0xFFFFFFFF, dst, 2, 0, 0])
    assert rv == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INSUFFICIENT_BUFFER
    assert dll_emu.mem_read(dst, 8) == b"\xcc" * 8


@pytest.mark.parametrize("count, text", [(5, "hello"), (5, "café")])
def test_multi_byte_to_wide_char_counts_only_the_given_bytes(dll_emu: Speakeasy, count: int, text: str) -> None:
    start_process(dll_emu)
    src = alloc(dll_emu, (text + " world\0").encode("utf-8"))
    need, _ = call(dll_emu, "kernel32", "MultiByteToWideChar", [CP_UTF8, 0, src, count, 0, 0])
    assert need == len(text)
    dst = alloc(dll_emu, b"\xcc" * 64)
    rv, _ = call(dll_emu, "kernel32", "MultiByteToWideChar", [CP_UTF8, 0, src, count, dst, need])
    assert rv == len(text)
    assert dll_emu.mem_read(dst, 2 * len(text) + 2) == text.encode("utf-16le") + b"\xcc\xcc"


def test_multi_byte_to_wide_char_checks_the_buffer_size(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    src = alloc(dll_emu, b"hello\0")
    dst = alloc(dll_emu, b"\xcc" * 16)
    rv, _ = call(dll_emu, "kernel32", "MultiByteToWideChar", [CP_UTF8, 0, src, 5, dst, 2])
    assert rv == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INSUFFICIENT_BUFFER
    assert dll_emu.mem_read(dst, 16) == b"\xcc" * 16


def encode(text: str, cw: int) -> bytes:
    return text.encode("utf-16le" if cw == 2 else "latin-1")


@pytest.mark.parametrize("api, cw", [("ExpandEnvironmentStringsA", 1), ("ExpandEnvironmentStringsW", 2)])
@pytest.mark.parametrize(
    "src, expanded",
    [
        ("%windir%\\x.exe", "C:\\Windows\\x.exe"),
        ("%WINDIR%\\%ComSpec%", "C:\\Windows\\C:\\Windows\\system32\\cmd.exe"),
        ("no vars", "no vars"),
    ],
)
def test_expand_environment_strings_returns_size_with_nul(
    dll_emu: Speakeasy, api: str, cw: int, src: str, expanded: str
) -> None:
    lp_src = alloc(dll_emu, encode(src + "\0", cw))
    need, _ = call(dll_emu, "kernel32", api, [lp_src, 0, 0])
    assert need == len(expanded) + 1
    dst = alloc(dll_emu, b"\xcc" * 0x100)
    rv, _ = call(dll_emu, "kernel32", api, [lp_src, dst, 4])
    assert rv == need
    assert dll_emu.mem_read(dst, 0x100) == b"\xcc" * 0x100
    rv, displays = call(dll_emu, "kernel32", api, [lp_src, dst, need])
    assert rv == need
    assert displays["lpDst"] == expanded
    assert dll_emu.mem_read(dst, need * cw + 1) == encode(expanded + "\0", cw) + b"\xcc"
