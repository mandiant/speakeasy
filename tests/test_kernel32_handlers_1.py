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
