"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.windows import objman
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


@pytest.mark.parametrize(
    "api, cw",
    [("GetEnvironmentStrings", 1), ("GetEnvironmentStringsA", 1), ("GetEnvironmentStringsW", 2)],
)
def test_environment_strings_is_a_double_nul_terminated_block(dll_emu: Speakeasy, api: str, cw: int) -> None:
    assert dll_emu.emu is not None
    env = dll_emu.emu.get_env()
    block = encode("".join(f"{k}={v}\0" for k, v in env.items()) + "\0", cw)
    ptr, _ = call(dll_emu, "kernel32", api, [])
    assert dll_emu.mem_read(ptr, len(block)) == block


@pytest.mark.parametrize("cw", [1, 2])
def test_lstrcat_ends_with_a_full_nul(dll_emu: Speakeasy, cw: int) -> None:
    api = "lstrcatW" if cw == 2 else "lstrcatA"
    dst = alloc(dll_emu, encode("A\0", cw) + b"\xcc" * 16)
    src = alloc(dll_emu, encode("BC\0", cw))
    rv, _ = call(dll_emu, "kernel32", api, [dst, src])
    assert rv == dst
    assert dll_emu.mem_read(dst, 4 * cw + 1) == encode("ABC\0", cw) + b"\xcc"


def test_terminate_process_returns_true(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    app = alloc(dll_emu, b"c:\\Windows\\system32\\cmd.exe\x00")
    si = alloc(dll_emu, b"\x00" * 0x44)
    pi = alloc(dll_emu, b"\x00" * 0x10)
    ok, _ = call(dll_emu, "kernel32", "CreateProcessA", [app, 0, 0, 0, 0, 0, 0, 0, si, pi])
    assert ok
    hproc = struct.unpack("<I", dll_emu.mem_read(pi, 4))[0]
    rv, _ = call(dll_emu, "kernel32", "TerminateProcess", [hproc, 0])
    assert rv is True


TH32CS_SNAPALL = 0xF


@pytest.mark.parametrize(
    "flags, walks",
    [
        (TH32CS_SNAPALL, ["Process32First", "Thread32First", "Module32First"]),
        (0x8 | 0x10, ["Module32First"]),
        (0x80000000 | 0x2, ["Process32First"]),
    ],
)
def test_toolhelp_snapshot_holds_every_requested_list(dll_emu: Speakeasy, flags: int, walks: list[str]) -> None:
    start_process(dll_emu)
    hsnap, _ = call(dll_emu, "kernel32", "CreateToolhelp32Snapshot", [flags, 0])
    for walk in walks:
        entry = alloc(dll_emu, b"\x00" * 0x400)
        rv, _ = call(dll_emu, "kernel32", walk, [hsnap, entry])
        assert rv, walk


def switch_to_new_thread(se: Speakeasy) -> None:
    emu = se.emu
    assert emu is not None and emu.curr_process is not None
    t = objman.Thread(emu, stack_base=emu.stack_base, stack_commit=0x1000)
    emu.om.objects.update({t.address: t})  # type: ignore[union-attr]
    emu.curr_process.threads.append(t)
    emu.curr_thread = t


def test_tls_index_is_valid_in_every_thread(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    first, _ = call(dll_emu, "kernel32", "TlsAlloc", [])
    switch_to_new_thread(dll_emu)
    second, _ = call(dll_emu, "kernel32", "TlsAlloc", [])
    assert second != first
    rv, _ = call(dll_emu, "kernel32", "TlsSetValue", [first, 0x1234])
    assert rv == 1
    value, _ = call(dll_emu, "kernel32", "TlsGetValue", [first])
    assert value == 0x1234
    switch_to_new_thread(dll_emu)
    value, _ = call(dll_emu, "kernel32", "TlsGetValue", [second])
    assert value == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_SUCCESS


def lcmap_argv(api: str, src: int, cch_src: int, dst: int, cch_dst: int) -> list[int]:
    if api == "LCMapStringEx":
        return [0, 0, src, cch_src, dst, cch_dst, 0, 0, 0]
    return [0x409, 0, src, cch_src, dst, cch_dst]


@pytest.mark.parametrize("api, cw", [("LCMapStringA", 1), ("LCMapStringW", 2), ("LCMapStringEx", 2)])
def test_lcmap_string_reads_a_nul_terminated_source(dll_emu: Speakeasy, api: str, cw: int) -> None:
    start_process(dll_emu)
    src = alloc(dll_emu, encode("hello\0", cw))
    need, _ = call(dll_emu, "kernel32", api, lcmap_argv(api, src, 0xFFFFFFFF, 0, 0))
    assert need == 6
    dst = alloc(dll_emu, b"\xcc" * 32)
    rv, _ = call(dll_emu, "kernel32", api, lcmap_argv(api, src, 0xFFFFFFFF, dst, 2))
    assert rv == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INSUFFICIENT_BUFFER
    assert dll_emu.mem_read(dst, 32) == b"\xcc" * 32
    rv, _ = call(dll_emu, "kernel32", api, lcmap_argv(api, src, 0xFFFFFFFF, dst, 16))
    assert rv == 6
    assert dll_emu.mem_read(dst, 6 * cw + 1) == encode("hello\0", cw) + b"\xcc"


@pytest.mark.parametrize("api, cw", [("GetStringTypeA", 1), ("GetStringTypeW", 2)])
def test_get_string_type_reads_a_nul_terminated_source(dll_emu: Speakeasy, api: str, cw: int) -> None:
    src = alloc(dll_emu, encode("a1\0", cw))
    out = alloc(dll_emu, b"\xcc" * 16)
    argv = [1, src, 0xFFFFFFFF, out]
    if api == "GetStringTypeA":
        argv = [0x409, *argv]
    rv, _ = call(dll_emu, "kernel32", api, argv)
    assert rv == 1
    assert dll_emu.mem_read(out, 8) == struct.pack("<HHH", 0x382, 0x284, 0x20) + b"\xcc\xcc"
