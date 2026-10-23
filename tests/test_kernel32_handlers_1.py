"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import speakeasy.common as common
from speakeasy import Speakeasy
from speakeasy.windows import objman
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process

PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
FILE_MAP_READ = 0x04
FILE_MAP_ALL_ACCESS = 0xF001F
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
SEC_IMAGE = 0x1000000


@pytest.fixture
def file_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes], tmp_path: Path) -> Iterator[Speakeasy]:
    host = tmp_path / "data.bin"
    host.write_bytes(b"".join(struct.pack("<I", i) for i in range(0x8000)))
    config["filesystem"]["files"].insert(0, {"mode": "full_path", "emu_path": "c:\\data.bin", "path": str(host)})
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


@pytest.fixture
def pe_file_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes], tmp_path: Path) -> Iterator[Speakeasy]:
    host = tmp_path / "image.dll"
    host.write_bytes(load_test_bin("dll_test_x64.dll.xz"))
    config["filesystem"]["files"].insert(0, {"mode": "full_path", "emu_path": "c:\\image.dll", "path": str(host)})
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


@pytest.mark.parametrize(("base", "mapped"), [(0, True), (0x30000000, True), (0x30001000, False)])
def test_map_view_of_file_ex_maps_at_the_requested_base(dll_emu: Speakeasy, base: int, mapped: bool) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    hmap, _ = call(
        dll_emu, "kernel32", "CreateFileMappingA", [windefs.INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0]
    )
    view, _ = call(dll_emu, "kernel32", "MapViewOfFileEx", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 4, base])
    if not mapped:
        assert view == 0
        assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_ADDRESS
        return
    assert view == (base or view) != 0
    dll_emu.mem_write(view, b"data")
    again, _ = call(dll_emu, "kernel32", "MapViewOfFileEx", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 4, view])
    assert again == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_ADDRESS


def test_unmap_view_of_section_frees_a_view_of_the_current_process(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    hmap, _ = call(
        dll_emu, "kernel32", "CreateFileMappingA", [windefs.INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0]
    )
    view, _ = call(dll_emu, "kernel32", "MapViewOfFileEx", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 4, 0x30000000])
    rv, _ = call(dll_emu, "ntdll", "NtUnmapViewOfSection", [0xFFFFFFFF, view + 4])
    assert rv == ddk.STATUS_SUCCESS
    rv, _ = call(dll_emu, "ntdll", "NtUnmapViewOfSection", [0xFFFFFFFF, view])
    assert rv == ddk.STATUS_NOT_MAPPED_VIEW
    again, _ = call(dll_emu, "kernel32", "MapViewOfFileEx", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 4, view])
    assert again == view


def test_unmap_view_of_section_frees_the_main_image(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    base = dll_emu.emu.get_current_process().base
    rv, _ = call(dll_emu, "ntdll", "ZwUnmapViewOfSection", [0xFFFFFFFF, base])
    assert rv == ddk.STATUS_SUCCESS
    rv, _ = call(dll_emu, "kernel32", "VirtualAlloc", [base, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE])
    assert rv == base


def test_virtual_alloc_at_an_address_in_use_fails(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    base = dll_emu.emu.get_current_process().base
    rv, _ = call(dll_emu, "kernel32", "VirtualAlloc", [base, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE])
    assert rv == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_ADDRESS


def test_virtual_alloc_at_a_free_address_uses_that_address(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "kernel32", "VirtualAlloc", [0x30000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE])
    assert rv == 0x30000000


def test_map_view_of_file_starts_at_the_offset(file_emu: Speakeasy) -> None:
    name = alloc(file_emu, b"c:\\data.bin\x00")
    hfile, _ = call(file_emu, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0])
    hmap, _ = call(file_emu, "kernel32", "CreateFileMappingA", [hfile, 0, 0x02, 0, 0, 0])
    view, _ = call(file_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_READ, 0, 0x10000, 0])
    assert file_emu.mem_read(view, 4) == struct.pack("<I", 0x4000)


def test_map_view_of_file_ignores_the_file_pointer(file_emu: Speakeasy) -> None:
    name = alloc(file_emu, b"c:\\data.bin\x00")
    hfile, _ = call(file_emu, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0])
    buf = alloc(file_emu, b"\xcc" * 4)
    read = alloc(file_emu, b"\xcc" * 4)
    assert call(file_emu, "kernel32", "ReadFile", [hfile, buf, 4, read, 0])[0]
    hmap, _ = call(file_emu, "kernel32", "CreateFileMappingA", [hfile, 0, 0x02, 0, 0, 0])
    for _ in range(2):
        view, _ = call(file_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_READ, 0, 0, 0])
        assert file_emu.mem_read(view, 8) == struct.pack("<II", 0, 1)
    assert call(file_emu, "kernel32", "ReadFile", [hfile, buf, 4, read, 0])[0]
    assert file_emu.mem_read(buf, 4) == struct.pack("<I", 1)


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


@pytest.mark.parametrize("cmdline", [b'"" "C:\\Windows\\system32\\sample" myarg1', b"   "])
def test_create_process_without_program_name_fails(dll_emu: Speakeasy, cmdline: bytes) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    cmd = alloc(dll_emu, cmdline + b"\x00")
    si = alloc(dll_emu, b"\x00" * 0x44)
    pi = alloc(dll_emu, b"\xcc" * 0x10)
    ok, _ = call(dll_emu, "kernel32", "CreateProcessA", [0, cmd, 0, 0, 0, 0, 0, 0, si, pi])
    assert ok == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_FILE_NOT_FOUND
    assert dll_emu.mem_read(pi, 0x10) == b"\xcc" * 0x10
    assert dll_emu.emu.child_processes == []


def test_win_exec_without_program_name_fails(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    cmd = alloc(dll_emu, b'"" arg\x00')
    rv, _ = call(dll_emu, "kernel32", "WinExec", [cmd, 0])
    assert rv == windefs.ERROR_FILE_NOT_FOUND


def create_suspended_child(se: Speakeasy) -> tuple[int, int]:
    start_process(se)
    app = alloc(se, b"c:\\Windows\\system32\\cmd.exe\x00")
    si = alloc(se, b"\x00" * 0x44)
    pi = alloc(se, b"\x00" * 0x10)
    ok, _ = call(se, "kernel32", "CreateProcessA", [app, 0, 0, 0, 0, windefs.CREATE_SUSPENDED, 0, 0, si, pi])
    assert ok
    hproc, hthread = struct.unpack("<II", se.mem_read(pi, 8))
    return hproc, hthread


def test_resume_thread_leaves_an_unmodified_child_for_child_emulation(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    _, hthread = create_suspended_child(dll_emu)
    queued = len(dll_emu.emu.run_queue)
    rv, _ = call(dll_emu, "kernel32", "ResumeThread", [hthread])
    assert rv == 1
    assert len(dll_emu.emu.run_queue) == queued
    assert len(dll_emu.emu.child_processes) == 1


def test_resume_thread_starts_a_child_after_write_process_memory(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    hproc, hthread = create_suspended_child(dll_emu)
    child = dll_emu.emu.child_processes[0]
    data = alloc(dll_emu, b"\x90" * 4)
    ok, _ = call(dll_emu, "kernel32", "WriteProcessMemory", [hproc, data + 0x100, data, 4, 0])
    assert ok
    queued = len(dll_emu.emu.run_queue)
    call(dll_emu, "kernel32", "ResumeThread", [hthread])
    assert len(dll_emu.emu.run_queue) == queued + 1
    assert dll_emu.emu.run_queue[-1].process_context is child
    assert dll_emu.emu.child_processes == []


def write_with_nt_write_virtual_memory(se: Speakeasy, hproc: int, hthread: int) -> None:
    data = alloc(se, b"\x90" * 4)
    rv, _ = call(se, "ntdll", "NtWriteVirtualMemory", [hproc, data + 0x100, data, 4, 0])
    assert rv == 0


def set_context_with(dll: str, api: str) -> Callable[[Speakeasy, int, int], None]:
    def change(se: Speakeasy, hproc: int, hthread: int) -> None:
        context = alloc(se, b"\x00" * 0x2CC)
        rv, _ = call(se, dll, api, [hthread, context])
        assert rv == (0 if dll == "ntdll" else 1)

    return change


def map_view_with_nt_map_view_of_section(se: Speakeasy, hproc: int, hthread: int) -> None:
    phnd = alloc(se, b"\x00" * 4)
    size = alloc(se, struct.pack("<Q", 0x1000))
    rv, _ = call(se, "ntdll", "NtCreateSection", [phnd, 0xF001F, 0, size, 0x40, 0x8000000, 0])
    assert rv == 0
    (hsect,) = struct.unpack("<I", se.mem_read(phnd, 4))
    base = alloc(se, b"\x00" * 4)
    view_size = alloc(se, b"\x00" * 4)
    rv, _ = call(se, "ntdll", "NtMapViewOfSection", [hsect, hproc, base, 0, 0, 0, view_size, 1, 0, 0x40])
    assert rv == 0


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(write_with_nt_write_virtual_memory, id="NtWriteVirtualMemory"),
        pytest.param(set_context_with("ntdll", "NtSetContextThread"), id="NtSetContextThread"),
        pytest.param(set_context_with("kernel32", "Wow64SetThreadContext"), id="Wow64SetThreadContext"),
        pytest.param(map_view_with_nt_map_view_of_section, id="NtMapViewOfSection"),
    ],
)
def test_resume_thread_starts_a_child_after_an_ntdll_change(
    dll_emu: Speakeasy, change: Callable[[Speakeasy, int, int], None]
) -> None:
    assert dll_emu.emu is not None
    hproc, hthread = create_suspended_child(dll_emu)
    child = dll_emu.emu.child_processes[0]
    change(dll_emu, hproc, hthread)
    queued = len(dll_emu.emu.run_queue)
    call(dll_emu, "kernel32", "ResumeThread", [hthread])
    assert len(dll_emu.emu.run_queue) == queued + 1
    assert dll_emu.emu.run_queue[-1].process_context is child


def test_map_view_into_the_current_process_does_not_start_a_child(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    _, hthread = create_suspended_child(dll_emu)
    map_view_with_nt_map_view_of_section(dll_emu, 0xFFFFFFFF, hthread)
    queued = len(dll_emu.emu.run_queue)
    call(dll_emu, "kernel32", "ResumeThread", [hthread])
    assert len(dll_emu.emu.run_queue) == queued


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


GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x4
GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x2


def test_get_module_handle_ex_from_address_finds_the_image(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    base = dll_emu.emu.modules[0].base
    out = alloc(dll_emu, b"\x00" * 4)
    flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
    rv, _ = call(dll_emu, "kernel32", "GetModuleHandleExA", [flags, base + 0x1000, out])
    assert rv
    assert dll_emu.mem_read(out, 4) == struct.pack("<I", base)


@pytest.mark.parametrize("api, cw", [("GetModuleFileNameA", 1), ("GetModuleFileNameW", 2)])
def test_get_module_file_name_without_a_current_module(dll_emu: Speakeasy, api: str, cw: int) -> None:
    assert dll_emu.emu is not None and dll_emu.emu.get_current_module() is None
    name = alloc(dll_emu, b"kernel32.dll\x00")
    hmod, _ = call(dll_emu, "kernel32", "GetModuleHandleA", [name])
    buf = alloc(dll_emu, b"\xcc" * 0x400)
    rv, displays = call(dll_emu, "kernel32", api, [hmod, buf, 0x200])
    path = displays["lpFilename"]
    assert path.lower().endswith("kernel32.dll")
    assert rv == len(path)
    assert dll_emu.mem_read(buf, (rv + 1) * cw) == encode(path + "\0", cw)


@pytest.mark.parametrize("api, cw", [("GetModuleFileNameA", 1), ("GetModuleFileNameW", 2)])
@pytest.mark.parametrize("room", ["no_nul", "small"])
def test_get_module_file_name_truncates_in_characters(dll_emu: Speakeasy, api: str, cw: int, room: str) -> None:
    start_process(dll_emu)
    buf = alloc(dll_emu, b"\xcc" * 0x400)
    rv, displays = call(dll_emu, "kernel32", api, [0, buf, 0x200])
    path = displays["lpFilename"]
    n = len(path) if room == "no_nul" else 5
    buf = alloc(dll_emu, b"\xcc" * 0x400)
    rv, _ = call(dll_emu, "kernel32", api, [0, buf, n])
    assert rv == n
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INSUFFICIENT_BUFFER
    assert dll_emu.mem_read(buf, n * cw + 1) == encode(path[: n - 1] + "\0", cw) + b"\xcc"


@pytest.mark.parametrize("api, cw", [("GetFullPathNameA", 1), ("GetFullPathNameW", 2)])
@pytest.mark.parametrize(
    "path, part",
    [("C:\\dir\\file.txt", "file.txt"), ("C:\\dir\\file", "file"), ("C:\\a\\a", "a"), ("C:\\dir\\", None)],
)
def test_get_full_path_name_sizes_and_file_part(
    dll_emu: Speakeasy, api: str, cw: int, path: str, part: str | None
) -> None:
    src = alloc(dll_emu, encode(path + "\0", cw))
    need, _ = call(dll_emu, "kernel32", api, [src, 0, 0, 0])
    assert need == len(path) + 1
    buf = alloc(dll_emu, b"\xcc" * 0x100)
    file_part = alloc(dll_emu, b"\xef\xbe\xad\xde")
    rv, _ = call(dll_emu, "kernel32", api, [src, len(path), buf, file_part])
    assert rv == need
    assert dll_emu.mem_read(buf, 0x100) == b"\xcc" * 0x100
    rv, _ = call(dll_emu, "kernel32", api, [src, need, buf, file_part])
    assert rv == len(path)
    assert dll_emu.mem_read(buf, need * cw) == encode(path + "\0", cw)
    ptr = struct.unpack("<I", dll_emu.mem_read(file_part, 4))[0]
    if part is None:
        assert ptr == 0
    else:
        assert ptr == buf + (len(path) - len(part)) * cw


@pytest.mark.parametrize("byte", [0x41, 0x81, 0xE0])
def test_code_page_1252_has_no_lead_bytes(dll_emu: Speakeasy, byte: int) -> None:
    acp, _ = call(dll_emu, "kernel32", "GetACP", [])
    assert acp == 1252
    rv, _ = call(dll_emu, "kernel32", "IsDBCSLeadByte", [byte])
    assert not rv


@pytest.mark.parametrize(
    "perms, protect",
    [
        (common.PERM_MEM_READ, windefs.PAGE_READONLY),
        (common.PERM_MEM_RW, windefs.PAGE_READWRITE),
        (common.PERM_MEM_RX, windefs.PAGE_EXECUTE_READ),
        (common.PERM_MEM_EXEC, windefs.PAGE_EXECUTE),
        (common.PERM_MEM_RWX, windefs.PAGE_EXECUTE_READWRITE),
        (common.PERM_MEM_NONE, windefs.PAGE_NOACCESS),
    ],
)
def test_virtual_query_reports_the_page_protection(dll_emu: Speakeasy, perms: int, protect: int) -> None:
    assert dll_emu.emu is not None
    addr = dll_emu.emu.mem_map(0x1000, perms=perms)
    mbi = alloc(dll_emu, b"\x00" * 28)
    rv, _ = call(dll_emu, "kernel32", "VirtualQuery", [addr, mbi, 28])
    assert rv == 28
    assert struct.unpack("<I", dll_emu.mem_read(mbi + 20, 4))[0] == protect


@pytest.mark.parametrize(
    "offset, base, size, protect",
    [
        (0x10, 0x0, 0x1000, windefs.PAGE_READONLY),
        (0x1010, 0x1000, 0x1000, windefs.PAGE_EXECUTE_READ),
        (0x3010, 0x3000, 0x1000, windefs.PAGE_READWRITE),
        (0x5010, 0x4000, 0x3000, windefs.PAGE_READONLY),
    ],
)
def test_virtual_query_reports_the_section_of_a_loaded_image(
    dll_emu: Speakeasy, offset: int, base: int, size: int, protect: int
) -> None:
    image = 0x10000000
    mbi = alloc(dll_emu, b"\x00" * 28)
    assert call(dll_emu, "kernel32", "VirtualQuery", [image + offset, mbi, 28])[0] == 28
    base_address, allocation_base, _, region_size, _, protect_field, _ = struct.unpack("<7I", dll_emu.mem_read(mbi, 28))
    assert (base_address, allocation_base, region_size, protect_field) == (image + base, image, size, protect)


def test_virtual_query_reports_free_memory_up_to_the_next_allocation(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    gap = 0x60000000
    assert all(dll_emu.emu.get_address_map(a) is None for a in range(gap, gap + 0x10000, 0x1000))
    dll_emu.emu.mem_map(0x1000, base=gap + 0x10000)
    mbi = alloc(dll_emu, b"\x00" * 28)
    assert call(dll_emu, "kernel32", "VirtualQuery", [gap + 0x2010, mbi, 28])[0] == 28
    base_address, allocation_base, _, region_size, state, protect, _ = struct.unpack("<7I", dll_emu.mem_read(mbi, 28))
    assert (base_address, allocation_base, region_size) == (gap + 0x2000, 0, 0xE000)
    assert (state, protect) == (windefs.MEM_FREE, windefs.PAGE_NOACCESS)


def test_virtual_query_reports_reserved_memory(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    base = dll_emu.emu.mem_reserve(0x3000, base=0x60000000)
    mbi = alloc(dll_emu, b"\x00" * 28)
    assert call(dll_emu, "kernel32", "VirtualQuery", [base + 0x1010, mbi, 28])[0] == 28
    base_address, allocation_base, _, region_size, state, _, _ = struct.unpack("<7I", dll_emu.mem_read(mbi, 28))
    assert (base_address, allocation_base, region_size, state) == (base + 0x1000, base, 0x2000, MEM_RESERVE)


def test_virtual_query_reports_committed_reserved_memory(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    base = dll_emu.emu.mem_reserve(0x1000, base=0x60000000)
    dll_emu.emu.mem_map_reserve(base)
    mbi = alloc(dll_emu, b"\x00" * 28)
    assert call(dll_emu, "kernel32", "VirtualQuery", [base + 0x10, mbi, 28])[0] == 28
    base_address, _, allocation_protect, _, state, protect, _ = struct.unpack("<7I", dll_emu.mem_read(mbi, 28))
    assert (base_address, state) == (base, windefs.MEM_COMMIT)
    assert allocation_protect == protect == windefs.PAGE_EXECUTE_READWRITE


def test_virtual_query_rejects_addresses_above_the_application_range(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    mbi = alloc(dll_emu, b"\x00" * 28)
    assert call(dll_emu, "kernel32", "VirtualQuery", [0x7FFF0000, mbi, 28])[0] == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


Y2K_FILETIME = 125911584000000000


@pytest.mark.parametrize(
    "fields, filetime",
    [
        ((2000, 1, 6, 1, 0, 0, 0, 0), Y2K_FILETIME),
        ((2024, 2, 4, 29, 13, 45, 30, 250), 133536879302500000),
    ],
)
def test_system_time_to_file_time_converts_the_input(
    dll_emu: Speakeasy, fields: tuple[int, ...], filetime: int
) -> None:
    st = alloc(dll_emu, struct.pack("<8H", *fields))
    ft = alloc(dll_emu, b"\x00" * 8)
    rv, _ = call(dll_emu, "kernel32", "SystemTimeToFileTime", [st, ft])
    assert rv
    assert struct.unpack("<Q", dll_emu.mem_read(ft, 8))[0] == filetime


@pytest.mark.parametrize("fields", [(2000, 13, 0, 1, 0, 0, 0, 0), (1600, 12, 0, 31, 0, 0, 0, 0)])
def test_system_time_to_file_time_rejects_a_bad_date(dll_emu: Speakeasy, fields: tuple[int, ...]) -> None:
    start_process(dll_emu)
    st = alloc(dll_emu, struct.pack("<8H", *fields))
    ft = alloc(dll_emu, b"\xcc" * 8)
    rv, _ = call(dll_emu, "kernel32", "SystemTimeToFileTime", [st, ft])
    assert not rv
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER
    assert dll_emu.mem_read(ft, 8) == b"\xcc" * 8


@pytest.mark.parametrize(
    "filetime, fields",
    [
        (Y2K_FILETIME, (2000, 1, 6, 1, 0, 0, 0, 0)),
        (133536879302500000, (2024, 2, 4, 29, 13, 45, 30, 250)),
        (Y2K_FILETIME + 9_999_999, (2000, 1, 6, 1, 0, 0, 0, 999)),
        (Y2K_FILETIME + 599_999_999, (2000, 1, 6, 1, 0, 0, 59, 999)),
        (0, (1601, 1, 1, 1, 0, 0, 0, 0)),
    ],
)
def test_file_time_to_system_time_counts_weekdays_from_sunday(
    dll_emu: Speakeasy, filetime: int, fields: tuple[int, ...]
) -> None:
    ft = alloc(dll_emu, struct.pack("<Q", filetime))
    st = alloc(dll_emu, b"\x00" * 16)
    rv, _ = call(dll_emu, "kernel32", "FileTimeToSystemTime", [ft, st])
    assert rv
    assert struct.unpack("<8H", dll_emu.mem_read(st, 16)) == fields


@pytest.mark.parametrize(
    "api, argv",
    [
        ("WriteProcessMemory", lambda buf: [0x9999, buf, buf, 4, 0]),
        ("ReadProcessMemory", lambda buf: [0x9999, buf, buf, 4, 0]),
        ("CreateRemoteThread", lambda buf: [0x9999, 0, 0, buf, 0, 0, 0]),
        ("VirtualProtectEx", lambda buf: [0x9999, buf, 4, windefs.PAGE_READWRITE, buf]),
    ],
)
def test_unknown_process_handle_is_invalid(dll_emu: Speakeasy, api: str, argv: Callable[[int], list[int]]) -> None:
    start_process(dll_emu)
    buf = alloc(dll_emu, b"\x00" * 16)
    rv, _ = call(dll_emu, "kernel32", api, argv(buf))
    assert not rv
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_HANDLE


@pytest.mark.parametrize("api", ["OpenMutexA", "OpenMutexW"])
def test_open_mutex_without_a_name_fails(dll_emu: Speakeasy, api: str) -> None:
    start_process(dll_emu)
    rv, _ = call(dll_emu, "kernel32", api, [0x1F0001, 0, 0])
    assert rv == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


@pytest.mark.parametrize("feature, present", [(10, 1), (41, 0), (42, 0), (0x1000, 0)])
def test_is_processor_feature_present_knows_unlisted_features(dll_emu: Speakeasy, feature: int, present: int) -> None:
    rv, _ = call(dll_emu, "kernel32", "IsProcessorFeaturePresent", [feature])
    assert rv == present


def test_get_tick_count64_sets_the_high_half_on_x86(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    assert emu is not None
    k32, _ = emu.normalize_import_miss("kernel32", "GetTickCount64")
    k32.tick_counter = 0x1_0000_0000
    emu.reg_write(e_arch.X86_REG_EDX, 0xDEADBEEF)
    rv, _ = call(dll_emu, "kernel32", "GetTickCount64", [])
    assert rv == 20
    assert emu.reg_read(e_arch.X86_REG_EDX) == 1


def test_process_id_to_session_id(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    assert emu is not None
    proc = emu.get_current_process()
    out = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "kernel32", "ProcessIdToSessionId", [proc.id, out])[0] is True
    assert struct.unpack("<I", dll_emu.mem_read(out, 4))[0] == proc.session


@pytest.mark.parametrize("pid, has_out", [(0xFFFF0, True), (None, False)])
def test_process_id_to_session_id_failure_sets_the_last_error(
    dll_emu: Speakeasy, pid: int | None, has_out: bool
) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    assert emu is not None
    emu.set_last_error(0)
    out = alloc(dll_emu, b"\xcc" * 4) if has_out else 0
    pid = emu.get_current_process().id if pid is None else pid
    assert call(dll_emu, "kernel32", "ProcessIdToSessionId", [pid, out])[0] is False
    assert emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


def test_fls_get_value2_reads_the_slot_without_setting_the_last_error(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    assert emu is not None
    index, _ = call(dll_emu, "kernel32", "FlsAlloc", [0])
    assert call(dll_emu, "kernel32", "FlsSetValue", [index, 0x12345678])[0]
    emu.set_last_error(0x57)
    assert call(dll_emu, "kernel32", "FlsGetValue2", [index])[0] == 0x12345678
    assert call(dll_emu, "kernel32", "FlsGetValue2", [index + 100])[0] == 0
    assert emu.get_last_error() == 0x57


def test_fls_index_is_valid_in_every_thread(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    assert emu is not None
    first = emu.get_current_thread()
    indexes = [call(dll_emu, "kernel32", "FlsAlloc", [0])[0] for _ in range(2)]
    assert indexes[0] != indexes[1]
    assert call(dll_emu, "kernel32", "FlsSetValue", [indexes[1], 0x1111])[0]

    second = objman.Thread(emu, stack_base=emu.stack_base, stack_commit=0x1000)
    emu.set_current_thread(second)
    assert call(dll_emu, "kernel32", "FlsGetValue", [indexes[1]])[0] == 0
    assert call(dll_emu, "kernel32", "FlsSetValue", [indexes[1], 0x2222])[0]
    assert call(dll_emu, "kernel32", "FlsGetValue", [indexes[1]])[0] == 0x2222
    assert call(dll_emu, "kernel32", "FlsGetValue2", [indexes[1]])[0] == 0x2222
    assert not call(dll_emu, "kernel32", "FlsSetValue", [indexes[1] + 100, 0x3333])[0]

    emu.set_current_thread(first)
    assert call(dll_emu, "kernel32", "FlsGetValue", [indexes[1]])[0] == 0x1111


@pytest.mark.parametrize("fixture, ptr", [("dll_emu", 4), ("dll64_emu", 8)])
@pytest.mark.parametrize("walk, cw", [("Module32First", 1), ("Module32FirstW", 2)])
def test_module32_first_fills_the_module_entry(
    request: pytest.FixtureRequest, fixture: str, ptr: int, walk: str, cw: int
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    emu = se.emu
    assert emu is not None
    module = emu.get_peb_modules()[0]
    hsnap, _ = call(se, "kernel32", "CreateToolhelp32Snapshot", [0x8, 0])
    entry = alloc(se, b"\xcc" * 0x800)
    assert call(se, "kernel32", walk, [hsnap, entry])[0]

    def read_ptr(offset: int) -> int:
        return int.from_bytes(se.mem_read(entry + offset, ptr), "little")

    def read_str(offset: int, chars: int) -> str:
        raw = se.mem_read(entry + offset, chars * cw)
        text = raw.decode("utf-16le" if cw == 2 else "latin-1")
        return text[: text.index("\x00")]

    head = 0x14 if ptr == 4 else 0x18
    names = head + 3 * ptr if ptr == 4 else 0x30
    assert read_ptr(head) == module.base
    assert read_ptr(names - ptr) == module.base
    assert read_str(names, 256) == module.name
    assert read_str(names + 256 * cw, 260) == module.emu_path


def test_map_view_of_image_section_keeps_the_input_metadata(pe_file_emu: Speakeasy) -> None:
    emu = pe_file_emu.emu
    assert emu is not None and emu.profiler is not None
    before = dict(emu.profiler.meta)
    assert before["arch"] == "x86"
    name = alloc(pe_file_emu, b"c:\\image.dll\x00")
    hfile, _ = call(pe_file_emu, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0])
    hmap, _ = call(pe_file_emu, "kernel32", "CreateFileMappingA", [hfile, 0, 0x02 | SEC_IMAGE, 0, 0, 0])
    view, _ = call(pe_file_emu, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_READ, 0, 0, 0])
    assert pe_file_emu.mem_read(view, 2) == b"MZ"
    assert emu.profiler.meta == before


RSMB = 0x52534D42


def get_smbios_structure_types(table: bytes) -> list[int]:
    types = []
    offset = 0
    while offset < len(table):
        kind, length = table[offset], table[offset + 1]
        types.append(kind)
        end = table.index(b"\x00\x00", offset + length)
        offset = end + 2
    assert offset == len(table)
    return types


def test_get_system_firmware_table_returns_a_raw_smbios_table(dll_emu: Speakeasy) -> None:
    size, _ = call(dll_emu, "kernel32", "GetSystemFirmwareTable", [RSMB, 0, 0, 0])
    buf = alloc(dll_emu, b"\x00" * size)
    assert call(dll_emu, "kernel32", "GetSystemFirmwareTable", [RSMB, 0, buf, size])[0] == size
    data = dll_emu.mem_read(buf, size)
    length = struct.unpack("<I", data[4:8])[0]
    assert length == size - 8
    assert get_smbios_structure_types(data[8:]) == [0, 1, 127]


def test_get_system_firmware_table_with_a_small_buffer_returns_the_size(dll_emu: Speakeasy) -> None:
    size, _ = call(dll_emu, "kernel32", "GetSystemFirmwareTable", [RSMB, 0, 0, 0])
    buf = alloc(dll_emu, b"\xcc" * 8)
    assert call(dll_emu, "kernel32", "GetSystemFirmwareTable", [RSMB, 0, buf, 8])[0] == size
    assert dll_emu.mem_read(buf, 8) == b"\xcc" * 8
