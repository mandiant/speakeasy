"""
Heap handlers work only on blocks that a heap allocator returned.
"""

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import call, start_process


@pytest.fixture
def emu(dll_emu: Speakeasy) -> Speakeasy:
    start_process(dll_emu)
    return dll_emu


def placeholder(se: Speakeasy) -> int:
    assert se.emu is not None
    return se.emu.mem_map(8, tag="emu.export_arg_0", base=0x41420000)


@pytest.mark.parametrize(
    "dll, name, args, rv, error",
    [
        ("kernel32", "HeapFree", "heap, 0, p", "0", windefs.ERROR_INVALID_PARAMETER),
        ("kernel32", "LocalFree", "p", "p", windefs.ERROR_INVALID_HANDLE),
        ("kernel32", "GlobalFree", "p", "p", windefs.ERROR_INVALID_HANDLE),
        ("ntdll", "RtlFreeHeap", "heap, 0, p", "0", None),
        ("msvcrt", "free", "p", None, None),
        ("msvcrt", "realloc", "p, 0", "0", None),
    ],
)
def test_free_keeps_memory_that_is_not_a_heap_block(
    emu: Speakeasy, dll: str, name: str, args: str, rv: str | None, error: int | None
) -> None:
    names = {"heap": call(emu, "kernel32", "GetProcessHeap", [])[0], "p": placeholder(emu)}
    p = names["p"]
    emu.mem_write(p, b"\x11\x22\x33\x44")
    result = call(emu, dll, name, [int(names.get(a, a)) for a in args.split(", ")])[0]
    if rv is not None:
        assert result == int(names.get(rv, rv))
    if error is not None:
        assert emu.emu is not None
        assert emu.emu.get_last_error() == error
    assert emu.mem_read(p, 4) == b"\x11\x22\x33\x44"


@pytest.mark.parametrize(
    "fixture, new, delete",
    [
        ("dll_emu", "??2@YAPAXI@Z", "??3@YAXPAX@Z"),
        ("dll_emu", "??_U@YAPAXI@Z", "??_V@YAXPAX@Z"),
        ("dll64_emu", "??2@YAPEAX_K@Z", "??3@YAXPEAX@Z"),
        ("dll64_emu", "??_U@YAPEAX_K@Z", "??_V@YAXPEAX@Z"),
    ],
)
def test_operator_delete_releases_operator_new_memory(
    request: pytest.FixtureRequest, fixture: str, new: str, delete: str
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    p = call(se, "msvcrt", new, [0x20])[0]
    assert p
    se.mem_write(p, b"\x41" * 0x20)
    call(se, "msvcrt", delete, [p])
    call(se, "msvcrt", delete, [0])
    assert se.emu is not None
    mm = se.emu.get_address_map(p)
    assert mm is None or mm.free


@pytest.mark.parametrize("size", [0x7, 0x10, 0x80, 0x81, 0x1001])
def test_heap_size_returns_the_requested_size(emu: Speakeasy, size: int) -> None:
    heap = call(emu, "kernel32", "GetProcessHeap", [])[0]
    block = call(emu, "kernel32", "HeapAlloc", [heap, 0, size])[0]
    assert call(emu, "kernel32", "HeapSize", [heap, 0, block])[0] == size
    handle = call(emu, "kernel32", "GlobalAlloc", [0, size])[0]
    assert call(emu, "kernel32", "GlobalSize", [handle])[0] == size


def test_heap_size_of_a_reallocated_block(emu: Speakeasy) -> None:
    heap = call(emu, "kernel32", "GetProcessHeap", [])[0]
    block = call(emu, "kernel32", "HeapAlloc", [heap, 0, 0x20])[0]
    block = call(emu, "kernel32", "HeapReAlloc", [heap, 0, block, 0x45])[0]
    assert call(emu, "kernel32", "HeapSize", [heap, 0, block])[0] == 0x45
