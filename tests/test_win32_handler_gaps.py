"""
Tests for WaitOnAddress, the delay-load APIs, ApiSetQueryApiSetPresence, the WOW64
state, SHTaskPoolGetUniqueContext and LoadStringW with cchBufferMax 0.
"""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.winenv.defs.windows import kernel32 as k32defs
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process, unicode_string
from tests.pe_builder import build_pe

INFINITE = 0xFFFFFFFF
ERROR_TIMEOUT = 1460
OS_WOW6432 = 30
KUSER_SHARED_DATA = 0x7FFE0000
RT_STRING = 6


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def any_emu(request: pytest.FixtureRequest) -> Speakeasy:
    se: Speakeasy = request.getfixturevalue(request.param)
    start_process(se)
    return se


def ptr_size(se: Speakeasy) -> int:
    size: int = se.emu.get_ptr_size()
    return size


def read_ptr(se: Speakeasy, addr: int) -> int:
    return int.from_bytes(se.mem_read(addr, ptr_size(se)), "little")


def last_error(se: Speakeasy) -> int:
    error: int = se.emu.get_last_error()
    return error


def api_names(se: Speakeasy) -> list[list[str]]:
    return [
        [event.api_name for event in (entry.events or []) if event.event == "api"]
        for entry in se.get_report().entry_points
    ]


def test_wait_on_address_returns_at_once_when_the_value_differs(any_emu: Speakeasy) -> None:
    value = alloc(any_emu, struct.pack("<I", 1))
    compare = alloc(any_emu, struct.pack("<I", 0))
    before = call(any_emu, "kernel32", "GetTickCount", [])[0]
    assert call(any_emu, "kernel32", "WaitOnAddress", [value, compare, 4, INFINITE])[0] == 1
    assert call(any_emu, "kernel32", "GetTickCount", [])[0] - before == 20


@pytest.mark.parametrize("size, fmt", [(1, "<B"), (8, "<Q")])
def test_wait_on_address_times_out_when_the_value_is_equal(any_emu: Speakeasy, size: int, fmt: str) -> None:
    value = alloc(any_emu, struct.pack(fmt, 7) + b"\xff" * 8)
    compare = alloc(any_emu, struct.pack(fmt, 7) + b"\x00" * 8)
    before = call(any_emu, "kernel32", "GetTickCount", [])[0]
    assert call(any_emu, "kernel32", "WaitOnAddress", [value, compare, size, 500])[0] == 0
    assert last_error(any_emu) == ERROR_TIMEOUT
    assert call(any_emu, "kernel32", "GetTickCount", [])[0] - before == 520


def test_wait_on_address_rejects_a_bad_size(any_emu: Speakeasy) -> None:
    value = alloc(any_emu, b"\x00" * 8)
    assert call(any_emu, "kernel32", "WaitOnAddress", [value, value, 3, 0])[0] == 0
    assert last_error(any_emu) == windefs.ERROR_INVALID_PARAMETER


def wait_and_wake_program(base: int, iat: dict[tuple[str, str], int]) -> bytes:
    """
    The main thread creates a thread, then calls WaitOnAddress with an INFINITE
    timeout on the flag at .data. The thread sets the flag and wakes it.
    """
    flag = base + 0x2000
    zero = base + 0x2004

    def imp(dll: str, name: str) -> bytes:
        return b"\xff\x15" + struct.pack("<I", base + iat[dll, name])

    main = b"\x6a\x00" * 2 + b"\x68" + struct.pack("<I", 0) + b"\x68XXXX" + b"\x6a\x00" * 2
    main += imp("kernel32.dll", "CreateThread")
    main += b"\x68" + struct.pack("<I", INFINITE) + b"\x6a\x04"
    main += b"\x68" + struct.pack("<I", zero) + b"\x68" + struct.pack("<I", flag)
    main += imp("api-ms-win-core-synch-l1-2-0.dll", "WaitOnAddress")
    main += imp("kernel32.dll", "GetTickCount")
    main += b"\xc3"
    start = base + 0x1000 + len(main)
    thread = b"\xc7\x05" + struct.pack("<II", flag, 1)
    thread += b"\x68" + struct.pack("<I", flag) + imp("api-ms-win-core-synch-l1-2-0.dll", "WakeByAddressSingle")
    thread += b"\x31\xc0\xc2\x04\x00"
    return main.replace(b"XXXX", struct.pack("<I", start)) + thread


def test_wait_on_address_with_infinite_timeout_ends_the_run() -> None:
    imports = {
        "kernel32.dll": ["CreateThread", "GetTickCount"],
        "api-ms-win-core-synch-l1-2-0.dll": ["WaitOnAddress", "WakeByAddressSingle"],
    }
    data, _ = build_pe(32, text=wait_and_wake_program, data=b"\0" * 8, imports=imports)
    with Speakeasy(config=get_default_config_dict()) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        assert api_names(se) == [
            ["kernel32.CreateThread", "kernel32.WaitOnAddress"],
            ["kernel32.WakeByAddressSingle"],
        ]
        assert [entry.error for entry in se.get_report().entry_points] == [None, None]


def delay_descriptor(se: Speakeasy, dll: str, thunks: list[int | str]) -> tuple[int, list[int]]:
    """
    Build an RVA-based IMAGE_DELAYLOAD_DESCRIPTOR in one block, with its DLL name,
    name table, IAT and module handle slot, at the start of the block. Return
    the block base and the IAT slot addresses.
    """
    width = ptr_size(se)
    block = bytearray(0x1000)
    name_rva, int_rva, iat_rva, hmod_rva, names_rva = 0x100, 0x200, 0x300, 0x400, 0x500
    struct.pack_into("<8I", block, 0, 1, name_rva, hmod_rva, iat_rva, int_rva, 0, 0, 0)
    block[name_rva : name_rva + len(dll) + 1] = dll.encode() + b"\0"
    for index, thunk in enumerate(thunks):
        if isinstance(thunk, int):
            value = (1 << (width * 8 - 1)) | thunk
        else:
            value = names_rva
            block[names_rva : names_rva + len(thunk) + 3] = b"\0\0" + thunk.encode() + b"\0"
            names_rva += 0x40
        block[int_rva + index * width : int_rva + (index + 1) * width] = value.to_bytes(width, "little")
        block[iat_rva + index * width : iat_rva + (index + 1) * width] = (0x1234).to_bytes(width, "little")
    base = alloc(se, bytes(block))
    return base, [base + iat_rva + index * width for index in range(len(thunks))]


@pytest.mark.parametrize(
    "dll, thunk, symbol",
    [
        ("api-ms-win-core-synch-l1-2-0.dll", "WaitOnAddress", "kernel32.WaitOnAddress"),
        ("user32.dll", "MessageBoxW", "user32.MessageBoxW"),
        ("comctl32.dll", 17, "comctl32.InitCommonControls"),
    ],
)
def test_resolve_delay_loaded_api_writes_the_iat_slot(
    any_emu: Speakeasy, dll: str, thunk: int | str, symbol: str
) -> None:
    base, [other, slot] = delay_descriptor(any_emu, dll, ["Unused", thunk])
    rv = call(any_emu, "kernel32", "ResolveDelayLoadedAPI", [base, base, 0, 0, slot, 0])[0]
    assert any_emu.emu.api_registry.symbol(rv) == symbol
    assert (read_ptr(any_emu, slot), read_ptr(any_emu, other)) == (rv, 0x1234)
    module = any_emu.emu.get_mod_from_addr(rv)
    assert module is not None and read_ptr(any_emu, base + 0x400) == module.base


def test_resolve_delay_loaded_api_fails_for_a_missing_export(any_emu: Speakeasy) -> None:
    name = any_emu.emu.modules[0].name
    base, [slot] = delay_descriptor(any_emu, name + ".dll", ["NoSuchExport"])
    assert call(any_emu, "kernel32", "ResolveDelayLoadedAPI", [base, base, 0, 0, slot, 0])[0] == 0
    assert last_error(any_emu) == windefs.ERROR_PROC_NOT_FOUND
    assert read_ptr(any_emu, slot) == 0x1234


def test_delay_load_failure_hook_returns_null(any_emu: Speakeasy) -> None:
    dll = alloc(any_emu, b"nosuch.dll\0")
    proc = alloc(any_emu, b"NoSuchProc\0")
    assert call(any_emu, "kernel32", "DelayLoadFailureHook", [dll, proc])[0] == 0
    assert last_error(any_emu) == windefs.ERROR_PROC_NOT_FOUND
    assert call(any_emu, "kernel32", "DelayLoadFailureHook", [dll, 5])[1] == {
        0: "nosuch.dll",
        1: "0x5",
    }


@pytest.mark.parametrize(
    "name, present",
    [
        ("api-ms-win-core-synch-l1-2-0", 1),
        ("api-ms-win-core-synch-l1-2-0.dll", 1),
        ("ext-ms-win-no-such-set-l1-1-0", 0),
        ("kernel32", 0),
    ],
)
def test_api_set_query_api_set_presence(dll_emu: Speakeasy, name: str, present: int) -> None:
    out = alloc(dll_emu, b"\xcc")
    rv, displays = call(dll_emu, "kernel32", "ApiSetQueryApiSetPresence", [unicode_string(dll_emu, name), out])
    assert (rv, dll_emu.mem_read(out, 1)) == (0, bytes([present]))
    assert displays["Namespace"] == name


@pytest.mark.parametrize("fixture, machine", [("dll_emu", 0x14C), ("dll64_emu", 0x8664)])
def test_wow64_state_matches(request: pytest.FixtureRequest, fixture: str, machine: int) -> None:
    se = request.getfixturevalue(fixture)
    start_process(se)
    out = alloc(se, b"\xcc" * 16)
    assert call(se, "kernel32", "IsWow64Process2", [0xFFFFFFFF, out, out + 2])[0] == 1
    assert struct.unpack("<HH", se.mem_read(out, 4)) == (0, machine)
    assert call(se, "kernel32", "IsWow64Process2", [0xFFFFFFFF, out + 4, 0])[0] == 1
    assert call(se, "kernel32", "IsWow64Process", [0xFFFFFFFF, out + 8])[0] == 1
    assert se.mem_read(out + 8, 4) == b"\0\0\0\0"
    assert call(se, "shlwapi", "IsOS", [OS_WOW6432])[0] == 0
    assert struct.unpack("<HH", se.mem_read(KUSER_SHARED_DATA + 0x2C, 4)) == (machine, machine)

    info = alloc(se, b"\0" * 64)
    call(se, "kernel32", "GetNativeSystemInfo", [info])
    arch = k32defs.PROCESSOR_ARCHITECTURE_INTEL if machine == 0x14C else k32defs.PROCESSOR_ARCHITECTURE_AMD64
    assert struct.unpack("<H", se.mem_read(info, 2))[0] == arch


def test_sh_task_pool_get_unique_context_returns_unique_values(any_emu: Speakeasy) -> None:
    first = call(any_emu, "shcore", "SHTaskPoolGetUniqueContext", [])[0]
    second = call(any_emu, "shcore", "SHTaskPoolGetUniqueContext", [])[0]
    assert 0 not in (first, second) and first != second


def string_table_pe(arch: int, block: int, strings: list[str]) -> bytes:
    """Build a PE whose resource directory at RVA 0x2000 holds one RT_STRING block."""
    rva = 0x2000

    def directory(entry_id: int, target: int) -> bytes:
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", entry_id, target)

    table = b"".join(struct.pack("<H", len(s)) + s.encode("utf-16le") for s in strings + [""] * (16 - len(strings)))
    rsrc = directory(RT_STRING, 0x80000000 | 0x18)
    rsrc += directory(block, 0x80000000 | 0x30)
    rsrc += directory(0x409, 0x48)
    rsrc += struct.pack("<IIII", rva + 0x58, len(table), 0, 0)
    rsrc += table
    data, _ = build_pe(arch, data=rsrc, extra_dirs={2: (rva, len(rsrc))})
    return data


@pytest.mark.parametrize("arch", [32, 64])
def test_load_string_w_with_zero_size_returns_a_pointer(config: dict, arch: int) -> None:
    data = string_table_pe(arch, 2, ["", "", "hello", "world"])
    for se in load_emu(config, data):
        base = se.emu.modules[0].base
        out = alloc(se, b"\xcc" * 8)
        rv, displays = call(se, "user32", "LoadStringW", [base, 18, out, 0])
        assert rv == 5
        pointer = read_ptr(se, out)
        assert base + 0x2000 <= pointer < base + 0x3000
        assert se.mem_read(pointer, 12) == "hello".encode("utf-16le") + struct.pack("<H", 5)
        assert displays["lpBuffer"] == "hello"

        assert call(se, "user32", "LoadStringW", [base, 17, out, 0])[0] == 0

        out = alloc(se, b"\xcc" * 8)
        assert call(se, "user32", "LoadStringA", [base, 18, out, 0])[0] == 0
        assert se.mem_read(out, 8) == b"\xcc" * 8
