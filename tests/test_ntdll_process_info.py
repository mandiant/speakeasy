import struct

import pytest

import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, start_process

PROCESS_DEBUG_FLAGS = 0x1F


def query(se: Speakeasy, info_class: int, length: int) -> tuple[int, bytes, int]:
    info = alloc(se, b"\xcc" * 0x40)
    retlen = alloc(se, b"\xcc" * 4)
    current_process = (1 << (8 * se.emu.get_ptr_size())) - 1
    rv, _ = call(se, "ntdll", "NtQueryInformationProcess", [current_process, info_class, info, length, retlen])
    return rv, se.mem_read(info, 0x40), struct.unpack("<I", se.mem_read(retlen, 4))[0]


@pytest.mark.parametrize("fixture, bits", [("dll_emu", 32), ("dll64_emu", 64)])
def test_query_process_debug_port_reports_no_debugger(request: pytest.FixtureRequest, fixture: str, bits: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    ptr = bits // 8
    rv, info, retlen = query(se, ddk.PROCESSINFOCLASS.ProcessDebugPort, ptr)
    assert rv == ddk.STATUS_SUCCESS
    assert info[:ptr] == b"\x00" * ptr
    assert retlen == ptr

    rv, info, _ = query(se, ddk.PROCESSINFOCLASS.ProcessDebugPort, ptr - 1)
    assert rv == ddk.STATUS_INFO_LENGTH_MISMATCH
    assert info[:ptr] == b"\xcc" * ptr


def test_query_process_debug_flags_reports_no_debugger(dll64_emu: Speakeasy) -> None:
    start_process(dll64_emu)
    rv, info, retlen = query(dll64_emu, PROCESS_DEBUG_FLAGS, 4)
    assert rv == ddk.STATUS_SUCCESS
    assert info[:4] == b"\x01\x00\x00\x00"
    assert retlen == 4


def test_query_process_debug_object_handle_writes_a_null_handle(dll64_emu: Speakeasy) -> None:
    start_process(dll64_emu)
    rv, info, _ = query(dll64_emu, ddk.PROCESSINFOCLASS.ProcessDebugObjectHandle, 8)
    assert rv == ddk.STATUS_PORT_NOT_SET
    assert info[:8] == b"\x00" * 8


@pytest.mark.parametrize("fixture, bits", [("dll_emu", 32), ("dll64_emu", 64)])
def test_query_process_basic_information(request: pytest.FixtureRequest, fixture: str, bits: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    ptr = bits // 8
    size = 6 * ptr
    proc = se.emu.get_current_process()

    rv, info, retlen = query(se, ddk.PROCESSINFOCLASS.ProcessBasicInformation, size)
    assert rv == ddk.STATUS_SUCCESS
    assert retlen == size
    fmt = "<" + ("I" if bits == 32 else "Q") * 6
    exit_status, peb, affinity, priority, pid, parent = struct.unpack(fmt, info[:size])
    assert exit_status == 0x103
    assert peb == proc.peb.address
    assert affinity == 1
    assert priority == 8
    assert pid == proc.pid
    explorer = [p for p in se.emu.get_processes() if p.name.lower() == "explorer"]
    assert parent == explorer[0].pid

    rv, info, _ = query(se, ddk.PROCESSINFOCLASS.ProcessBasicInformation, size - 1)
    assert rv == ddk.STATUS_INFO_LENGTH_MISMATCH
    assert info[:size] == b"\xcc" * size
