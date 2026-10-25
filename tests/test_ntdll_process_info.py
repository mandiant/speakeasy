import struct

import pytest

import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.kernel32 import PROCESSOR_COUNT
from tests.handler_harness import alloc, call, start_process

CURRENT_THREAD = 0xFFFFFFFF_FFFFFFFE
PROCESS_DEBUG_FLAGS = 0x1F
THREAD_HIDE_FROM_DEBUGGER = 0x11


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


@pytest.mark.parametrize(
    ("handle", "info", "length", "status"),
    [
        (CURRENT_THREAD, True, 12345, ddk.STATUS_INFO_LENGTH_MISMATCH),
        (0xFFFF, False, 0, ddk.STATUS_INVALID_HANDLE),
        (CURRENT_THREAD, False, 0, ddk.STATUS_SUCCESS),
    ],
)
def test_set_thread_hide_from_debugger_checks_its_arguments(
    dll64_emu: Speakeasy, handle: int, info: bool, length: int, status: int
) -> None:
    start_process(dll64_emu)
    buf = alloc(dll64_emu, b"\x00" * 8) if info else 0
    rv, _ = call(dll64_emu, "ntdll", "NtSetInformationThread", [handle, THREAD_HIDE_FROM_DEBUGGER, buf, length])
    assert rv == status


@pytest.mark.parametrize(
    "arch, start, stop, offset",
    [
        ("x86", 0x4613, 0x4626, 0x64),
        ("x64", 0x4212, 0x422F, 0xB8),
    ],
    ids=["x86", "x64"],
)
def test_peb_number_of_processors_matches_get_system_info(
    config: dict, load_test_bin, arch: str, start: int, stop: int, offset: int
) -> None:
    """
    al-khaser reads NumberOfProcessors from the PEB, at eax/rax + offset, and reports a
    virtual machine when it is less than 2: cl = NumberOfProcessors < 2, then a call to its
    report function.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(f"al-khaser_{arch}.exe.xz"))
        seen = []

        def at_report(emu, address, size):
            peb = se.reg_read("eax" if arch == "x86" else "rax")
            processors = int.from_bytes(se.mem_read(peb + offset, 4), "little")
            seen.append((processors, se.reg_read("ecx") & 0xFF))
            se.stop()

        se.add_code_hook(at_report, begin=module.base + stop, end=module.base + stop)
        se.run_module(module, entry_point=start)
        run = next(e for e in se.get_report().entry_points if e.ep_type == "module_entry")

    assert run.error is None
    assert seen == [(PROCESSOR_COUNT, 0)]
