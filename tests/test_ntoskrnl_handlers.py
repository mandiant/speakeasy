import struct
from typing import Any

import pytest

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ntoskrnl as ntdefs
from speakeasy import Speakeasy
from speakeasy.windows import objman
from speakeasy.winenv.api.usermode.msvcrt import Msvcrt
from speakeasy.winenv.defs.enums import TOKEN_INFORMATION_CLASS
from speakeasy.winenv.defs.nt import ddk
from tests.handler_harness import (
    alloc,
    ansi_string,
    call,
    get_kernel_emu,
    load_emu,
    object_attributes,
    start_process,
    unicode_string,
)

RET_ADDR = 0x41414141
CDECL = _arch.CALL_CONV_CDECL
STDCALL = _arch.CALL_CONV_STDCALL
FASTCALL = _arch.CALL_CONV_FASTCALL


def call_x86(se: Speakeasy, name: str, args: list[int], conv: int) -> tuple[int, int]:
    """
    Call ``name`` through import dispatch with ``args`` laid out as the caller passes them.

    Return EAX and the number of argument bytes the callee left on the stack.
    """
    emu = se.emu
    top = emu.stack_base - 0x100
    emu.set_func_args(top, RET_ADDR, *args, conv=conv)
    emu.reg_write(_arch.X86_REG_EIP, 0x1000)
    emu.dispatch_api_call("ntoskrnl", name)
    assert emu.reg_read(_arch.X86_REG_EIP) == RET_ADDR
    return emu.reg_read(_arch.X86_REG_EAX), top - emu.reg_read(_arch.X86_REG_ESP)


BUF = -1


@pytest.mark.parametrize(
    ("name", "args", "conv"),
    [
        ("memmove", [BUF, BUF, 4], CDECL),
        ("wcsnlen", [BUF, 4], CDECL),
        ("mbstowcs", [BUF, BUF, 4], CDECL),
        ("ObfReferenceObject", [BUF], FASTCALL),
        ("ExAcquireFastMutex", [BUF], FASTCALL),
        ("ExReleaseFastMutex", [BUF], FASTCALL),
        ("KeSetTimer", [BUF, 0, 0, 0], STDCALL),
        ("CmUnRegisterCallback", [0, 0], STDCALL),
        ("ExAllocatePool2", [0x40, 0, 0x10, 0x6B736154], STDCALL),
        ("KdChangeOption", [0, 0, 0, 0, 0, 0], STDCALL),
    ],
)
def test_x86_callee_cleans_the_stack_per_its_convention(
    driver_emu: Speakeasy, name: str, args: list[int], conv: int
) -> None:
    buf = alloc(driver_emu, b"\x00" * 16)
    args = [buf if a == BUF else a for a in args]
    _, left = call_x86(driver_emu, name, args, conv)
    assert left == (4 * len(args) if conv == CDECL else 0)


def test_x86_ex_allocate_pool2_reads_the_64_bit_flags(driver_emu: Speakeasy) -> None:
    pool_flag_paged = 0x100
    addr, _ = call_x86(driver_emu, "ExAllocatePool2", [pool_flag_paged, 0, 0x10, 0x6B736154], STDCALL)
    assert addr
    assert get_kernel_emu(driver_emu).pool_allocs[-1] == (addr, ddk.POOL_TYPE.PagedPool, 0x10, "Task")


def test_x64_ex_allocate_pool2_reads_the_flags_slot(driver64_emu: Speakeasy) -> None:
    pool_flag_non_paged = 0x40
    addr, displays = call(driver64_emu, "ntoskrnl", "ExAllocatePool2", [pool_flag_non_paged, 0x10, 0x6B736154, 0])
    assert addr
    assert get_kernel_emu(driver64_emu).pool_allocs[-1] == (addr, ddk.POOL_TYPE.NonPagedPool, 0x10, "Task")
    assert displays[2] == "Task"


@pytest.mark.parametrize(
    ("value", "count", "expected"),
    [
        (0x00000001_80000001, 1, 0x00000003_00000002),
        (0x00000000_12345678, 32, 0x12345678_00000000),
        (0x00000000_00000001, 63, 0x80000000_00000000),
        (0x00000000_00000001, 64, 0),
        (0x00000000_00000001, 0xFFFFFF04, 0x00000000_00000010),
    ],
)
def test_allshl_shifts_edx_eax_by_cl(driver_emu: Speakeasy, value: int, count: int, expected: int) -> None:
    emu = driver_emu.emu
    emu.reg_write(_arch.X86_REG_EAX, value & 0xFFFFFFFF)
    emu.reg_write(_arch.X86_REG_EDX, value >> 32)
    emu.reg_write(_arch.X86_REG_ECX, count)
    eax, left = call_x86(driver_emu, "_allshl", [], CDECL)
    assert (emu.reg_read(_arch.X86_REG_EDX) << 32 | eax) == expected
    assert left == 0


def test_zw_open_key_reports_a_missing_key(driver_emu: Speakeasy) -> None:
    phnd = alloc(driver_emu, b"\xcc" * 4)
    oa = object_attributes(driver_emu, "\\Registry\\Machine\\Software\\NoSuchVendor\\NoSuchKey")
    rv, _ = call(driver_emu, "ntoskrnl", "ZwOpenKey", [phnd, 0xF003F, oa])
    assert rv == ddk.STATUS_OBJECT_NAME_NOT_FOUND
    assert driver_emu.mem_read(phnd, 4) == b"\xcc" * 4


@pytest.mark.parametrize(
    ("a", "b", "length", "expected"),
    [
        (b"abcd", b"abcd", 4, 4),
        (b"abcd", b"abcx", 4, 3),
        (b"abcd", b"xbcd", 4, 0),
        (b"abcd", b"abcd", 0, 0),
    ],
)
def test_rtl_compare_memory_counts_matching_bytes(
    driver_emu: Speakeasy, a: bytes, b: bytes, length: int, expected: int
) -> None:
    rv, _ = call(driver_emu, "ntoskrnl", "RtlCompareMemory", [alloc(driver_emu, a), alloc(driver_emu, b), length])
    assert rv == expected


@pytest.mark.parametrize(
    "name",
    [
        "_snprintf",
        "_snprintf_s",
        "_snwprintf",
        "_stricmp",
        "_vsnprintf",
        "_vsnwprintf",
        "_wcsicmp",
        "_wcsnicmp",
        "mbstowcs",
        "memcpy",
        "memmove",
        "memset",
        "sprintf",
        "strchr",
        "strrchr",
        "vsprintf_s",
        "wcscat",
        "wcschr",
        "wcscpy",
        "wcslen",
        "wcsncpy",
    ],
)
def test_ntoskrnl_crt_function_runs_the_msvcrt_handler(driver_emu: Speakeasy, name: str) -> None:
    mod, _ = driver_emu.emu.get_api_handler("ntoskrnl", name)
    assert isinstance(mod, Msvcrt)


def test_zw_map_view_of_section_rejects_an_unknown_section(driver_emu: Speakeasy) -> None:
    base = alloc(driver_emu, b"\x00" * 4)
    view_size = alloc(driver_emu, b"\x00" * 4)
    argv = [0x1234, 0xFFFFFFFF, base, 0, 0, 0, view_size, 1, 0, 0x04]
    rv, _ = call(driver_emu, "ntoskrnl", "ZwMapViewOfSection", argv)
    assert rv == ddk.STATUS_INVALID_HANDLE


def test_zw_map_view_of_section_maps_the_whole_section_without_a_view_size(driver_emu: Speakeasy) -> None:
    phnd = alloc(driver_emu, b"\x00" * 4)
    max_size = alloc(driver_emu, (0x2000).to_bytes(8, "little"))
    rv, _ = call(driver_emu, "ntoskrnl", "ZwCreateSection", [phnd, 0xF001F, 0, max_size, 0x04, 0x8000000, 0])
    assert rv == ddk.STATUS_SUCCESS
    section = int.from_bytes(driver_emu.mem_read(phnd, 4), "little")

    base = alloc(driver_emu, b"\x00" * 4)
    argv = [section, 0xFFFFFFFF, base, 0, 0, 0, 0, 1, 0, 0x04]
    rv, _ = call(driver_emu, "ntoskrnl", "ZwMapViewOfSection", argv)
    assert rv == ddk.STATUS_SUCCESS
    view = int.from_bytes(driver_emu.mem_read(base, 4), "little")
    driver_emu.mem_write(view + 0x1FFF, b"\x01")


def read_unicode_string_x86(se: Speakeasy, addr: int) -> tuple[int, int, bytes]:
    length, max_length, buf = struct.unpack("<HHI", se.mem_read(addr, 8))
    return length, max_length, se.mem_read(buf, length)


def empty_unicode_string_x86(se: Speakeasy, max_length: int) -> int:
    buf = alloc(se, b"\xee" * max_length)
    return alloc(se, struct.pack("<HHI", 0, max_length, buf))


@pytest.mark.parametrize(
    ("max_length", "expected"),
    [
        (64, "hello"),
        (6, "hel"),
    ],
)
def test_rtl_copy_unicode_string_sets_the_destination_length(
    driver_emu: Speakeasy, max_length: int, expected: str
) -> None:
    dest = empty_unicode_string_x86(driver_emu, max_length)
    call(driver_emu, "ntoskrnl", "RtlCopyUnicodeString", [dest, unicode_string(driver_emu, "hello")])
    data = expected.encode("utf-16le")
    assert read_unicode_string_x86(driver_emu, dest) == (len(data), max_length, data)


def test_rtl_copy_unicode_string_empties_the_destination_for_a_null_source(driver_emu: Speakeasy) -> None:
    dest = empty_unicode_string_x86(driver_emu, 64)
    call(driver_emu, "ntoskrnl", "RtlCopyUnicodeString", [dest, unicode_string(driver_emu, "old")])
    call(driver_emu, "ntoskrnl", "RtlCopyUnicodeString", [dest, 0])
    assert read_unicode_string_x86(driver_emu, dest)[0] == 0


@pytest.mark.parametrize(
    ("flags", "text", "max_length", "terminated"),
    [
        (0, "hello", 10, False),
        (1, "hello", 12, True),
        (3, "", 2, True),
    ],
)
def test_rtl_duplicate_unicode_string_allocates_a_copy(
    driver_emu: Speakeasy, flags: int, text: str, max_length: int, terminated: bool
) -> None:
    src = unicode_string(driver_emu, text)
    out = alloc(driver_emu, b"\xee" * 8)
    assert call(driver_emu, "ntoskrnl", "RtlDuplicateUnicodeString", [flags, src, out])[0] == ddk.STATUS_SUCCESS
    data = text.encode("utf-16le")
    length, maximum, buf = struct.unpack("<HHI", driver_emu.mem_read(out, 8))
    assert (length, maximum) == (len(data), max_length)
    assert buf != struct.unpack("<I", driver_emu.mem_read(src + 4, 4))[0]
    assert driver_emu.mem_read(buf, length) == data
    if terminated:
        assert driver_emu.mem_read(buf + length, 2) == b"\x00\x00"


@pytest.mark.parametrize(("flags", "text"), [(1, ""), (0, "")])
def test_rtl_duplicate_unicode_string_returns_a_null_string_for_empty_input(
    driver_emu: Speakeasy, flags: int, text: str
) -> None:
    out = alloc(driver_emu, b"\xee" * 8)
    src = unicode_string(driver_emu, text)
    assert call(driver_emu, "ntoskrnl", "RtlDuplicateUnicodeString", [flags, src, out])[0] == ddk.STATUS_SUCCESS
    assert driver_emu.mem_read(out, 8) == b"\x00" * 8


@pytest.mark.parametrize(("flags", "has_out"), [(2, True), (4, True), (1, False)])
def test_rtl_duplicate_unicode_string_rejects_bad_parameters(driver_emu: Speakeasy, flags: int, has_out: bool) -> None:
    out = alloc(driver_emu, b"\xee" * 8) if has_out else 0
    src = unicode_string(driver_emu, "hello")
    rv = call(driver_emu, "ntoskrnl", "RtlDuplicateUnicodeString", [flags, src, out])[0]
    assert rv == ddk.STATUS_INVALID_PARAMETER


def test_x64_ps_create_system_thread_writes_pointer_size_ids(driver64_emu: Speakeasy) -> None:
    phnd = alloc(driver64_emu, b"\xcc" * 8)
    cid = alloc(driver64_emu, b"\xcc" * 16)
    rv, _ = call(driver64_emu, "ntoskrnl", "PsCreateSystemThread", [phnd, 0x1FFFFF, 0, 0, cid, 0x401000, 0])
    assert rv == ddk.STATUS_SUCCESS
    hnd = int.from_bytes(driver64_emu.mem_read(phnd, 8), "little")
    thread = driver64_emu.emu.get_object_from_handle(hnd)
    assert thread is not None
    assert struct.unpack("<QQ", driver64_emu.mem_read(cid, 16)) == (4, thread.tid)


def test_x64_io_create_synchronization_event_writes_a_pointer_size_handle(driver64_emu: Speakeasy) -> None:
    phnd = alloc(driver64_emu, b"\xcc" * 8)
    name = "\\BaseNamedObjects\\evt".encode("utf-16le")
    us = alloc(driver64_emu, struct.pack("<HHIQ", len(name), len(name), 0, alloc(driver64_emu, name)))
    evt, _ = call(driver64_emu, "ntoskrnl", "IoCreateSynchronizationEvent", [us, phnd])
    hnd = int.from_bytes(driver64_emu.mem_read(phnd, 8), "little")
    assert driver64_emu.emu.get_object_from_handle(hnd).address == evt


def unnamed_object_attributes(se: Speakeasy) -> int:
    return alloc(se, struct.pack("<IIIIII", 24, 0, 0, 0, 0, 0))


@pytest.mark.parametrize("name", [None, "", "\\BaseNamedObjects\\evt"])
def test_zw_create_event_accepts_an_unnamed_event(driver_emu: Speakeasy, name: str | None) -> None:
    oa = 0
    if name == "":
        oa = unnamed_object_attributes(driver_emu)
    elif name:
        oa = object_attributes(driver_emu, name)
    phnd = alloc(driver_emu, b"\x00" * 4)
    rv, _ = call(driver_emu, "ntoskrnl", "ZwCreateEvent", [phnd, 0x1F0003, oa, 0, 0])
    assert rv == ddk.STATUS_SUCCESS
    hnd = int.from_bytes(driver_emu.mem_read(phnd, 4), "little")
    assert driver_emu.emu.get_object_from_handle(hnd) is not None


@pytest.mark.parametrize("with_oa", [False, True])
def test_zw_open_event_without_a_name_finds_nothing(driver_emu: Speakeasy, with_oa: bool) -> None:
    oa = unnamed_object_attributes(driver_emu) if with_oa else 0
    phnd = alloc(driver_emu, b"\x00" * 4)
    rv, _ = call(driver_emu, "ntoskrnl", "ZwOpenEvent", [phnd, 0x1F0003, oa])
    assert rv == ddk.STATUS_OBJECT_NAME_NOT_FOUND


def test_rtl_init_ansi_string_accepts_a_null_source(driver_emu: Speakeasy) -> None:
    dest = alloc(driver_emu, b"\xcc" * 8)
    call(driver_emu, "ntoskrnl", "RtlInitAnsiString", [dest, 0])
    assert driver_emu.mem_read(dest, 8) == b"\x00" * 8


@pytest.mark.parametrize(
    ("name", "argv", "status"),
    [
        ("ObOpenObjectByPointer", [0x1234, 0, 0, 0, 0, 0, "out"], ddk.STATUS_INVALID_PARAMETER),
        ("ZwWriteVirtualMemory", [0x1234, "out", "out", 4, 0], ddk.STATUS_INVALID_HANDLE),
        ("ZwAllocateVirtualMemory", [0x1234, "out", 0, "size", 0x3000, 0x04], ddk.STATUS_INVALID_HANDLE),
    ],
)
def test_unknown_objects_fail_with_a_status(driver_emu: Speakeasy, name: str, argv: list, status: int) -> None:
    slots = {"out": alloc(driver_emu, b"\x00" * 8), "size": alloc(driver_emu, (0x1000).to_bytes(4, "little"))}
    rv, _ = call(driver_emu, "ntoskrnl", name, [slots[a] if isinstance(a, str) else a for a in argv])
    assert rv == status


def set_current_system_thread(se: Speakeasy) -> None:
    emu = get_kernel_emu(se)
    assert emu.om is not None
    emu.get_current_process()
    proc = emu.get_system_process()
    emu.set_current_process(proc)
    thread = objman.Thread(emu, stack_base=emu.stack_base, stack_commit=0x1000)
    emu.om.objects.update({thread.address: thread})
    proc.threads.append(thread)
    emu.set_current_thread(thread)


@pytest.mark.parametrize("pseudo", ["process", "thread"])
def test_ob_reference_object_by_handle_resolves_pseudo_handles(driver_emu: Speakeasy, pseudo: str) -> None:
    set_current_system_thread(driver_emu)
    emu = driver_emu.emu
    hnd, expected = (
        (0xFFFFFFFF, emu.get_current_process()) if pseudo == "process" else (0xFFFFFFFE, emu.get_current_thread())
    )
    out = alloc(driver_emu, b"\x00" * 4)
    rv, _ = call(driver_emu, "ntoskrnl", "ObReferenceObjectByHandle", [hnd, 0x1FFFFF, 0, 0, out, 0])
    assert rv == ddk.STATUS_SUCCESS
    assert int.from_bytes(driver_emu.mem_read(out, 4), "little") == expected.address


def test_rtl_ansi_string_to_unicode_string_keeps_the_caller_buffer_size(driver_emu: Speakeasy) -> None:
    dest = empty_unicode_string_x86(driver_emu, 64)
    rv, _ = call(driver_emu, "ntoskrnl", "RtlAnsiStringToUnicodeString", [dest, ansi_string(driver_emu, b"ab"), 0])
    assert rv == ddk.STATUS_SUCCESS
    assert read_unicode_string_x86(driver_emu, dest) == (4, 64, "ab".encode("utf-16le"))


@pytest.mark.parametrize(("limit", "expected"), [(3, 3), (8, 8), (20, 8)])
def test_wcsnlen_stops_at_the_limit(driver_emu: Speakeasy, limit: int, expected: int) -> None:
    s = alloc(driver_emu, "abcdefgh\0".encode("utf-16le"))
    rv, _ = call(driver_emu, "ntoskrnl", "wcsnlen", [s, limit])
    assert rv == expected


@pytest.mark.parametrize(("limit", "expected"), [(3, 3), (8, 8), (20, 8)])
def test_strnlen_stops_at_the_limit(driver_emu: Speakeasy, limit: int, expected: int) -> None:
    s = alloc(driver_emu, b"abcdefgh\0")
    rv, _ = call(driver_emu, "ntoskrnl", "strnlen", [s, limit])
    assert rv == expected


@pytest.mark.parametrize(("length", "status"), [(8, ddk.STATUS_SUCCESS), (4, ddk.STATUS_INFO_LENGTH_MISMATCH)])
def test_x64_zw_query_information_process_wow64(driver64_emu: Speakeasy, length: int, status: int) -> None:
    emu = get_kernel_emu(driver64_emu)
    emu.get_current_process()
    emu.set_current_process(emu.get_system_process())
    info = alloc(driver64_emu, b"\xcc" * 8)
    retlen = alloc(driver64_emu, b"\xcc" * 8)
    wow64_information = ddk.PROCESSINFOCLASS.ProcessWow64Information
    argv = [0xFFFFFFFF_FFFFFFFF, wow64_information, info, length, retlen]
    rv, _ = call(driver64_emu, "ntoskrnl", "ZwQueryInformationProcess", argv)
    assert rv == status
    assert driver64_emu.mem_read(retlen, 8) == b"\x08\x00\x00\x00" + b"\xcc" * 4
    if status == ddk.STATUS_SUCCESS:
        assert driver64_emu.mem_read(info, 8) == b"\x00" * 8


@pytest.mark.parametrize("name", ["ZwGetContextThread", "ZwSetContextThread"])
def test_context_thread_calls_return_ntstatus(driver_emu: Speakeasy, name: str) -> None:
    set_current_system_thread(driver_emu)
    emu = driver_emu.emu
    hnd = emu.get_object_handle(emu.get_current_thread())
    context = alloc(driver_emu, b"\x00" * 0x2CC)
    assert call(driver_emu, "ntoskrnl", name, [hnd, context])[0] == ddk.STATUS_SUCCESS
    assert call(driver_emu, "ntoskrnl", name, [0xFFFFFFFE, context])[0] == ddk.STATUS_SUCCESS
    assert call(driver_emu, "ntoskrnl", name, [0x1234, context])[0] == ddk.STATUS_INVALID_HANDLE


def test_x64_io_allocate_mdl_splits_a_high_address(driver64_emu: Speakeasy) -> None:
    va = 0xFFFFF80012345678
    p_mdl, _ = call(driver64_emu, "ntoskrnl", "IoAllocateMdl", [va, 0x100, 0, 0, 0])
    mdl = ntdefs.MDL(8)
    mdl = mdl.cast(driver64_emu.mem_read(p_mdl, mdl.sizeof()))
    assert (mdl.StartVa, mdl.ByteOffset, mdl.ByteCount) == (0xFFFFF80012345000, 0x678, 0x100)
    assert mdl.MdlFlags == 0x8


def test_mm_map_locked_pages_maps_the_mdl_memory(driver_emu: Speakeasy) -> None:
    buf = alloc(driver_emu, b"original")
    p_mdl, _ = call(driver_emu, "ntoskrnl", "IoAllocateMdl", [buf, 8, 0, 0, 0])
    mapped, _ = call(driver_emu, "ntoskrnl", "MmMapLockedPagesSpecifyCache", [p_mdl, 0, 1, 0, 0, 0x10])
    assert driver_emu.mem_read(mapped, 8) == b"original"
    driver_emu.mem_write(mapped, b"patched!")
    assert driver_emu.mem_read(buf, 8) == b"patched!"


def test_rtl_decompress_buffer_rejects_xpress(driver_emu: Speakeasy) -> None:
    comp = alloc(driver_emu, bytes.fromhex("ffffffff") + b"abc")
    out = alloc(driver_emu, b"\x00" * 0x100)
    final = alloc(driver_emu, b"\xcc" * 4)
    argv = [ddk.COMPRESSION_FORMAT_XPRESS, out, 0x100, comp, 7, final]
    rv, _ = call(driver_emu, "ntoskrnl", "RtlDecompressBuffer", argv)
    assert rv == ddk.STATUS_UNSUPPORTED_COMPRESSION


@pytest.mark.parametrize("data", [b"\x00", b"\x05\xb0abc", b"\x02\xb0\x01\x00\x00"])
def test_rtl_decompress_buffer_reports_bad_lznt1_data(driver_emu: Speakeasy, data: bytes) -> None:
    comp = alloc(driver_emu, data)
    out = alloc(driver_emu, b"\x00" * 0x100)
    final = alloc(driver_emu, b"\xcc" * 4)
    argv = [ddk.COMPRESSION_FORMAT_LZNT1, out, 0x100, comp, len(data), final]
    rv, _ = call(driver_emu, "ntoskrnl", "RtlDecompressBuffer", argv)
    assert rv == ddk.STATUS_BAD_COMPRESSION_BUFFER


def test_zw_query_system_information_rejects_an_unhandled_class(driver_emu: Speakeasy) -> None:
    info = alloc(driver_emu, b"\x00" * 0x40)
    retlen = alloc(driver_emu, b"\xcc" * 4)
    rv, _ = call(driver_emu, "ntoskrnl", "ZwQuerySystemInformation", [0, info, 0x40, retlen])
    assert rv == ddk.STATUS_INVALID_INFO_CLASS
    assert driver_emu.mem_read(retlen, 4) == b"\xcc" * 4


def test_ob_reference_object_by_name_finds_a_configured_driver(driver_emu: Speakeasy) -> None:
    emu = driver_emu.emu
    out = alloc(driver_emu, b"\xcc" * 4)
    argv = [unicode_string(driver_emu, "\\Driver\\Disk"), 0, 0, 0, 0, 0, 0, out]
    assert call(driver_emu, "ntoskrnl", "ObReferenceObjectByName", argv)[0] == ddk.STATUS_SUCCESS
    drv = emu.get_object_from_addr(struct.unpack("<I", driver_emu.mem_read(out, 4))[0])
    assert isinstance(drv, objman.Driver)
    assert drv.name == "\\Driver\\Disk"


def test_ob_reference_object_by_name_rejects_an_unknown_driver(driver_emu: Speakeasy) -> None:
    out = alloc(driver_emu, b"\xcc" * 4)
    argv = [unicode_string(driver_emu, "\\Driver\\NoSuchDriver"), 0, 0, 0, 0, 0, 0, out]
    assert call(driver_emu, "ntoskrnl", "ObReferenceObjectByName", argv)[0] == ddk.STATUS_OBJECT_NAME_NOT_FOUND
    assert driver_emu.mem_read(out, 4) == b"\xcc" * 4


def test_ps_get_process_id_reads_the_eprocess(driver_emu: Speakeasy) -> None:
    set_current_system_thread(driver_emu)
    emu = driver_emu.emu
    proc = emu.get_current_process()
    pid, _ = call(driver_emu, "ntoskrnl", "PsGetProcessId", [proc.address])
    assert pid == proc.pid
    assert call(driver_emu, "ntoskrnl", "PsGetProcessId", [0x1234])[0] == 0


def open_section(se: Speakeasy, name: str) -> tuple[int, bytes]:
    phnd = alloc(se, b"\xcc" * 4)
    rv, _ = call(se, "ntdll", "NtOpenSection", [phnd, 4, object_attributes(se, name)])
    return rv, se.mem_read(phnd, 4)


def test_nt_open_section_denies_physical_memory(dll_emu: Speakeasy) -> None:
    assert open_section(dll_emu, "\\Device\\PhysicalMemory") == (ddk.STATUS_ACCESS_DENIED, b"\xcc" * 4)


def test_nt_open_section_reports_a_missing_section(dll_emu: Speakeasy) -> None:
    assert open_section(dll_emu, "\\BaseNamedObjects\\NoSuchSection") == (
        ddk.STATUS_OBJECT_NAME_NOT_FOUND,
        b"\xcc" * 4,
    )


def test_nt_open_section_opens_a_named_section(dll_emu: Speakeasy) -> None:
    phnd = alloc(dll_emu, b"\0" * 4)
    size = alloc(dll_emu, struct.pack("<Q", 0x1000))
    oa = object_attributes(dll_emu, "\\BaseNamedObjects\\Shared")
    rv, _ = call(dll_emu, "ntdll", "NtCreateSection", [phnd, 0xF001F, oa, size, 4, 0x8000000, 0])
    assert rv == ddk.STATUS_SUCCESS

    rv, handle = open_section(dll_emu, "\\Sessions\\1\\BaseNamedObjects\\shared")
    assert rv == ddk.STATUS_SUCCESS
    fman = dll_emu.emu.get_file_manager()
    mapping = fman.get_mapping(int.from_bytes(handle, "little"))
    assert mapping is fman.get_mapping(int.from_bytes(dll_emu.mem_read(phnd, 4), "little"))


def read_ptr(se: Speakeasy, addr: int) -> int:
    return int.from_bytes(se.mem_read(addr, se.emu.get_ptr_size()), "little")


def open_process(se: Speakeasy, dll: str, pid: int | None) -> tuple[int, int]:
    ptr_size = se.emu.get_ptr_size()
    out = alloc(se, b"\xcc" * ptr_size)
    cid = 0 if pid is None else alloc(se, pid.to_bytes(ptr_size, "little") + bytes(ptr_size))
    rv, _ = call(se, dll, "NtOpenProcess", [out, 0x400, alloc(se, bytes(0x30)), cid])
    return rv, read_ptr(se, out)


def open_process_token(se: Speakeasy, dll: str, process: int) -> int:
    out = alloc(se, b"\xcc" * se.emu.get_ptr_size())
    rv, _ = call(se, dll, "NtOpenProcessToken", [process, 8, out])
    assert rv == ddk.STATUS_SUCCESS
    return read_ptr(se, out)


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_nt_query_information_token_gives_the_user_sid_of_an_opened_process(
    request: pytest.FixtureRequest, fixture: str
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    ptr_size = se.emu.get_ptr_size()
    rv, process = open_process(se, "ntdll", se.emu.get_current_process().pid)
    assert rv == ddk.STATUS_SUCCESS
    token = open_process_token(se, "ntdll", process)

    ret_len = alloc(se, bytes(4))
    argv = [token, TOKEN_INFORMATION_CLASS.TokenUser, 0, 0, ret_len]
    rv, _ = call(se, "ntdll", "NtQueryInformationToken", argv)
    size = int.from_bytes(se.mem_read(ret_len, 4), "little")
    assert (rv, size) == (ddk.STATUS_BUFFER_TOO_SMALL, 2 * ptr_size + 28)

    info = alloc(se, b"\xcc" * size)
    argv = [token, TOKEN_INFORMATION_CLASS.TokenUser, info, size, ret_len]
    rv, _ = call(se, "ntdll", "NtQueryInformationToken", argv)
    sid = read_ptr(se, info)
    assert (rv, sid) == (ddk.STATUS_SUCCESS, info + 2 * ptr_size)
    authority = bytes([1, 5]) + (5).to_bytes(6, "big")
    assert se.mem_read(sid, 28) == authority + struct.pack("<5I", 21, 1111111111, 2222222222, 3333333333, 1001)


@pytest.mark.parametrize(
    ("pid", "status"), [(0xFFF0, ddk.STATUS_INVALID_CID), (None, ddk.STATUS_INVALID_PARAMETER_MIX)]
)
def test_nt_open_process_rejects_a_missing_process(dll_emu: Speakeasy, pid: int | None, status: int) -> None:
    start_process(dll_emu)
    assert open_process(dll_emu, "ntdll", pid) == (status, 0xCCCCCCCC)


@pytest.mark.parametrize(
    ("length", "status"),
    [(4, ddk.STATUS_SUCCESS), (0, ddk.STATUS_INFO_LENGTH_MISMATCH), (8, ddk.STATUS_INFO_LENGTH_MISMATCH)],
)
def test_nt_query_information_token_needs_the_exact_elevation_size(
    dll_emu: Speakeasy, length: int, status: int
) -> None:
    start_process(dll_emu)
    token = open_process_token(dll_emu, "ntdll", 0xFFFFFFFF)
    info = alloc(dll_emu, b"\xcc" * 8)
    argv = [token, TOKEN_INFORMATION_CLASS.TokenElevation, info, length, alloc(dll_emu, bytes(4))]
    rv, _ = call(dll_emu, "ntdll", "NtQueryInformationToken", argv)
    elevated = struct.pack("<I", dll_emu.emu.config.user.is_admin)
    expected = elevated if status == ddk.STATUS_SUCCESS else b"\xcc" * 4
    assert (rv, dll_emu.mem_read(info, 4)) == (status, expected)


def test_zw_open_process_opens_the_system_process(driver_emu: Speakeasy) -> None:
    rv, process = open_process(driver_emu, "ntoskrnl", 4)
    assert rv == ddk.STATUS_SUCCESS
    token = open_process_token(driver_emu, "ntoskrnl", process)
    ret_len = alloc(driver_emu, bytes(4))
    argv = [token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, 0, 0, ret_len]
    assert call(driver_emu, "ntoskrnl", "ZwQueryInformationToken", argv)[0] == ddk.STATUS_BUFFER_TOO_SMALL
    assert driver_emu.mem_read(ret_len, 4) == struct.pack("<I", 20)


def test_x86_ke_query_performance_counter_returns_in_edx_eax(driver_emu: Speakeasy) -> None:
    freq = alloc(driver_emu, b"\x00" * 8)
    rv, _ = call(driver_emu, "hal", "KeQueryPerformanceCounter", [freq])
    counter = driver_emu.emu.reg_read(_arch.X86_REG_EDX) << 32 | rv
    assert counter > 0xFFFFFFFF
    assert struct.unpack("<Q", driver_emu.mem_read(freq, 8))[0] == 10_000_000


def test_x64_ke_query_performance_counter_accepts_a_null_frequency(driver64_emu: Speakeasy) -> None:
    first, _ = call(driver64_emu, "hal", "KeQueryPerformanceCounter", [0])
    second, _ = call(driver64_emu, "hal", "KeQueryPerformanceCounter", [0])
    assert 0 < first < second


def test_x64_ke_get_current_irql_reports_the_emulator_irql(driver64_emu: Speakeasy) -> None:
    get_kernel_emu(driver64_emu).set_current_irql(ddk.DISPATCH_LEVEL)
    assert call(driver64_emu, "ntoskrnl", "KeGetCurrentIrql", [])[0] == ddk.DISPATCH_LEVEL


def test_io_queue_work_item_runs_the_routine_with_the_device_and_context(driver_emu: Speakeasy) -> None:
    device = 0x7000
    item = call(driver_emu, "ntoskrnl", "IoAllocateWorkItem", [device])[0]
    assert item
    call(driver_emu, "ntoskrnl", "IoQueueWorkItem", [item, 0x401000, 1, 0x1234])
    assert [cb.function for cb in driver_emu.emu.get_current_run().guest_callbacks] == [0x401000]
    sp = driver_emu.emu.get_stack_ptr()
    assert struct.unpack("<3I", driver_emu.mem_read(sp, 12))[1:] == (device, 0x1234)
    call(driver_emu, "ntoskrnl", "IoFreeWorkItem", [item])


TRUNCATE = 0xFFFFFFFF


@pytest.mark.parametrize(
    ("size", "count", "rv", "written"),
    [
        (16, TRUNCATE, 5, b"ab-42\0"),
        (4, TRUNCATE, -1, b"ab-\0"),
        (16, 3, -1, b"ab-\0"),
        (6, 5, 5, b"ab-42\0"),
        (4, 8, -1, b"\0"),
    ],
)
@pytest.mark.parametrize("name", ["_snprintf_s", "_vsnprintf_s"])
def test_snprintf_s_always_ends_the_string(
    driver_emu: Speakeasy, name: str, size: int, count: int, rv: int, written: bytes
) -> None:
    out = alloc(driver_emu, b"\xee" * 32)
    args = [alloc(driver_emu, b"ab\0"), 42]
    if name.startswith("_v"):
        args = [alloc(driver_emu, struct.pack("<2I", *args))]
    result, _ = call(driver_emu, "ntoskrnl", name, [out, size, count, alloc(driver_emu, b"%s-%d\0"), *args])
    assert result & 0xFFFFFFFF == rv & 0xFFFFFFFF
    assert driver_emu.mem_read(out, len(written) + 1) == written + b"\xee"


@pytest.mark.parametrize(("name", "head"), [("vDbgPrintEx", []), ("vDbgPrintExWithPrefix", ["[drv] "])])
def test_vdbgprintex_formats_the_message(driver_emu: Speakeasy, name: str, head: list[str]) -> None:
    prefix = [alloc(driver_emu, (h + "\0").encode()) for h in head]
    fmt = alloc(driver_emu, b"%s=%d\0")
    args = alloc(driver_emu, struct.pack("<2I", alloc(driver_emu, b"pid\0"), 4))
    rv, displays = call(driver_emu, "ntoskrnl", name, [*prefix, 0x4D, 3, fmt, args])
    assert rv == ddk.STATUS_SUCCESS
    assert "".join(head) + "pid=4" in displays.values()


def io_status(se: Speakeasy, addr: int) -> tuple[int, int]:
    ios = se.mem_cast(ntdefs.IO_STATUS_BLOCK(se.get_ptr_size()), addr)
    return ios.Status, ios.Information


def test_nt_write_and_read_file_fill_the_io_status_block(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    path = alloc(se, b"C:\\Windows\\Temp\\nt_io.bin\0")
    handle = call(se, "kernel32", "CreateFileA", [path, 0xC0000000, 0, 0, 2, 0x80, 0])[0]
    ios = alloc(se, b"\xff" * 16)
    data = alloc(se, b"hello world")

    assert call(se, "ntdll", "NtWriteFile", [handle, 0, 0, 0, ios, data, 11, 0, 0])[0] == ddk.STATUS_SUCCESS
    assert io_status(se, ios) == (0, 11)

    offset = alloc(se, struct.pack("<q", 6))
    out = alloc(se, b"\0" * 16)
    assert call(se, "ntdll", "NtReadFile", [handle, 0, 0, 0, ios, out, 3, offset, 0])[0] == ddk.STATUS_SUCCESS
    assert io_status(se, ios) == (0, 3)
    assert se.mem_read(out, 4) == b"wor\0"

    assert call(se, "ntdll", "NtReadFile", [handle, 0, 0, 0, ios, out, 16, 0, 0])[0] == ddk.STATUS_SUCCESS
    assert io_status(se, ios) == (0, 2)
    assert call(se, "ntdll", "NtReadFile", [handle, 0, 0, 0, ios, out, 16, 0, 0])[0] == ddk.STATUS_END_OF_FILE
    assert io_status(se, ios) == (ddk.STATUS_END_OF_FILE, 0)


def test_rtl_allocate_heap_blocks_can_be_freed(driver64_emu: Speakeasy) -> None:
    addr, _ = call(driver64_emu, "ntoskrnl", "RtlAllocateHeap", [0, 0, 0x20])
    assert addr
    freed, _ = call(driver64_emu, "ntoskrnl", "RtlFreeHeap", [0, 0, addr])
    assert freed == 1


def query_time_of_day(se: Speakeasy, dll: str, length: int) -> tuple[int, int, bytes]:
    buf = alloc(se, b"\xcc" * 0x40)
    retlen = alloc(se, b"\0" * 4)
    rv, _ = call(
        se,
        dll,
        "NtQuerySystemInformation",
        [ddk.SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation, buf, length, retlen],
    )
    return rv, int.from_bytes(se.mem_read(retlen, 4), "little"), bytes(se.mem_read(buf, 0x40))


def get_file_time(se: Speakeasy) -> int:
    ft = alloc(se, b"\0" * 8)
    call(se, "kernel32", "GetSystemTimeAsFileTime", [ft])
    return int.from_bytes(se.mem_read(ft, 8), "little")


def test_nt_query_system_time_of_day_follows_the_kernel32_clock(dll_emu: Speakeasy) -> None:
    before = get_file_time(dll_emu)
    rv, size, data = query_time_of_day(dll_emu, "ntdll", 48)
    after = get_file_time(dll_emu)

    assert (rv, size) == (ddk.STATUS_SUCCESS, 48)
    boot, current, bias, zone_id, _, boot_bias, sleep_bias = struct.unpack_from("<QQQIIQQ", data)
    assert 0 < boot < before < current < after
    assert (bias, zone_id, boot_bias, sleep_bias) == (0, 0, 0, 0)
    assert data[48:] == b"\xcc" * 16


def test_nt_query_system_time_of_day_fills_a_short_buffer(dll_emu: Speakeasy) -> None:
    rv, size, data = query_time_of_day(dll_emu, "ntdll", 32)
    tick_count, _ = call(dll_emu, "kernel32", "GetTickCount", [])

    assert (rv, size) == (ddk.STATUS_SUCCESS, 32)
    assert data[32:] == b"\xcc" * 32
    boot, current = struct.unpack_from("<QQ", data)
    assert 0 < tick_count - (current - boot) // 10000 <= 20


def test_nt_query_system_time_of_day_rejects_a_long_buffer(dll_emu: Speakeasy) -> None:
    rv, _, data = query_time_of_day(dll_emu, "ntdll", 49)

    assert rv == ddk.STATUS_INFO_LENGTH_MISMATCH
    assert data == b"\xcc" * 0x40


@pytest.mark.parametrize("name", ["KeQuerySystemTime", "KeQuerySystemTimePrecise"])
def test_ke_query_system_time_shares_the_clock_of_zw_query_system_information(driver_emu: Speakeasy, name: str) -> None:
    def query_system_time() -> int:
        out = alloc(driver_emu, b"\0" * 8)
        call(driver_emu, "ntoskrnl", name, [out])
        return int.from_bytes(driver_emu.mem_read(out, 8), "little")

    before = query_system_time()
    _, _, data = query_time_of_day(driver_emu, "ntoskrnl", 48)
    after = query_system_time()

    assert before < struct.unpack_from("<Q", data, 8)[0] < after


def test_rtl_time_to_time_fields_splits_the_time(driver_emu: Speakeasy) -> None:
    # 2021-03-14 15:09:26.535 UTC, a Sunday, in 100 ns units since 1601-01-01
    time = alloc(driver_emu, struct.pack("<Q", 132602081665350000))
    fields = alloc(driver_emu, b"\xcc" * 16)

    call(driver_emu, "ntoskrnl", "RtlTimeToTimeFields", [time, fields])

    assert struct.unpack("<8H", driver_emu.mem_read(fields, 16)) == (2021, 3, 14, 15, 9, 26, 535, 0)


def test_ps_get_version_writes_zero_for_a_null_build(config: dict[str, Any], load_test_bin: Any) -> None:
    config["os_ver"] = {"major": 6, "minor": 1, "build": None}
    for se in load_emu(config, load_test_bin("wdm_test_x86.sys.xz")):
        out = alloc(se, b"\xcc" * 12)
        rv, _ = call(se, "ntoskrnl", "PsGetVersion", [out, out + 4, out + 8, 0])
        assert rv == 0
        assert struct.unpack("<III", se.mem_read(out, 12)) == (6, 1, 0)


def test_rtl_sid_functions_build_the_administrators_sid(driver_emu: Speakeasy) -> None:
    size = call(driver_emu, "ntoskrnl", "RtlLengthRequiredSid", [2])[0]
    sid = alloc(driver_emu, b"\xcc" * size)
    nt_authority = alloc(driver_emu, bytes([0, 0, 0, 0, 0, 5]))
    assert call(driver_emu, "ntoskrnl", "RtlInitializeSid", [sid, nt_authority, 2])[0] == ddk.STATUS_SUCCESS
    for index, value in enumerate((32, 544)):
        ptr = call(driver_emu, "ntoskrnl", "RtlSubAuthoritySid", [sid, index])[0]
        driver_emu.mem_write(ptr, struct.pack("<I", value))
    # S-1-5-32-544
    assert driver_emu.mem_read(sid, size) == bytes.fromhex("0102000000000005") + struct.pack("<II", 32, 544)
