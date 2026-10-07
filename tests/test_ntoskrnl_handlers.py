import struct

import pytest

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, object_attributes, unicode_string

RET_ADDR = 0x41414141
CDECL = _arch.CALL_CONV_CDECL
STDCALL = _arch.CALL_CONV_STDCALL
FASTCALL = _arch.CALL_CONV_FASTCALL


def call_x86(se: Speakeasy, name: str, args: list[int], conv: int) -> tuple[int, int]:
    """
    Call ``name`` through import dispatch with ``args`` laid out as the
    caller passes them. Return EAX and the number of argument bytes the callee
    left on the stack.
    """
    emu = se.emu
    assert emu is not None
    top = emu.stack_base - 0x100
    emu.set_func_args(top, RET_ADDR, *args, conv=conv)
    emu.reg_write(_arch.X86_REG_EIP, 0x1000)
    emu.handle_import_func("ntoskrnl", name)
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
    assert driver_emu.emu.pool_allocs[-1] == (addr, ddk.POOL_TYPE.PagedPool, 0x10, "Task")


def test_x64_ex_allocate_pool2_reads_the_flags_slot(driver64_emu: Speakeasy) -> None:
    pool_flag_non_paged = 0x40
    addr, displays = call(driver64_emu, "ntoskrnl", "ExAllocatePool2", [pool_flag_non_paged, 0x10, 0x6B736154, 0])
    assert addr
    assert driver64_emu.emu.pool_allocs[-1] == (addr, ddk.POOL_TYPE.NonPagedPool, 0x10, "Task")
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


def test_memset_fills_with_the_low_byte_of_c(driver_emu: Speakeasy) -> None:
    buf = alloc(driver_emu, b"\x00" * 8)
    rv, _ = call(driver_emu, "ntoskrnl", "memset", [buf, 0xFFFFFFFF, 4])
    assert rv == buf
    assert driver_emu.mem_read(buf, 8) == b"\xff" * 4 + b"\x00" * 4


@pytest.mark.parametrize(
    ("name", "text", "c", "offset"),
    [
        ("strchr", b"caf\xe9!\xe9", 0xFFFFFFE9, 3),
        ("strrchr", b"caf\xe9!\xe9", 0xE9, 5),
        ("strchr", b"\xff\xfeab", ord("b"), 3),
        ("strrchr", b"\xff\xfeab", ord("a"), 2),
        ("strchr", b"abc", 0, 3),
        ("strrchr", b"abc", 0, 3),
        ("strchr", b"abc", ord("x"), None),
    ],
)
def test_strchr_searches_the_raw_bytes(
    driver_emu: Speakeasy, name: str, text: bytes, c: int, offset: int | None
) -> None:
    s = alloc(driver_emu, text + b"\x00")
    rv, _ = call(driver_emu, "ntoskrnl", name, [s, c])
    assert rv == (0 if offset is None else s + offset)


@pytest.mark.parametrize(
    ("text", "c", "index"),
    [
        ("abc", 0xABCD0062, 1),
        ("䉁C", 0x4342, None),
        ("abc", 0, 3),
    ],
)
def test_wcschr_searches_whole_characters(driver_emu: Speakeasy, text: str, c: int, index: int | None) -> None:
    s = alloc(driver_emu, text.encode("utf-16le") + b"\x00\x00")
    rv, _ = call(driver_emu, "ntoskrnl", "wcschr", [s, c])
    assert rv == (0 if index is None else s + 2 * index)


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
    ("count", "fmt", "args", "rv", "written"),
    [
        (4, "%s-%s", ["AAAAAAAA", "BBBBBBBB"], -1, "AAAA"),
        (16, "%s-%d", ["ab", 42], 5, "ab-42\0"),
        (5, "%d", [12345], 5, "12345"),
        (0, "hello", [], -1, ""),
        (5, "hello", [], 5, "hello"),
        (16, "hello", [], 5, "hello\0"),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_snprintf_writes_at_most_count_characters(
    driver_emu: Speakeasy, width: int, count: int, fmt: str, args: list, rv: int, written: str
) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    name = "_snprintf" if width == 1 else "_snwprintf"
    argv = [alloc(driver_emu, (a + "\0").encode(enc)) if isinstance(a, str) else a for a in args]
    out = alloc(driver_emu, b"\xee" * 64)
    result, _ = call(driver_emu, "ntoskrnl", name, [out, count, alloc(driver_emu, (fmt + "\0").encode(enc)), *argv])
    assert result == rv
    data = written.encode(enc)
    assert driver_emu.mem_read(out, len(data) + width) == data + b"\xee" * width


@pytest.mark.parametrize(
    ("count", "written"),
    [
        (2, "ab"),
        (4, "abc\0"),
        (6, "abc\0\0\0"),
    ],
)
def test_wcsncpy_copies_count_characters(driver_emu: Speakeasy, count: int, written: str) -> None:
    out = alloc(driver_emu, b"\xee" * 32)
    rv, _ = call(driver_emu, "ntoskrnl", "wcsncpy", [out, alloc(driver_emu, "abc\0".encode("utf-16le")), count])
    assert rv == out
    data = written.encode("utf-16le")
    assert driver_emu.mem_read(out, len(data) + 2) == data + b"\xee\xee"


def test_wcscpy_returns_the_destination(driver_emu: Speakeasy) -> None:
    out = alloc(driver_emu, b"\xee" * 32)
    rv, _ = call(driver_emu, "ntoskrnl", "wcscpy", [out, alloc(driver_emu, "abc\0".encode("utf-16le"))])
    assert rv == out
    assert driver_emu.mem_read(out, 8) == "abc\0".encode("utf-16le")


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
    rv, _ = call(driver_emu, "ntoskrnl", name, [slots.get(a, a) if isinstance(a, str) else a for a in argv])
    assert rv == status
