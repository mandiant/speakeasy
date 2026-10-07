import pytest

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, object_attributes

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
