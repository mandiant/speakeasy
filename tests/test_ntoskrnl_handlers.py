import pytest

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy import Speakeasy
from tests.handler_harness import alloc, call

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
