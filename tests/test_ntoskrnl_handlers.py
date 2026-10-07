import pytest

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from tests.handler_harness import alloc

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
    ],
)
def test_x86_callee_cleans_the_stack_per_its_convention(
    driver_emu: Speakeasy, name: str, args: list[int], conv: int
) -> None:
    buf = alloc(driver_emu, b"\x00" * 16)
    args = [buf if a == BUF else a for a in args]
    _, left = call_x86(driver_emu, name, args, conv)
    assert left == (4 * len(args) if conv == CDECL else 0)
