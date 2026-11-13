"""
CPU exceptions as Windows reports them to user mode.

Unicorn reports interrupts, invalid instructions and IN/OUT with its own rules
for where the program counter points. This module converts each of these events
to the exception code, ExceptionAddress, parameters and context instruction
pointer that a Windows exception handler sees. The conversion follows Wine
(dlls/ntdll/unix/signal_x86_64.c), which copies the quirks that anti-debugging
code uses.
"""

from dataclasses import dataclass

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.defs.nt import ddk

STATUS_GUARD_PAGE_VIOLATION = 0x80000001
STATUS_ASSERTION_FAILURE = 0xC0000420

# Interrupt gates that user mode can use. Any other `int n` is a general protection fault.
INT_BREAKPOINT = 0x03
INT_OVERFLOW = 0x04
INT_ASSERTION = 0x2C
INT_DEBUG_SERVICE = 0x2D

# Gates for system calls, which the emulator does not send to exception handlers: 0x29 is
# __fastfail and 0x2e is KiSystemService, and on x86 0x2a is KiGetTickCount and 0x2b is KiCallbackReturn
SYSTEM_GATES = {_arch.ARCH_AMD64: (0x29, 0x2E), _arch.ARCH_X86: (0x29, 0x2A, 0x2B, 0x2E)}

# The first parameter of an access violation
ACCESS_CODES = {"read": 0, "write": 1, "fetch": 8}

# With these debug service codes in rax, `int 2d` raises no exception when no debugger is attached
DEBUG_SERVICE_NO_EXCEPTION = (1, 3, 4, 5)


@dataclass(frozen=True)
class CpuException:
    code: int
    address: int  # ExceptionAddress
    pc: int  # instruction pointer in the exception's context
    params: tuple[int, ...] = ()


def from_interrupt(intno: int, pc: int, code_bytes: bytes, rax: int, trap_flag: bool) -> CpuException | None:
    """
    Get the exception for an interrupt that Unicorn reports.

    pc is the program counter, which is after an ``int n`` instruction or at a faulting
    instruction. code_bytes are the two bytes before pc. trap_flag tells a single step
    from ``int 1``.

    Return None when Windows raises no exception. Then execution continues at
    ``skip_debug_service(pc)``.
    """
    if intno == 0:  # divide error: pc is at the faulting instruction
        return CpuException(ddk.STATUS_INTEGER_DIVIDE_BY_ZERO, pc, pc)
    if intno == 1:
        if not trap_flag and code_bytes == b"\xcd\x01":  # `int 1` is not a user mode gate
            return general_protection(pc - 2)
        # trap flag: pc is after the stepped instruction
        return CpuException(ddk.STATUS_SINGLE_STEP, pc, pc)
    if intno == INT_BREAKPOINT:
        # The kernel moves the address back one byte: to `int3`, or into the middle of `int 3`
        return CpuException(ddk.STATUS_BREAKPOINT, pc - 1, pc - 1, (0,))
    if intno == INT_OVERFLOW:  # `into` or `int 4`: pc is after the instruction
        return CpuException(ddk.STATUS_INTEGER_OVERFLOW, pc, pc)
    if intno == INT_DEBUG_SERVICE:
        if rax in DEBUG_SERVICE_NO_EXCEPTION:
            return None
        # The kernel skips the byte after `int 2d`, then backs up one for the breakpoint
        return CpuException(ddk.STATUS_BREAKPOINT, pc + 1, pc, (rax,))
    if intno == INT_ASSERTION:
        return CpuException(STATUS_ASSERTION_FAILURE, pc - 2, pc - 2)
    if code_bytes == bytes((0xCD, intno)):  # `int n` through a gate user mode may not use
        return general_protection(pc - 2)
    # a fault such as #GP: pc is at the faulting instruction
    return general_protection(pc)


def get_interrupt_instruction(intno: int, pc: int, code_bytes: bytes) -> int:
    """
    Get the address of the instruction that raised an interrupt that Unicorn reports.

    After ``int n``, ``int3`` and ``into``, Unicorn gives the pc of the next instruction. After a
    fault, pc is at the faulting instruction, and after a single step, pc is the next instruction
    to run. code_bytes are the two bytes before pc, or one byte at the start of a region.
    """
    if code_bytes[-2:] == bytes((0xCD, intno)):
        return pc - 2
    if (intno, code_bytes[-1:]) in ((INT_BREAKPOINT, b"\xcc"), (INT_OVERFLOW, b"\xce")):
        return pc - 1
    return pc


def skip_debug_service(pc: int) -> int:
    """Get the address where execution continues after an ``int 2d`` that raises no exception."""
    return pc + 1


def general_protection(pc: int) -> CpuException:
    return CpuException(ddk.STATUS_ACCESS_VIOLATION, pc, pc, (0, 0xFFFFFFFFFFFFFFFF))


def from_invalid_instruction(pc: int, code_bytes: bytes) -> CpuException:
    """Get the exception for an instruction at pc that Unicorn cannot execute."""
    if code_bytes[:1] == b"\xf1":  # icebp: a debug trap after the instruction
        return CpuException(ddk.STATUS_SINGLE_STEP, pc + 1, pc + 1)
    return CpuException(ddk.STATUS_ILLEGAL_INSTRUCTION, pc, pc)


def privileged_instruction(pc: int) -> CpuException:
    return CpuException(ddk.STATUS_PRIVILEGED_INSTRUCTION, pc, pc)


def memory_fault(
    pc: int, address: int, access_type: str | None, code: int = ddk.STATUS_ACCESS_VIOLATION
) -> CpuException:
    """Get the access violation, or the guard page violation, of an access to address by the instruction at pc."""
    return CpuException(code, pc, pc, (ACCESS_CODES.get(access_type or "", 0), address))
