"""
CPU exceptions as Windows reports them to user mode.

Unicorn reports interrupts, invalid instructions and IN/OUT with its own
conventions for where the program counter points. This module turns each of
those into the exception code, ExceptionAddress, parameters and context
instruction pointer that a Windows exception handler would see, following
Wine's implementation, which reproduces the quirks that anti-debugging code
depends on (dlls/ntdll/unix/signal_x86_64.c).
"""

from dataclasses import dataclass

import speakeasy.winenv.defs.nt.ddk as ddk

STATUS_GUARD_PAGE_VIOLATION = 0x80000001
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096
STATUS_ASSERTION_FAILURE = 0xC0000420

# Interrupt gates user mode may use; any other `int n` is a general protection fault
INT_BREAKPOINT = 0x03
INT_ASSERTION = 0x2C
INT_DEBUG_SERVICE = 0x2D

# The first parameter of an access violation
ACCESS_CODES = {"read": 0, "write": 1, "fetch": 8}

# With these debug service codes in rax, `int 2d` does nothing when no debugger is attached
DEBUG_SERVICE_NO_EXCEPTION = (1, 3, 4, 5)


@dataclass(frozen=True)
class CpuException:
    code: int
    address: int  # ExceptionAddress
    pc: int  # instruction pointer in the exception's context
    params: tuple[int, ...] = ()


def from_interrupt(intno: int, pc: int, code_bytes: bytes, rax: int, trap_flag: bool) -> CpuException | None:
    """
    The exception for an interrupt Unicorn reports with the program counter at pc,
    which is past an `int n` instruction and code_bytes, the two bytes before it.
    trap_flag tells a single step from `int 1`.

    Returns None when Windows raises no exception: then execution continues at the
    returned exception-less pc, see skip_debug_service.
    """
    if intno == 0:  # divide error: pc is at the faulting instruction
        return CpuException(ddk.STATUS_INTEGER_DIVIDE_BY_ZERO, pc, pc)
    if intno == 1:
        if not trap_flag and code_bytes == b"\xcd\x01":  # `int 1` is not a user mode gate
            return general_protection(pc - 2)
        # trap flag: pc is after the stepped instruction
        return CpuException(ddk.STATUS_SINGLE_STEP, pc, pc)
    if intno == INT_BREAKPOINT:
        # The kernel backs up one byte: onto `int3`, or into the middle of `int 3`
        return CpuException(ddk.STATUS_BREAKPOINT, pc - 1, pc - 1, (0,))
    if intno == INT_DEBUG_SERVICE:
        if rax in DEBUG_SERVICE_NO_EXCEPTION:
            return None
        # The kernel skips the byte after `int 2d`, then backs up one for the breakpoint
        return CpuException(ddk.STATUS_BREAKPOINT, pc + 1, pc, (rax,))
    if intno == INT_ASSERTION:
        return CpuException(STATUS_ASSERTION_FAILURE, pc - 2, pc - 2)
    return general_protection(pc - 2)


def skip_debug_service(pc: int) -> int:
    """Where execution continues after an `int 2d` that raises no exception."""
    return pc + 1


def general_protection(pc: int) -> CpuException:
    return CpuException(ddk.STATUS_ACCESS_VIOLATION, pc, pc, (0, 0xFFFFFFFFFFFFFFFF))


def from_invalid_instruction(pc: int, code_bytes: bytes) -> CpuException:
    """The exception for an instruction at pc that Unicorn cannot execute."""
    if code_bytes[:1] == b"\xf1":  # icebp: a debug trap after the instruction
        return CpuException(ddk.STATUS_SINGLE_STEP, pc + 1, pc + 1)
    return CpuException(STATUS_ILLEGAL_INSTRUCTION, pc, pc)


def privileged_instruction(pc: int) -> CpuException:
    return CpuException(STATUS_PRIVILEGED_INSTRUCTION, pc, pc)


def memory_fault(
    pc: int, address: int, access_type: str | None, code: int = ddk.STATUS_ACCESS_VIOLATION
) -> CpuException:
    """An access violation, or a guard page violation, at address by the instruction at pc."""
    return CpuException(code, pc, pc, (ACCESS_CODES.get(access_type or "", 0), address))
