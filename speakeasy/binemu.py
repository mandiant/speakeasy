# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import fnmatch
import logging
import math
import multiprocessing.synchronize
import re
import struct
import threading
import traceback
from abc import ABC, abstractmethod
from typing import Any, TypeVar

import capstone as cs
from unicorn.x86_const import UC_X86_INS_IN

import speakeasy.winenv.arch as e_arch
from speakeasy import common, version
from speakeasy.config import SpeakeasyConfig
from speakeasy.engines import unicorn_eng
from speakeasy.errors import CpuError
from speakeasy.hooks import (
    ApiHookCallback,
    CodeHookCallback,
    DynCodeHookCallback,
    InHookCallback,
    InterruptHookCallback,
    InvalidInstructionHookCallback,
    MemAccessHookCallback,
    MemMapHookCallback,
    OutHookCallback,
    SyscallHookCallback,
)
from speakeasy.memmgr import MemoryManager
from speakeasy.profiler import Profiler
from speakeasy.profiler_events import StackEntry
from speakeasy.report import ErrorInfo, ErrorType, Report
from speakeasy.winenv.codepage import decode_ansi, encode_ansi

logger = logging.getLogger(__name__)


def double_bits_to_fp80(bits):
    """
    Convert the IEEE 754 bits of a double to an x87 80-bit register value.

    Returns:
        The (mantissa, sign and exponent) pair of the register.
    """
    sign = (bits >> 63) << 15
    exponent = (bits >> 52) & 0x7FF
    fraction = bits & ((1 << 52) - 1)
    if exponent == 0x7FF:
        return (1 << 63) | (fraction << 11), sign | 0x7FFF
    if exponent == 0:
        if fraction == 0:
            return 0, sign
        shift = 53 - fraction.bit_length()
        return fraction << (11 + shift), sign | (16383 - 1022 - shift)
    return (1 << 63) | (fraction << 11), sign | (exponent - 1023 + 16383)


def fp80_to_double_bits(mantissa, sign_exponent):
    """
    Convert an x87 80-bit register value to the IEEE 754 bits of a double.

    Args:
        mantissa: Mantissa of the register.
        sign_exponent: Sign and exponent of the register.
    """
    sign = -1.0 if sign_exponent & 0x8000 else 1.0
    exponent = sign_exponent & 0x7FFF
    if exponent == 0x7FFF:
        value = math.nan if mantissa & ((1 << 63) - 1) else sign * math.inf
    else:
        try:
            value = sign * math.ldexp(mantissa, exponent - 16383 - 63)
        except OverflowError:
            value = sign * math.inf
    return struct.unpack("<Q", struct.pack("<d", value))[0]


EMU_ENGINES = (("unicorn", unicorn_eng.EmuEngine),)

WILDCARD_FLAG = bool
API_LEVEL = tuple[dict[str, list[common.ApiHook]], WILDCARD_FLAG]
MODULE_LEVEL = tuple[dict[str, API_LEVEL], WILDCARD_FLAG]

HookT = TypeVar("HookT", bound=common.Hook)


# Generic emulator class for binary code
class BinaryEmulator(MemoryManager, ABC):
    """
    Base class for emulating binaries.

    Subclasses must define the following attributes:
        arch: Architecture constant (for example, ``ARCH_X86`` or ``ARCH_AMD64``).
        modules: Loaded modules.
        input: Input metadata dictionary, or ``None``.
        exit_event: Event that stops the emulation when it is set, or ``None``.
    """

    arch: int
    modules: list[Any]
    input: dict[str, Any] | None
    exit_event: threading.Event | multiprocessing.synchronize.Event | None
    emu_eng: unicorn_eng.EmuEngine
    disasm_eng: cs.Cs
    ptr_size: int

    @abstractmethod
    def _unmap_reserved_range(self) -> None:
        """Unmap the reserved memory range. Subclasses must implement."""
        ...

    @abstractmethod
    def on_emu_complete(self) -> None:
        """Called when emulation completes. Subclasses must implement."""
        ...

    @abstractmethod
    def get_current_run(self) -> Any:
        """Get the current run context. Subclasses must implement."""
        ...

    def __init__(self, config):
        super().__init__()

        self.stack_base: int = 0
        self.has_builtin_hooks: bool = False
        self._in_dispatch_handle: int = 0
        self.config: SpeakeasyConfig = config
        self.hooks: dict[int, Any] = {}

        self.profiler: Profiler = Profiler(config.analysis)

        self.runtime: float = 0

    def get_profiler(self) -> Profiler:
        """Get the current event profiler object (if any)."""
        return self.profiler

    def get_report(self) -> Report:
        """Get the emulation report for all runs that were executed."""
        return self.profiler.get_report()

    def get_json_report(self) -> str:
        """Get the emulation report for all runs that were executed formatted as a JSON string."""
        return self.profiler.get_json_report()

    def _parse_config(self, config: SpeakeasyConfig):
        """Parse the config to be used for emulation."""
        self.config = config

        _eng = config.emu_engine
        for name, eng in EMU_ENGINES:
            if name.lower() == _eng.lower():
                self.emu_eng = eng()
                break
        else:
            raise CpuError(f"Unsupported emulation engine: {_eng}")

        self.env: dict[str, str] = dict(config.env)

    def get_emu_version(self):
        """Get the version of the emulator."""
        return version.__version__

    def get_osver_string(self):
        """Get the human readable OS version string."""
        osver = self.config.os_ver
        if osver:
            os_name = osver.name
            major = osver.major
            minor = osver.minor
            if major is not None and minor is not None:
                return f"{os_name}.{major}_{minor}"
        return None

    def sizeof(self, obj):
        """Get the size (in the emulation space) of the supplied object."""
        return obj.sizeof()

    def get_bytes(self, obj):
        """Get the bytes represented in the emulation space of the supplied object."""
        return obj.get_bytes()

    def stop(self) -> None:
        """Stop emulation completely."""
        self.emu_eng.stop()
        if self.profiler:
            self.profiler.stop_run_clock()

    def start(self, addr, size):
        """Begin emulation."""
        self.set_hooks()
        self._unmap_reserved_range()
        if self.profiler:
            self.profiler.set_start_time()
        try:
            self.emu_eng.start(addr, timeout=self.config.max_run_time, count=self.config.max_instructions)
        except Exception as e:
            if self.profiler:
                error = ErrorInfo(
                    type=ErrorType.INTERNAL_ERROR, traceback=traceback.format_exc(), message=str(e) or type(e).__name__
                )
                self.profiler.record_error_event(error)
            self.on_emu_complete()

    def reg_write(self, reg, val) -> None:
        """
        Write a value to an emulated cpu register.

        Raises:
            CpuError: if ``reg`` is a name that is not a register.
        """
        if isinstance(reg, str):
            _reg = e_arch.REG_LOOKUP.get(reg.lower())
            if not _reg:
                raise CpuError(f"Invalid register access {reg}")
            reg = _reg

        self.emu_eng.reg_write(reg, val)

    def reg_read(self, reg) -> int:
        """
        Read a value from an emulated cpu register.

        Raises:
            CpuError: if ``reg`` is a name that is not a register.
        """
        if isinstance(reg, str):
            _reg = e_arch.REG_LOOKUP.get(reg.lower())
            if not _reg:
                raise CpuError(f"Invalid register access {reg}")
            reg = _reg

        value: int = self.emu_eng.reg_read(reg)
        return value

    def set_hooks(self):
        """Set instruction level hooks."""
        for ht in (
            common.HOOK_CODE,
            common.HOOK_MEM_READ,
            common.HOOK_MEM_WRITE,
            common.HOOK_MEM_INVALID,
            common.HOOK_INTERRUPT,
        ):
            for hook in self.hooks.get(ht, []):
                if not hook.added:
                    hook.add()

    def _cs_disasm(self, mem, addr, fast=True) -> tuple[str, str, str] | list[cs.CsInsn]:
        """Disassemble bytes using capstone."""
        try:
            if fast:
                tu = [i for i in self.disasm_eng.disasm_lite(bytes(mem), addr)]
                address, size, mnem, oper = tu[0]
            else:
                return [i for i in self.disasm_eng.disasm(bytes(mem), addr)]
        except IndexError:
            raise CpuError(f"Failed to disasm at address: 0x{addr:x}") from None

        op = f"{mnem} {oper}"
        return (mnem, oper, op)

    def disasm(self, mem: bytes, addr: int, *, fast: bool = True) -> tuple[str, str, str] | list[cs.CsInsn]:
        """
        Disassemble bytes at a specified address.

        Raises:
            CpuError: if ``fast`` is ``True`` and no instruction decodes at ``addr``.
        """
        return self._cs_disasm(mem, addr, fast=fast)

    def get_register_state(self) -> dict[str, int]:
        """Get the current state of registers from the emulator."""
        regs = {}
        if self.get_arch() == e_arch.ARCH_X86:
            for name, reg in (
                ("esp", e_arch.X86_REG_ESP),
                ("ebp", e_arch.X86_REG_EBP),
                ("eip", e_arch.X86_REG_EIP),
                ("esi", e_arch.X86_REG_ESI),
                ("edi", e_arch.X86_REG_EDI),
                ("eax", e_arch.X86_REG_EAX),
                ("ebx", e_arch.X86_REG_EBX),
                ("ecx", e_arch.X86_REG_ECX),
                ("edx", e_arch.X86_REG_EDX),
            ):
                regs[name] = self.reg_read(reg)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            for name, reg in (
                ("rsp", e_arch.AMD64_REG_RSP),
                ("rbp", e_arch.AMD64_REG_RBP),
                ("rip", e_arch.AMD64_REG_RIP),
                ("rsi", e_arch.AMD64_REG_RSI),
                ("rdi", e_arch.AMD64_REG_RDI),
                ("rax", e_arch.AMD64_REG_RAX),
                ("rbx", e_arch.AMD64_REG_RBX),
                ("rcx", e_arch.AMD64_REG_RCX),
                ("rdx", e_arch.AMD64_REG_RDX),
                ("r8", e_arch.AMD64_REG_R8),
                ("r9", e_arch.AMD64_REG_R9),
                ("r10", e_arch.AMD64_REG_R10),
                ("r11", e_arch.AMD64_REG_R11),
                ("r12", e_arch.AMD64_REG_R12),
                ("r13", e_arch.AMD64_REG_R13),
                ("r14", e_arch.AMD64_REG_R14),
                ("r15", e_arch.AMD64_REG_R15),
            ):
                regs[name] = self.reg_read(reg)
        return regs

    def get_disasm(self, addr: int, size: int, *, fast: bool = True) -> tuple[str, str, str] | list[cs.CsInsn]:
        """Get the disassembly from an address."""
        return self.disasm(self.mem_read(addr, size), addr, fast=fast)

    def set_func_args(self, stack_addr, ret_addr, *args, conv, home_space=True):
        """
        Set the arguments before an emulated function call.

        Lays out ``args`` according to ``conv`` and the current architecture,
        writes ``ret_addr`` at the top of the resulting stack frame, and
        updates the stack pointer register.

        On x86 fastcall the first two arguments go into ECX and EDX. On x64
        the first four go into RCX, RDX, R8 and R9. The remaining arguments
        go onto the stack. On x64 a 32-byte shadow (home) space is
        reserved above the return address when ``home_space`` is ``True``.

        Args:
            stack_addr: Base address of the stack region.
            ret_addr: Return address to place on the stack.
            *args: Argument values to pass to the callee.
            conv: Calling convention (for example, ``CALL_CONV_STDCALL``).
            home_space: Whether to reserve the 32-byte x64 shadow space.
        """
        nargs = len(args)
        curr_sp = stack_addr

        if self.get_arch() == e_arch.ARCH_X86:
            sp_reg = e_arch.X86_REG_ESP

            if conv == e_arch.CALL_CONV_FASTCALL:
                for r in (e_arch.X86_REG_ECX, e_arch.X86_REG_EDX):
                    if nargs == 0:
                        break
                    self.reg_write(r, args[len(args) - nargs])
                    nargs -= 1

        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp_reg = e_arch.AMD64_REG_RSP

            for i, r in enumerate(
                (e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX, e_arch.AMD64_REG_R8, e_arch.AMD64_REG_R9)
            ):
                if nargs == 0:
                    break
                self.reg_write(r, args[i])
                nargs -= 1
        else:
            raise CpuError("Unsupported architecture")

        if nargs > 0:
            for arg in args[-nargs:][::-1]:
                curr_sp -= self.ptr_size
                self.mem_write(curr_sp, arg.to_bytes(self.ptr_size, byteorder="little"))

        if self.get_arch() == e_arch.ARCH_AMD64 and home_space:
            curr_sp -= 0x20

        curr_sp -= self.ptr_size
        self.mem_write(curr_sp, ret_addr.to_bytes(self.ptr_size, byteorder="little"))
        self.reg_write(sp_reg, curr_sp)

    def get_func_argv(self, callconv, argc):
        """Get the arguments for a function given the supplied calling convention."""
        argv = []
        ptr_size = self.get_ptr_size()
        arch = self.get_arch()
        nargs = argc
        # x86 passes doubles on the stack; x64 passes them in xmm0-xmm3
        if callconv == e_arch.CALL_CONV_FLOAT:
            if arch == e_arch.ARCH_X86:
                sp = self.reg_read(e_arch.X86_REG_ESP) + ptr_size
                for i in range(argc):
                    argv.append(int.from_bytes(self.mem_read(sp + 8 * i, 8), "little"))
                return argv
            if arch == e_arch.ARCH_AMD64:
                for r in (e_arch.X86_REG_XMM0, e_arch.X86_REG_XMM1, e_arch.X86_REG_XMM2, e_arch.X86_REG_XMM3)[:argc]:
                    argv.append(self.reg_read(r) & 0xFFFFFFFFFFFFFFFF)
                return argv

        if arch == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
            if callconv == e_arch.CALL_CONV_FASTCALL:
                if nargs >= 2:
                    argv.append(self.reg_read(e_arch.X86_REG_ECX))
                    argv.append(self.reg_read(e_arch.X86_REG_EDX))
                    nargs -= 2
                elif nargs == 1:
                    argv.append(self.reg_read(e_arch.X86_REG_ECX))
                    nargs -= 1
        elif arch == e_arch.ARCH_AMD64:
            sp = self.reg_read(e_arch.AMD64_REG_RSP)
            sp += 0x20

            for r in (e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX, e_arch.AMD64_REG_R8, e_arch.AMD64_REG_R9):
                if nargs == 0:
                    break
                val = self.reg_read(r)
                argv.append(val)
                nargs -= 1
        else:
            raise CpuError("Unsupported architecture")

        # Skip past the saved ret addr
        sp += ptr_size
        for _ in range(nargs):
            ptr = self.mem_read(sp, ptr_size)
            argv.append(int.from_bytes(ptr, "little"))
            sp += ptr_size

        return argv

    def do_call_return(self, argc, ret_addr=None, ret_value=None, conv=None):
        """Set the emulation state after a call has completed."""
        if self.get_arch() == e_arch.ARCH_X86:
            sp = e_arch.X86_REG_ESP
            pc = e_arch.X86_REG_EIP
            rr = e_arch.X86_REG_EAX
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = e_arch.AMD64_REG_RSP
            pc = e_arch.AMD64_REG_RIP
            rr = e_arch.AMD64_REG_RAX
        else:
            raise CpuError("Unsupported architecture")

        if conv == e_arch.CALL_CONV_FLOAT:
            rr = e_arch.X86_REG_XMM0

        stk_ptr = self.reg_read(sp)

        if ret_addr:
            self.reg_write(sp, stk_ptr + self.ptr_size)
            self.reg_write(pc, ret_addr)
        if ret_value is not None:
            if conv == e_arch.CALL_CONV_FLOAT and self.get_arch() == e_arch.ARCH_X86:
                self.push_fpu_double(ret_value)
            else:
                self.reg_write(rr, ret_value)

        # Cleanup the stack
        if conv in (e_arch.CALL_CONV_CDECL, e_arch.CALL_CONV_FLOAT):
            # If cdecl, the emu engine will clean the stack
            pass
        elif conv == e_arch.CALL_CONV_FASTCALL:
            if self.get_arch() == e_arch.ARCH_X86:
                if argc > 2:
                    self.clean_stack_args(argc - 2)
        else:
            self.clean_stack_args(argc)

    def push_fpu_double(self, bits):
        """Push a double, given as its IEEE 754 bits, onto the x87 register stack."""
        fpsw = self.reg_read(e_arch.X86_REG_FPSW)
        top = (((fpsw >> 11) & 7) - 1) & 7
        self.reg_write(e_arch.X86_REG_FP0 + top, double_bits_to_fp80(bits))
        self.reg_write(e_arch.X86_REG_FPSW, (fpsw & ~0x3800) | (top << 11))
        self.reg_write(e_arch.X86_REG_FPTAG, self.reg_read(e_arch.X86_REG_FPTAG) & ~(3 << (2 * top)))

    def pop_fpu_double(self):
        """Pop the x87 register stack and return the value as the IEEE 754 bits of a double."""
        fpsw = self.reg_read(e_arch.X86_REG_FPSW)
        top = (fpsw >> 11) & 7
        bits = fp80_to_double_bits(*self.emu_eng.reg_read(e_arch.X86_REG_FP0 + top))
        self.reg_write(e_arch.X86_REG_FPSW, (fpsw & ~0x3800) | (((top + 1) & 7) << 11))
        self.reg_write(e_arch.X86_REG_FPTAG, self.reg_read(e_arch.X86_REG_FPTAG) | (3 << (2 * top)))
        return bits

    def get_ret_address(self) -> int:
        """Get the return address from the stack."""
        sp = self.get_stack_ptr()
        return int.from_bytes(self.mem_read(sp, self.ptr_size), "little")

    def set_ret_address(self, addr) -> None:
        """Set the return address on the stack."""
        sp = self.get_stack_ptr()
        self.mem_write(sp, addr.to_bytes(self.get_ptr_size(), "little"))

    def push_stack(self, val):
        """Put a value on the stack and adjust the stack pointer."""
        sp = self.get_stack_ptr()
        bval = val.to_bytes(self.ptr_size, "little")
        sp -= self.ptr_size
        self.mem_write(sp, bval)
        self.set_stack_ptr(sp)
        return val

    def pop_stack(self) -> int:
        """Get value from the stack and adjust the stack pointer."""
        sp = self.get_stack_ptr()
        val = int.from_bytes(self.mem_read(sp, self.ptr_size), "little")
        sp += self.ptr_size
        self.set_stack_ptr(sp)
        return val

    def get_stack_ptr(self) -> int:
        """Get the current address of the stack pointer."""
        if self.get_arch() == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = self.reg_read(e_arch.AMD64_REG_RSP)
        return sp

    def set_stack_ptr(self, addr):
        """Set the current address of the stack pointer."""
        if self.get_arch() == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_ESP, addr)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            self.reg_write(e_arch.AMD64_REG_RSP, addr)

    def get_stack_trace(self, num_ptrs=16) -> list[StackEntry]:
        """Get the current stack state. The first slot that is not mapped ends the list."""
        trace = []
        sp = self.get_stack_ptr()
        ptr_size = self.get_ptr_size()
        for i in range(num_ptrs):
            offset = i * ptr_size
            try:
                data = self.mem_read(sp + offset, ptr_size)
            except Exception:
                trace.append(StackEntry(offset=offset))
                break
            ptr = int.from_bytes(data, "little")
            trace.append(StackEntry(offset=offset, value=ptr, tag=self.get_address_tag(ptr) or None))
        return trace

    def get_pc(self) -> int:
        """Get the value of the current program counter."""
        if self.get_arch() == e_arch.ARCH_X86:
            pc = self.reg_read(e_arch.X86_REG_EIP)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            pc = self.reg_read(e_arch.AMD64_REG_RIP)
        else:
            raise CpuError("Unsupported architecture")
        return pc

    def set_pc(self, addr):
        """Set the value of the current program counter."""
        if self.get_arch() == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_EIP, addr)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            self.reg_write(e_arch.AMD64_REG_RIP, addr)
        else:
            raise CpuError("Unsupported architecture")

    def get_return_val(self):
        """Get the current value in the return register."""
        if self.get_arch() == e_arch.ARCH_X86:
            val = self.reg_read(e_arch.X86_REG_EAX)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            val = self.reg_read(e_arch.AMD64_REG_RAX)
        else:
            raise CpuError("Unsupported architecture")
        return val

    def reset_cpu_context(self):
        """
        Zero the general-purpose registers and reset EFLAGS and the x87 and SSE control state.

        The values are those of a new Windows thread. This method does not change SP, BP or IP.
        ``reset_stack`` and the run setup manage them.
        """
        arch = self.get_arch()
        if arch == e_arch.ARCH_X86:
            for reg in (
                e_arch.X86_REG_EAX,
                e_arch.X86_REG_EBX,
                e_arch.X86_REG_ECX,
                e_arch.X86_REG_EDX,
                e_arch.X86_REG_ESI,
                e_arch.X86_REG_EDI,
            ):
                self.reg_write(reg, 0)
        elif arch == e_arch.ARCH_AMD64:
            for reg in (
                e_arch.AMD64_REG_RAX,
                e_arch.AMD64_REG_RBX,
                e_arch.AMD64_REG_RCX,
                e_arch.AMD64_REG_RDX,
                e_arch.AMD64_REG_RSI,
                e_arch.AMD64_REG_RDI,
                e_arch.AMD64_REG_R8,
                e_arch.AMD64_REG_R9,
                e_arch.AMD64_REG_R10,
                e_arch.AMD64_REG_R11,
                e_arch.AMD64_REG_R12,
                e_arch.AMD64_REG_R13,
                e_arch.AMD64_REG_R14,
                e_arch.AMD64_REG_R15,
            ):
                self.reg_write(reg, 0)
        self.reg_write(e_arch.X86_REG_EFLAGS, 0x2)
        self.reg_write(e_arch.X86_REG_FPCW, 0x27F)
        self.reg_write(e_arch.X86_REG_FPSW, 0)
        self.reg_write(e_arch.X86_REG_FPTAG, 0xFFFF)
        self.reg_write(e_arch.X86_REG_MXCSR, 0x1F80)

    def reset_stack(self, base) -> tuple[int, int]:
        """Reset stack to the supplied base address."""
        arch = self.get_arch()
        ptr = base

        if arch == e_arch.ARCH_X86:
            # Save room for stack arguments beyond the ones a run supplies
            ptr -= self.ptr_size * 64
            self.reg_write(e_arch.X86_REG_ESP, ptr)
            self.reg_write(e_arch.X86_REG_EBP, ptr)
        elif arch == e_arch.ARCH_AMD64:
            # Save room for stack arguments beyond the ones a run supplies; an odd count keeps rsp % 16
            ptr -= self.ptr_size * 65
            self.reg_write(e_arch.AMD64_REG_RSP, ptr)
            self.reg_write(e_arch.AMD64_REG_RBP, ptr)

        return base, ptr

    def alloc_stack(self, size):
        """Allocate memory to use for the program stack."""
        # Allocate memory for our stack
        # Stack grows down
        chunk = self.get_valid_ranges(size, addr=0x1200000)
        addr, block_size = chunk
        self.mem_map(block_size, base=addr, tag="emu.stack", perms=common.PERM_MEM_RW)

        base = addr + block_size
        self.mem_reserve(size, base=base)

        base, ptr = self.reset_stack(base)

        return base, ptr

    def clean_stack_args(self, argc):
        """Adjust the stack for arguments that were supplied."""
        ptr_size = self.get_ptr_size()
        arch = self.get_arch()

        if argc == 0:
            return

        if arch == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
            sp += ptr_size * argc
            self.reg_write(e_arch.X86_REG_ESP, sp)

        elif arch == e_arch.ARCH_AMD64:
            return
        else:
            raise CpuError("Unsupported architecture")

    def get_arch(self) -> int:
        """Get the current emulated architecture."""
        return self.arch

    def get_address_limit(self) -> int | None:
        if self.arch == e_arch.ARCH_X86:
            return 0x7FFF0000
        if self.arch == e_arch.ARCH_AMD64:
            return 0x7FFFFFFF0000
        return None

    def read_mem_string(self, address, width=1, max_chars=0) -> str:
        """
        Read a string from emulated memory.

        Raises:
            ValueError: if ``width`` is not 1 or 2.
        """
        char = b"\xff"
        string = b""
        i = 0

        if width not in (1, 2):
            raise ValueError("Invalid string encoding")

        while int.from_bytes(char, "little") != 0:
            if max_chars and i >= max_chars:
                break
            char = self.mem_read(address, width)

            string += char
            address += width
            i += 1

        text = decode_ansi(string) if width == 1 else string.decode("utf-16le", "replace")
        return text.replace("\x00", "")

    def mem_string_len(self, address, width=1):
        """Get the length of a string from emulated memory."""
        slen = -1
        char = b"\xff"

        while int.from_bytes(char, "little") != 0:
            char = self.mem_read(address, width)
            address += width
            slen += 1
        return slen

    def get_ansi_strings(self, data, min_len=4):
        """Get all ansi strings from a supplied memory blob."""
        astrs = []
        pat = b"[\x20-\x7f]{%d,}" % (min_len)
        res = re.compile(pat)
        hits = res.findall(data)
        offset = 0
        for s in hits:
            offset = data.find(s, offset)
            astrs.append((offset, decode_ansi(s)))
            offset += 1
        return astrs

    def get_unicode_strings(self, data, min_len=4):
        """Get all unicode strings from a supplied memory blob."""
        wstrs = []
        pat = b"(?:[\x20-\x7f]\x00){%d,}" % (min_len)
        res = re.compile(pat)
        hits = res.findall(data)
        offset = 0
        for ws in hits:
            try:
                offset = data.find(ws, offset)
                ws = ws.decode("utf-16le")
                wstrs.append((offset, ws))
                offset += 1
            except UnicodeDecodeError:
                continue
        return wstrs

    def mem_copy(self, dst, src, n):
        """Copy bytes from one emulated address to another."""
        sbytes = self.mem_read(src, n)
        self.mem_write(dst, sbytes)
        return n

    def write_mem_string(self, string, address, width=1):
        """
        Write string data to an emulated memory address.

        Appends a terminating zero byte if the string does not end with one.

        Raises:
            ValueError: if ``width`` is not 1 or 2.
        """
        if width not in (1, 2):
            raise ValueError("Invalid string encoding")

        if not string.endswith("\0"):
            string += "\0"

        enc_str = encode_ansi(string) if width == 1 else string.encode("utf-16le")
        self.mem_write(address, enc_str)

    def read_ptr(self, address):
        val = self.mem_read(address, self.ptr_size)
        return int.from_bytes(val, "little")

    def write_ptr(self, address, val):
        self.mem_write(address, val.to_bytes(self.ptr_size, "little"))

    def get_ptr_size(self) -> int:
        """Get the pointer size of the current emulation state."""
        return self.ptr_size

    def get_machine_word(self, value: int | None) -> int | None:
        """Get the register-width unsigned value of an integer, so that -1 becomes 0xffffffff on x86."""
        if value is None:
            return None
        bits: int = self.get_ptr_size() * 8
        return value & ((1 << bits) - 1)

    def get_mem_strings(self):
        """Get ansi and unicode strings from emulated memory."""
        tgt_tag_prefixes = ("emu.stack", "api")
        ansi_strings = []
        unicode_strings = []

        for mmap in self.get_mem_maps():
            tag = mmap.tag
            if tag and tag.startswith(tgt_tag_prefixes):
                data = self.mem_read(mmap.base, mmap.size - 1)
                data = data[: len(data.rstrip(b"\x00")) + 1]
                lead = len(data) - len(data.lstrip(b"\x00"))
                lead -= lead % 2
                data = data[lead:]
                ansi_strings += [(lead + off, s) for off, s in self.get_ansi_strings(data)]
                unicode_strings += [(lead + off, s) for off, s in self.get_unicode_strings(data)]

        return (list(dict.fromkeys(ansi_strings)), list(dict.fromkeys(unicode_strings)))

    def set_ptr_size(self, arch):
        """
        Set the current pointer size used in the emulator.

        Raises:
            CpuError: if ``arch`` is not x86 or AMD64.
        """
        if arch == e_arch.ARCH_AMD64:
            self.ptr_size = 8
        elif arch == e_arch.ARCH_X86:
            self.ptr_size = 4
        else:
            raise CpuError("Unsupported architecture")

    def get_module_from_addr(self, addr):
        """If the supplied address belongs to a module, return it."""
        for mod in self.modules:
            base = mod.base
            size = mod.image_size
            if addr >= base and addr <= base + size:
                return mod
        return None

    def get_api_hooks(self, mod_name, func_name) -> list[common.ApiHook]:
        """If an API hook has been set, return it here."""
        mod_name = mod_name.lower()
        func_name = func_name.lower()
        try:
            hook_struct, wildcard_module = self.hooks[common.HOOK_API]
        except KeyError:
            return []
        try:
            modules = [hook_struct[mod_name]]
        except KeyError:
            modules = []
        if wildcard_module:
            for module_name_saved, value in hook_struct.items():
                if fnmatch.fnmatch(mod_name, module_name_saved) and mod_name != module_name_saved:
                    modules.append(value)
        user_hooks = []
        for module in modules:
            hooks, wildcard_api = module
            try:
                user_hooks.extend(hooks[func_name])
            except KeyError:
                pass
            if wildcard_api:
                for func_name_saved, list_of_hooks in hooks.items():
                    if fnmatch.fnmatch(func_name, func_name_saved) and func_name != func_name_saved:
                        user_hooks.extend(list_of_hooks)
        return [hook for hook in user_hooks if hook.enabled]

    def add_hook(self, hook: HookT) -> HookT:
        """
        Bind a hook to this emulator and add it.

        When multiple hooks are registered for the same event, they run in
        FIFO order (first registered, first called). All hooks in the chain run,
        and the return value of the last hook is used. This order applies to all
        hook types in Speakeasy. An IN instruction is the exception: only the first
        IN hook that is enabled and covers the address runs.

        Raises:
            ValueError: if the engine rejects the hook, for example an instruction hook on an
                instruction that the engine does not support.
        """
        hook.bind(self)
        if isinstance(hook, common.ApiHook):
            self._add_api_hook(hook)
        else:
            hl = self.hooks.setdefault(hook.htype, [])
            if not hl and hook.htype == common.HOOK_MEM_INVALID:
                dispatch_hook = common.InvalidMemHook(self._hook_mem_invalid_dispatch, native_hook=True)
                dispatch_hook.bind(self)
                dispatch_hook.add()
                hl.append(dispatch_hook)
            hl.append(hook)
        if isinstance(hook, common.InstructionHook) and UC_X86_INS_IN in hook.insns and not self._in_dispatch_handle:
            self._in_dispatch_handle = self.emu_eng.hook_add(
                htype=common.HOOK_INSN, cb=self._hook_in_dispatch, arg1=UC_X86_INS_IN
            )
        try:
            hook.add()
        except ValueError:
            # A hook that the engine rejects must not stay in the hook list
            self.remove_hook(hook)
            raise
        return hook

    def remove_hook(self, hook: common.Hook) -> None:
        """
        Remove a hook, so that its callback is not called again.

        Raises:
            ValueError: if the emulator does not have the hook.
        """
        try:
            if isinstance(hook, common.ApiHook):
                module_dict, _ = self.hooks[common.HOOK_API]
                api_dict, _ = module_dict[hook.module]
                api_dict[hook.api_name].remove(hook)
            else:
                self.hooks[hook.htype].remove(hook)
        except (KeyError, ValueError):
            raise ValueError("The emulator does not have this hook") from None
        hook.remove()

    def _add_api_hook(self, hook: common.ApiHook) -> None:
        module = hook.module
        api_name = hook.api_name

        wildcard_module, wildcard_api = False, False
        for wc in ["?", "*", "[", "]"]:
            if wc in module:
                wildcard_module = True
            if wc in api_name:
                wildcard_api = True

        _hooks: MODULE_LEVEL | None = self.hooks.get(common.HOOK_API)

        api_dictionary = ({api_name: [hook]}, wildcard_api)
        if not _hooks:
            # First addition
            obj = ({module: api_dictionary}, wildcard_module)
        else:
            module_dict, previous_wildcard_module = _hooks
            try:
                api_dict, previous_wildcard_api = module_dict[module]
            except KeyError:
                # The module asked is not present, so we just add the api dictionary
                module_dict[module] = api_dictionary
            else:
                # The module asked is present, so we can just add the hook
                api_dict.setdefault(api_name, []).append(hook)
                module_dict[module] = (api_dict, previous_wildcard_api | wildcard_api)
            obj = (module_dict, previous_wildcard_module | wildcard_module)
        self.hooks.update({common.HOOK_API: obj})

    def add_api_hook(self, cb: ApiHookCallback, module="", api_name="", argc=0, call_conv=None) -> common.ApiHook:
        """Add an API level hook (for example, ``kernel32.CreateFile``)."""
        return self.add_hook(common.ApiHook(cb, module, api_name, argc, call_conv))

    def add_code_hook(self, cb: CodeHookCallback, begin=1, end=0) -> common.CodeHook:
        """Add a hook that will fire for every CPU instruction."""
        return self.add_hook(common.CodeHook(cb, begin, end))

    def _fire_dyn_code_hooks(self, addr):
        profiler = self.get_profiler()
        mm = self.get_address_map(addr)
        if profiler:
            run = self.get_current_run()
            profiler.record_dyn_code_event(run, mm.tag, mm.base, mm.size)

        # Copy the list, because a callback can remove its hook.
        for h in list(self.hooks.get(common.HOOK_DYN_CODE, [])):
            if h.enabled:
                h.cb(h.emu, mm)

    def _set_dyn_code_hook(self, addr, size):
        """Set the top level dispatch hook for dynamic code execution."""
        max_hook_size = 0x10
        if size > max_hook_size:
            size = max_hook_size

        hook_ref: list[common.CodeHook | None] = [None]

        def _dynamic_code_cb(emu, addr, size):
            self._fire_dyn_code_hooks(addr)
            if hook_ref[0]:
                hook_ref[0].disable()

        hook_ref[0] = self.add_code_hook(cb=_dynamic_code_cb, begin=addr, end=addr + size)

    def add_dyn_code_hook(self, cb: DynCodeHookCallback) -> common.DynCodeHook:
        """Add a hook that will fire when dynamically generated/copied code is executed."""
        return self.add_hook(common.DynCodeHook(cb))

    def add_mem_read_hook(self, cb: MemAccessHookCallback, begin=1, end=0) -> common.ReadMemHook:
        """Add a hook that will fire for memory reads."""
        return self.add_hook(common.ReadMemHook(cb, begin, end))

    def add_mem_write_hook(self, cb: MemAccessHookCallback, begin=1, end=0) -> common.WriteMemHook:
        """Add a hook that will fire for memory writes."""
        return self.add_hook(common.WriteMemHook(cb, begin, end))

    def add_mem_map_hook(self, cb: MemMapHookCallback, begin=1, end=0) -> common.MapMemHook:
        """Add a hook that will fire for memory maps."""
        return self.add_hook(common.MapMemHook(cb, begin, end))

    def _intercept_api_trap(self, access, address, size):
        return False

    def _hook_mem_invalid_dispatch(self, emu, access, address, size, value):
        """This handler will dispatch other invalid memory hooks."""
        if self._intercept_api_trap(access, address, size):
            return False
        hl = self.hooks.get(common.HOOK_MEM_INVALID, [])

        rv = True
        for mem_access_hook in hl[1:]:
            if mem_access_hook.enabled:
                rv = mem_access_hook.cb(mem_access_hook.emu, access, address, size, value)
                if rv is False:
                    break
        return rv

    def add_mem_invalid_hook(self, cb: MemAccessHookCallback) -> common.InvalidMemHook:
        """Add a hook that will fire for invalid memory access."""
        return self.add_hook(common.InvalidMemHook(cb))

    def add_interrupt_hook(self, cb: InterruptHookCallback) -> common.InterruptHook:
        """Add a hook that will fire for software interrupts."""
        return self.add_hook(common.InterruptHook(cb))

    def add_instruction_hook(
        self, cb: InHookCallback | OutHookCallback | SyscallHookCallback, begin=1, end=0, *, insn: int
    ) -> common.InstructionHook:
        """
        Add a hook that will fire for an IN, OUT, SYSCALL, or SYSENTER instruction.

        Raises:
            ValueError: if the engine does not support hooks on ``insn``.
        """
        return self.add_hook(common.InstructionHook(cb, begin, end, insns=(insn,)))

    def _hook_in_dispatch(self, uc_engine, port, size, user_data):
        # Unicorn uses the value of the first IN hook and does not call the others, so one
        # engine hook calls the first IN hook that is enabled and covers the address.
        for hook in self.hooks.get(common.HOOK_INSN, []):
            if hook.enabled and UC_X86_INS_IN in hook.insns and hook.covers_pc():
                return hook.cb(hook.emu, port, size)
        return 0

    def add_invalid_instruction_hook(self, cb: InvalidInstructionHookCallback) -> common.InvalidInstructionHook:
        """Add a hook that will fire for invalid instructions."""
        return self.add_hook(common.InvalidInstructionHook(cb))
