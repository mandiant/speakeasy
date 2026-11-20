"""Find the instruction that called an API, from the state of the guest at the API."""

from __future__ import annotations

import functools
import itertools
from typing import TYPE_CHECKING

import capstone as cs
import capstone.x86 as cs_x86
import unicorn as uc

import speakeasy.winenv.arch as e_arch

if TYPE_CHECKING:
    from speakeasy.windows.winemu import WindowsEmulator

_MAX_INSTRUCTION_SIZE = 15
_PAGE_SIZE = 0x1000
_MAX_THUNK_JUMPS = 4
_STACK_POINTERS = (cs_x86.X86_REG_ESP, cs_x86.X86_REG_RSP)
# The guest sets a base for these segments, and the other segments start at 0.
_SEGMENTS_WITH_BASE = (cs_x86.X86_REG_FS, cs_x86.X86_REG_GS)


def find_call_site(emu: WindowsEmulator, entry: int) -> int | None:
    """
    Find the instruction that took the guest to the API at ``entry``, from the return address of the API call.

    The guest must be at the API. There, each register has the value that it had at the call instruction, but
    the stack pointer is at the return address.

    Return the address of the call instruction that ends at the return address, if its target is ``entry``.
    If its target is a thunk of ``jmp`` instructions that goes to ``entry``, return the address of the last
    ``jmp``. Return None if no such call ends at the return address, for example when a ``jmp`` or a ``ret``
    took the guest to the API.
    """
    try:
        return_address = emu.get_ret_address()
    except uc.UcError:
        return None
    return _Guest(emu, return_address).find_call_site(entry)


class CallSiteDecoder:
    """
    Decode the instructions that take the guest to an API.

    Each emulator has its own decoder, because a capstone engine is not safe to use from two threads at once. The
    guest calls the same APIs from the same places many times, so the decoder keeps the decoded instructions by
    their bytes and address.
    """

    def __init__(self, mode: int):
        self.engine = cs.Cs(cs.CS_ARCH_X86, mode)
        self.engine.detail = True
        self.get_calls_before = functools.lru_cache(maxsize=4096)(self._decode_calls_before)
        self.get_instruction = functools.lru_cache(maxsize=4096)(self._decode_instruction)

    def _decode_calls_before(self, code: bytes, start: int) -> tuple[cs.CsInsn, ...]:
        """Decode the call instructions in ``code`` at ``start`` that end at the end of ``code``, shortest first."""
        calls = []
        for offset in range(len(code) - 1, -1, -1):
            for address, size, mnemonic, _ in self.engine.disasm_lite(code[offset:], start + offset, 1):
                if size == len(code) - offset and "call" in mnemonic.split():
                    calls.append(next(self.engine.disasm(code[offset:], address, 1)))
        return tuple(calls)

    def _decode_instruction(self, code: bytes, address: int) -> cs.CsInsn | None:
        return next(self.engine.disasm(code, address, 1), None)


class _Guest:
    """The registers and the memory of the guest at an API whose call returns to ``return_address``."""

    def __init__(self, emu: WindowsEmulator, return_address: int):
        self.emu = emu
        self.return_address = return_address
        self.ptr_size = emu.get_ptr_size()
        self.mask = (1 << 8 * self.ptr_size) - 1
        self.decoder = emu.call_site_decoder

    def find_call_site(self, entry: int) -> int | None:
        end = self.return_address
        start = end - _MAX_INSTRUCTION_SIZE
        code = self.read(start, _MAX_INSTRUCTION_SIZE)
        if not code:
            start = max(start, end & ~(_PAGE_SIZE - 1))
            code = self.read(start, end - start)
        # Try the shortest call first, because the bytes before a short call can decode to a longer call.
        calls = self.decoder.get_calls_before(code, start)
        for call, longer in itertools.zip_longest(calls, calls[1:]):
            site = self.get_last_instruction(call.address, self.get_target(call, is_call=True), entry)
            if site is None:
                continue
            # The byte before a call can be a REX prefix that does not change the target, or the last byte of the
            # instruction before it. Compilers do not use such a prefix, except a linker with import optimization,
            # which also puts a 5-byte nop after the call.
            if (
                longer is not None
                and longer.rex
                and not call.rex
                and longer.address == call.address - 1
                and self.is_nop_after_import_call(end)
            ):
                prefixed = self.get_last_instruction(longer.address, self.get_target(longer, is_call=True), entry)
                if prefixed is not None:
                    site = prefixed
            return site
        return None

    def is_nop_after_import_call(self, address: int) -> bool:
        nop = self.decoder.get_instruction(self.read_code(address), address)
        return nop is not None and nop.mnemonic == "nop" and nop.size == 5

    def get_last_instruction(self, site: int, target: int | None, entry: int) -> int | None:
        """
        Get the instruction that goes to ``entry``, when the call at ``site`` goes to ``target``.

        This is ``site``, or the last ``jmp`` of the thunk at ``target``. Return None if the call does not come to
        ``entry``.
        """
        for _ in range(_MAX_THUNK_JUMPS + 1):
            if target is None:
                return None
            if target == entry:
                return site
            site, target = target, self.get_jump_target(target)
        return None

    def get_jump_target(self, address: int) -> int | None:
        """Get the target of the ``jmp`` at ``address``, or None if there is no ``jmp`` at ``address``."""
        jump = self.decoder.get_instruction(self.read_code(address), address)
        if jump is None or "jmp" not in jump.mnemonic.split():
            return None
        return self.get_target(jump, is_call=False)

    def get_target(self, instruction: cs.CsInsn, is_call: bool) -> int | None:
        """
        Get the target of a ``call`` or ``jmp`` instruction from the registers and the memory of the guest.

        Return None if the operand is in memory that is not mapped, or if it uses a register or a segment that
        this function does not read.
        """
        (operand,) = instruction.operands
        if operand.type == cs_x86.X86_OP_IMM:
            return int(operand.imm) & self.mask
        if operand.type == cs_x86.X86_OP_REG:
            return self.read_register(instruction, operand.reg, is_call)
        memory = operand.mem
        if memory.segment in _SEGMENTS_WITH_BASE:
            return None
        address = memory.disp
        if memory.base == cs_x86.X86_REG_RIP:
            address += instruction.address + instruction.size
        elif memory.base:
            base = self.read_register(instruction, memory.base, is_call)
            if base is None:
                return None
            address += base
        if memory.index:
            index = self.read_register(instruction, memory.index, is_call)
            if index is None:
                return None
            address += index * memory.scale
        return self.read_pointer(address & self.mask)

    def read_register(self, instruction: cs.CsInsn, register: int, is_call: bool) -> int | None:
        """Read the value that a register had at a ``call`` or ``jmp`` instruction, or None for other registers."""
        name = instruction.reg_name(register)
        if name not in e_arch.REG_LOOKUP:
            return None
        value = self.emu.reg_read(name)
        if is_call and register in _STACK_POINTERS:
            # The call instruction pushed the return address.
            value += self.ptr_size
        return value & self.mask

    def read_pointer(self, address: int) -> int | None:
        data = self.read(address, self.ptr_size)
        return int.from_bytes(data, "little") if data else None

    def read_code(self, address: int) -> bytes:
        """Read the bytes of the instruction at ``address``, up to the end of the mapped memory."""
        return self.read(address, _MAX_INSTRUCTION_SIZE) or self.read(
            address, min(_MAX_INSTRUCTION_SIZE, _PAGE_SIZE - address % _PAGE_SIZE)
        )

    def read(self, address: int, size: int) -> bytes:
        """Read memory. Return no bytes if a part of the range is not mapped."""
        if address < 0 or address + size > self.mask + 1:
            return b""
        try:
            return self.emu.mem_read(address, size)
        except uc.UcError:
            return b""
