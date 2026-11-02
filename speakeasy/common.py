# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from unicorn.x86_const import UC_X86_INS_IN, UC_X86_INS_OUT

if TYPE_CHECKING:
    from speakeasy.binemu import BinaryEmulator
    from speakeasy.engines.unicorn_eng import EmuEngine

# Emulation hook types
HOOK_CODE = 1000
HOOK_MEM_INVALID = 1001
HOOK_MEM_PERM_EXEC = 1002
HOOK_MEM_READ = 1003
HOOK_MEM_WRITE = 1004
HOOK_INTERRUPT = 1005
HOOK_MEM_ACCESS = 1006
HOOK_MEM_PERM_WRITE = 1007
HOOK_API = 1008
HOOK_DYN_CODE = 1009
HOOK_INSN = 1010
HOOK_MEM_MAP = 1011
HOOK_INSN_INVALID = 1012

# Emulation memory protection types
PERM_MEM_NONE = 0
PERM_MEM_EXEC = 0x10
PERM_MEM_READ = 0x02
PERM_MEM_WRITE = 0x04
PERM_MEM_RW = PERM_MEM_READ | PERM_MEM_WRITE
PERM_MEM_RX = PERM_MEM_READ | PERM_MEM_EXEC
PERM_MEM_RWX = PERM_MEM_READ | PERM_MEM_WRITE | PERM_MEM_EXEC

# Emulation memory access types
INVALID_MEM_EXEC = 2000
INVALID_MEM_READ = 2001
INVALID_MEM_WRITE = 2002
INVAL_PERM_MEM_WRITE = 2003
INVAL_PERM_MEM_EXEC = 2004
INVAL_PERM_MEM_READ = 2005


def normalize_package_path(path):
    """Get the supplied path in relation to the package root."""

    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__))

    root_var = "$ROOT$"
    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)
    return path


class Hook:
    """
    Base class for all emulator hooks.

    A hook has no emulator until ``bind`` gives it one. ``Speakeasy`` keeps the hooks
    that a caller adds before the load, and binds them before the emulator runs.
    """

    htype: int
    emu: BinaryEmulator
    emu_eng: EmuEngine

    def __init__(self, cb, native_hook=False):
        """
        Create a hook.

        Args:
            cb: Python callback function. Its first argument is the emulator.
            native_hook: If true, register a new, raw callback with the underlying
                emulation engine, which calls it directly. Otherwise, dispatch the hook
                through a wrapper hook (for example ``_wrap_code_cb``).
        """
        self.cb: Callable[..., Any] = cb
        self.handle: int = 0
        self.enabled: bool = True
        self.added: bool = False
        self.native_hook: bool = native_hook

    def bind(self, emu: BinaryEmulator) -> None:
        """Give the hook the emulator that calls it."""
        self.emu = emu
        self.emu_eng = emu.emu_eng

    def add(self):
        self.added = True

    def enable(self):
        self.enabled = True
        if self.added:
            self.emu_eng.hook_enable(self.handle)

    def disable(self):
        # A hook that is not added yet has no engine. It keeps the flag, and add() does not change it.
        self.enabled = False
        if self.added:
            self.emu_eng.hook_disable(self.handle)

    def remove(self):
        """Remove the hook from the engine, so that the engine does not call it again."""
        if self.added and self.native_hook:
            self.emu_eng.hook_remove(self.handle)
        self.handle = 0
        self.added = False
        self.enabled = False

    def _wrap_code_cb(self, emu, addr, size, ctx=None):
        try:
            if self.enabled:
                if self.emu.exit_event and self.emu.exit_event.is_set():
                    self.emu.stop()
                    return False
                return self.cb(self.emu, addr, size)
            return True
        except KeyboardInterrupt:
            self.emu.stop()
            return False

    def _wrap_intr_cb(self, emu, num, ctx=None):
        if self.enabled:
            return self.cb(self.emu, num)
        return True

    def _wrap_memory_access_cb(self, emu, access, addr, size, value, ctx=None):
        try:
            if self.enabled:
                if self.emu.exit_event and self.emu.exit_event.is_set():
                    self.emu.stop()
                    return False
                return self.cb(self.emu, access, addr, size, value)
            return True
        except KeyboardInterrupt:
            self.emu.stop()
            return False

    def _wrap_invalid_insn_cb(self, emu, ctx=None):
        if self.enabled:
            return self.cb(self.emu)
        # Unicorn reads True as "handled", so a disabled hook must not claim the instruction.
        return False


class ApiHook(Hook):
    """This hook type is used when using a specific API (e.g. kernel32.CreateFile)."""

    htype = HOOK_API

    def __init__(self, cb, module="", api_name="", argc=0, call_conv=None):
        super().__init__(cb)
        self.module: str = module.lower()
        self.api_name: str = api_name.lower()
        self.argc: int = argc
        self.call_conv: int | None = call_conv


class DynCodeHook(Hook):
    """
    Hook that fires when dynamically created or copied code runs.

    It fires once per dynamic code mapping. This is useful for unpacking.
    """

    htype = HOOK_DYN_CODE


class CodeHook(Hook):
    """This hook callback will fire for every CPU instruction."""

    htype = HOOK_CODE

    def __init__(self, cb, begin=1, end=0, native_hook=True):
        super().__init__(cb, native_hook=native_hook)
        self.begin: int = begin
        self.end: int = end

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_CODE, cb=self._wrap_code_cb, begin=self.begin, end=self.end)
        self.added = True


class ReadMemHook(Hook):
    """This hook will fire each time a valid chunk of memory is read from."""

    htype = HOOK_MEM_READ

    def __init__(self, cb, begin=1, end=0, native_hook=True):
        super().__init__(cb, native_hook=native_hook)
        self.begin: int = begin
        self.end: int = end

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(
                htype=HOOK_MEM_READ, cb=self._wrap_memory_access_cb, begin=self.begin, end=self.end
            )
        self.added = True


class WriteMemHook(Hook):
    """This hook will fire each time a valid chunk of memory is written to."""

    htype = HOOK_MEM_WRITE

    def __init__(self, cb, begin=1, end=0, native_hook=True):
        super().__init__(cb, native_hook=native_hook)
        self.begin: int = begin
        self.end: int = end

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(
                htype=HOOK_MEM_WRITE, cb=self._wrap_memory_access_cb, begin=self.begin, end=self.end
            )
        self.added = True


class MapMemHook(Hook):
    """This hook will fire each time a chunk of memory is mapped."""

    htype = HOOK_MEM_MAP

    def __init__(self, cb, begin=1, end=0):
        super().__init__(cb)
        self.begin: int = begin
        self.end: int = end


class InvalidMemHook(Hook):
    """This hook will fire each time a invalid chunk of memory is accessed."""

    htype = HOOK_MEM_INVALID

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_MEM_INVALID, cb=self._wrap_memory_access_cb)
        self.added = True


class InterruptHook(Hook):
    """This hook will fire each time a a software interrupt is triggered."""

    htype = HOOK_INTERRUPT

    def __init__(self, cb, native_hook=True):
        super().__init__(cb, native_hook=native_hook)

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_INTERRUPT, cb=self._wrap_intr_cb)
        self.added = True


class InstructionHook(Hook):
    """
    Hook that fires when a selected instruction executes.

    Unicorn supports only the instructions IN, OUT, SYSCALL, and SYSENTER. The emulator
    calls the IN hooks through one dispatch hook (see ``BinaryEmulator._hook_in_dispatch``).
    """

    htype = HOOK_INSN

    def __init__(self, cb, begin=1, end=0, insns=(), native_hook=True):
        super().__init__(cb, native_hook=native_hook)
        self.begin: int = begin
        self.end: int = end
        self.insns: tuple[int, ...] = tuple(insns)
        self.handles: list[int] = []

    def covers_pc(self) -> bool:
        """Get whether the pc is in the range of the hook. ``begin > end`` means all addresses."""
        # Unicorn does not check the range of an IN or OUT hook, and checks a SYSENTER hook
        # against a pc that is not up to date, so the wrappers check the range here.
        # A hook with no range does not read the pc, because the read costs about 1 us.
        return self.begin > self.end or self.begin <= self.emu.get_pc() <= self.end

    def add(self):
        if not self.added and self.native_hook:
            for insn in self.insns:
                if insn == UC_X86_INS_IN:
                    continue
                cb = self._wrap_out_insn_cb if insn == UC_X86_INS_OUT else self._wrap_syscall_insn_cb
                self.handles.append(self.emu_eng.hook_add(htype=HOOK_INSN, cb=cb, arg1=insn))
        self.added = True

    def remove(self):
        for handle in self.handles:
            self.emu_eng.hook_remove(handle)
        self.handles.clear()
        self.added = False
        self.enabled = False

    def _wrap_out_insn_cb(self, emu, port, size, value, ctx=None):
        if self.enabled and self.covers_pc():
            self.cb(self.emu, port, size, value)

    def _wrap_syscall_insn_cb(self, emu, ctx=None):
        if self.enabled and self.covers_pc():
            self.cb(self.emu)


class InvalidInstructionHook(Hook):
    """Hook that fires when the emulator hits an invalid instruction."""

    htype = HOOK_INSN_INVALID

    def __init__(self, cb, native_hook=True):
        super().__init__(cb, native_hook=native_hook)

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_INSN_INVALID, cb=self._wrap_invalid_insn_cb)
        self.added = True
