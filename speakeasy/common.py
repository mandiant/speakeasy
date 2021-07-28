# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os

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
PERM_MEM_RWX = PERM_MEM_READ | PERM_MEM_WRITE | PERM_MEM_EXEC

# Emulation memory access types
INVALID_MEM_EXEC = 2000
INVALID_MEM_READ = 2001
INVALID_MEM_WRITE = 2002
INVAL_PERM_MEM_WRITE = 2003
INVAL_PERM_MEM_EXEC = 2004
INVAL_PERM_MEM_READ = 2005


def normalize_package_path(path):
    """
    Get the supplied path in relation to the package root
    """
    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__))

    root_var = '$ROOT$'
    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)
    return path


class Hook(object):
    """
    Base class for all emulator hooks
    """
    def __init__(self, se_obj, emu_eng, cb, ctx=[], native_hook=False):
        """
        Arguments:
            se_obj: speakeasy emulator object
            emu_eng: emulation engine object
            cb: Python callback function
            ctx: Arbitrary context that be passed between hook callbacks
            native_hook: When set to True, a new, raw callback will be registered with
                         with the underlying emulation engine that is called directly by the DLL.
                         Otherwise, this hook will be dispatched via a wrapper hook
                         (e.g. see _wrap_code_cb below)
        """
        self.cb = cb
        self.handle = 0
        self.enabled = False
        self.added = False
        self.native_hook = native_hook
        self.emu_eng = emu_eng
        self.se_obj = se_obj
        self.ctx = ctx

    def enable(self):
        self.enabled = True
        self.emu_eng.hook_enable(self.handle)

    def disable(self):
        self.enabled = False
        self.emu_eng.hook_disable(self.handle)

    def _wrap_code_cb(self, emu, addr, size, ctx=[]):
        try:
            if self.enabled:
                if self.se_obj.exit_event and self.se_obj.exit_event.is_set():
                    self.se_obj.stop()
                    return False
                return self.cb(self.se_obj, addr, size, self.ctx)
            return True
        except KeyboardInterrupt:
            self.se_obj.stop()
            return False

    def _wrap_intr_cb(self, emu, num, ctx=[]):
        if self.enabled:
            return self.cb(self.se_obj, num, self.ctx)
        return True

    def _wrap_in_insn_cb(self, emu, port, size, ctx=[]):
        if self.enabled:
            return self.cb(self.se_obj, port, size)
        return True

    def _wrap_syscall_insn_cb(self, emu, ctx=[]):
        if self.enabled:
            return self.cb(self.se_obj)
        return True

    def _wrap_memory_access_cb(self, emu, access, addr, size, value, ctx):
        try:
            if self.enabled:
                if self.se_obj.exit_event and self.se_obj.exit_event.is_set():
                    self.se_obj.stop()
                    return False
                return self.cb(self.se_obj, access, addr, size, value, ctx)
            return True
        except KeyboardInterrupt:
            self.se_obj.stop()
            return False

    def _wrap_invalid_insn_cb(self, emu, ctx=[]):
        if self.enabled:
            return self.cb(self.se_obj, self.ctx)
        return True

class ApiHook(Hook):
    """
    This hook type is used when using a specific API (e.g. kernel32.CreateFile)
    """
    def __init__(self, se_obj, emu_eng, cb, module='', api_name='', argc=0, call_conv=None):
        super(ApiHook, self).__init__(se_obj, emu_eng, cb)
        self.module = module
        self.api_name = api_name
        self.argc = argc
        self.call_conv = call_conv


class DynCodeHook(Hook):
    """
    This hook type is used to get a callback when dynamically created/copied code is executed
    Currently, this will only fire once per dynamic code mapping. Could be useful for unpacking.
    """
    def __init__(self, se_obj, emu_eng, cb, ctx=[]):
        super(DynCodeHook, self).__init__(se_obj, emu_eng, cb)


class CodeHook(Hook):
    """
    This hook callback will fire for every CPU instruction
    """

    def __init__(self, se_obj, emu_eng, cb, begin=1, end=0, ctx=[],
                 native_hook=True):
        super(CodeHook, self).__init__(se_obj, emu_eng, cb, ctx=ctx, native_hook=native_hook)
        self.begin = begin
        self.end = end

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_CODE, cb=self._wrap_code_cb,
                                                begin=self.begin, end=self.end)
        self.added = True
        self.enabled = True


class ReadMemHook(Hook):
    """
    This hook will fire each time a valid chunk of memory is read from
    """
    def __init__(self, se_obj, emu_eng, cb, begin=1, end=0, native_hook=True):
        super(ReadMemHook, self).__init__(se_obj, emu_eng, cb, native_hook=native_hook)
        self.begin = begin
        self.end = end

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_MEM_READ,
                                                cb=self._wrap_memory_access_cb,
                                                begin=self.begin, end=self.end)
        self.added = True
        self.enabled = True


class WriteMemHook(Hook):
    """
    This hook will fire each time a valid chunk of memory is written to
    """
    def __init__(self, se_obj, emu_eng, cb, begin=1, end=0, native_hook=True):
        super(WriteMemHook, self).__init__(se_obj, emu_eng, cb, native_hook=native_hook)
        self.begin = begin
        self.end = end

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_MEM_WRITE,
                                                cb=self._wrap_memory_access_cb,
                                                begin=self.begin, end=self.end)
        self.added = True
        self.enabled = True


class MapMemHook(Hook):
    """
    This hook will fire each time a chunk of memory is mapped
    """
    def __init__(self, se_obj, emu_eng, cb, begin=1, end=0):
        super(MapMemHook, self).__init__(se_obj, emu_eng, cb)
        self.begin = begin
        self.end = end

    def add(self):
        self.added = True
        self.enabled = True


class InvalidMemHook(Hook):
    """
    This hook will fire each time a invalid chunk of memory is accessed
    """
    def __init__(self, se_obj, emu_eng, cb, native_hook=False):
        super(InvalidMemHook, self).__init__(se_obj, emu_eng, cb, native_hook=native_hook)

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_MEM_INVALID,
                                                cb=self._wrap_memory_access_cb)
        self.added = True
        self.enabled = True


class InterruptHook(Hook):
    """
    This hook will fire each time a a software interrupt is triggered
    """
    def __init__(self, se_obj, emu_eng, cb, ctx=[], native_hook=True):
        super(InterruptHook, self).__init__(se_obj, emu_eng, cb, ctx=ctx, native_hook=native_hook)

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_INTERRUPT, cb=self._wrap_intr_cb)
        self.added = True
        self.enabled = True


class InstructionHook(Hook):
    """
    This hook will fire each time a instruction hook is triggered,
    Only the instructions: IN, OUT, SYSCALL, and SYSENTER are supported by unicorn.
    """
    def __init__(self, se_obj, emu_eng, cb, ctx=[], native_hook=True, insn=None):
        super(InstructionHook, self).__init__(se_obj, emu_eng, cb, ctx=ctx,
                                              native_hook=native_hook)
        self.insn = insn

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_INSN, cb=self._wrap_syscall_insn_cb,
                                                arg1=self.insn)
        self.added = True
        self.enabled = True

class InvalidInstructionHook(Hook):
    """
    This hook will fire every time an invalid instruction is attempted
    to be executed
    """
    def __init__(self, se_obj, emu_eng, cb, ctx=[], native_hook=True):
        super(InvalidInstructionHook, self).__init__(se_obj, emu_eng, cb,
                ctx=ctx, native_hook=native_hook)

    def add(self):
        if not self.added and self.native_hook:
            self.handle = self.emu_eng.hook_add(htype=HOOK_INSN_INVALID,
                    cb=self._wrap_invalid_insn_cb)

        self.added = True
        self.enabled = True
