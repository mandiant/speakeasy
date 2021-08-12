# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Unicorn specific wrappers and abstraction implemented here

import platform
import ctypes as ct

import unicorn as uc
import unicorn.unicorn
import unicorn.x86_const as u

import speakeasy.winenv.arch as arch
import speakeasy.common as common
from speakeasy.errors import EmuEngineError

_uc = unicorn.unicorn._uc
_uc.uc_hook_add = _uc.uc_hook_add
_uc.uc_hook_add.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p,
                            ct.c_void_p, ct.c_uint64, ct.c_uint64]
_uc.uc_hook_add.restype = ct.c_uint32
hook_id = ct.c_void_p()


def is_platform_intel():
    mach = platform.machine()
    if mach in ('x86_64', 'i386', 'x86'):
        return True
    return False


class ToggleableHook(object):
    """
    Hook than can be toggled on/off at arbitrary times.
    """

    def __init__(self, cb):
        self.cb = cb
        self.enabled = False

    def enable(self):
        if self.enabled:
            return
        self.enabled = True

    def disable(self):
        self.enabled = False


class EmuEngine(object):
    """Wrapper class for underlying cpu emulation engines"""

    def __init__(self):
        self.name = 'unicorn'
        self.emu = None
        self.mmap = None
        self._callbacks = {}

        self.regs = {
                        arch.X86_REG_EAX: u.UC_X86_REG_EAX,
                        arch.X86_REG_EBX: u.UC_X86_REG_EBX,
                        arch.X86_REG_ESP: u.UC_X86_REG_ESP,
                        arch.X86_REG_EIP: u.UC_X86_REG_EIP,
                        arch.X86_REG_EBP: u.UC_X86_REG_EBP,
                        arch.X86_REG_ECX: u.UC_X86_REG_ECX,
                        arch.X86_REG_EDX: u.UC_X86_REG_EDX,
                        arch.X86_REG_EDI: u.UC_X86_REG_EDI,
                        arch.X86_REG_ESI: u.UC_X86_REG_ESI,
                        arch.X86_REG_EFLAGS: u.UC_X86_REG_EFLAGS,
                        arch.AMD64_REG_RIP: u.UC_X86_REG_RIP,
                        arch.AMD64_REG_RAX: u.UC_X86_REG_RAX,
                        arch.AMD64_REG_RBX: u.UC_X86_REG_RBX,
                        arch.AMD64_REG_RSP: u.UC_X86_REG_RSP,
                        arch.AMD64_REG_RCX: u.UC_X86_REG_RCX,
                        arch.AMD64_REG_RDX: u.UC_X86_REG_RDX,
                        arch.AMD64_REG_RSI: u.UC_X86_REG_RSI,
                        arch.AMD64_REG_RDI: u.UC_X86_REG_RDI,
                        arch.AMD64_REG_RBP: u.UC_X86_REG_RBP,
                        arch.AMD64_REG_R8: u.UC_X86_REG_R8,
                        arch.AMD64_REG_R9: u.UC_X86_REG_R9,
                        arch.AMD64_REG_R10: u.UC_X86_REG_R10,
                        arch.AMD64_REG_R11: u.UC_X86_REG_R11,
                        arch.AMD64_REG_R12: u.UC_X86_REG_R12,
                        arch.AMD64_REG_R13: u.UC_X86_REG_R13,
                        arch.AMD64_REG_R14: u.UC_X86_REG_R14,
                        arch.AMD64_REG_R15: u.UC_X86_REG_R15,
                        arch.X86_REG_IDTR: u.UC_X86_REG_IDTR,
                        arch.X86_REG_XMM0: u.UC_X86_REG_XMM0,
                        arch.X86_REG_XMM1: u.UC_X86_REG_XMM1,
                        arch.X86_REG_XMM2: u.UC_X86_REG_XMM2,
                        arch.X86_REG_XMM3: u.UC_X86_REG_XMM3,
                        arch.X86_REG_GDTR: u.UC_X86_REG_GDTR,
                        arch.X86_REG_CS: u.UC_X86_REG_CS,
                        arch.X86_REG_ES: u.UC_X86_REG_ES,
                        arch.X86_REG_SS: u.UC_X86_REG_SS,
                        arch.X86_REG_DS: u.UC_X86_REG_DS,
                        arch.X86_REG_FS: u.UC_X86_REG_FS,
                        arch.X86_REG_GS: u.UC_X86_REG_GS,
                        arch.X86_REG_MSR: u.UC_X86_REG_MSR
        }

        self.mem_access = {
                            uc.UC_MEM_FETCH_UNMAPPED: common.INVALID_MEM_EXEC, # noqa
                            uc.UC_MEM_READ_UNMAPPED: common.INVALID_MEM_READ,
                            uc.UC_MEM_FETCH_PROT: common.INVAL_PERM_MEM_EXEC,
                            uc.UC_MEM_WRITE_PROT: common.INVAL_PERM_MEM_WRITE,
                            uc.UC_MEM_READ_PROT: common.INVAL_PERM_MEM_READ,
                            uc.UC_MEM_WRITE_UNMAPPED: common.INVALID_MEM_WRITE
        }

        self.perms = {
                    common.PERM_MEM_RWX: uc.UC_PROT_ALL,
                    common.PERM_MEM_WRITE: uc.UC_PROT_WRITE,
                    common.PERM_MEM_READ: uc.UC_PROT_READ,
                    common.PERM_MEM_RW: uc.UC_PROT_READ | uc.UC_PROT_WRITE
        }

        self.hook_types = {
                        common.HOOK_CODE: uc.UC_HOOK_CODE,
                        common.HOOK_MEM_ACCESS: uc.UC_HOOK_MEM_VALID,
                        common.HOOK_MEM_INVALID: uc.UC_HOOK_MEM_INVALID,
                        common.HOOK_MEM_PERM_EXEC: uc.UC_HOOK_MEM_FETCH_PROT,
                        common.HOOK_MEM_PERM_WRITE: uc.UC_HOOK_MEM_WRITE_PROT,
                        common.HOOK_MEM_READ: uc.UC_HOOK_MEM_READ,
                        common.HOOK_MEM_WRITE: uc.UC_HOOK_MEM_WRITE,
                        common.HOOK_INTERRUPT: uc.UC_HOOK_INTR,
                        common.HOOK_INSN: uc.UC_HOOK_INSN,
                        common.HOOK_INSN_INVALID: uc.UC_HOOK_INSN_INVALID
        }

    def _sec_to_usec(self, sec):
        """
        Unicorn expects timeouts to be supplied in microsecond granularity
        """
        return sec * 1000000

    def init_engine(self, eng_arch, mode):
        """Initialize cpu engine"""
        if eng_arch == arch.ARCH_X86 or eng_arch == arch.ARCH_AMD64:
            _arch = uc.UC_ARCH_X86
        else:
            raise Exception('Invalid architecture')

        if mode == arch.BITS_32:
            _mode = uc.UC_MODE_32
        elif mode == arch.BITS_64:
            _mode = uc.UC_MODE_64
        else:
            raise Exception('Invalid bitness')

        self.emu = uc.Uc(_arch, _mode)

    def mem_map(self, base, size, perms=common.PERM_MEM_RWX):
        """Allocate memory in the cpu engine"""
        perm = self.perms.get(perms, uc.UC_PROT_ALL)
        return self.emu.mem_map(base, size, perm)

    def mem_unmap(self, addr, size):
        """Free memory in the cpu engine"""
        return self.emu.mem_unmap(addr, size)

    def mem_regions(self):
        """Get current memory allocations from the engine"""
        return self.emu.mem_regions()

    def mem_write(self, addr, data):
        """Write data into the address space of the engine"""
        return self.emu.mem_write(addr, data)

    def mem_read(self, addr, size):
        """Read data from the address space of the engine"""
        return self.emu.mem_read(addr, size)

    def mem_protect(self, addr, size, perms):
        """Change the memory protections for pages in the emu engine"""
        perm = self.perms.get(perms, uc.UC_PROT_ALL)
        return self.emu.mem_protect(addr, size, perm)

    def reg_write(self, reg, val):
        """Modify register values"""
        ereg = self.regs.get(reg)
        if not ereg:
            raise EmuEngineError('Unknown register: %d' % (reg))
        return self.emu.reg_write(ereg, val)

    def reg_read(self, reg):
        """Read register values"""
        ereg = self.regs.get(reg)
        if not ereg:
            raise EmuEngineError('Unknown register: %d' % (reg))
        return self.emu.reg_read(ereg)

    def stop(self):
        """Stop the emulation engine"""
        return self.emu.emu_stop()

    def start(self, addr, timeout=0, count=0):
        """Start the emulation engine"""
        if count == -1:
            count = 0

        # Unicorn expects the timeout to be in microseconds, convert it here
        timeout = self._sec_to_usec(timeout)
        return self.emu.emu_start(addr, 0xFFFFFFFF, timeout=timeout, count=count)

    def hook_add(self, addr=None, cb=None, htype=None, ctx=None, begin=1, end=0, arg1=0):
        """
        Add a callback function for a specific event type or address
        """
        hook_type = self.hook_types.get(htype)
        if not hook_type:
            raise EmuEngineError('Invalid hook type')

        handle = self.emu._uch

        # The unicorn bindings have a default python wrapper. We want to use
        # our own wrapper and don't need the extra overhead. Add callbacks directly
        # to the unicorn library here.
        if hook_type == uc.UC_HOOK_INSN:
            if arg1 == u.UC_X86_INS_IN:  # IN instruction
                cb = ct.cast(unicorn.unicorn.UC_HOOK_INSN_IN_CB(cb),
                             unicorn.unicorn.UC_HOOK_INSN_IN_CB)
            elif arg1 in (u.UC_X86_INS_SYSCALL, u.UC_X86_INS_SYSENTER):  # SYSCALL/SYSENTER
                cb = ct.cast(unicorn.unicorn.UC_HOOK_INSN_SYSCALL_CB(cb),
                             unicorn.unicorn.UC_HOOK_INSN_SYSCALL_CB)
        elif hook_type == uc.UC_HOOK_CODE:
            cb = ct.cast(unicorn.unicorn.UC_HOOK_CODE_CB(cb),
                         unicorn.unicorn.UC_HOOK_CODE_CB)
        elif hook_type in (uc.UC_HOOK_MEM_READ, uc.UC_HOOK_MEM_WRITE):
            cb = ct.cast(unicorn.unicorn.UC_HOOK_MEM_ACCESS_CB(cb),
                         unicorn.unicorn.UC_HOOK_MEM_ACCESS_CB)
        elif hook_type == uc.UC_HOOK_MEM_INVALID:
            cb = ct.cast(unicorn.unicorn.UC_HOOK_MEM_INVALID_CB(cb),
                         unicorn.unicorn.UC_HOOK_MEM_INVALID_CB)
        else:
            return self.emu.hook_add(htype=hook_type, callback=cb, user_data=ctx,
                                     begin=begin, end=end)
        ptr = ct.cast(cb, ct.c_void_p)
        # uc_hook_add requires an additional paramter for the hook type UC_HOOK_INSN
        if hook_type == uc.UC_HOOK_INSN:
            insn = ct.c_int(arg1)
            rv = _uc.uc_hook_add(handle, ct.byref(hook_id), hook_type, ptr.value,
                                 None, begin, end, insn)
        else:
            rv = _uc.uc_hook_add(handle, ct.byref(hook_id), hook_type, ptr.value,
                                 None, begin, end)
        if rv != uc.UC_ERR_OK:
            raise uc.UcError(rv)

        th = ToggleableHook(cb)
        self._callbacks.update({hook_id.value: th})

        return hook_id.value

    def hook_enable(self, hook_handle):
        """
        Enable a previously disabled hook
        """
        hook = self._callbacks.get(hook_handle)
        if hook:
            return hook.enable()

    def hook_disable(self, hook_handle):
        """
        Disable a previously enabled hook
        """
        hook = self._callbacks.get(hook_handle)
        if hook:
            return hook.disable()

    def hook_remove(self, hid):
        return self.emu.hook_del(hid)
