# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import re
import json
import fnmatch
import traceback
from typing import List, Tuple, Dict

import binascii

import speakeasy.common as common
import speakeasy.winenv.arch as e_arch
from speakeasy.engines import unicorn_eng
from speakeasy.profiler import Profiler
import speakeasy.version as version
from speakeasy.memmgr import MemoryManager

from speakeasy.errors import EmuException

EMU_ENGINES = (
              ('unicorn', unicorn_eng.EmuEngine),
              )

WILDCARD_FLAG = bool
API_LEVEL = Tuple[Dict[str, List[common.ApiHook]], WILDCARD_FLAG]
MODULE_LEVEL = Tuple[Dict[str, API_LEVEL], WILDCARD_FLAG]


# Generic emulator class for binary code
class BinaryEmulator(MemoryManager):
    """
    Base class for emulating binaries
    """
    def __init__(self, config, logger=None):

        super(BinaryEmulator, self).__init__()

        self.stack_base = 0
        self.page_size = None
        self.inst_count = 0
        self.curr_instr_size = 0
        self.disasm_eng = None
        self.builtin_hooks_set = False
        self.emu_eng = None
        self.maps = []
        self.config = config
        self.hooks = {}

        self.profiler = Profiler()

        self.runtime = 0

        self.emu_version = self.get_emu_version()
        self.logger = logger

    def log_info(self, msg):
        if self.logger:
            self.logger.info(msg)

    def log_error(self, msg):
        if self.logger:
            self.logger.error(msg)

    def log_exception(self, msg):
        if self.logger:
            self.logger.exception(msg)

    def get_profiler(self):
        """
        Get the current event profiler object (if any)
        """
        return self.profiler

    def get_report(self):
        """
        Get the emulation report for all runs that were executed
        """
        if self.profiler:
            return self.profiler.get_report()

    def get_json_report(self):
        """
        Get the emulation report for all runs that were executed formatted as a JSON string
        """
        if self.profiler:
            return self.profiler.get_json_report()

    def _parse_config(self, config):
        """
        Parse the config to be used for emulation
        """
        if isinstance(config, str):
            config = json.loads(config)
        self.config = config

        _eng = config.get('emu_engine', '')
        for name, eng in EMU_ENGINES:
            if name.lower() == _eng.lower():
                self.emu_eng = eng()
        if not self.emu_eng:
            raise EmuException('Unsupported emulation engine: %s' % (_eng))

        self.osversion = config.get('os_ver', {})
        self.env = config.get('env', {})
        self.user_config = config.get('user', {})
        self.domain = config.get('domain')
        self.hostname = config.get('hostname')
        self.symlinks = config.get('symlinks', [])
        self.config_modules = config.get('modules', {})
        self.config_system_modules = self.config_modules.get('system_modules', [])
        self.config_processes = config.get('processes', [])
        self.config_user_modules = self.config_modules.get('user_modules', [])

        self.config_analysis = config.get('analysis', {})
        self.max_instructions = config.get('max_instructions', -1)
        self.timeout = config.get('timeout', 0)
        self.max_api_count = config.get('max_api_count', 5000)
        self.exceptions = config.get('exceptions', {})
        self.drive_config = config.get('drives', [])
        self.filesystem_config = config.get('filesystem', {})
        self.keep_memory_on_free = config.get('keep_memory_on_free', False)

        self.network_config = config.get('network', {})
        self.network_adapters = self.network_config.get('adapters', [])
        self.command_line = config.get('command_line', '')

    def get_emu_version(self):
        """
        Get the version of the emulator
        """
        return version.__version__

    def get_os_version(self):
        """
        Get version of the OS being emulated
        """
        return self.osversion

    def get_osver_string(self):
        """
        Get the human readable OS version string
        """
        osver = self.get_os_version()
        if osver:
            os_name = osver.get('name', '')
            major = osver.get('major')
            minor = osver.get('minor')
            if major is not None and minor is not None:
                verstr = '%s.%d_%d' % (os_name, major, minor)
                return verstr

    def get_domain(self):
        """
        Get domain of the machine being emulated
        """
        return self.domain

    def get_hostname(self):
        """
        Get hostname of the machine being emulated
        """
        return self.hostname

    def get_user(self):
        """
        Get the current emulated user properties
        """
        return self.user_config

    def sizeof(self, obj):
        """
        Get the size (in the emulation space) of the supplied object
        """
        return obj.sizeof()

    def get_bytes(self, obj):
        """
        Get the bytes represented in the emulation space of the supplied object
        """
        return obj.get_bytes()

    def stop(self):
        """
        Stop emulation completely
        """
        self.emu_eng.stop()
        if self.profiler:
            self.profiler.stop_run_clock()

    def start(self, addr, size):
        """
        Begin emulation
        """
        self.set_hooks()
        self._set_emu_hooks()
        if self.profiler:
            self.profiler.set_start_time()
        try:
            self.emu_eng.start(addr, timeout=self.timeout, count=self.max_instructions)
        except Exception:
            if self.profiler:
                self.profiler.log_error(traceback.format_exc())
            self.on_emu_complete()

    def get_network_config(self):
        """
        Get the network settings specified in the network section of the config file
        """
        return self.network_config

    def get_network_adapters(self):
        """
        Get the network adapters specified in the network section of the config file
        """
        return self.network_adapters

    def get_filesystem_config(self):
        """
        Get the filesystem settings specified in the filesystem section of the config file
        """
        return self.filesystem_config

    def get_drive_config(self):
        """
        Get the drive settings specified in the drives section of the config file
        """
        return self.drive_config

    def reg_write(self, reg, val):
        """
        Write a value to an emulated cpu register
        """
        if isinstance(reg, str):
            _reg = e_arch.REG_LOOKUP.get(reg.lower())
            if not _reg:
                raise EmuException('Invalid register access %s' % (reg))
            reg = _reg

        self.emu_eng.reg_write(reg, val)

    def reg_read(self, reg):
        """
        Read a value from an emulated cpu register
        """
        if isinstance(reg, str):
            _reg = e_arch.REG_LOOKUP.get(reg.lower())
            if not _reg:
                raise EmuException('Invalid register access %s' % (reg))
            reg = _reg

        return self.emu_eng.reg_read(reg)

    def set_hooks(self):
        """
        Set instruction level hooks
        """
        for ht in (common.HOOK_CODE, common.HOOK_MEM_READ, common.HOOK_MEM_WRITE,
                   common.HOOK_MEM_INVALID, common.HOOK_INTERRUPT):
            for hook in self.hooks.get(ht, []):
                if not hook.added:
                    hook.add()

    def _cs_disasm(self, mem, addr, fast=True):
        """
        Disassemble bytes using capstone
        """
        try:
            if fast:
                tu = [i for i in self.disasm_eng.disasm_lite(bytes(mem), addr)]
                address, size, mnem, oper = tu[0]
            else:
                return [i for i in self.disasm_eng.disasm(bytes(mem), addr)]
        except IndexError:
            raise EmuException("Failed to disasm at address: 0x%x" % (addr))

        op = '%s %s' % (mnem, oper)
        return ((mnem, oper, op))

    def disasm(self, mem, addr, fast=True):
        """
        Disassemble bytes at a specified address
        """
        return self._cs_disasm(mem, addr, fast=fast)

    def get_register_state(self):
        """
        Get the current state of registers from the emulator
        """
        regs = {}
        if e_arch.ARCH_X86 == self.get_arch():
            for name, reg in (('esp', e_arch.X86_REG_ESP),
                              ('ebp', e_arch.X86_REG_EBP),
                              ('eip', e_arch.X86_REG_EIP),
                              ('esi', e_arch.X86_REG_ESI),
                              ('edi', e_arch.X86_REG_EDI),
                              ('eax', e_arch.X86_REG_EAX),
                              ('ebx', e_arch.X86_REG_EBX),
                              ('ecx', e_arch.X86_REG_ECX),
                              ('edx', e_arch.X86_REG_EDX)):
                val = self.reg_read(reg)
                regs[name] = "{0:#0{1}x}".format(val, 2 + (self.get_ptr_size() * 2))
        elif e_arch.ARCH_AMD64 == self.get_arch():
            for name, reg in (('rsp', e_arch.AMD64_REG_RSP),
                              ('rbp', e_arch.AMD64_REG_RBP),
                              ('rip', e_arch.AMD64_REG_RIP),
                              ('rsi', e_arch.AMD64_REG_RSI),
                              ('rdi', e_arch.AMD64_REG_RDI),
                              ('rax', e_arch.AMD64_REG_RAX),
                              ('rbx', e_arch.AMD64_REG_RBX),
                              ('rcx', e_arch.AMD64_REG_RCX),
                              ('rdx', e_arch.AMD64_REG_RDX),
                              ('r8',  e_arch.AMD64_REG_R8),
                              ('r9',  e_arch.AMD64_REG_R9),
                              ('r10', e_arch.AMD64_REG_R10),
                              ('r11', e_arch.AMD64_REG_R11),
                              ('r12', e_arch.AMD64_REG_R12),
                              ('r13', e_arch.AMD64_REG_R13),
                              ('r14', e_arch.AMD64_REG_R14),
                              ('r15', e_arch.AMD64_REG_R15)):
                val = self.reg_read(reg)
                regs[name] = "{0:#0{1}x}".format(val, 2 + (self.get_ptr_size() * 2))
        return regs

    def get_disasm(self, addr, size, fast=True):
        """
        Get the disassembly from an address
        """
        return self.disasm(self.mem_read(addr, size), addr, fast)

    def set_func_args(self, stack_addr, ret_addr, *args, home_space=True):
        """
        Set the arguments before an emulated function call. This is how we pass
        arguments to a function when calling it through the emulator.
        """
        curr_sp = stack_addr - self.ptr_size
        nargs = len(args)

        if self.get_arch() == e_arch.ARCH_X86:
            sp = e_arch.X86_REG_ESP
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = e_arch.AMD64_REG_RSP
            i = 0
            for i, r in enumerate((e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX,
                                   e_arch.AMD64_REG_R8, e_arch.AMD64_REG_R9)):
                if nargs == 0:
                    break
                self.reg_write(r, args[i])
                nargs -= 1
            # Set the stack home space
            if home_space:
                curr_sp -= 0x20
            self.reg_write(sp, curr_sp)
        else:
            raise EmuException('Unsupported architecture')

        if nargs > 0:
            for arg in args[-nargs:][::-1]:
                a = arg.to_bytes(self.ptr_size, byteorder='little')

                self.mem_write(curr_sp, a)
                self.reg_write(sp, curr_sp)
                curr_sp -= self.ptr_size

        # Set the return address
        r = ret_addr.to_bytes(self.ptr_size, byteorder='little')
        self.mem_write(curr_sp, r)
        self.reg_write(sp, curr_sp)

    def get_func_argv(self, callconv, argc):
        """
        Get the arguments for a function given the supplied calling convention
        """
        argv = []
        ptr_size = self.get_ptr_size()
        arch = self.get_arch()
        nargs = argc
        endian = 'little'

        # Handle calling conventions using floats
        if arch in (e_arch.ARCH_X86, e_arch.ARCH_AMD64):
            if callconv == e_arch.CALL_CONV_FLOAT:

                for i, r in enumerate((e_arch.X86_REG_XMM0,
                                       e_arch.X86_REG_XMM1,
                                       e_arch.X86_REG_XMM2,
                                       e_arch.X86_REG_XMM3)):
                    if nargs == 0:
                        break
                    val = self.reg_read(r)
                    argv.append(val)
                    nargs -= 1

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

            for i, r in enumerate((e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX,
                                   e_arch.AMD64_REG_R8, e_arch.AMD64_REG_R9)):
                if nargs == 0:
                    break
                val = self.reg_read(r)
                argv.append(val)
                nargs -= 1
        else:
            raise EmuException('Unsupported architecture')

        # Skip past the saved ret addr
        sp += ptr_size
        for i in range(nargs):
            ptr = self.mem_read(sp, ptr_size)
            argv.append(int.from_bytes(ptr, endian))
            sp += ptr_size

        return argv

    def do_call_return(self, argc, ret_addr=None, ret_value=None, conv=None):
        """
        Set the emulation state after a call has completed
        """
        if self.get_arch() == e_arch.ARCH_X86:
            sp = e_arch.X86_REG_ESP
            pc = e_arch.X86_REG_EIP
            rr = e_arch.X86_REG_EAX
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = e_arch.AMD64_REG_RSP
            pc = e_arch.AMD64_REG_RIP
            rr = e_arch.AMD64_REG_RAX
        else:
            raise EmuException('Unsupported architecture')

        if conv == e_arch.CALL_CONV_FLOAT:
            rr = e_arch.X86_REG_XMM0

        stk_ptr = self.reg_read(sp)

        if ret_addr:
            self.reg_write(sp, stk_ptr + self.ptr_size)
            self.reg_write(pc, ret_addr)
        if ret_value is not None:
            self.reg_write(rr, ret_value)

        # Cleanup the stack
        if conv == e_arch.CALL_CONV_CDECL:
            # If cdecl, the emu engine will clean the stack
            pass
        elif conv == e_arch.CALL_CONV_FASTCALL:
            if self.get_arch() == e_arch.ARCH_X86:
                if argc > 2:
                    self.clean_stack_args(argc - 2)
        else:
            self.clean_stack_args(argc)

    def get_ret_address(self):
        """
        Get the return address from the stack
        """

        endian = 'little'

        sp = self.get_stack_ptr()
        ret = self.mem_read(sp, self.ptr_size)
        ret = int.from_bytes(ret, endian)
        return ret

    def push_stack(self, val):
        """
        Put a value on the stack and adjust the stack pointer
        """
        endian = 'little'
        sp = self.get_stack_ptr()
        bval = val.to_bytes(self.ptr_size, endian)
        sp -= self.ptr_size
        self.mem_write(sp, bval)
        self.set_stack_ptr(sp)
        return val

    def pop_stack(self):
        """
        Get value from the stack and adjust the stack pointer
        """
        endian = 'little'
        sp = self.get_stack_ptr()
        val = self.mem_read(sp, self.ptr_size)
        val = int.from_bytes(val, endian)
        sp += self.ptr_size
        self.set_stack_ptr(sp)
        return val

    def get_stack_ptr(self):
        """
        Get the current address of the stack pointer
        """
        if self.get_arch() == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = self.reg_read(e_arch.AMD64_REG_RSP)
        return sp

    def set_stack_ptr(self, addr):
        """
        Set the current address of the stack pointer
        """
        if self.get_arch() == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_ESP, addr)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            self.reg_write(e_arch.AMD64_REG_RSP, addr)

    def format_stack(self, num_ptrs):
        """
        Get the stack and format it for display
        """
        out = []
        sp = self.get_stack_ptr()
        for i in range(num_ptrs):
            try:
                ptr = self.mem_read(sp, self.get_ptr_size())
            except Exception:
                return out
            ptr = int.from_bytes(ptr, 'little')
            tag = self.get_address_tag(ptr)
            out.append((sp, ptr, tag))
            sp += self.get_ptr_size()
        return out

    def print_stack(self, num_ptrs):
        """
        This a debug function used to print the current stack state
        """
        ptrs = self.format_stack(num_ptrs)
        print('Stack:')
        print('***********************')
        for p in ptrs:
            sp, ptr, tag = p
            if tag:
                fmt = 'sp=0x%x:\t0x%x\t->\t%s' % (sp, ptr, tag)
            else:
                fmt = 'sp=0x%x:\t0x%x\t' % (sp, ptr)

            print(fmt.expandtabs(5))
            sp += self.get_ptr_size()

    def get_stack_trace(self, num_ptrs=16):
        """
        Get the current stack state
        """
        trace = []
        sp = self.get_stack_ptr()
        try:
            for i in range(num_ptrs):
                ptr = self.mem_read(sp, self.get_ptr_size())
                ptr = int.from_bytes(ptr, 'little')
                tag = self.get_address_tag(ptr)
                fmt = "{0:#0{1}x}".format(ptr, 2 + (self.get_ptr_size() * 2))
                sp_off = "{0:#0{1}x}".format(i * self.get_ptr_size(), 2 * 2)
                if not tag:
                    entry = 'sp+%s: %s' % (sp_off, fmt)
                else:
                    entry = 'sp+%s: %s -> %s' % (sp_off, fmt, tag)
                trace.append(entry)
                sp += self.get_ptr_size()
        finally:
            return trace

    def get_pc(self):
        """
        Get the value of the current program counter
        """
        if self.get_arch() == e_arch.ARCH_X86:
            pc = self.reg_read(e_arch.X86_REG_EIP)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            pc = self.reg_read(e_arch.AMD64_REG_RIP)
        else:
            raise EmuException('Unsupported architecture')
        return pc

    def set_pc(self, addr):
        """
        Set the value of the current program counter
        """
        if self.get_arch() == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_EIP, addr)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            self.reg_write(e_arch.AMD64_REG_RIP, addr)
        else:
            raise EmuException('Unsupported architecture')

    def get_return_val(self):
        """
        Get the current value in the return register
        """
        if self.get_arch() == e_arch.ARCH_X86:
            val = self.reg_read(e_arch.X86_REG_EAX)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            val = self.reg_read(e_arch.AMD64_REG_RAX)
        else:
            raise EmuException('Unsupported architecture')
        return val

    def reset_stack(self, base):
        """
        Reset stack to the supplied base address
        """
        arch = self.get_arch()
        ptr = base

        if arch == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_ESP, base)
            self.reg_write(e_arch.X86_REG_EBP, base)
        elif arch == e_arch.ARCH_AMD64:
            # Save room for the "home space"
            ptr -= self.ptr_size * 5
            self.reg_write(e_arch.AMD64_REG_RSP, ptr)
            self.reg_write(e_arch.AMD64_REG_RBP, ptr)

        return base, ptr

    def alloc_stack(self, size):
        """
        Allocate memory to use for the program stack
        """
        # Allocate memory for our stack
        # Stack grows down
        chunk = self.get_valid_ranges(size, addr=0x1200000)
        addr, block_size = chunk
        self.mem_map(block_size, base=addr, tag='emu.stack')

        base = addr + block_size
        self.mem_reserve(size, base=base)

        base, ptr = self.reset_stack(base)

        return base, ptr

    def clean_stack_args(self, argc):
        """
        Adjust the stack for arguments that were supplied
        """
        ptr_size = self.get_ptr_size()
        arch = self.get_arch()

        if argc == 0:
            return

        if arch == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
            sp += (ptr_size * argc)
            self.reg_write(e_arch.X86_REG_ESP, sp)

        elif arch == e_arch.ARCH_AMD64:
            return
        else:
            raise EmuException('Unsupported architecture')

    def get_arch(self):
        """
        Get the current emulated architecture
        """
        return self.arch

    def get_arch_name(self):
        """
        Get the name of current emulated architecture
        """
        if self.arch == e_arch.ARCH_AMD64:
            return 'amd64'
        elif self.arch == e_arch.ARCH_X86:
            return 'x86'
        return ''

    def eval_emu_var(self):
        """
        Used to expand variables supplied in the emulator config file. This
        might be useful for accessing files that are a relative path of the
        speakeasy package.
        For example:
            $ROOT$: This variable corresponds to the package root for speakeasy
        """

    def read_mem_string(self, address, width=1, max_chars=0):
        """
        Read a string from emulated memory
        """
        char = b'\xFF'
        string = b''
        i = 0

        if width == 1:
            decode = 'latin1'
        elif width == 2:
            decode = 'utf-16le'
        else:
            raise ValueError('Invalid string encoding')

        while int.from_bytes(char, 'little') != 0:
            if max_chars and i >= max_chars:
                break
            char = self.mem_read(address, width)

            string += char
            address += width
            i += 1

        try:
            dec = string.decode(decode, 'ignore').replace('\x00', '')
        except Exception:
            dec = string.replace(b'\x00', b'')
        return dec

    def mem_string_len(self, address, width=1):
        """
        Get the length of a string from emulated memory
        """
        slen = -1
        char = b'\xFF'

        while int.from_bytes(char, 'little') != 0:
            char = self.mem_read(address, width)
            address += width
            slen += 1
        return slen

    def get_ansi_strings(self, data, min_len=4):
        """
        Get all ansi strings from a supplied memory blob
        """
        astrs = []
        pat = b'[\x20-\x7f]{%d,}' % (min_len)
        res = re.compile(pat)
        hits = res.findall(data)
        offset = 0
        for s in hits:
            try:
                offset = data.find(s, offset)
                s = s.decode('utf-8')
                astrs.append((offset, s))
                offset += 1
            except UnicodeDecodeError:
                continue
        return astrs

    def get_unicode_strings(self, data, min_len=4):
        """
        Get all unicode strings from a supplied memory blob
        """
        wstrs = []
        pat = b'(?:[\x20-\x7f]\x00){%d,}' % (min_len)
        res = re.compile(pat)
        hits = res.findall(data)
        offset = 0
        for ws in hits:
            try:
                offset = data.find(ws, offset)
                ws = ws.decode('utf-16le')
                wstrs.append((offset, ws))
                offset += 1
            except UnicodeDecodeError:
                continue
        return wstrs

    def mem_copy(self, dst, src, n):
        """
        Copy bytes from one emulated address to another
        """
        sbytes = self.mem_read(src, n)
        self.mem_write(dst, sbytes)
        return n

    def write_mem_string(self, string, address, width=1):
        """
        Write string data to an emulated memory address
        """

        if width == 1:
            encode = 'utf-8'
        elif width == 2:
            encode = 'utf-16le'
        else:
            raise ValueError('Invalid string encoding')

        enc_str = string.encode(encode)
        self.mem_write(address, enc_str)

    def read_ptr(self, address):
        val = self.mem_read(address, self.ptr_size)
        return int.from_bytes(val, 'little')

    def write_ptr(self, address, val):
        self.mem_write(address, val.to_bytes(self.ptr_size, 'little'))

    def get_ptr_size(self):
        """
        Get the pointer size of the current emulation state
        """
        return self.ptr_size

    def get_mem_strings(self):
        """
        Get ansi and unicode strings from emulated memory
        """
        tgt_tag_prefixes = ('emu.stack', 'api')
        ansi_strings = []
        unicode_strings = []
        ret_ansi = []
        ret_unicode = []

        for mmap in self.get_mem_maps():
            tag = mmap.get_tag()
            if tag and tag.startswith(tgt_tag_prefixes) and tag != self.input.get('mem_tag'):
                data = self.mem_read(mmap.get_base(), mmap.get_size()-1)
                ansi_strings += self.get_ansi_strings(data)
                unicode_strings += self.get_unicode_strings(data)

        [ret_ansi.append(a) for a in ansi_strings if a not in ret_ansi]
        [ret_unicode.append(a) for a in unicode_strings if a not in ret_unicode]

        return (ret_ansi, ret_unicode)

    def set_ptr_size(self, arch):
        """
        Set the current pointer size used in the emulator
        """
        if arch == e_arch.ARCH_AMD64:
            self.ptr_size = 8
        elif arch == e_arch.ARCH_X86:
            self.ptr_size = 4
        else:
            raise EmuException('Unsupported architecture')

    def get_module_from_addr(self, addr):
        """
        If the supplied address belongs to a module, return it
        """
        for mod in self.modules:
            base, size = mod[1]
            if addr >= base and addr <= base + size:
                return mod[0]
        return None

    def get_api_hooks(self, mod_name, func_name) -> List[common.ApiHook]:
        """
        If an API hook has been set, return it here
        """

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
                    if (fnmatch.fnmatch(func_name, func_name_saved) and
                       func_name != func_name_saved):
                        user_hooks.extend(list_of_hooks)
        return user_hooks

    def add_api_hook(self, cb, module='', api_name='', argc=0, call_conv=None,
                     emu=None) -> common.ApiHook:
        """
        Add an API level hook (e.g. kernel32.CreateFile) here
        """
        module = module.lower()
        api_name = api_name.lower()

        wildcard_module, wildcard_api = False, False
        for wc in ['?', '*', '[', ']']:
            if wc in module:
                wildcard_module = True
            if wc in api_name:
                wildcard_api = True

        if not emu:
            emu = self
        hook = common.ApiHook(emu, self.emu_eng, cb, module, api_name, argc, call_conv)
        _hooks: MODULE_LEVEL = self.hooks.get(common.HOOK_API)

        api_dictionary = (
            {
              api_name: [hook]
            },
            wildcard_api)
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
        return hook

    def add_code_hook(self, cb, begin=1, end=0, ctx={}, emu=None):
        """
        Add a hook that will fire for every CPU instruction
        """
        hl = self.hooks.get(common.HOOK_CODE, [])
        if not emu:
            emu = self
        hook = common.CodeHook(self, self.emu_eng, cb, begin, end, ctx)
        if not hl:
            self.hooks.update({common.HOOK_CODE: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def _dynamic_code_cb(self, emu, addr, size, ctx={}):
        """
        Call all subscribers that want callbacks dynamic code callbacks
        """

        profiler = self.get_profiler()
        mm = self.get_address_map(addr)
        if profiler:
            run = self.get_current_run()
            profiler.log_dyn_code(run, mm.get_tag(), mm.get_base(), mm.get_size())

        for h in self.hooks.get(common.HOOK_DYN_CODE, []):
            h.cb(mm)

        # Delete the code hook that got us here
        if ctx and isinstance(ctx, dict):
            h = ctx.get('_delete_hook')
            if h:
                h.disable()

    def _set_dyn_code_hook(self, addr, size, ctx={}):
        """
        Set the top level dispatch hook for dynamic code execution
        """
        max_hook_size = 0x10
        if size > max_hook_size:
            size = max_hook_size

        ch = self.add_code_hook(cb=self._dynamic_code_cb, begin=addr, end=addr + size, ctx=ctx)
        ctx.update({'_delete_hook': ch})

    def add_dyn_code_hook(self, cb, ctx=[], emu=None):
        """
        Add a hook that will fire when dynamically generated/copied code is executed
        """
        if not emu:
            emu = self
        hl = self.hooks.get(common.HOOK_DYN_CODE, [])

        hook = common.DynCodeHook(emu, self.emu_eng, cb, ctx)
        if not hl:
            self.hooks.update({common.HOOK_DYN_CODE: [hook, ]})
        else:
            hl.insert(0, hook)

        return hook

    def add_mem_read_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for memory reads
        """
        if not emu:
            emu = self
        hook = common.ReadMemHook(emu, self.emu_eng, cb, begin, end)
        hl = self.hooks.get(common.HOOK_MEM_READ)
        if not hl:
            self.hooks.update({common.HOOK_MEM_READ: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_mem_write_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for memory writes
        """
        if not emu:
            emu = self
        hook = common.WriteMemHook(emu, self.emu_eng, cb, begin, end)
        hl = self.hooks.get(common.HOOK_MEM_WRITE)
        if not hl:
            self.hooks.update({common.HOOK_MEM_WRITE: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_mem_map_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for memory maps
        """
        if not emu:
            emu = self
        hook = common.MapMemHook(emu, self.emu_eng, cb, begin, end)
        hl = self.hooks.get(common.HOOK_MEM_MAP)
        if not hl:
            self.hooks.update({common.HOOK_MEM_MAP: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def _hook_mem_invalid_dispatch(self, emu, access, address, size, value, ctx):
        """
        This handler will dispatch other invalid memory hooks
        """
        hl = self.hooks.get(common.HOOK_MEM_INVALID, [])

        rv = True
        for mem_access_hook in hl[:-1]:
            if mem_access_hook.enabled:
                rv = mem_access_hook.cb(emu, access, address, size, value, ctx)
                if rv is False:
                    break
        return rv

    def add_mem_invalid_hook(self, cb, emu=None):
        """
        Add a hook that will fire for invalid memory access
        """
        hook = common.InvalidMemHook(self, self.emu_eng, cb, native_hook=False)
        hl = self.hooks.get(common.HOOK_MEM_INVALID)
        if not emu:
            emu = self
        if not hl:
            dispatch_hook = common.InvalidMemHook(emu, self.emu_eng,
                                                  self._hook_mem_invalid_dispatch,
                                                  native_hook=True)
            if self.emu_eng:
                dispatch_hook.add()

            self.hooks.update({common.HOOK_MEM_INVALID: [hook, dispatch_hook]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_interrupt_hook(self, cb, ctx=[], emu=None):
        """
        Add a hook that will fire for software interrupts
        """
        if not emu:
            emu = self
        hook = common.InterruptHook(emu, self.emu_eng, cb, ctx=[])
        hl = self.hooks.get(common.HOOK_INTERRUPT)
        if not hl:
            self.hooks.update({common.HOOK_INTERRUPT: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_instruction_hook(self, cb, begin=1, end=0, ctx=[], emu=None, insn=None):
        """
        Add a hook that will fire for IN, SYSCALL, or SYSENTER instructions
        """
        if not emu:
            emu = self
        hook = common.InstructionHook(emu, self.emu_eng, cb, ctx=[], insn=insn)
        hl = self.hooks.get(common.HOOK_INSN)
        if not hl:
            self.hooks.update({common.HOOK_INSN: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_invalid_instruction_hook(self, cb, ctx=[], emu=None):
        if not emu:
            emu = self

        hook = common.InvalidInstructionHook(emu, self.emu_eng, cb, ctx=[])
        hl = self.hooks.get(common.HOOK_INSN_INVALID)

        if not hl:
            self.hooks.update({common.HOOK_INSN_INVALID: [hook, ]})
        else:
            hl.insert(0, hook)

        if self.emu_eng:
            hook.add()

        return hook
