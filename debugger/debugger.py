# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import os
import sys
import cmd
import shlex
import fnmatch
import logging
import binascii
import argparse
import traceback

import hexdump

import speakeasy
import speakeasy.winenv.arch as e_arch
from speakeasy.errors import SpeakeasyError

if sys.platform != 'win32':
    import readline # noqa (used by cmd)


class DebuggerException(Exception):
    pass


def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('sedbg')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger


class Breakpoint(object):
    _id = 0

    def __init__(self, address):
        if isinstance(address, int):
            self.address = address
        else:
            self.address = address.lower()
        self.id = Breakpoint._id
        Breakpoint._id += 1


class SpeakeasyDebugger(cmd.Cmd):
    prompt = '(sedbg) '

    file = None

    def __init__(self, target=None, is_sc=False, arch=None, data=None, logger=None, se_inst=None):
        super(SpeakeasyDebugger, self).__init__()

        self.target = target
        self.is_sc = is_sc
        self.arch = arch
        self.logger = logger
        if not se_inst:
            self.se = speakeasy.Speakeasy(logger=self.logger)
        else:
            self.se = se_inst
        self.loaded_modules = []
        self.loaded_shellcode = []
        self.targets = []
        self.breakpoints = {}
        self.init_state()
        if self.is_sc and not self.arch:
            raise DebuggerException('Architecture required when debugging shellcode')

        if self.target:
            if not self.is_sc:
                # Load the initial target module
                self.load_module(self.target)
            else:
                self.load_shellcode(self.target, self.arch)

    def init_state(self):
        if self.se:
            self.se.add_code_hook(self.code_hook)
            self.se.add_api_hook(self.api_hook, '*', '*')  # hook every API
        self.step = False
        self.running = False
        self._do_stop = False
        self.exit = False
        self.step_over = 0
        self.next_pc = 0

    def error(self, msg):
        self.logger.error('[-] ' + msg)

    def info(self, msg):
        self.logger.info(msg)

    def log_disasm(self, addr, size):
        ds = self.se.disasm(addr, size, False)[0]
        out = '0x%x: %s %s' % (ds.address, ds.mnemonic, ds.op_str)
        self.info(out)

    def format_hexdump(self, data, address=0):
        output = []
        for line in hexdump.hexdump(data, result='generator'):
            offset = line[: line.find(':')]
            rest = line[line.find(':'):]

            offset = int.from_bytes(binascii.unhexlify(offset), 'big')

            if address > 0xFFFFFFFF:
                fmt = r'%016X'
            else:
                fmt = r'%08X'

            addr = fmt % (offset + address)
            output.append(addr + rest)
        return '\n'.join(output)

    def _break(self, addr):
        '''
        Return execution back to the debugger and do not execute the
        current instruction.
        '''
        self.step = False
        self._do_stop = True
        self.next_pc = addr
        self.se.stop()

    def api_hook(self, emu, api_name, func, params):
        '''
        Hook called for API calls
        '''
        rv = func(params)
        addr = emu.get_ret_address()

        bp = self.breakpoints.get(api_name.lower())
        if bp:
            self.info('\nBreakpoint %d hit for %s' % (bp.id, api_name))
            self.step = True
            return rv

        elif '.' in api_name:
            fn = api_name.split('.')[1]
            bp = self.breakpoints.get(fn.lower())
            if bp:
                self.info('\nBreakpoint %d hit for %s' % (bp.id, api_name))
                self.step = True
                return rv

        for addr, bp in self.breakpoints.items():
            if not isinstance(addr, int):
                if fnmatch.fnmatch(api_name.lower(), addr.lower()):
                    self.info('\nBreakpoint %d hit for %s' % (bp.id, api_name))
                    self.step = True
                    return rv
        return rv

    def code_hook(self, emu, addr, size, ctx):
        '''
        Hook called for each instruction while debugging
        '''

        if self._do_stop:
            self.next_pc = addr
            self._do_stop = False
            return True

        if self.breakpoints:
            bp = self.breakpoints.get(addr)
            if bp:
                self.log_disasm(addr, size)
                self.info('\nBreakpoint %d hit for 0x%x' % (bp.id, addr))
                self._break(addr)
                return True

        if self.step:
            sres, eres = emu.get_reserved_ranges()
            if sres < addr < eres:
                addr = emu.get_ret_address()

            self.log_disasm(addr, size)
            self._break(addr)
            return True

    def stop(self):
        '''
        Stop running the emulator
        '''
        self.se.stop()
        self.running = False

    def convert_bin_str(self, hstr):
        '''
        Convert a hex string to an int
        '''
        # Was a register supplied? Read it.
        regs = self.se.get_all_registers()
        val = regs.get(hstr.lower())
        if val:
            hstr = val

        if hstr.startswith('0x'):
            int_val = int(hstr, 16)
        else:
            int_val = int(hstr, 10)
        return int_val

    def dump_mem(self, address, length):
        '''
        Dump memory (until an invalid memory read or max length occurs)
        '''
        data = []
        try:
            for i in range(length):
                data.append(self.se.mem_read(address + i, 1))
        except SpeakeasyError:
            self.error("Failed memory read at address: 0x%x" % (address + i))
        return b''.join(data)

    def write_mem(self, address, data):
        '''
        Write memory (until an invalid memory read or max length occurs)
        '''
        try:
            for i, b in enumerate(bytes(data)):
                self.se.mem_write(address + i, data[i: i + 1])
        except Exception:
            self.error("Failed memory write at address: 0x%x" % (address + i))
        finally:
            return

    def do_maps(self, args):
        '''
        Get a list of all memory maps in the emulation space

        Usage:
            maps
        '''
        self.info('Base\t\t   Size\t      Tag')
        for mm in self.se.get_mem_maps():
            line = '0x%016x 0x%08x %s' % (mm.get_base(), mm.get_size(), mm.get_tag())
            self.info(line)

    def do_bl(self, args):
        '''
        List all current breakpoints and their IDs

        Usage:
            bl
        '''
        self.info('Breakpoints:')
        for addr, bp in self.breakpoints.items():
            if isinstance(addr, int):
                line = '%d: 0x%016x' % (bp.id, addr)
            else:
                line = '%d: %s' % (bp.id, addr)
            self.info(line)

    def do_bp(self, args):
        '''
        Set a breakpoint at the specified address or API name

        Usage:
            bp [ <breakpoint_addr> | <api_name> ]
            bp 0x10001020
        '''
        split_args = shlex.split(args)
        address = split_args[0]
        try:
            address = self.convert_bin_str(address)
            bp = Breakpoint(address)
            msg = '[*] Breakpoint %d set at address 0x%x' % (bp.id, address)
            rv = address
        except Exception:
            orig = address
            address = address.lower()
            bp = Breakpoint(address)
            msg = '[*] Breakpoint %d set at %s' % (bp.id, orig)
            rv = None

        self.breakpoints.update({address: bp})
        self.info(msg)
        return rv

    def do_bc(self, args):
        '''
        Remove a breakpoint by ID

        Usage:
            bc <breakpoint_id>
            bc 1
        '''
        split_args = shlex.split(args)
        try:
            _id = int(split_args[0])
        except Exception:
            self.error('Invalid breakpoint id')
            return None

        for addr, bp in self.breakpoints.items():
            if _id == bp.id:
                self.info('[*] Removing breakpoint %d' % (_id))
                self.breakpoints.pop(addr)
                return addr

    def do_disas(self, args):
        '''
        Disassemble an address

        Usage:
            disas <address> [length]
        '''
        split_args = shlex.split(args)

        if not split_args:
            self.error('Invalid arguments: disas <address> [size]')
            return

        address = ''
        length = '0x10'
        address = split_args[0]
        try:
            length = split_args[1]
        except IndexError:
            # Use the default length
            pass

        try:
            addr = self.convert_bin_str(address)
            length = self.convert_bin_str(length)
            instrs = self.se.disasm(addr, length, False)
        except ValueError:
            self.error('Invalid arguments')
            return
        except SpeakeasyError:
            self.error('Failed to disassemble at address: %s' % (address))
            return

        for i in instrs:
            self.info('0x%x: %s %s' % (i.address, i.mnemonic, i.op_str))

    def load_module(self, module):
        '''
        Load a module into the emulation space
        '''
        if not os.path.exists(module):
            self.error('Can\'t find module: %s' % (module))
        else:
            module = self.se.load_module(module)
            self.loaded_modules.append(module)

    def load_shellcode(self, sc_path, arch):
        '''
        Load shellcode into the emulation space
        '''

        if self.is_sc:
            arch = arch.lower()
            if arch in ('x86', 'i386'):
                arch = e_arch.ARCH_X86
            elif arch in ('x64', 'amd64'):
                arch = e_arch.ARCH_AMD64
            else:
                raise Exception('Unsupported architecture: %s' % arch)

        if not os.path.exists(sc_path):
            self.error('Can\'t find shellcode: %s' % (sc_path))
        else:
            sc = self.se.load_shellcode(sc_path, arch)
            self.loaded_shellcode.append(sc)
            return sc

    def do_restart(self, arg):
        '''
        Restart emulation from the entry point
        '''
        self.se = speakeasy.Speakeasy(logger=self.logger)
        if self.target:
            if not self.is_sc:
                # Load the initial target module
                self.load_module(self.target)
            else:
                self.load_shellcode(self.target, self.arch)
        self.init_state()
        self.do_run(None)

    def do_load_module(self, arg):
        '''
        Wrapper to load a module
        '''
        self.load_module(arg)

    def do_eb(self, args):
        '''
        Edit bytes at the specified address

        Usage:
            eb <address> <byte_string>
        Example:
            eb 0x401000 9090909090c3
        '''
        split_args = shlex.split(args)
        if len(split_args) < 2:
            self.error('Invalid arguments: eb <address> <byte_string>')
            return

        address = split_args[0]
        address = self.convert_bin_str(address)
        data = ''.join(split_args[1:])

        # Do some basic normalization
        if data.startswith('0x'):
            data = data[2:]
        data = data.replace(' ', '')
        if len(data) % 2:
            data = '0' + data

        data = binascii.unhexlify(data)
        self.write_mem(address, data)

    def do_db(self, args):
        '''
        Dump bytes from emulated memory

        Usage:
            db <address> [length]
        Example:
            db 0x401000
        '''
        split_args = shlex.split(args)

        if len(split_args) < 1:
            self.error('Invalid arguments: db <address> <size>')
            return

        address = split_args[0]
        address = self.convert_bin_str(address)

        decoy = self.se.emu.get_mod_from_addr(address)
        if decoy:
            self.se.emu.map_decoy(decoy)

        if len(split_args) == 1:
            address = split_args[0]
            address = self.convert_bin_str(address)
            data = self.dump_mem(address, 0x50)
        elif len(split_args) == 2:
            address, length = split_args
            address = self.convert_bin_str(address)
            length = self.convert_bin_str(length)
            data = self.dump_mem(address, length)
        output = self.format_hexdump(data, address=address)
        self.info(output)

    def do_lm(self, args):
        '''
        List user modules loaded into the emulation space

        Usage:
            lm
        '''
        ums = self.se.get_user_modules()

        self.info('Start\t\t\tEnd\t\t\tName\t\tPath')
        for um in ums:
            base = '0x%016x' % um.get_base()
            end = '0x%016x' % (um.get_base() + um.get_image_size())
            name = um.get_base_name().ljust(16)
            path = um.get_emu_path()
            self.info('%s\t%s\t%s%s' % (base, end, name, path))

    def do_lmk(self, args):
        '''
        List kernel modules loaded into the emulation space

        Usage:
            lmk
        '''
        kms = self.se.get_sys_modules()

        self.info('Start\t\t\tEnd\t\t\tName\t\tPath')
        for km in kms:
            base = '0x%016x' % km.get_base()
            end = '0x%016x' % (km.get_base() + km.get_image_size())
            name = km.get_base_name().ljust(16)
            path = km.get_emu_path()
            self.info('%s\t%s\t%s%s' % (base, end, name, path))

    def do_reg(self, arg):
        '''
        Read or write the contents of the emulated cpu registers

        Usage:
            reg
            reg <reg_to_read>
            reg <reg_to_write>=<value>
        '''
        # Is the user requesting all registers?
        regs = self.se.get_all_registers()
        if not arg:
            o = ''
            for i, (r, v) in enumerate(regs.items()):
                o += '%s=%s ' % (r, v)
                if not ((i + 1) % 3):
                    o += '\n'
            self.info(o)
            return

        # Is the user trying to modify a register?
        reg_write = [a.strip() for a in arg.split('=')]
        if len(reg_write) > 1:
            if len(reg_write) != 2:
                self.error('Invalid register write syntax: (e.g. eax=0')
                return
            reg, val = reg_write
            if not regs.get(reg):
                self.error('Invalid register: %s' % (reg))
                return
            try:
                int_val = self.convert_bin_str(val)
            except ValueError:
                self.error('Invalid write value')
                return
            if int_val is not None:
                self.se.reg_write(reg, int_val)
            return

        val = regs.get(arg.lower())
        if not val:
            self.error('Invalid register: %s' % (arg))
        else:
            self.info('%s=%s' % (arg, val))

    def do_run(self, arg):
        '''Begin emulation of a loaded module'''
        if not self.is_sc and not len(self.loaded_modules):
            self.error('No modules have been loaded yet')

        if not self.running:
            if not self.is_sc:
                if len(self.loaded_modules) == 1:
                    self.se.run_module(self.loaded_modules[0],
                                       all_entrypoints=False)
            else:
                self.se.run_shellcode(self.loaded_shellcode[0], 0)
            self.running = True
        else:
            self.step = False
            self.se.resume(self.next_pc, count=-1)

    def do_stepi(self, arg):
        '''
        Step into an instruction
        '''
        if not self.running:
            self.step = True
            self.running = True
            if not self.is_sc:
                self.se.run_module(self.loaded_modules[0],
                                   all_entrypoints=False)
            else:
                self.se.run_shellcode(self.loaded_shellcode[0], 0)
        else:
            self.step = True
            self.se.resume(self.next_pc, count=1)

    def do_stack(self, arg):
        '''
        Show the current stack layout
        '''
        stack = self.se.emu.format_stack(16)
        ptr_size = self.se.emu.get_ptr_size()
        ptr_fmt = '0x%0' + str(ptr_size * 2) + 'x'
        for loc in stack:
            sp, ptr, tag = loc

            if tag:
                fmt = 'sp=0x%x:\t' + ptr_fmt + '\t->\t%s'
                fmt = fmt % (sp, ptr, tag)
            else:
                fmt = 'sp=0x%x:\t' + ptr_fmt + '\t'
                fmt = fmt % (sp, ptr)
            self.info(fmt.expandtabs(5))

    def do_strings(self, arg):
        '''
        Scan all memory segments for strings
        '''
        tgt_tag_prefixes = ('emu.stack', 'api')
        for mmap in self.se.emu.get_mem_maps():
            tag = mmap.get_tag()
            base = mmap.get_base()
            if (tag and tag.startswith(tgt_tag_prefixes) and
               tag != self.se.emu.input.get('mem_tag')):
                data = self.se.mem_read(mmap.get_base(), mmap.get_size()-1)
                ansi_strings = self.se.emu.get_ansi_strings(data)
                for offset, astr in ansi_strings:
                    addr = base + offset
                    self.info('0x%x: %s' % (addr, astr))

                uni_strings = self.se.emu.get_unicode_strings(data)
                for offset, wstr in uni_strings:
                    addr = base + offset
                    self.info('0x%x: %s' % (addr, wstr))

    def do_exit(self, arg):
        '''
        Quit debugging
        '''
        self.exit = True
        return True


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Debug a Windows binary with speakeasy')
    parser.add_argument('-t', '--target', action='store', dest='target',
                        required=True, help='Path to input file to emulate')
    parser.add_argument('-r', '--raw', action='store_true', dest='raw',
                        required=False, help='Attempt to emulate file as-is '
                                             'with no parsing (e.g. shellcode)')
    parser.add_argument('-a', '--arch', action='store', dest='arch',
                        required=False,
                        help='Force architecture to use during emulation (for '
                             'multi-architecture files or shellcode). '
                             'Supported archs: [ x86 | amd64 ]')

    args = parser.parse_args()

    dbg = SpeakeasyDebugger(args.target, args.raw, args.arch, logger=get_logger())
    dbg.info('Welcome to the speakeasy debugger')
    while True:
        try:
            dbg.cmdloop()
            if dbg.exit:
                break
        except KeyboardInterrupt:
            dbg.info('\n[*] User exited')
            break
        # Catch all other exceptions here
        except Exception:
            dbg.info(traceback.format_exc())
