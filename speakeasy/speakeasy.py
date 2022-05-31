# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import json
import ntpath
import hashlib
import zipfile
from io import BytesIO
from typing import Callable


from pefile import MACHINE_TYPE
import jsonschema
import jsonschema.exceptions

import speakeasy
import speakeasy.winenv.arch as _arch
from speakeasy import PeFile
from speakeasy import Win32Emulator
from speakeasy import WinKernelEmulator

from speakeasy.errors import SpeakeasyError, ConfigError, NotSupportedError


class Speakeasy(object):
    """
    Wrapper class for invoking the speakeasy emulators
    """

    def check_init(func):

        """Wrapper to make sure the emulator is initialized"""

        def wrap(self, *args, **kwargs):
            if not self.emu:
                raise SpeakeasyError('Emulator not initialized')
            return func(self, *args, **kwargs)
        return wrap

    def __init__(self, config=None, logger=None, argv=[], debug=False, exit_event=None):

        self.logger = logger
        self._init_config(config)
        self.emu = None
        self.api_hooks = []
        self.code_hooks = []
        self.dyn_code_hooks = []
        self.invalid_insn_hooks = []
        self.mem_read_hooks = []
        self.argv = argv
        self.exit_event = exit_event
        self.debug = debug
        self.loaded_bins = []
        self.mem_write_hooks = []
        self.mem_invalid_hooks = []
        self.interrupt_hooks = []
        self.mem_map_hooks = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        del self

    def _init_config(self, config: dict) -> None:
        """
        Init the emulator config
        args:
            config: The configuration data to set up the emulator environment
                    If none is supplied, a default config is used.
        return:
            None
        """
        if not config:
            config_path = os.path.join(os.path.dirname(speakeasy.__file__),
                                       'configs', 'default.json')
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = config

        try:
            validate_config(self.config)
        except jsonschema.exceptions.SchemaError as err:
            if self.logger:
                self.logger.exception('Invalid config schema: %s', str(err))
            raise ConfigError('Invalid config schema')
        except jsonschema.exceptions.ValidationError as err:
            if self.logger:
                self.logger.exception('Invalid config: %s', str(err))
            raise ConfigError('Invalid config')

    def _init_emulator(self, path=None, data=None, is_raw_code=False) -> None:
        """
        Based on the PE metadata, use the appropriate emulator. That is,
        a user mode emulator vs a kernel mode emulator

        """
        if not is_raw_code:
            pe = PeFile(path=path, data=data)
            # Get the machine type we only support x86/x64 atm
            mach = MACHINE_TYPE[pe.FILE_HEADER.Machine].split('_')[-1:][0].lower()
            if mach not in ('amd64', 'i386'):
                raise SpeakeasyError('Unsupported architecture: %s' % mach)

            if pe.is_dotnet():
                raise NotSupportedError('.NET assemblies are not currently supported')

            if pe.is_driver():
                self.emu = WinKernelEmulator(config=self.config, logger=self.logger,
                                             debug=self.debug, exit_event=self.exit_event)
            else:
                self.emu = Win32Emulator(config=self.config, logger=self.logger, argv=self.argv,
                                         debug=self.debug, exit_event=self.exit_event)
        else:
            self.emu = Win32Emulator(config=self.config, logger=self.logger, argv=self.argv,
                                     debug=self.debug, exit_event=self.exit_event)

    def _init_hooks(self) -> None:
        """
        Lazily add hooks if users added them early before emulator engine was instantiated
        """
        # Add any configured hooks here
        while self.api_hooks:
            h = self.api_hooks.pop(0)
            cb, mod, func, argc, cconv = h
            self.add_api_hook(cb, mod, func, argc, cconv)
        while self.code_hooks:
            h = self.code_hooks.pop(0)
            cb, begin, end, ctx = h
            self.add_code_hook(cb, begin, end, ctx)
        while self.dyn_code_hooks:
            h = self.dyn_code_hooks.pop(0)
            cb, ctx = h
            self.add_dyn_code_hook(cb, ctx)
        while self.invalid_insn_hooks:
            h = self.invalid_insn_hooks.pop(0)
            cb, ctx = h
            self.add_invalid_instruction_hook(cb, ctx)
        while self.mem_read_hooks:
            h = self.mem_read_hooks.pop(0)
            cb, begin, end = h
            self.add_mem_read_hook(cb, begin, end)
        while self.mem_write_hooks:
            h = self.mem_write_hooks.pop(0)
            cb, begin, end = h
            self.add_mem_write_hook(cb, begin, end)
        while self.mem_invalid_hooks:
            h = self.mem_invalid_hooks.pop(0)
            cb, = h
            self.add_mem_invalid_hook(cb)
        while self.interrupt_hooks:
            h = self.interrupt_hooks.pop(0)
            cb, ctx = h
            self.add_interrupt_hook(cb, ctx)
        while self.mem_map_hooks:
            h = self.mem_map_hooks.pop(0)
            self.add_mem_map_hook(h)

    def disasm(self, addr: int, size: int, fast=True):
        """
        Get the disassembly from an address

        args:
            addr: address to being disassebmly
            size: number of bytes to include
        return:
            A tuple of: (mnemonic, operands, and the full instruction)
        """
        try:
            return self.emu.get_disasm(addr, size, fast)
        except Exception:
            raise SpeakeasyError("Failed to disassemble at address: 0x%x" % (addr))

    def is_pe(self, data: bytes) -> bool:
        """
        Test data to see if it looks like a PE

        args:
            data: Bytes to be tested for a PE
        return:
            True is data appears to be a PE
        """
        # Check for the PE header
        if data[:2] == b'MZ':
            return True
        else:
            return False

    def load_module(self, path=None, data=None) -> PeFile:
        """
        Load a module into the speakeasy emulator

        args:
            path: Path to file to load into the emulation space
            data: Raw data to load as a module into the emulation space
        return:
            A PeFile object representing the newly loaded module
        """
        if not path and not data:
            raise SpeakeasyError('No emulation target supplied')

        if path and not os.path.exists(path):
            raise SpeakeasyError('Target file not found: %s' % (path))

        if data:
            test = data
        else:
            with open(path, 'rb') as f:
                test = f.read(4)

        self.loaded_bins.append(path)

        if not self.is_pe(test):
            raise SpeakeasyError('Target file is not a PE')

        self._init_emulator(path=path, data=data)

        return self.emu.load_module(path=path, data=data)

    @check_init
    def run_module(self, module, all_entrypoints=False, emulate_children=False) -> None:
        """
        Run a previously loaded module through the configured emulator

        args:
            module: The module whose entry point to be run
            all_entrypoints: If true, all exports will be emulated, otherwise
            just the main PE entry point is emulated.
            emulate_children: If true, any child processes created by this
            module will be emulated, otherwise, just this module is
            emulated.
        return:
            None
        """
        self._init_hooks()

        if isinstance(self.emu, Win32Emulator):
            return self.emu.run_module(module=module,
                    all_entrypoints=all_entrypoints,
                    emulate_children=emulate_children)
        else:
            return self.emu.run_module(module=module,
                    all_entrypoints=all_entrypoints)

    def load_shellcode(self, fpath, arch, data=None) -> int:
        """
        Load a shellcode blob into emulation space

        args:
            fpath: file path containing shellcode blob
            arch: Architecture (x86 | amd64) to load shellcode as
            data: bytes object containing shellcode blob
        return:
            Address of the loaded shellcode in the emulation space
        """
        self._init_emulator(is_raw_code=True)
        self.loaded_bins.append(fpath)

        return self.emu.load_shellcode(fpath, arch, data=data)

    @check_init
    def run_shellcode(self, sc_addr: int, offset=0) -> None:
        """
        Run a previously loaded shellcode blob by address

        args:
            sc_addr: address of the previously loaded shellcode blog to emulate
            offset: offset within the blob to begin emulation
        return:
            None
        """
        self._init_hooks()
        return self.emu.run_shellcode(sc_addr, offset=offset)

    @check_init
    def get_report(self) -> dict:
        """
        Get the emulation report from the emulator

        return:
            Get the raw emulation report as a python dictionary
        """
        return self.emu.get_report()

    @check_init
    def get_json_report(self) -> str:
        """
        Get the emulation report from the emulator formatted as a JSON string
        return:
            Get the emulation report as a JSON object
        """
        return self.emu.get_json_report()

    def add_api_hook(self, cb: Callable, module='', api_name='', argc=0, call_conv=None):
        """
        Set a callback to fire when a specified API is called during emulation

        args:
            cb: Callable python function to execute
            module: name of the module containing the target API
            api_name: Name of the API to hook. Wild cards (e.g. *) are supported.
            argc: force the emulator to account for this amount of arguments (for stack cleanup)
            call_conv: force the emulator to use the supplied calling convention for this hook
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.api_hooks.append((cb, module, api_name, argc, call_conv))
            return
        return self.emu.add_api_hook(cb, module=module, api_name=api_name, argc=argc,
                                     call_conv=call_conv, emu=self)

    def resume(self, addr, count=-1):
        """
        Resume emulating at the specified address

        args:
            addr: Address to being emulation at
            count: number of instructions
        return:
            None
        """
        self.emu.run_complete = False
        self.emu.resume(addr, count=count)

    def stop(self) -> None:
        """
        Stops emulation
        """
        return self.emu.stop()

    def shutdown(self) -> None:
        """
        Closes the emulation instance
        """
        # TODO
        return

    def call(self, addr: int, params=[]) -> None:
        """
        Start emulating at the specified address

        args:
            addr: Address to being emulation at
            params: list of arguments to push onto the stack for the call
        return:
            None
        """
        return self.emu.call(addr, params=params)

    def add_code_hook(self, cb: Callable, begin=1, end=0, ctx={}):
        """
        Set a callback to fire for every CPU instruction that is emulated

        args:
            cb: Callable python function to execute
            begin: beginning of the address range to hook
            end: end of the address range to hook
            ctx: Optional context to pass back and forth between the hook function
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.code_hooks.append((cb, begin, end, ctx))
            return
        return self.emu.add_code_hook(cb, begin=begin, end=end, ctx=ctx, emu=self)

    def add_dyn_code_hook(self, cb: Callable, ctx={}):
        """
        Set a callback to fire when dynamically generated/copied code is executed

        args:
            cb: Callable python function to execute
            ctx: Optional context to pass back and forth between the hook function
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.dyn_code_hooks.append((cb, ctx))
            return
        return self.emu.add_dyn_code_hook(cb, ctx=ctx, emu=self)

    def add_mem_read_hook(self, cb: Callable, begin=1, end=0):
        """
        Set a callback to fire when a memory address is read from

        args:
            cb: Callable python function to execute
            begin: beginning of the address range to hook
            end: end of the address range to hook
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.mem_read_hooks.append((cb, begin, end))
            return
        return self.emu.add_mem_read_hook(cb, begin=begin, end=end, emu=self)

    def add_mem_write_hook(self, cb: Callable, begin=1, end=0):
        """
        Set a callback to fire when a memory address is written to

        args:
            cb: Callable python function to execute
            begin: beginning of the address range to hook
            end: end of the address range to hook
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.mem_write_hooks.append((cb, begin, end))
            return
        return self.emu.add_mem_write_hook(cb, begin=begin, end=end, emu=self)

    def add_IN_instruction_hook(self, cb: Callable, begin=1, end=0):
        """
        Set a callback to fire when an IN instruction executes

        args:
            cb: Callable python function to execute
            begin: beginning of the address range to hook
            end: end of the address range to hook
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.mem_write_hooks.append((cb, begin, end))
            return
        return self.emu.add_instruction_hook(cb, begin=begin, end=end, emu=self, insn=218)

    def add_SYSCALL_instruction_hook(self, cb: Callable, begin=1, end=0):
        """
        Set a callback to fire when a SYSCALL / SYSENTER instruction executes

        args:
            cb: Callable python function to execute
            begin: beginning of the address range to hook
            end: end of the address range to hook
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.mem_write_hooks.append((cb, begin, end))
            return
        return self.emu.add_instruction_hook(cb, begin=begin, end=end, emu=self, insn=700)

    def add_invalid_instruction_hook(self, cb: Callable, ctx=[]):
        """
        Set a callback to fire when an invalid instruction is attempted
        to be executed

        args:
            cb: Callable python function to execute
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.invalid_insn_hooks.append((cb, ctx))
            return
        return self.emu.add_invalid_instruction_hook(cb, ctx)

    def add_mem_invalid_hook(self, cb: Callable):
        """
        Get a callback for when a memory access violation occurs

        args:
            cb: Callable python function to execute
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.mem_invalid_hooks.append((cb, ))
            return
        return self.emu.add_mem_invalid_hook(cb, emu=self)

    def add_interrupt_hook(self, cb: Callable, ctx={}):
        """
        Get a callback for software interrupts

        args:
            cb: Callable python function to execute
            ctx: Optional context to pass back and forth between the hook function
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.interrupt_hooks.append((cb, ))
            return
        return self.emu.add_interrupt_hook(cb, ctx=ctx, emu=self)

    def get_registry_key(self, handle=0, path=''):
        """
        Get registry key by path or handle

        args:
            handle: handle corresponding for a registry key
            path: Path to a registry key
        return:
            If valid, a registry key object
        """
        return self.emu.reg_get_key(handle=handle, path=path)

    def get_address_map(self, addr: int):
        """
        Get the address mapping object associated with the specified address

        args:
            addr: Address in the emulation space
        return:
            A memory map object that holds the specified address
        """
        return self.emu.get_address_map(addr)

    def get_user_modules(self) -> list:
        """
        Get the address ranges of loaded user modules

        return:
            List of all currently loaded user modules
        """
        return self.emu.get_user_modules()

    def get_sys_modules(self) -> list:
        """
        Get the address ranges of loaded system modules

        return:
            List of all currently loaded system modules
        """
        return self.emu.get_sys_modules()

    def mem_alloc(self, size, base=None, tag='speakeasy.None') -> int:
        """
        Allocate a block of memory in the emulation space

        args:
            size: Size of requested memory block
            base: Optionally request a base address. If in use, the next nearest
                  address will be returned
            tag: Tag to assign the new memory mapping
        return:
            Address of the newly allocated memory block
        """
        return self.emu.mem_map(size, base=base, tag=tag)

    def mem_free(self, base: int) -> None:
        """
        Free a block of memory in the emulation space
        args:
            base: Address to free
        return:
            None
        """
        return self.emu.mem_free(base)

    def mem_read(self, addr: int, size: int) -> bytes:
        """
        Read bytes from a memory address

        args:
            addr: address to read bytes from
            size: number of bytes to read
        return:
            Python bytes object contained the data read
        """
        try:
            return self.emu.mem_read(addr, size)
        except Exception:
            raise SpeakeasyError("Failed to read %d bytes at address: 0x%x" % (size, addr))

    def mem_write(self, addr: int, data: bytes) -> None:
        """
        Write bytes to a memory address

        args:
            addr: address to write bytes to
            data: data to write
        return:
            None
        """
        try:
            return self.emu.mem_write(addr, data)
        except Exception:
            raise SpeakeasyError("Failed to write %d bytes at address: 0x%x" % (len(data), addr))

    def mem_cast(self, obj, addr: int):
        """
        Cast an address as an object for easy access

        args:
            obj: object to cast into
            addr: address containing the data to cast into type "obj"
        return:
            Python object based on the data located at addr
        """
        return self.emu.mem_cast(obj, addr)

    def reg_read(self, reg: str) -> int:
        """
        Read value from a register

        args:
            reg: name of the register to read from
        return:
            value contained in the requested register
        """
        return self.emu.reg_read(reg)

    def get_dyn_imports(self) -> list:
        """
        Returns the imports dynamically resolved at runtime

        return:
            List of functions that were resolved at runtime (e.g. GetProcAddress,
                                                                  MmGetSystemRoutineAddress)
        """
        return self.emu.get_dyn_imports()

    def reg_write(self, reg: str, val: int) -> None:
        """
        Write value to a register

        args:
            reg: name of the register to write to
        return:
            None
        """
        return self.emu.reg_write(reg, val)

    def get_dropped_files(self) -> list:
        """
        Get files that were written to disk during emulation

        return:
            Returns a list of files that were written by the sample
        """
        return self.emu.get_dropped_files()

    def create_file_archive(self) -> bytes:
        """
        Creates a file archive package.
        The archive contains a manifest that can be used to match dropped files
        metadata with the acquired files.

        return:
            A Bytes object containing a zip archive of dropped files
        """
        manifest = []
        _zip = BytesIO()
        files = self.get_dropped_files()

        if not files:
            return b''

        with zipfile.ZipFile(_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:

            for f in files:

                path = f.get_path()
                file_name = ntpath.basename(path)
                manifest.append({'path': path,
                                 'file_name': file_name,
                                 'size': f.get_size(),
                                 'sha256': f.get_hash()})
                zf.writestr(file_name, f.get_data())

            manifest = json.dumps(manifest, indent=4, sort_keys=False)
            zf.writestr('speakeasy_manifest.json', manifest)

        return _zip.getvalue()

    def get_mem_maps(self) -> list:
        """
        Get all memory maps in the emulation space

        return:
            A list of all valid memory maps from the emulator
        """
        return self.emu.get_mem_maps()

    def get_memory_dumps(self) -> tuple:
        """
        Returns all memory contents along with context information

        return:
            A generator of tuples of all valid memory with context
        """
        for mm in self.emu.get_mem_maps():
            base = mm.get_base()
            size = mm.get_size()
            tag = mm.get_tag()
            proc = mm.get_process()
            is_free = mm.is_free()
            try:
                data = self.emu.mem_read(base, size)
            except Exception:
                continue
            yield (tag, base, size, is_free, proc, data)

    def read_mem_string(self, address: int, width=1, max_chars=0) -> str:
        """
        Read a string from emulated memory

        args:
            address: address of the string to read
            width: character width
            max_chars: maximum characters to read, 0 reads until null terminator

        return:
            decoded string
        """
        return self.emu.read_mem_string(address, width, max_chars)

    def get_symbols(self) -> dict:
        """
        Returns a dictionary of symbol information

        return:
            a dictionary of symbol information
        """
        return self.emu.symbols

    def get_ret_address(self) -> int:
        """
        Returns the value stored at the top of the stack

        return:
            value stored at the top of the stack
        """
        return self.emu.get_ret_address()

    def push_stack(self, val: int) -> None:
        """
        Put a value on the stack and adjust the stack pointer

        args:
            val: value to push to the stack
        return:
            None
        """
        self.emu.push_stack(val)

    def pop_stack(self) -> int:
        """
        Get value from the stack and adjust the stack pointer

        return:
            value stored at the top of the stack
        """
        return self.emu.pop_stack()

    def get_stack_ptr(self) -> int:
        """
        Get the current address of the stack pointer

        return:
            address of stack pointer
        """
        return self.emu.get_stack_ptr()

    def set_stack_ptr(self, addr: int) -> None:
        """
        Set the current address of the stack pointer

        args:
            addr: address to set the stack pointer to
        return:
            None
        """
        self.emu.set_stack_ptr(addr)

    def get_pc(self) -> int:
        """
        Get the value of the current program counter

        return:
            value of the program counter
        """
        return self.emu.get_pc()

    def set_pc(self, addr: int) -> None:
        """
        Set the value of the current program counter

        args:
            addr: address to set the program counter to
        return:
            None
        """
        self.emu.set_pc(addr)

    def reset_stack(self, base: int) -> tuple:
        """
        Reset stack to the supplied base address

        args:
            base: stack base address
        return:
            base, ptr
        """
        return self.emu.reset_stack(base)

    def get_stack_base(self) -> int:
        """
        Get the base address of the stack

        return:
            base address of stack
        """
        return self.emu.stack_base

    def get_arch(self) -> int:
        """
        Get the architecture of the emulator

        return:
            emulator architecture constant value
        """
        return self.emu.get_arch()

    def get_ptr_size(self) -> int:
        """
        Get the size of a pointer

        return:
            pointer size
        """
        return self.emu.ptr_size

    def get_all_registers(self) -> dict:
        """
        Get the state of all registers

        return:
            Dict containing emulation register states
        """
        return self.emu.get_register_state()

    def get_symbol_from_address(self, address: int) -> str:
        """
        If the supplied address is related to a known symbol, look it up here

        args:
            address: address to lookup

        return:
            symbol name
        """
        return self.emu.get_symbol_from_address(address)

    def is_address_valid(self, address: int) -> bool:
        """
        Was this address previously reserved or mapped?

        args:
            address: address to check

        return:
            True if address is valid, false otherwise
        """
        return self.emu.is_address_valid(address)

    def add_mem_map_hook(self, cb: Callable, begin=1, end=0):
        """
        Set a callback to fire when a memory address is mapped

        args:
            cb: Callable python function to execute
            begin: beginning of the address range to hook
            end: end of the address range to hook
        return:
            Hook object for newly registered hooks
        """
        if not self.emu:
            self.mem_map_hooks.append((cb, begin, end))
            return
        return self.emu.add_mem_map_hook(cb, begin=begin, end=end, emu=self)

    def create_memdump_archive(self) -> bytes:
        """
        Creates a memory dump archive package of the emulated sample.
        The archive contains a manifest that can be used to match memory chunk
        metadata with the dumped binary memory files.

        return:
            Bytes object containing a zip of all memory
        """
        manifest = []
        _zip = BytesIO()

        loaded_bins = [os.path.splitext(os.path.basename(b))[0] for b in self.loaded_bins]

        with zipfile.ZipFile(_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            procs = []
            [procs.append(block[4]) for block in self.get_memory_dumps()
             if block[4] not in procs]

            for process in procs:
                memory_blocks = []
                arch = self.emu.get_arch()
                if arch == _arch.ARCH_X86:
                    arch = 'x86'
                else:
                    arch = 'amd64'

                if process:
                    pid = process.get_pid()
                    path = process.get_process_path()
                else:
                    continue

                manifest.append({'pid': pid, 'process_name': path, 'arch': arch,
                                 'memory_blocks': memory_blocks})
                for block in self.get_memory_dumps():

                    tag, base, size, is_free, _proc, data = block

                    if not tag:
                        continue
                    if _proc != process:
                        continue
                    # Ignore emulator noise such as structures created by the emulator, or
                    # modules that were loaded
                    if tag and tag.startswith('emu') and not tag.startswith('emu.shellcode.'):
                        bns = [b for b in loaded_bins if b in tag]
                        if not len(bns):
                            continue

                    h = hashlib.sha256()
                    h.update(data)
                    _hash = h.hexdigest()

                    file_name = '%s.mem' % (tag)

                    memory_blocks.append({'tag':  tag, 'base': hex(base), 'size': hex(size),
                                          'is_free': is_free, 'sha256': _hash,
                                          'file_name': file_name})
                    zf.writestr(file_name, data)

            manifest = json.dumps(manifest, indent=4, sort_keys=False)
            zf.writestr('speakeasy_manifest.json', manifest)

        return _zip.getvalue()


def validate_config(config) -> None:
    """
    Validates the given configuration objects against the built-in schemas.

    Raises jsonschema.exceptions.ValidationError on invalid configuration.
    Expose the underlying jsonschema exception due to it having lots of information
    about failures.

    On success, returns without exception.
    """
    schema_path = os.path.join(os.path.dirname(speakeasy.__file__), 'config_schema.json')
    with open(schema_path, 'r') as ff:
        schema = json.load(ff)
    validator = jsonschema.Draft7Validator(schema)
    validator.validate(config)
