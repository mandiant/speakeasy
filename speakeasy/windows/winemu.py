# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import io
import os
import ntpath
import traceback
import shlex

import speakeasy.winenv.arch as _arch
from speakeasy.binemu import BinaryEmulator
from speakeasy.profiler import MemAccess

import speakeasy.common as common
from speakeasy.profiler import Run
import speakeasy.windows.common as winemu
import speakeasy.windows.objman as objman
from speakeasy.windows.regman import RegistryManager
from speakeasy.windows.fileman import FileManager
from speakeasy.windows.cryptman import CryptoManager
from speakeasy.windows.netman import NetworkManager
from speakeasy.windows.hammer import ApiHammer
from speakeasy.windows.driveman import DriveManager

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windef

from speakeasy.struct import EmuStruct
from speakeasy.errors import WindowsEmuError

# When disassembling, a minimum instruction size needs to be supplied
# This number is arbitrary and just needs to be large enough to cover
# the size of the current disasm target
DISASM_SIZE = 0x20


class WindowsEmulator(BinaryEmulator):
    """
    Base class providing emulation of all Windows modules and shellcode.
    This class is meant to provide overlapping functionality for both
    user mode and kernel mode samples.
    """

    def __init__(self, config, logger=None, exit_event=None, debug=False):
        super(WindowsEmulator, self).__init__(config, logger=logger)

        self.debug = debug
        self.arch = 0
        self.modules = []
        self.pic_buffers = []
        self.curr_run = None
        self.restart_curr_run = False
        self.curr_mod = None
        self.runs = []
        self.input = None
        self.exit_event = exit_event
        self.page_size = 4096
        self.ptr_size = None
        self.user_modules = []
        self.max_runs = 100

        self.sys_modules = []
        self.symbols = {}
        self.ansi_strings = []
        self.unicode_strings = []
        self.tmp_maps = []
        self.impdata_queue = []
        self.run_queue = []
        self.suspended_runs = []
        self.cd = ''
        self.emu_hooks_set = True
        self.api = None
        self.curr_process = None
        self.om = None
        self.dyn_imps = []
        self.callbacks = []
        self.mem_trace_hooks = []
        self.kernel_mode = False
        self.virtual_mem_base = 0x50000

        self.mem_tracing_enabled = False
        self.tmp_code_hook = None
        self.veh_handlers = []

        self.run_complete = False
        self.emu_complete = False
        self.global_data = {}
        self.processes = []
        # Child processes created by calls to CreateProcess
        # by any module. This is separate from self.processes in order
        # to not mix up config processes with child processes
        self.child_processes = []
        self.curr_thread = None
        self.curr_exception_code = 0
        self.prev_pc = 0
        self.unhandled_exception_filter = 0

        self.fs_addr = 0
        self.gs_addr = 0

        self.return_hook = winemu.EMU_RETURN_ADDR
        self.exit_hook = winemu.EXIT_RETURN_ADDR
        self._parse_config(config)

        self.wintypes = windef
        # OS resource managers
        self.regman = RegistryManager(self.get_registry_config())
        self.fileman = FileManager(config, self)
        self.netman = NetworkManager(config=self.get_network_config())
        self.driveman = DriveManager(config=self.get_drive_config())
        self.cryptman = CryptoManager()
        self.hammer = ApiHammer(self)

    def _parse_config(self, config):
        """
        Parse the emulation config file
        """
        def _normalize_image(img):
            # Normalize the architecture
            if img['arch'].lower() in ('x86', 'i386'):
                img['arch'] = _arch.ARCH_X86
            elif img['arch'].lower() in ('x64', 'amd64'):
                img['arch'] = _arch.ARCH_AMD64
            else:
                raise WindowsEmuError('Unsupported image arch: %s'
                                      % (img['arch']))

        super(WindowsEmulator, self)._parse_config(config)
        for umod in self.config_user_modules:
            for img in umod.get('images', []):
                _normalize_image(img)

        for proc in self.config_processes:
            for img in proc.get('images', []):
                _normalize_image(img)

        self.cd = self.config.get('current_dir', '')

        self.dispatch_handlers = self.exceptions.get('dispatch_handlers', True)
        self.mem_tracing_enabled = self.config_analysis.get('memory_tracing', False)
        self.do_strings = self.config_analysis.get('strings', False)
        self.registry_config = self.config.get('registry', {})
        self.modules_always_exist = self.config_modules.get('modules_always_exist', False)
        self.functions_always_exist = self.config_modules.get('functions_always_exist', False)

    def get_registry_config(self):
        """
        Get the registry settings specified in the registry section of the config file
        """
        return self.registry_config

    def on_run_complete(self):
        """
        Clean up after a run completes (implemented in the child class) since
        this may mean different things depending. This function will pop the
        next run from the run queue and emulate it.
        """
        # Implemented by a subclass (e.g. kernel/user mode emulators)
        raise NotImplementedError()

    def enable_code_hook(self):
        if not self.tmp_code_hook and not self.mem_tracing_enabled:
            self.tmp_code_hook = self.add_code_hook(cb=self._hook_code)

        if self.tmp_code_hook:
            self.tmp_code_hook.enable()

    def disable_code_hook(self):
        if self.tmp_code_hook:
            self.tmp_code_hook.disable()

    def _module_access_hook(self, emu, addr, size, ctx):
        symbol = self.get_symbol_from_address(addr)
        if symbol:
            mod_name, fn = symbol.split('.')
            self.handle_import_func(mod_name, fn)
            return True

    def set_mem_tracing_hooks(self):
        if not self.mem_tracing_enabled:
            return

        if len(self.mem_trace_hooks) > 0:
            return

        self.mem_trace_hooks = (
            self.add_code_hook(cb=self._hook_code),
            self.add_mem_read_hook(cb=self._hook_mem_read),
            self.add_mem_write_hook(cb=self._hook_mem_write)
        )

    def cast(self, obj, bytez):
        """
        Create a formatted structure from bytes
        """
        if not isinstance(obj, EmuStruct):
            raise WindowsEmuError('Invalid object for cast')
        return obj.cast(bytez)

    def _unset_emu_hooks(self):
        """
        Create a formatted structure from bytes
        """
        if self.emu_hooks_set:
            self.emu_eng.mem_map(winemu.EMU_RETURN_ADDR,
                                 winemu.EMU_RESERVE_SIZE)
        self.emu_hooks_set = False

    def file_open(self, path, create=False):
        """
        Open an emulated from using the file manager
        """
        return self.fileman.file_open(path, create)

    def pipe_open(self, path, mode, num_instances, out_size, in_size):
        """
        Open an emulated named pipe
        """
        return self.fileman.pipe_open(path, mode, num_instances, out_size, in_size)

    def does_file_exist(self, path):
        """
        Test if a file handler for a specified emulated file exists
        """
        return self.fileman.does_file_exist(path)

    def file_create_mapping(self, hfile, name, size, prot):
        """
        Create a memory mapping for an emulated file
        """
        return self.fileman.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        """
        Get a file object from a handle
        """
        return self.fileman.get_file_from_handle(handle)

    def file_delete(self, path):
        """
        Delete a file
        """
        return self.fileman.delete_file(path)

    def pipe_get(self, handle):
        """
        Get a pipe object from a handle
        """
        return self.fileman.get_pipe_from_handle(handle)

    def get_file_manager(self):
        """
        Get the file emulation manager
        """
        return self.fileman

    def get_network_manager(self):
        """
        Get the network emulation manager
        """
        return self.netman

    def get_crypt_manager(self):
        """
        Get the crypto manager
        """
        return self.cryptman

    def get_drive_manager(self):
        """
        Get the drive manager
        """
        return self.driveman

    def reg_open_key(self, path, create=False):
        """
        Open or create a registry key in the emulation space
        """
        return self.regman.open_key(path, create)

    def reg_get_subkeys(self, hkey):
        """
        Get subkeys for a given registry key
        """
        return self.regman.get_subkeys(hkey)

    def reg_get_key(self, handle=0, path=''):
        """
        Get registry key by path or handle
        """
        if path:
            return self.regman.get_key_from_path(path)
        return self.regman.get_key_from_handle(handle)

    def reg_create_key(self, path):
        """
        Create a registry key
        """
        return self.regman.create_key(path)

    def _set_emu_hooks(self):
        """
        Unmap reserved memory space so we can handle events (e.g. import APIs,
        entry point returns, etc.)
        """
        if not self.emu_hooks_set:
            self.mem_unmap(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)
            self.emu_hooks_set = True

    def add_run(self, run):
        """
        Add a run to the emulation run queue
        """
        self.run_queue.append(run)

    def _exec_next_run(self):
        """
        Execute the next run from the emulation queue
        """
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            self.on_emu_complete()
            return None

        self.run_complete = False
        self.reset_stack(self.stack_base)
        return self._exec_run(run)

    def call(self, addr, params=[]):
        """
        Start emulating at the specified address
        """
        self.reset_stack(self.stack_base)
        run = Run()
        run.type = 'call_0x%x' % (addr)
        run.start_addr = addr
        run.args = params

        if not self.run_queue:
            self.add_run(run)
            self.start()
        else:
            self.add_run(run)

    def _exec_run(self, run):
        """
        Begin emulating the specified run
        """
        self.log_info("* exec: %s" % run.type)

        self.curr_run = run
        if self.profiler:
            self.profiler.add_run(run)

        self.runs.append(self.curr_run)

        stk_ptr = self.get_stack_ptr()

        self.set_func_args(stk_ptr, self.return_hook, *run.args)
        stk_ptr = self.get_stack_ptr()
        stk_map = self.get_address_map(stk_ptr)

        self.curr_run.stack = MemAccess(base=stk_map.base, size=stk_map.size)

        # Set the process context if possible
        if run.process_context:
            # Init a new peb if the process context changed:
            if run.process_context != self.get_current_process():
                self.alloc_peb(run.process_context)
            self.set_current_process(run.process_context)
        if run.thread:
            self.set_current_thread(run.thread)

        if not self.kernel_mode:
            # Reset the TIB data
            thread = self.get_current_thread()
            if thread:
                self.init_teb(thread, self.curr_process.get_peb())
                self.init_tls(thread)

        self.set_pc(run.start_addr)
        return run

    def mem_cast(self, obj, addr):
        """
        Turn bytes from an emulated memory pointer into an object
        """
        size = obj.sizeof()
        struct_bytes = self.mem_read(addr, size)
        return self.cast(obj, struct_bytes)

    def mem_purge(self):
        """
        Unmap all memory chunks
        """
        self.purge_memory()

    def setup_user_shared_data(self):
        """
        Setup the shared user data section that is often used to share data
        between user mode and kernel mode
        """
        if self.get_arch() == _arch.ARCH_X86:
            self.mem_map(self.page_size, base=0xFFDF0000,
                         tag='emu.struct.KUSER_SHARED_DATA')
        elif self.get_arch() == _arch.ARCH_AMD64:
            self.mem_map(self.page_size, base=0xFFFFF78000000000,
                         tag='emu.struct.KUSER_SHARED_DATA')

    def resume(self, addr, count=-1):
        """
        Resume emulation at the specified address.
        """
        self.emu_eng.start(addr, timeout=self.timeout,
                           count=count)

    def start(self):
        """
        Begin emulation executing each run in the specified run queue
        """
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            return

        self.run_complete = False
        self.set_hooks()
        self._set_emu_hooks()
        if self.profiler:
            self.profiler.set_start_time()
        self._exec_run(run)

        while True:
            try:
                self.curr_mod = self.get_module_from_addr(self.curr_run.start_addr)
                self.emu_eng.start(self.curr_run.start_addr, timeout=self.timeout,
                                   count=self.max_instructions)
                if self.profiler:
                    if self.profiler.get_run_time() > self.timeout:
                        self.log_error('* Timeout of %d sec(s) reached.' % (self.timeout))
            except KeyboardInterrupt:
                self.log_error('* User exited.')
                return
            except Exception as e:
                if self.exit_event and self.exit_event.is_set():
                    return
                stack_trace = traceback.format_exc()

                try:
                    mnem, op, instr = self.get_disasm(self.get_pc(), DISASM_SIZE)
                except Exception as dis_err:
                    self.log_error(str(dis_err))

                error = self.get_error_info(str(e), self.get_pc(),
                                            traceback=stack_trace)
                self.curr_run.error = error

                run = self.on_run_complete()
                if not run:
                    break
                continue
            break

        self.on_emu_complete()

    def get_current_run(self):
        """
        Get the current run that is being emulated
        """
        return self.curr_run

    def get_current_module(self):
        """
        Get the currently running module
        """
        return self.curr_mod

    def get_dropped_files(self):
        """
        Get all files written by the sample from the file manager
        """
        if self.fileman:
            return self.fileman.get_dropped_files()

    def set_hooks(self):
        """
        Reserves memory that will be used to handle events that occur
        during emulation
        """
        super(WindowsEmulator, self).set_hooks()

    def get_processes(self):
        """
        Get the current processes that exist in the emulation space
        """
        if not self.processes:
            self.init_processes(self.config_processes)
        return self.processes

    def kill_process(self, proc):
        """
        Terminate a process (i.e. remove it from the known process list)
        """
        try:
            self.processes.remove(proc)
        except ValueError:
            pass

    def get_current_thread(self):
        """
        Get the current thread that is emulating
        """
        return self.curr_thread

    def get_current_process(self):
        """
        Get the current process that is emulating
        """
        return self.curr_process

    def set_current_process(self, process):
        """
        Set the current process that is emulating
        """
        self.curr_process = process

    def set_current_thread(self, thread):
        """
        Set the current thread
        """
        self.curr_thread = thread

    def _setup_gdt(self, arch):
        """
        Set up the GDT so we can access segment registers correctly
        This will be done a little differently depending on architecture
        """

        GDT_SIZE = 0x1000
        SEG_SIZE = 0x1000
        ENTRY_SIZE = 0x8
        num_gdt_entries = 31
        fs_addr = 0
        gs_addr = 0
        gdt_addr = None

        # For a detailed explaination of whats happening here, see:
        # https://wiki.osdev.org/Global_Descriptor_Table
        # We need to init the GDT so that shellcode can accurately access
        # segment registers which is needed for TEB access in user mode

        def _make_entry(index, base, access, limit=0xFFFFF000):
            access = access | (winemu.GDT_ACCESS_BITS.PresentBit |
                               winemu.GDT_ACCESS_BITS.DirectionConformingBit)
            entry = 0xFFFF & limit
            entry |= (0xFFFFFF & base) << 16
            entry |= (0xFF & access) << 40
            entry |= (0xFF & (limit >> 16)) << 48
            entry |= (0xFF & winemu.GDT_ACCESS_BITS.ProtMode32) << 52
            entry |= (0xFF & (base >> 24)) << 56
            entry = entry.to_bytes(8, 'little')

            offset = index * ENTRY_SIZE
            self.mem_write(gdt_addr + offset, entry)

        def _create_selector(index, flags):
            return flags | (index << 3)

        gdt_addr, gdt_size = self.get_valid_ranges(GDT_SIZE)
        self.mem_map(gdt_size, base=gdt_addr, tag='emu.gdt')
        seg_addr, seg_size = self.get_valid_ranges(SEG_SIZE)
        self.mem_map(seg_size, base=seg_addr, tag='emu.segment.gdt')

        access = (winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable |
                  winemu.GDT_ACCESS_BITS.Ring3)
        _make_entry(16, 0, access)

        access = (winemu.GDT_ACCESS_BITS.Code | winemu.GDT_ACCESS_BITS.CodeReadable |
                  winemu.GDT_ACCESS_BITS.Ring3)
        _make_entry(17, 0, access)

        access = (winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable |
                  winemu.GDT_ACCESS_BITS.Ring0)
        _make_entry(18, 0, access)

        self.reg_write(_arch.X86_REG_GDTR, (0, gdt_addr,
                                            num_gdt_entries * ENTRY_SIZE-1, 0x0))
        selector = _create_selector(16, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_DS, selector)
        selector = _create_selector(17, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_CS, selector)
        selector = _create_selector(18, winemu.GDT_FLAGS.Ring0)
        self.reg_write(_arch.X86_REG_SS, selector)

        if _arch.ARCH_X86 == arch:
            # FS segment needed for PEB access at fs:[0x30]
            fs_addr, fs_size = self.get_valid_ranges(SEG_SIZE)
            self.mem_map(fs_size, base=fs_addr, tag='emu.segment.fs')

            access = (winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable |
                      winemu.GDT_ACCESS_BITS.Ring3)
            _make_entry(19, fs_addr, access)

            selector = _create_selector(19,  winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_FS, selector)

        elif _arch.ARCH_AMD64 == arch:
            # GS Segment needed for PEB access at gs:[0x60]
            gs_addr, gs_size = self.get_valid_ranges(SEG_SIZE)
            self.mem_map(gs_size, base=gs_addr, tag='emu.segment.gs')

            access = (winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable |
                      winemu.GDT_ACCESS_BITS.Ring3)
            _make_entry(15, gs_addr, access, limit=SEG_SIZE)

            selector = _create_selector(15,  winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_GS, selector)

        self.fs_addr = fs_addr
        self.gs_addr = gs_addr

        return fs_addr, gs_addr

    def init_peb(self, user_mods, proc=None):
        """
        Initialize the Process Environment Block
        """
        p = proc
        if not p:
            p = self.curr_process
        p.init_peb(user_mods)
        self.mem_write(self.peb_addr,
                       p.peb.address.to_bytes(self.get_ptr_size(), 'little'))
        return p.peb

    def init_teb(self, thread, peb):
        """
        Initialize the Thread Information Block
        """
        if self.get_arch() == _arch.ARCH_X86:
            thread.init_teb(self.fs_addr, peb.address)
        elif self.get_arch() == _arch.ARCH_AMD64:
            thread.init_teb(self.gs_addr, peb.address)

    def init_tls(self, thread):
        """
        Initialize implicit thread local storage. Meant to be
        called after init_teb.
        """
        ptrsz = self.get_ptr_size()
        run = self.curr_run
        module = self.get_mod_from_addr(run.start_addr)

        if module:
            modname = module.emu_path
            tokens = modname.split("\\")
            modname = tokens[len(tokens) - 1]

            # Get the virtual address of the TLS directory, which will always
            # be 9 in the data directory
            tls_dirp = module.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress
            tls_dirp += module.OPTIONAL_HEADER.ImageBase

            tls_dir = self.mem_read(tls_dirp, ptrsz)

            thread.init_tls(tls_dir, os.path.splitext(modname)[0])

        return

    def load_pe(self, path=None, data=None, imp_id=winemu.IMPORT_HOOK_ADDR):
        """
        Parse a PE that will be used during emulation. PE type and architecture
        are automatically determined.
        """

        if not data and not os.path.exists(path):
            raise WindowsEmuError('File: %s not found' % (path))

        pe = winemu.PeFile(path=path, data=data, imp_id=imp_id, imp_step=4)

        pe_type = 'unknown'
        if pe.is_driver():
            pe_type = 'driver'
        elif pe.is_dll():
            pe_type = 'dll'
        elif pe.is_exe():
            pe_type = 'exe'

        arch = 'unknown'
        if pe.arch == _arch.ARCH_AMD64:
            arch = 'x64'
        elif pe.arch == _arch.ARCH_X86:
            arch = 'x86'

        self.input = {'path': pe.path, 'sha256': pe.hash,
                      'size': pe.file_size, 'arch': arch,
                      'filetype': pe_type, 'emu_version': self.get_emu_version(),
                      'os_run': self.get_osver_string()}
        if self.profiler:
            self.profiler.add_input_metadata(self.input)
        return pe

    def map_pe(self, pe, mod_name='none', emu_path=''):
        """
        Map the specified PE into the emulation space
        """
        image_size = pe.image_size
        base = pe.base
        ranges = self.get_valid_ranges(image_size, addr=base)
        base, size = ranges
        addr = self.mem_map(size, base=base, tag='emu.module.%s' % (mod_name))
        self.modules.append((pe, ranges, emu_path))

        return addr

    def get_sys_modules(self):
        """
        Get the system modules (e.g. drivers) that are loaded in the emulator
        """
        # Generate the decoy module list
        if not self.sys_modules:
            self.sys_modules = \
                self.init_sys_modules(self.config_system_modules)
        return self.sys_modules

    def get_user_modules(self):
        """
        Get the user modules (e.g. dlls) that are loaded in the emulator
        """
        # Generate the decoy user module list
        if not self.user_modules:
            self.user_modules = \
                self.init_user_modules(self.config_user_modules)
        return self.user_modules

    def get_mod_from_addr(self, addr):
        """
        Get the module (if any) that corresponds to the supplied address
        """
        if self.curr_mod:
            end = self.curr_mod.get_base() + self.curr_mod.get_image_size()
            if addr >= self.curr_mod.get_base() and addr <= end:
                return self.curr_mod

        # First check if this addr belongs to mapped decoy image we know about
        sys_mods = self.get_sys_modules()
        for m in sys_mods:
            if addr >= m.get_base() and addr < m.get_base() + m.image_size:
                return m

        user_mods = self.get_user_modules()
        for m in user_mods:
            if addr >= m.get_base() and addr < m.get_base() + m.image_size:
                return m

    def get_system_root(self):
        """
        Get the path of the "SYSTEMROOT" environment variable
        """
        sysroot = self.env.get('systemroot', 'C:\\WINDOWS\\system32')
        if not sysroot.endswith('\\'):
            sysroot += '\\'
        return sysroot

    def get_windows_dir(self):
        """
        Get the path of the "WINDIR" environment variable
        """
        sysroot = self.env.get('windir', 'C:\\WINDOWS')
        if not sysroot.endswith('\\'):
            sysroot += '\\'
        return sysroot

    def get_cd(self):
        """
        Get the path of the current directory
        """
        if not self.cd:
            self.cd = self.env.get('cd', 'C:\\WINDOWS\\system32')
            if not self.cd.endswith('\\'):
                self.cd += '\\'
        return self.cd

    def set_cd(self, cd):
        """
        Sets the current directory path
        """
        self.cd = cd

    def get_env(self):
        return self.env

    def set_env(self, var, val):
        return self.env.update({var.lower(): val})

    def get_os_version(self):
        return self.osversion

    def get_object_from_addr(self, addr):
        return self.om.get_object_from_addr(addr)

    def get_object_from_id(self, id):
        return self.om.get_object_from_id(id)

    def get_object_from_name(self, name):
        return self.om.get_object_from_name(name)

    def get_object_from_handle(self, handle):
        obj = self.om.get_object_from_handle(handle)
        if obj:
            return obj
        obj = self.fileman.get_object_from_handle(handle)
        if obj:
            return obj

    def get_object_handle(self, obj):
        obj = self.om.objects.get(obj.address)
        if obj:
            return self.om.get_handle(obj)

    def add_object(self, obj):
        self.om.add_object(obj)

    def search_path(self, file_name):
        # For now, return the current directory, add emulated path walking later
        if '\\' in file_name:
            return file_name
        fp = self.get_cd()
        if not fp.endswith('\\'):
            fp += '\\'
        return fp + file_name

    def new_object(self, otype):
        return self.om.new_object(otype)

    def create_process(self, path=None, cmdline=None, image=None, child=False):
        """
        Create a process object that will exist in the emulator
        """
        if not path and cmdline:
            path = cmdline

        # See if we are trying to create a process based off a file
        # inside the object manager and serve that
        # Setting posix to false makes shlex not treat '\' as an
        # escape character, but if each token was surrounded with
        # quotes, those are kept, so we have to delete them
        file_path = shlex.split(path, posix=False)[0]

        if file_path[0] == '\"' and file_path[len(file_path) - 1] == '\"':
            file_path = file_path[1:-1]

        p = self.om.new_object(objman.Process)

        mod_data = self.get_module_data_from_emu_file(file_path)

        if mod_data:
            # We'll create a PE out of this when we go to execute it
            p.pe_data = mod_data
        else:
            new_mod = self.init_module(name=file_path, emu_path=path)
            self.map_decoy(new_mod)
            p.pe = new_mod

        p.path = file_path
        p.cmdline = cmdline

        # Create a thread object for the new process
        t = self.om.new_object(objman.Thread)
        t.process = p
        t.tid = self.om.new_id()

        p.threads.append(t)

        if child:
            self.child_processes.append(p)
        else:
            self.processes.append(p)

        return p

    def create_thread(self, addr, ctx, proc_obj, thread_type='thread', is_suspended=False):
        """
        Create a thread object that will exist in the emulator
        """
        if len(self.run_queue) >= self.max_runs:
            return 0, None

        thread = self.om.new_object(objman.Thread)
        thread.process = proc_obj
        hnd = self.om.get_handle(thread)

        run = Run()
        run.type = thread_type
        run.start_addr = addr
        run.instr_cnt = 0
        run.args = (ctx,)
        run.process_context = proc_obj
        run.thread = thread

        if not is_suspended:
            self.run_queue.append(run)
        else:
            self.suspended_runs.append(run)

        # Returns handle
        return hnd, thread

    def resume_thread(self, thread):
        """
        Resume a previously suspended thread
        """
        for r in self.suspended_runs:
            if r.thread == thread:
                _run = self.suspended_runs.pop(self.suspended_runs.index(r))
                self.run_queue.append(_run)
                return True
        return False

    def get_dyn_imports(self):
        return self.dyn_imps

    def get_process_peb(self, process):
        return process.peb

    def add_callback(self, mod_name, func_name):
        """
        Adds a callback to the emulation callback list. A "callback" in this
        context refers to a function that in not imported statically or dynamically.

        For example, a pointer that is set in a function table
        (e.g. PsSetCreateProcessNotifyRoutine).
        """
        for addr, mod, fn in self.callbacks:
            if mod_name == mod and func_name == fn:
                return addr

        if not self.callbacks:
            curr_idx = winemu.EMU_CALLBACK_RESERVE
            self.callbacks.append((curr_idx, mod_name, func_name))
        else:
            curr_idx = self.callbacks[-1][0]
            curr_idx += 1
            self.callbacks.append((curr_idx, mod_name, func_name))

        return curr_idx

    def get_proc(self, mod_name, func_name):
        """
        Get a pointer for a supplied function name, similar to how the
        "GetProcAddress" API functions.
        """
        for addr, mod, fn in self.dyn_imps:
            if mod_name == mod and func_name == fn:
                return addr

        if not self.dyn_imps:
            curr_idx = winemu.DYM_IMP_RESERVE
            self.dyn_imps.append((curr_idx, mod_name, func_name))
        else:
            curr_idx = self.dyn_imps[-1][0]
            curr_idx += 1
            self.dyn_imps.append((curr_idx, mod_name, func_name))

        return curr_idx

    def handle_import_data(self, mod_name, sym, data_ptr=0):
        """
        Data that is imported (e.g. KeTickCount) is handled with a initializer function.
        Call it here if there is a handler for the imported variable.
        """
        module, func = self.api.get_data_export_handler(mod_name, sym)
        if not func:
            module, func = self.api.get_export_func_handler(mod_name, sym)
            if not func:
                return None

            proc_addr = self.get_proc(mod_name, sym)
            return proc_addr

        data_addr = self.api.call_data_func(module, func, data_ptr)
        return data_addr

    def _handle_invalid_fetch(self, emu, address, size, value, ctx):
        """
        Called when an attempt to emulate an instruction from an invalid address
        """
        if address == self.return_hook or address == self.exit_hook:
            self._unset_emu_hooks()
            return True

        if not self.curr_mod:
            self.curr_mod = self.get_module_from_addr(self.get_pc())

        if self.curr_mod:
            impfunc = self.curr_mod.import_table.get(address)
            if impfunc:
                mod_name, func_name = impfunc
                self.handle_import_func(mod_name, func_name)
                self._unset_emu_hooks()
                return True

        # Is the address a func ptr resolved at runtime?
        for addr, mod, fn in self.dyn_imps:
            if addr == address:
                self.handle_import_func(mod, fn)
                self._unset_emu_hooks()
                return True

        # Is the address a callback func ptr?
        for addr, mod, fn in self.callbacks:
            if addr == address:
                self.handle_import_func(mod, fn)
                self._unset_emu_hooks()
                return True

        # Are there any SEH handlers registered?
        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_fetch', address)
        self.curr_run.error = error
        self.tmp_maps.append((fakeout, self.page_size))
        self.on_run_complete()
        return True

    def get_error_info(self, desc, address, traceback=None):
        """
        Collect emulator state information in the event of an error
        """
        run = self.get_current_run()
        pc = self.get_pc()
        error = {}
        self.log_error('0x%x: %s: Caught error: %s' % (pc, run.type, desc))
        error['type'] = desc
        error['pc'] = hex(pc)
        error['address'] = hex(address)
        try:
            mnem, op, instr = self.get_disasm(pc, DISASM_SIZE)
        except Exception as e:
            self.log_error(str(e))
            instr = 'disasm_failed'
        error['instr'] = instr
        error['regs'] = self.get_register_state()
        error['stack'] = self.get_stack_trace()

        if traceback:
            error['traceback'] = traceback

        return error

    def normalize_import_miss(self, dll, name):
        """
        This function attempts to fold as many function handlers together as possible.
        For example, ntdll functions will be handled by the ntoskrnl handlers, multiple versions
        of the C runtime are folded together, and Zw/Nt functions use the same handler.
        """
        alt_imp_api = ''
        alt_imp_dll = ''
        mod, func_attrs = None, None

        # Handle ANSI vs UNICODE functions
        if name.endswith('A') or name.endswith('W'):
            alt_imp_api = name[:-1]

        # Handle Zw*/Nt* function overlap
        if dll.lower().startswith('ntoskrnl'):
            if name.startswith('Zw'):
                alt_imp_api = 'Nt%s' % (name[2:])
            elif name.startswith('Nt'):
                name = 'Zw' + name[2:]
                alt_imp_api = 'Zw%s' % (name[2:])

        alt_imp_dll = winemu.normalize_dll_name(dll)

        # Bridge ntdll funcs to ntoskrnl if supported
        if dll.lower().startswith('ntdll'):
            alt_imp_dll = 'ntoskrnl'
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll,
                                                               name)
            if not func_attrs:
                if name.startswith('Zw'):
                    alt_imp_api = 'Nt%s' % (name[2:])
                elif name.startswith('Nt'):
                    name = 'Zw' + name[2:]
                    alt_imp_api = 'Zw%s' % (name[2:])
                mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll,
                                                                   alt_imp_api)
            return mod, func_attrs

        if alt_imp_api:
            mod, func_attrs = self.api.get_export_func_handler(dll,
                                                               alt_imp_api)
        elif alt_imp_dll:
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll,
                                                               name)
        return mod, func_attrs

    def read_unicode_string(self, addr):
        """
        Read string data from a UNICODE_STRING object located at the specified address
        """
        us = windef.UNICODE_STRING(self.get_ptr_size())
        us = self.mem_cast(us, addr)

        string = self.read_mem_string(us.Buffer, width=2)
        return string

    def log_api(self, pc, imp_api, rv, argv):
        call_str = '%s(' % (imp_api)
        for arg in argv:
            if isinstance(arg, int):
                call_str += '0x%x' % (arg)
            elif isinstance(arg, str):
                call_str += '\"%s\"' % (arg.replace("\n", "\\n"))
            elif isinstance(arg, bytes):
                call_str += '\"%s\"' % (arg)
            call_str += ', '
        if call_str.endswith(', '):
            call_str = call_str[:-2]
        call_str += ')'

        _rv = rv
        if _rv is not None:
            _rv = hex(rv)
        self.log_info('%s: %s -> %s' % (hex(pc), repr(call_str), _rv))
        if self.profiler:
            # Log the API args and return value
            self.profiler.log_api(self.curr_run, pc, imp_api, rv, argv)

    def handle_import_func(self, dll, name):
        """
        Forward imported functions to the corresponding handler (if any).
        """
        imp_api = '%s.%s' % (dll, name)
        oret = self.get_ret_address()
        opc = self.get_pc()
        mod, func_attrs = self.api.get_export_func_handler(dll, name)
        if not func_attrs:
            mod, func_attrs = self.normalize_import_miss(dll, name)

        if func_attrs:
            handler_name, func, argc, conv, ordinal = func_attrs

            if name.startswith('ordinal_'):
                name = handler_name

            argv = self.get_func_argv(conv, argc)
            imp_api = '%s.%s' % (dll, name)
            default_ctx = {'func_name': imp_api}

            self.hammer.handle_import_func(imp_api, conv, argc)
            hooks = self.get_api_hooks(dll, name)
            if hooks:
                from types import MethodType
                hooked_func = MethodType(func, mod)
                orig = lambda args: hooked_func(self, args, default_ctx) # noqa
                for hook in hooks:
                    # each hook is called with the arguments, and only the last return value is
                    # considered
                    rv = hook.cb(self, imp_api, orig, argv)
            else:
                try:
                    rv = self.api.call_api_func(mod, func, argv, ctx=default_ctx)
                except Exception as e:
                    self.log_exception('0x%x: Error while calling API handler for %s:' %
                                       (oret, imp_api))
                    error = self.get_error_info(str(e), self.get_pc(),
                                                traceback=traceback.format_exc())
                    self.curr_run.error = error
                    self.on_run_complete()
                    return

            ret = self.get_ret_address()
            pc = self.get_pc()
            mm = self.get_address_map(ret)

            # Is this function being called from a dynamcially allocated memory segment?
            if mm and 'virtualalloc' in mm.get_tag().lower():
                self._dynamic_code_cb(self, ret, 0, {})

            # Log the API args and return value
            self.log_api(oret, imp_api, rv, argv)

            if not self.run_complete and ret == oret and pc == opc:
                self.do_call_return(argc, ret, rv, conv=conv)

        else:
            # See if a user defined a hook for this unsupported function
            hooks = self.get_api_hooks(dll, name)
            if hooks:
                # Since the function is unsupported, just call the most accurate defined hook
                hook = hooks[0]
                imp_api = '%s.%s' % (dll, name)

                if hook.call_conv is None:
                    hook.call_conv = _arch.CALL_CONV_STDCALL

                argv = self.get_func_argv(hook.call_conv, hook.argc)
                self.hammer.handle_import_func(imp_api, hook.call_conv, hook.argc)
                rv = hook.cb(self, imp_api, None, argv)
                ret = self.get_ret_address()
                self.log_api(ret, imp_api, rv, argv)
                self.do_call_return(hook.argc, ret, rv, conv=hook.call_conv)
                return
            elif self.functions_always_exist:
                imp_api = '%s.%s' % (dll, name)
                conv = _arch.CALL_CONV_STDCALL
                argc = 4
                argv = self.get_func_argv(conv, argc)
                rv = 1
                ret = self.get_ret_address()
                self.log_api(ret, imp_api, rv, argv)
                self.do_call_return(argc, ret, rv, conv=conv)
                return

            run = self.get_current_run()
            error = self.get_error_info('unsupported_api', self.get_pc())
            self.log_error("Unsupported API: %s (ret: 0x%x)" % (imp_api, oret))
            error['api_name'] = imp_api
            self.curr_run.error = error
            self.on_run_complete()

        run = self.get_current_run()
        if run and run.get_api_count() > self.max_api_count:
            self.log_info("* Maximum number of API calls reached. Stopping current run.")
            run.error['type'] = 'max_api_count'
            run.error['count'] = self.max_api_count
            run.error['pc'] = hex(self.get_pc())
            run.error['last_api'] = imp_api
            self.on_run_complete()

    def _hook_mem_unmapped(self, emu, access, address, size, value, ctx):
        """
        High level function used to catch all invalid memory accesses that occur during
        emulation
        """
        try:
            access = self.emu_eng.mem_access.get(access)
            self.prev_pc = self.get_pc()

            if not self.tmp_code_hook and not self.mem_tracing_enabled:
                self.tmp_code_hook = self.add_code_hook(cb=self._hook_code)

            self.enable_code_hook()

            if access == common.INVALID_MEM_EXEC:

                if address == winemu.SEH_RETURN_ADDR:
                    self.continue_seh()
                    self._unset_emu_hooks()
                    return True
                elif address == winemu.API_CALLBACK_HANDLER_ADDR:
                    run = self.get_current_run()
                    if run.api_callbacks:
                        pc, orig_func, args = run.api_callbacks.pop(0)
                        self.do_call_return(len(args), pc)
                        self._unset_emu_hooks()
                    return True
                return self._handle_invalid_fetch(emu, address, size,
                                                  value, ctx)

            elif access == common.INVALID_MEM_READ:
                return self._handle_invalid_read(emu, address, size,
                                                 value, ctx)

            elif access == common.INVAL_PERM_MEM_EXEC:
                return self._handle_prot_fetch(emu, address, size,
                                               value, ctx)
            elif access == common.INVALID_MEM_WRITE:

                fakeout = address & 0xFFFFFFFFFFFFF000
                self.mem_map(self.page_size, base=fakeout)
                self.tmp_maps.append((fakeout, self.page_size))

                return self._handle_invalid_write(emu, address, size,
                                                  value, ctx)
            elif access == common.INVAL_PERM_MEM_WRITE:
                return self._handle_prot_write(emu, address, size,
                                               value, ctx)
        except Exception as e:
            self.log_exception('Invalid memory exception')
            error = self.get_error_info(str(e), self.get_pc(),
                                        traceback=traceback.format_exc())
            self.curr_run.error = error
            self.on_emu_complete()
            return False

    def _handle_prot_write(self, emu, address, size, value, ctx):

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_protect_write', address)
        self.curr_run.error = error

        self.tmp_maps.append((fakeout, self.page_size))
        self.on_run_complete()
        return True

    def restart_run(self, run):
        """
        Restart the current run
        """
        run.instr_cnt = 0
        self.set_pc(run.start_addr)

    def get_symbol_from_address(self, address):
        """
        If the supplied address is related to a known symbol, look it up here
        """
        symbol = None
        sym = self.symbols.get(address)
        if sym:
            symbol = '%s.%s' % sym
        return symbol

    def _hook_mem_read(self, emu, access, address, size, value, ctx):
        """
        Hook each memory read event that occurs. This hook is used to lookup symbols and modules
        that are read from during emulation.
        """

        try:
            symbol = self.get_symbol_from_address(address)

            if symbol:
                mod = self.get_mod_from_addr(address)
                if not mod.is_decoy():
                    mac = self.curr_run.sym_access.get(address)
                    if not mac:
                        mac = MemAccess(sym=symbol)
                    mac.reads += 1
                    self.curr_run.sym_access.update({address: mac})
                else:
                    gdata = self.global_data.get(address)
                    ptr = 0
                    if gdata:
                        symbol, ptr = gdata

                    if not ptr:
                        mn, fn = symbol.split('.')[:2]
                        data_ptr = self.handle_import_data(mn, fn)
                        if data_ptr:
                            pc = self.get_pc()
                            self.impdata_queue.append(((pc, address, symbol, data_ptr)))
                            self.set_pc(pc)
                        mac = self.curr_run.sym_access.get(address)
                        if not mac:
                            mac = MemAccess(sym=symbol)
                        mac.reads += 1
                        self.curr_run.sym_access.update({address: mac})
                        self.enable_code_hook()
                        return True

            for read_access in self.curr_run.read_cache:
                if read_access.base <= address <= (read_access.base + read_access.size) - 1:
                    read_access.reads += 1
                    return True

            mmap = self.get_address_map(address)
            if not mmap:
                return False

            maccess = self.curr_run.mem_access.get(mmap)
            if not maccess:
                maccess = MemAccess(base=mmap.base, size=mmap.size)
            self.curr_run.read_cache.appendleft(maccess)
            self.curr_run.mem_access.update({mmap: maccess})
            maccess.reads += 1

            return True
        except Exception as e:
            self.log_exception('Exception during memory read')
            error = self.get_error_info(str((type(e).__name__)), self.get_pc(),
                                        traceback=traceback.format_exc())
            self.curr_run.error = error
            self.on_emu_complete()
            return False

    def _hook_mem_write(self, emu, access, address, size, value, ctx):
        """
        Hook each memory write event that occurs. This hook is used to track memory modifications
        to interesting memory locations.
        """
        try:

            symbol = self.get_symbol_from_address(address)
            if symbol:
                mac = self.curr_run.sym_access.get(address)
                if not mac:
                    mac = MemAccess(sym=symbol)
                mac.writes += 1
                self.curr_run.sym_access.update({address: mac})

            for write_access in self.curr_run.write_cache:
                if write_access.base <= address <= (write_access.base + write_access.size) - 1:
                    write_access.writes += 1
                    return True

            mmap = self.get_address_map(address)
            if not mmap:
                return False

            maccess = self.curr_run.mem_access.get(mmap)
            if not maccess:
                maccess = MemAccess(base=mmap.base, size=mmap.size)
            self.curr_run.write_cache.appendleft(maccess)
            self.curr_run.mem_access.update({mmap: maccess})
            maccess.writes += 1

            return True

        except Exception as e:
            self.log_exception('Exception during memory write')
            error = self.get_error_info(str((type(e).__name__)), self.get_pc(),
                                        traceback=traceback.format_exc())
            self.curr_run.error = error
            self.on_emu_complete()
            return False

    def _handle_invalid_read(self, emu, address, size, value, ctx):
        """
        Hook each invalid memory read event that occurs.
        """
        # Check if the sample is trying to read from another module
        decoy = self.get_mod_from_addr(address)
        if decoy:
            return self.map_decoy(decoy)

        if address >= winemu.EMU_RESERVED and \
           address <= (winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE):
            self._unset_emu_hooks()
            return True

        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True
        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_read', address)
        self.curr_run.error = error

        # Let the next run know to remove this map since its
        # technically invalid
        self.tmp_maps.append((fakeout, self.page_size))
        self.on_run_complete()
        return True

    def _handle_prot_fetch(self, emu, address, size, value, ctx):
        """
        Called when non-executable code is emulated
        """
        # Get the symbol that the sample was trying to execute
        symbol = self.get_symbol_from_address(address)
        if not symbol:
            return True

        mac = self.curr_run.sym_access.get(address)
        if not mac:
            mac = MemAccess(sym=symbol)
        mac.execs += 1
        self.curr_run.sym_access.update({address: mac})

        mod_name, fn = symbol.split('.')

        self.handle_import_func(mod_name, fn)
        return True

    def _handle_invalid_write(self, emu, address, size, value, ctx):
        """
        Called when non-writable address is written to
        """
        # ignore patches to APIs
        if address >= winemu.EMU_RESERVED and \
                address <= (winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE):
            return True

        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_write', address)
        self.curr_run.error = error

        self.tmp_maps.append((fakeout, self.page_size))
        self.on_run_complete()
        return True

    def _hook_code(self, emu, addr, size, ctx):
        """
        Hook called before every emulated instruction. Ideally we want to
        stay out of this hook as much as possible for speed considerations.
        """

        if self.debug:
            x = self.get_disasm(addr, size)[2]
            print('0x%x: %s, edi=0x%x : esi=0x%x : ebp=0x%x : eax=0x%x' % (addr, x, self.reg_read('edi'), self.reg_read('esi'), self.reg_read('ebp'), self.reg_read('eax'))) # noqa
        try:
            if self.curr_exception_code != 0:
                self.dispatch_seh(self.curr_exception_code)
                self.curr_exception_code = 0
                self.disable_code_hook()
                return True

            if self.restart_curr_run:
                self.set_pc(self.curr_run.start_addr)
                self.restart_curr_run = False
                return False

            if addr == self.return_hook or self.run_complete:
                self.on_run_complete()
                return False

            if self.tmp_maps:
                for base, size in self.tmp_maps:
                    try:
                        self.mem_unmap(base, size)
                    except Exception:
                        self.disable_code_hook()
                        return True
                self.tmp_maps = []

            if len(self.impdata_queue):

                imp = self.impdata_queue.pop(0)
                pc, read_addr, sym, data_ptr = imp
                if data_ptr is None:
                    return True

                self.global_data.update({read_addr: [sym, data_ptr]})
                self.mem_write(read_addr,
                               data_ptr.to_bytes(self.get_ptr_size(),
                                                 'little'))
                return True

            if not self.mem_tracing_enabled:
                # Disabling the code hook here grants a significant speed bump
                if not self.debug:
                    self.disable_code_hook()

            if self.max_instructions != -1 and self.curr_run.instr_cnt >= self.max_instructions:
                self.on_run_complete()
                return False

            self.curr_instr_size = size

        # Get the symbol that the sample was trying to execute

            symbol = self.get_symbol_from_address(addr)
            if self.mem_tracing_enabled and symbol:
                mod_name, fn = symbol.split('.')

                mac = self.curr_run.sym_access.get(addr)
                if not mac:
                    mac = MemAccess(sym=symbol)
                mac.execs += 1
                self.curr_run.sym_access.update({addr: mac})

                self.handle_import_func(mod_name, fn)
                return True

            self._set_emu_hooks()

            if not self.mem_tracing_enabled:
                return

            # Increment the instruction counter
            self.curr_run.instr_cnt += 1

            for exec_access in self.curr_run.exec_cache:
                if exec_access.base <= addr <= (exec_access.base + exec_access.size) - 1:
                    exec_access.execs += 1
                    return True

            mmap = self.get_address_map(addr)
            if not mmap:
                return False
            maccess = self.curr_run.mem_access.get(mmap)
            if not maccess:
                maccess = MemAccess(base=mmap.base, size=mmap.size)
            self.curr_run.exec_cache.appendleft(maccess)
            self.curr_run.mem_access.update({mmap: maccess})
            maccess.execs += 1

            return True

        except Exception as e:
            self.log_exception('Exception during code hook')
            error = self.get_error_info(str(e), self.get_pc(),
                                        traceback=traceback.format_exc())
            self.curr_run.error = error
            self.on_emu_complete()
            return False

    def get_native_module_path(self, mod_name=''):
        """
        Get the full filesystem path of a default decoy that is supplied by
        speakeasy
        """

        def get_fp(path, mod_name):
            path = common.normalize_package_path(path)
            files = [os.path.join(path, fn) for fn in os.listdir(path)]
            for fp in files:
                bn = os.path.basename(fp.lower())
                bn = os.path.splitext(bn)[0]
                if mod_name == bn:
                    return fp

        mod_name = mod_name.lower()
        decoy_arch_dir = {_arch.ARCH_X86: ('module_directory_x86', 'x86'),
                          _arch.ARCH_AMD64: ('module_directory_x64', 'amd64')}
        dirs = decoy_arch_dir[self.get_arch()]
        mod_dir = dirs[0]

        path = self.config_modules.get(mod_dir, '')

        fp = get_fp(path, mod_name)
        if not fp:
            path = os.path.join(os.path.dirname(__file__), os.pardir, 'winenv', 'decoys', dirs[1])
            fp = get_fp(path, mod_name)

        return fp

    def load_library(self, mod_name):
        """
        Load a new module into the emulation space if necessary
        """
        ums = self.get_user_modules()
        lib = ntpath.basename(mod_name)
        lib = os.path.splitext(lib)[0]

        for um in ums:
            base = ntpath.basename(um.get_emu_path())
            base = os.path.splitext(base)[0]
            if lib.lower() == base.lower():
                hmod = um.get_base()
                return hmod

        # If we get here, the library is not found, if configured to do so,
        # we can return a fake module in every instance
        if not self.modules_always_exist:
            return 0

        mod = self.init_module(name=lib, default_base=0x6f000000)

        ums.append(mod)

        # Add the newly loaded module to the current process's PEB module list
        proc = self.get_current_process()
        if self.get_address_map(proc.get_peb_ldr().address):
            proc.add_module_to_peb(mod)

        return mod.get_base()

    def generate_export_table(self, modname):
        '''
        Generates a PE export table that can be parsed by malware
        The export names are based on the API handlers that are currently implemented
        '''

        if not modname:
            return
        modname = modname.lower()
        mod_handler = self.api.load_api_handler(modname)
        if mod_handler:

            jit = winemu.JitPeFile(self.get_arch())

            funcs = [(f[4], f[0]) for k, f in mod_handler.funcs.items() if isinstance(k, str)]
            data_exports = [k for k, d in mod_handler.data.items() if isinstance(k, str)]
            new = funcs.copy()

            if modname == 'ntdll':
                nt_handler = self.api.load_api_handler('ntoskrnl')
                funcs = [(f[4], f[0]) for k, f in nt_handler.funcs.items() if isinstance(k, str)]
                funcs = new + funcs
                new = funcs.copy()

            if modname in ('ntdll', 'ntoskrnl'):
                for o, fn in funcs:
                    if fn.startswith('Nt'):
                        new.append((None, 'Zw' + fn[2:]))
                    elif fn.startswith('Zw'):
                        new.append((None, 'Nt' + fn[2:]))
            else:
                for o, fn in funcs:
                    new.append((None, fn + 'A'))
                    new.append((None, fn + 'W'))
            func_names = new

            func_names = [fn for o, fn in func_names]
            func_names.sort()

            exports = []
            ords = [o for o, fn in funcs if o is not None]
            if ords:
                if max(ords) > len(exports):
                    num_exports = max(ords) + 1
                else:
                    num_exports = len(exports) + 1

                exports = ['ordinal_%d' % (i) for i in range(num_exports)]

                for o, fn in funcs:
                    if o is not None:
                        exports[o-1] = fn

                [exports.append(fn) for fn in func_names if fn not in exports]

            if not exports:
                exports = func_names

            exports += data_exports
            img = jit.get_decoy_pe_image(modname, exports)
            mod = winemu.DecoyModule(data=img, is_jitted=True)

            return mod
        return None

    def init_module(self, modconf={}, name='none', emu_path='', default_base=None):
        """
        Initialize a module from a config entry
        """
        modname = modconf.get('name', name)

        mod = None

        images = modconf.get('images', [])
        default_file_path = self.get_native_module_path(mod_name=modname)
        if not images:
            if not default_file_path:
                mod = self.generate_export_table(modname)
                default_file_path = self.get_native_module_path(mod_name='default_exe')

        path = None
        for img in images:
            arch = img['arch']
            if arch == self.get_arch():
                path = self.get_native_module_path(mod_name=img['name'])

        if not path:
            path = default_file_path

        if not mod:
            mod = winemu.DecoyModule(path=path)
        base = modconf.get('base_addr', default_base)
        if isinstance(base, str):
            base = int(base, 16)

        mod.decoy_path = modconf.get('path', emu_path) or (name + '.dll')
        # Reserve memory for the module
        res, size = self.get_valid_ranges(mod.image_size,
                                          base)
        mod.decoy_base = res
        mod.name = modconf.get('name', name)
        self.mem_reserve(size, base=res, tag='emu.module.%s' % (mod.name),
                         perms=common.PERM_MEM_RW)

        if mod.decoy_path == '' and name != '':
            mod.decoy_path = self.config.get('current_dir', 'C:\\Windows\\system32') + '\\' + name

        mod.base_name = ntpath.basename(mod.decoy_path)

        return mod

    # This will create a module from a file inside Speakeasy's
    # object manager. file_path is expected to point to a valid PE
    # file, like it would on a real Windows machine
    # Returns: raw data that represents a PE file
    def get_module_data_from_emu_file(self, file_path):
        if not self.does_file_exist(file_path):
            return None

        mod_file = self.fileman.get_file_from_path(file_path)

        if not mod_file:
            return None

        # This file could have been read from, so don't mess
        # with its file offset pointer. Just get the raw bytes
        # from the BytesIO object
        return mod_file.data.getvalue()

    def init_sys_modules(self, modules_config):
        """
        Initialize kernel mode modules that may be accessed by emulated modules
        """
        sys_mods = []

        for modconf in modules_config:
            mod = self.init_module(modconf)
            sys_mods.append(mod)
        return sys_mods

    def init_user_modules(self, modules_config):
        """
        Initialize user mode modules that may be accessed by emulated modules
        """
        user_mods = []

        for modconf in modules_config:
            mod = self.init_module(modconf, default_base=0x6f000000)
            user_mods.append(mod)

        return user_mods

    def map_decoy(self, decoy):
        """
        Map a decoy PE into memory. This allows samples such as shellcode to
        parse a PE's export table while resolving exported functions
        """
        if not decoy.is_mapped:
            decoy.full_load()

            for exp in decoy.get_exports():
                if exp.name:
                    sym = exp.name
                    mod_name = decoy.get_base_name()
                    addr = exp.address
                    self.symbols.update({addr: (mod_name, sym)})
                    m, hndlr = self.api.get_data_export_handler(mod_name, sym)
                    if hndlr and not self.mem_tracing_enabled:
                        self.add_mem_read_hook(cb=self._hook_mem_read, begin=addr, end=addr)
                        self.add_mem_write_hook(cb=self._hook_mem_write, begin=addr, end=addr)

            # Map the module into the emulation address space
            mem = self.mem_map_reserve(decoy.get_base())
            if mem is None:
                base, size = self.get_valid_ranges(decoy.image_size,
                                                   addr=decoy.get_base())
                mem = self.mem_map(size, base=base, tag='emu.module.%s' % (decoy.name),
                                   perms=common.PERM_MEM_RW)

            decoy.is_mapped = True
            img = decoy.get_memory_mapped_image(base=mem)
            self.mem_write(mem, bytes(img))
            if not self.mem_tracing_enabled:
                self.add_code_hook(cb=self._module_access_hook, begin=mem, end=mem+len(img))
            decoy.base = mem
            return True

    def get_thread_context(self, thread=None):
        """
        Get the current thread CPU context
        """
        if thread:
            return thread.get_context()
        else:
            ctx = self.wintypes.CONTEXT(self.get_ptr_size())
            if self.get_arch() == _arch.ARCH_X86:
                ctx.Edi = self.reg_read(_arch.X86_REG_EDI)
                ctx.Esi = self.reg_read(_arch.X86_REG_ESI)
                ctx.Eax = self.reg_read(_arch.X86_REG_EAX)
                ctx.Ebp = self.reg_read(_arch.X86_REG_EBP)
                ctx.Edx = self.reg_read(_arch.X86_REG_EDX)
                ctx.Ecx = self.reg_read(_arch.X86_REG_ECX)
                ctx.Ebx = self.reg_read(_arch.X86_REG_EBX)
                ctx.Esp = self.reg_read(_arch.X86_REG_ESP)
                ctx.Eip = self.reg_read(_arch.X86_REG_EIP)

                ctx.EFlags = self.reg_read(_arch.X86_REG_EFLAGS)
                ctx.SegCs = self.reg_read(_arch.X86_REG_CS)
                ctx.SegSs = self.reg_read(_arch.X86_REG_SS)
                ctx.SegDs = self.reg_read(_arch.X86_REG_DS)
                ctx.SegFs = self.reg_read(_arch.X86_REG_FS)
                ctx.SegGs = self.reg_read(_arch.X86_REG_GS)
                ctx.SegEs = self.reg_read(_arch.X86_REG_ES)
            elif self.get_arch() == _arch.ARCH_AMD64:
                ctx = self.wintypes.CONTEXT64(self.get_ptr_size())
        return ctx

    def load_thread_context(self, ctx, thread=None):
        """
        Set the current thread CPU context
        """
        if self.get_arch() == _arch.ARCH_X86:
            self.reg_write(_arch.X86_REG_EDI, ctx.Edi)
            self.reg_write(_arch.X86_REG_ESI, ctx.Esi)
            self.reg_write(_arch.X86_REG_EAX, ctx.Eax)
            self.reg_write(_arch.X86_REG_EBP, ctx.Ebp)
            self.reg_write(_arch.X86_REG_EDX, ctx.Edx)
            self.reg_write(_arch.X86_REG_ECX, ctx.Ecx)
            self.reg_write(_arch.X86_REG_EBX, ctx.Ebx)
            self.reg_write(_arch.X86_REG_ESP, ctx.Esp)
            self.reg_write(_arch.X86_REG_EIP, ctx.Eip)

            self.reg_write(_arch.X86_REG_EFLAGS, ctx.EFlags)
            self.reg_write(_arch.X86_REG_CS, ctx.SegCs)
            self.reg_write(_arch.X86_REG_SS, ctx.SegSs)
            self.reg_write(_arch.X86_REG_DS, ctx.SegDs)
            self.reg_write(_arch.X86_REG_FS, ctx.SegFs)
            self.reg_write(_arch.X86_REG_GS, ctx.SegGs)
            self.reg_write(_arch.X86_REG_ES, ctx.SegEs)

        elif self.get_arch() == _arch.ARCH_AMD64:
            raise NotImplementedError()

    def _get_exception_list(self):
        """
        Retrieves the exception handler list for the current thread
        """
        thread = self.get_current_thread()
        if not thread:
            return 0
        teb = thread.get_teb()
        teb = teb.read_back()
        return teb.object.NtTib.ExceptionList

    def _dispatch_seh_x86(self, except_code):
        """
        Get the initial SEH handler when dispatching a CPU exception
        that occurs during emulation
        """

        thread = self.get_current_thread()
        if not thread:
            return False
        seh = thread.get_seh()
        exception_list = self._get_exception_list()
        ptr_size = self.get_ptr_size()

        seh.last_exception_code = except_code
        # Create the _EXCEPTION_RECORD
        record = self.wintypes.EXCEPTION_RECORD(self.get_ptr_size())
        record.ExceptionCode = except_code
        record.ExceptionFlags = 0
        record.ExceptionAddress = self.get_pc()
        record.NumberParameters = 0

        ereg = self.wintypes.EXCEPTION_REGISTRATION(self.get_ptr_size())
        if exception_list:

            entry = self.mem_cast(ereg, exception_list)
            sp = self.get_stack_ptr()

            exp_ptrs = self.wintypes.EXCEPTION_POINTERS(self.get_ptr_size())

            p_exp_ptrs = self.mem_map(exp_ptrs.sizeof(), tag='emu.struct.EXCEPTION_POINTERS')
            prec = self.mem_map(record.sizeof(), tag='emu.struct.EXCEPTION_RECORD')
            pctx = self.mem_map(record.sizeof(), tag='emu.struct.EXCEPTION_CONTEXT')

            exp_ptrs.ExceptionRecord = prec
            exp_ptrs.ContextRecord = pctx

            _ctx = self.get_thread_context()
            self.mem_write(pctx, _ctx.get_bytes())
            seh.set_context(_ctx, address=pctx)

            p_exp_ptrs_bytes = (p_exp_ptrs).to_bytes(ptr_size, 'little')

            self.mem_write(p_exp_ptrs, exp_ptrs.get_bytes())
            self.mem_write(prec, record.get_bytes())

            # Write the record to the ms_exc.exc_ptr offset
            self.mem_write(exception_list - ptr_size,
                           p_exp_ptrs_bytes)

            args = [prec, exception_list, pctx, 0]
            self.set_func_args(sp, winemu.SEH_RETURN_ADDR, *args)

            run = self.get_current_run()
            regs = self.get_register_state()

            pc = self.prev_pc
            try:
                mnem, op, instr = self.get_disasm(pc, DISASM_SIZE)
            except Exception as e:
                self.log_error(str(e))
                instr = 'disasm_failed'

            self.log_info('0x%x: Exception caught: code:0x%x, handler=0x%x, instr=\"%s\"'
                          % (pc, except_code, entry.Handler, instr))

            run.handled_exceptions.append({"pc": hex(pc),
                                           "instr": instr,
                                           "exception_code": hex(except_code),
                                           "handler_address": hex(entry.Handler),
                                           "registers": regs,
                                           })

            # EBX clobber, -1 is what I observed inside a VM
            self.reg_write(_arch.X86_REG_EBX, 0xffffffff)
            self.set_pc(entry.Handler)
            return True
        return False

    def get_reserved_ranges(self):
        """
        Get the allocated memory ranges that the emulator reserves
        """
        return (winemu.EMU_RESERVED, winemu.EMU_RESERVED_END)

    def _continue_seh_x86(self):
        """
        Get the next exception handler while processing SEH
        """
        thread = self.get_current_thread()
        seh = thread.get_seh()
        sp = self.get_stack_ptr()
        ret_val = self.get_return_val()

        if seh.handler_ret_val is None:
            seh.handler_ret_val = ret_val

        ctx = seh.get_context()

        if seh.context_address:
            ctx = self.mem_cast(ctx, seh.context_address)

        # Always restore thread context, is it correct to always
        # do this?
        self.load_thread_context(ctx)

        for frame in seh.get_frames():
            if not frame.searched:
                seh.set_current_frame(frame)
                scope_record = frame.scope_records[0]
                if (not scope_record.filter_called and
                   scope_record.record.FilterFunc):
                    self.set_func_args(sp, winemu.SEH_RETURN_ADDR)
                    self.set_pc(scope_record.record.FilterFunc)
                    seh.set_last_func(scope_record.record.FilterFunc)
                    scope_record.filter_called = True
                    return

                if (windef.EXCEPTION_EXECUTE_HANDLER == ret_val or
                   scope_record.record.FilterFunc == 0 or
                   scope_record.record.FilterFunc == 0xFFFFFFFF):
                    if not scope_record.handler_called:
                        # If no filter was provided, this is a finally block
                        self.set_pc(scope_record.record.HandlerAddress)
                        seh.set_last_func(scope_record.record.HandlerAddress)
                        scope_record.handler_called = True
                        return
                elif windef.EXCEPTION_CONTINUE_EXECUTION == ret_val:
                    ctx = seh.get_context()
                    if seh.context_address:
                        _ctx = self.mem_cast(ctx, seh.context_address)
                    self.load_thread_context(_ctx)
                    self.set_pc(ctx.Eip)
                    return

                elif windef.EXCEPTION_CONTINUE_SEARCH == ret_val:
                    pass

                frame.searched = True

        if windef.EXCEPTION_CONTINUE_SEARCH == ret_val and not len(seh.get_frames()):
            ctx = seh.get_context()
            self.set_pc(ctx.Eip)
            return

        self.run_complete = True

    def dispatch_seh(self, except_code, faulting_address=None):
        rv = False
        if self.get_arch() == _arch.ARCH_X86:
            rv = self._dispatch_seh_x86(except_code)
        if not rv and self.unhandled_exception_filter:
            # Create the _EXCEPTION_RECORD
            record = self.wintypes.EXCEPTION_RECORD(self.get_ptr_size())
            record.ExceptionCode = except_code
            record.ExceptionFlags = 0
            record.ExceptionAddress = self.get_pc()
            record.NumberParameters = 0

            exp_ptrs = self.wintypes.EXCEPTION_POINTERS(self.get_ptr_size())
            p_exp_ptrs = self.mem_map(exp_ptrs.sizeof(), tag='emu.struct.EXCEPTION_POINTERS')
            prec = self.mem_map(record.sizeof(), tag='emu.struct.EXCEPTION_RECORD')
            pctx = self.mem_map(record.sizeof(), tag='emu.struct.EXCEPTION_CONTEXT')

            exp_ptrs.ExceptionRecord = prec
            exp_ptrs.ContextRecord = pctx

            self.mem_write(p_exp_ptrs, exp_ptrs.get_bytes())
            self.mem_write(prec, record.get_bytes())

            sp = self.get_stack_ptr()
            args = [p_exp_ptrs]
            self.set_func_args(sp, winemu.EMU_RETURN_ADDR, *args)
            self.set_pc(self.unhandled_exception_filter)
            self.unhandled_exception_filter = 0
            if faulting_address:
                fakeout = faulting_address & 0xFFFFFFFFFFFFF000
                self.mem_map(self.page_size, base=fakeout)
                self.tmp_maps.append((fakeout, self.page_size))
            rv = True
        return rv

    def continue_seh(self):
        if self.get_arch() == _arch.ARCH_X86:
            self._continue_seh_x86()

    def create_event(self, name=''):
        """
        Create a kernel event object
        """
        evt = self.new_object(objman.Event)
        evt.name = name
        hnd = self.om.get_handle(evt)
        return hnd, evt

    def dec_ref(self, obj):
        """
        Dereference an object
        """
        return self.om.dec_ref(obj)

    def create_mutant(self, name=''):
        """
        Create a kernel mutant object
        """
        if name == 0:
            name = ''
        mtx = self.new_object(objman.Mutant)
        mtx.name = name
        hnd = self.om.get_handle(mtx)
        return hnd, mtx

    def _hook_interrupt(self, emu, intnum, ctx=[]):
        """
        Called when software interrupts occur
        """
        def _tmp_hook(emu, addr, size, ctx):
            ret = self.pop_stack()
            self.set_pc(ret)
            hook_obj = ctx.pop(0)
            hook_obj.disable()

        exception_list = self._get_exception_list()
        if exception_list and self.dispatch_handlers:
            # Catch software breakpoint interrupts
            if intnum == 3 or intnum == 0x2d:
                self.curr_exception_code = ddk.STATUS_BREAKPOINT
                self.prev_pc = self.get_pc()
                self.enable_code_hook()
                return True
            # Catch single step exceptions
            elif intnum == 1:
                self.curr_exception_code = ddk.STATUS_SINGLE_STEP
                self.enable_code_hook()
                self.prev_pc = self.get_pc()
                eflags = self.reg_read(_arch.X86_REG_EFLAGS)
                # Remove the trap flag
                eflags &= 0xFFFFFEFF
                self.reg_write(_arch.X86_REG_EFLAGS, eflags)
                return True

        # Handle __fastfail interrupt introduced in Windows 8
        if intnum == 0x29:
            ecx = self.reg_read(_arch.X86_REG_ECX)
            # Cookie security init failed, just return since we are in __security_init_cookie
            if ecx == 6:
                ctx.append(self.add_code_hook(cb=_tmp_hook, ctx=ctx))
                return True

        pc = self.get_pc()
        self.log_error('0x%x: Unhandled interrupt: intnum=0x%x' % (pc, intnum))
        error = self.get_error_info('unhandled_interrupt', pc)
        error.update({'interrupt_num': intnum})
        self.curr_run.error = error

        self.restart_curr_run = True
        self.on_run_complete()
        return False
