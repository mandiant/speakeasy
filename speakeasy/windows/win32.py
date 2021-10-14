# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import binascii
import os
import shlex

import ntpath
import hashlib
import capstone as cs

import speakeasy.winenv.arch as _arch
import speakeasy.windows.common as w32common
from speakeasy.profiler import Run
from speakeasy.windows.winemu import WindowsEmulator
import speakeasy.windows.objman as objman
from speakeasy.winenv.api.winapi import WindowsApi
import speakeasy.common as common
from speakeasy.errors import Win32EmuError

from speakeasy.windows.sessman import SessionManager
from speakeasy.windows.com import COM


DLL_PROCESS_DETACH = 0
DLL_PROCESS_ATTACH = 1

MAX_EXPORTS_TO_EMULATE = 10


class Win32Emulator(WindowsEmulator):
    """
    User Mode Windows Emulator Class
    """
    def __init__(self, config, argv=[], debug=False, logger=None, exit_event=None):
        super(Win32Emulator, self).__init__(config, debug=debug, logger=logger,
                                            exit_event=exit_event)

        self.last_error = 0
        self.peb_addr = 0
        self.heap_allocs = []
        self.argv = argv
        self.sessman = SessionManager(config)
        self.com = COM(config)

    def get_argv(self):
        """
        Get command line arguments (if any) that are being passed
        to the emulated process. (e.g. main(argv))
        """
        argv0 = ''
        out = []

        if len(self.argv):
            for m in self.modules:
                pe = m[0]
                emu_path = m[2]
                if pe.is_exe():
                    argv0 = emu_path
            out = [argv0] + self.argv
        elif self.command_line:
            out = shlex.split(self.command_line, posix=False)
        return out

    def set_last_error(self, code):
        """
        Set the last error code for the current thread
        """
        if self.curr_thread:
            self.curr_thread.set_last_error(code)

    def get_last_error(self):
        """
        Get the last error code for the current thread
        """
        if self.curr_thread:
            return self.curr_thread.get_last_error()

    def get_session_manager(self):
        """
        Get the session manager for the emulator. This will manage things like desktops,
        windows, and session isolation
        """
        return self.sessman

    def add_vectored_exception_handler(self, first, handler):
        """
        Add a vectored exception handler that will be executed on an exception
        """
        self.veh_handlers.append(handler)

    def remove_vectored_exception_handler(self, handler):
        """
        Remove a vectored exception handler
        """
        self.veh_handlers.remove(handler)

    def get_processes(self):
        if len(self.processes) <= 1:
            self.init_processes(self.config_processes)
        return self.processes

    def init_processes(self, processes):
        """
        Initialize configured processes set in the emulator config
        """
        for proc in processes:
            p = objman.Process(self)
            self.add_object(p)

            p.name = proc.get('name', '')
            new_pid = proc.get('pid')
            if new_pid:
                p.pid = new_pid

            base = proc.get('base_addr')

            if isinstance(base, str):
                base = int(base, 16)
            p.base = base
            p.path = proc.get('path')
            p.session = proc.get('session', 0)
            p.image = ntpath.basename(p.path)

            self.processes.append(p)

    def load_module(self, path=None, data=None, first_time_setup=True):
        """
        Load a module into the emulator space from the specified path
        """
        self._init_name(path, data)
        pe = self.load_pe(path=path, data=data, imp_id=w32common.IMPORT_HOOK_ADDR)

        if pe.arch == _arch.ARCH_X86:
            disasm_mode = cs.CS_MODE_32
        elif pe.arch == _arch.ARCH_AMD64:
            disasm_mode = cs.CS_MODE_64
        else:
            raise Win32EmuError('Unsupported architecture: %s', pe.arch)

        if not self.arch:
            self.arch = pe.arch
            self.set_ptr_size(self.arch)

        # No need to initialize the engine and Capstone again
        if first_time_setup:
            self.emu_eng.init_engine(_arch.ARCH_X86, pe.arch)

            if not self.disasm_eng:
                self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, disasm_mode)

        self.api = WindowsApi(self)

        cd = self.get_cd()
        if not cd.endswith('\\'):
            cd += '\\'
        emu_path = cd + self.file_name

        if not data:
            with open(path, 'rb') as f:
                data = f.read()
        self.fileman.add_existing_file(emu_path, data)

        # Strings the initial buffer so that we can detect decoded strings later on
        if self.profiler and self.do_strings:
            self.profiler.strings['ansi'] = [a[1] for a in self.get_ansi_strings(data)]
            self.profiler.strings['unicode'] = [u[1] for u in self.get_unicode_strings(data)]

        # Set the emulated path
        emu_path = ''
        self.cd = self.get_cd()
        if self.cd:
            if not self.cd.endswith('\\'):
                self.cd += '\\'
            emu_path = self.cd + os.path.basename(self.file_name)

        pe.set_emu_path(emu_path)

        # There's a bit of a problem here, if we cannot reserve memory
        # at the PE's desired base address, and the relocation table
        # is not present, we can't rebase it. So this is gonna have to
        # be a bit of a hack for binaries without a relocation table.
        # This logic is really only for child processes, since we're pretty
        # much guarenteed memory at the base address of the main module.
        #   1. If the memory at the child's desired load address is already
        #      being used, remap it somewhere else. I'm pretty sure that
        #      the already-used memory will always be for a module,
        #      since desired load addresses don't really vary across PEs
        #   2. Fix up any modules that speakeasy has open for the parent
        #      to reflect where it was remapped
        #   3. Try and grab memory at the child's desired base address,
        #      if that isn't still isn't possible, we're out of luck
        #
        # But if the relocation table is present, we can rebase it,
        # so we do that instead of the above hack.
        imgbase = pe.OPTIONAL_HEADER.ImageBase
        ranges = self.get_valid_ranges(pe.image_size, addr=imgbase)
        base, size = ranges

        if base != imgbase:
            if pe.has_reloc_table():
                pe.rebase(base)
            else:
                parent_map = self.get_address_map(imgbase)

                # Already being used by the parent, so let's remap the parent
                # Do get_valid_ranges on the parent map size so we get a
                # suitable region for it
                new_parent_mem, unused = self.get_valid_ranges(parent_map.size)
                new_parent_mem = self.mem_remap(imgbase, new_parent_mem)

                # Failed
                if new_parent_mem == -1:
                    # XXX what to do here
                    pass

                # Update parent module pointer
                for pe_, ranges_, emu_path_ in self.modules:
                    base_, size_ = ranges_

                    if base_ == imgbase:
                        self.modules.remove((pe_, ranges_, emu_path_))
                        self.modules.append((pe_, (new_parent_mem, size_), emu_path_))
                        break

                # Alright, let's try to grab that memory for the child again
                ranges = self.get_valid_ranges(pe.image_size, addr=imgbase)
                base, size = ranges

                if base != imgbase:
                    # Out of luck
                    # XXX what to do here
                    pass

        self.mem_map(pe.image_size, base=base,
                tag='emu.module.%s' % (self.mod_name))

        self.modules.append((pe, ranges, emu_path))
        self.mem_write(pe.base, pe.mapped_image)

        self.setup(first_time_setup=first_time_setup)

        if not self.stack_base:
            self.stack_base, stack_addr = self.alloc_stack(0x12000)
        self.set_func_args(self.stack_base, self.return_hook)

        # Init imported data
        for addr, imp in pe.imports.items():
            mn, fn = imp
            mod, eh = self.api.get_data_export_handler(mn, fn)
            if eh:
                data_ptr = self.handle_import_data(mn, fn)
                sym = "%s.%s" % (mn, fn)
                self.global_data.update({addr: [sym, data_ptr]})
                self.mem_write(addr, data_ptr.to_bytes(self.get_ptr_size(),
                                                       'little'))
        return pe

    def prepare_module_for_emulation(self, module, all_entrypoints):
        if not module:
            self.stop()
            raise Win32EmuError('Module not found')

        # Check if any TLS callbacks exist, these run before the module's entry point
        tls = module.get_tls_callbacks()
        for i, cb_addr in enumerate(tls):
            base = module.get_base()
            if base < cb_addr < base + module.get_image_size():
                run = Run()
                run.start_addr = cb_addr
                run.type = 'tls_callback_%d' % (i)
                run.args = [base, DLL_PROCESS_ATTACH, 0]
                self.add_run(run)

        ep = module.base + module.ep

        run = Run()
        run.start_addr = ep

        main_exe = None
        if not module.is_exe():
            run.args = [module.base, DLL_PROCESS_ATTACH, 0]
            run.type = 'dll_entry.DLL_PROCESS_ATTACH'
            container = self.init_container_process()
            if container:
                self.processes.append(container)
                self.curr_process = container
        else:
            run.type = 'module_entry'
            main_exe = module
            run.args = [self.mem_map(8, tag='emu.module_arg_%d' % (i)) for i in range(4)]

        if main_exe:
            self.user_modules = [main_exe] + self.user_modules

        self.add_run(run)

        if all_entrypoints:
            # Only emulate a subset of all the exported functions
            # There are some modules (such as the windows kernel) with
            # thousands of exports
            exports = [k for k in module.get_exports()[: MAX_EXPORTS_TO_EMULATE]]

            if exports:
                args = [self.mem_map(8, tag='emu.export_arg_%d' % (i), base=0x41420000) for i in range(4)] # noqa
                for exp in exports:
                    if exp.name in ('DllMain', ):
                        continue
                    run = Run()
                    if exp.name:
                        fn = exp.name
                    else:
                        fn = 'no_name'

                    run.type = 'export.%s' % (fn)
                    run.start_addr = exp.address
                    if exp.name == 'ServiceMain':
                        # ServiceMain accepts a (argc, argv) pair like main().
                        #
                        # now, we're not exactly sure if we're in A or W mode.
                        # maybe there are some hints we could take to guess this.
                        # instead, we'll assume W mode and use default service name "IPRIP".
                        #
                        # hack: if we're actually in A mode, then string routines
                        # will think the service name is "I" which isn't perfect,
                        # but might still be good enough.
                        #
                        # layout:
                        #   argc: 1
                        #   argv:
                        #     0x00:    (argv[0]) pointer to +0x10 -+
                        #     0x04/08: (argv[1]) 0x0               |
                        #     0x10:    "IPRIP"  <------------------+
                        svc_name = "IPRIP\x00".encode('utf-16le')
                        argc = 1
                        argv = self.mem_map(len(svc_name) + 0x10, tag='emu.export_ServiceMain_argv', base=0x41420000)

                        self.write_ptr(argv, argv + 0x10)
                        self.mem_write(argv + 0x10, svc_name)

                        run.args = [argc, argv]
                    else:
                        # Here we set dummy args to pass into the export function
                        run.args = args
                    # Store these runs and only queue them before the unload
                    # routine this is because some exports may not be ready to
                    # be called yet
                    self.add_run(run)

        return

    def run_module(self, module, all_entrypoints=False, emulate_children=False):
        """
        Begin emulating a previously loaded module

        Arguments:
            module: Module to emulate
        """
        self.prepare_module_for_emulation(module, all_entrypoints)

        # Create an empty process object for the module if none is
        # supplied, only do this for the main module
        if len(self.processes) == 0:
            p = objman.Process(self, path=module.get_emu_path(), base=module.base,
                               pe=module, cmdline=self.command_line)
            self.curr_process = p
            self.om.objects.update({p.address: p})
            mm = self.get_address_map(module.base)
            if mm:
                mm.process = self.curr_process

        t = objman.Thread(self,
                          stack_base=self.stack_base,
                          stack_commit=module.stack_commit)

        self.om.objects.update({t.address: t})
        self.curr_process.threads.append(t)
        self.curr_thread = t

        peb = self.alloc_peb(self.curr_process)

        # Set the TEB
        self.init_teb(t, peb)

        # Begin emulation of main module
        self.start()

        if not emulate_children or len(self.child_processes) == 0:
            return

        # Emulate any child processes
        while len(self.child_processes) > 0:
            child = self.child_processes.pop(0)

            child.pe = self.load_module(data=child.pe_data,
                    first_time_setup=False)
            self.prepare_module_for_emulation(child.pe, all_entrypoints)

            self.command_line = child.cmdline

            self.curr_process = child
            self.curr_process.base = child.pe.base
            self.curr_thread = child.threads[0]

            self.om.objects.update({self.curr_thread.address: self.curr_thread})

            # PEB and TEB will be initialized when the next run happens

            self.start()

        return

    def _init_name(self, path, data=None):
        if not data:
            self.file_name = os.path.basename(path)
            self.mod_name = os.path.splitext(self.file_name)[0]
        else:
            mod_hash = hashlib.sha256()
            mod_hash.update(data)
            mod_hash = mod_hash.hexdigest()
            self.mod_name = mod_hash
            self.file_name = f"{self.mod_name}.exe"
        self.bin_base_name = os.path.basename(self.file_name)

    def emulate_module(self, path):
        """
        Load and emulate binary from the given path
        """
        mod = self.load_module(path)
        self.run_module(mod)

    def load_shellcode(self, path, arch, data=None):
        """
        Load position independent code (i.e. shellcode) to prepare for emulation
        """
        sc_hash = None
        self._init_name(path, data)
        if arch == 'x86':
            arch = _arch.ARCH_X86
        elif arch in ('x64', 'amd64'):
            arch = _arch.ARCH_AMD64

        self.arch = arch

        if data:
            sc_hash = hashlib.sha256()
            sc_hash.update(data)
            sc_hash = sc_hash.hexdigest()
            sc = data
        else:
            with open(path, 'rb') as scpath:
                sc = scpath.read()

            sc_hash = hashlib.sha256()
            sc_hash.update(sc)
            sc_hash = sc_hash.hexdigest()

        if self.arch == _arch.ARCH_X86:
            disasm_mode = cs.CS_MODE_32
        elif self.arch == _arch.ARCH_AMD64:
            disasm_mode = cs.CS_MODE_64
        else:
            raise Win32EmuError('Unsupported architecture: %s' % self.arch)

        self.emu_eng.init_engine(_arch.ARCH_X86, self.arch)


        if not self.disasm_eng:
            self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, disasm_mode)

        sc_tag = 'emu.shellcode.%s' % (sc_hash)

        # Map the shellcode into memory
        sc_addr = self.mem_map(len(sc), tag=sc_tag)
        self.mem_write(sc_addr, sc)

        self.pic_buffers.append((path, sc_addr, len(sc)))

        sc_arch = 'unknown'
        if arch == _arch.ARCH_AMD64:
            sc_arch = 'x64'
        elif arch == _arch.ARCH_X86:
            sc_arch = 'x86'

        if self.profiler:
            self.input = {'path': path, 'sha256': sc_hash, 'size': len(sc),
                          'arch': sc_arch, 'mem_tag': sc_tag,
                          'emu_version': self.get_emu_version(),
                          'os_run': self.get_osver_string()}
            self.profiler.add_input_metadata(self.input)
            # Strings the initial buffer so that we can detect decoded strings later on
            if self.do_strings:
                self.profiler.strings['ansi'] = [a[1] for a in self.get_ansi_strings(sc)]
                self.profiler.strings['unicode'] = [u[1] for u in self.get_unicode_strings(sc)]
        self.setup()

        return sc_addr

    def run_shellcode(self, sc_addr, offset=0):
        """
        Begin emulating position independent code (i.e. shellcode) to prepare for emulation
        """

        target = None
        for sc_path, _sc_addr, size in self.pic_buffers:
            if _sc_addr == sc_addr:
                target = _sc_addr
                break

        if not target:
            raise Win32EmuError('Invalid shellcode address')

        stack_commit = 0x4000

        self.stack_base, stack_addr = self.alloc_stack(stack_commit)
        self.set_func_args(self.stack_base, self.return_hook, 0x7000)

        run = Run()
        run.type = 'shellcode'
        run.start_addr = sc_addr + offset
        run.instr_cnt = 0
        args = [self.mem_map(1024, tag='emu.shellcode_arg_%d' % (i), base=0x41420000 + i)
                for i in range(4)]
        run.args = (args)

        self.reg_write(_arch.X86_REG_ECX, 1024)

        self.add_run(run)

        # Create an empty process object for the shellcode if none is
        # supplied
        container = self.init_container_process()
        if container:
            self.processes.append(container)
            self.curr_process = container
        else:
            p = objman.Process(self)
            self.processes.append(p)
            self.curr_process = p

        mm = self.get_address_map(sc_addr)
        if mm:
            mm.set_process(self.curr_process)

        t = objman.Thread(self,
                          stack_base=self.stack_base, stack_commit=stack_commit)
        self.om.objects.update({t.address: t})
        self.curr_process.threads.append(t)

        self.curr_thread = t

        peb = self.alloc_peb(self.curr_process)

        # Set the TEB
        self.init_teb(t, peb)

        self.start()

    def alloc_peb(self, proc):
        """
        Allocate memory for the Process Environment Block (PEB)
        """
        if proc.is_peb_active:
            return
        size = proc.get_peb_ldr().sizeof()
        res, size = self.get_valid_ranges(size)
        self.mem_reserve(size, base=res, tag='emu.struct.PEB_LDR_DATA')
        proc.set_peb_ldr_address(res)

        peb = proc.get_peb()
        proc.is_peb_active = True
        peb.object.ImageBaseAddress = proc.base
        peb.object.OSMajorVersion = self.osversion['major']
        peb.object.OSMinorVersion = self.osversion['minor']
        peb.object.OSBuildNumber = self.osversion['build']
        peb.write_back()
        return peb

    def set_unhandled_exception_handler(self, handler_addr):
        """
        Establish a handler for unhandled exceptions that occur during emulation
        """
        self.unhandled_exception_filter = handler_addr

    def setup(self, stack_commit=0, first_time_setup=True):
        if first_time_setup:
            # Set the emulator to run in protected mode
            self.om = objman.ObjectManager(emu=self)

        arch = self.get_arch()
        self._setup_gdt(arch)
        self.setup_user_shared_data()
        self.set_ptr_size(self.arch)

        if arch == _arch.ARCH_X86:
            self.peb_addr = self.fs_addr + 0x30
        elif arch == _arch.ARCH_AMD64:
            self.peb_addr = self.gs_addr + 0x60

        self.api = WindowsApi(self)

        # Init symlinks
        for sl in self.symlinks:
            self.om.add_symlink(sl['name'], sl['target'])

        self.init_sys_modules(self.config_system_modules)

    def init_sys_modules(self, modules_config):
        """
        Get the system modules (e.g. drivers) that are loaded in the emulator
        """
        sys_mods = []

        for modconf in modules_config:

            mod = w32common.DecoyModule()
            mod.name = modconf['name']
            base = modconf.get('base_addr')
            if isinstance(base, str):
                base = int(base, 16)

            mod.decoy_base = base
            mod.decoy_path = modconf['path']

            drv = modconf.get('driver')
            if drv:
                devs = drv.get('devices')
                for dev in devs:
                    name = dev.get('name', '')
                    do = self.new_object(objman.Device)
                    do.name = name

            sys_mods.append(mod)
        return sys_mods

    def init_container_process(self):
        """
        Create a process to be used to host shellcode or DLLs
        """
        for p in self.config_processes:
            if p.get('is_main_exe'):
                name = p.get('name', '')
                emu_path = p.get('path', '')
                base = p.get('base_addr', 0)
                if isinstance(base, str):
                    base = int(base, 0)
                cmd_line = p.get('command_line', '')

                proc = objman.Process(self, name=name,
                                      path=emu_path, base=base, cmdline=cmd_line)
                return proc
        return None

    def get_user_modules(self):
        """
        Get the user modules (e.g. dlls) that are loaded in the emulator
        """
        # Generate the decoy user module list
        if len(self.user_modules) < 2:
            # Check if we have a host process configured
            proc_mod = None
            for p in self.config_processes:

                if not self.user_modules and p.get('is_main_exe'):
                    proc_mod = p
                    break

            if proc_mod:
                all_user_mods = [proc_mod] + self.config_user_modules
                user_modules = self.init_user_modules(all_user_mods)
            else:
                user_modules = self.init_user_modules(self.config_user_modules)

            self.user_modules += user_modules
            # add sample to user modules list if it is a dll
            if self.modules and not self.modules[0][0].is_exe():
                self.user_modules.append(self.modules[0][0])

        return self.user_modules

    def exit_process(self):
        """
        An emulated binary is attempted to terminate its current process.
        Signal that the run has finished.
        """
        self.enable_code_hook()
        self.run_complete = True

    def _hook_mem_unmapped(self, emu, access, address, size, value, user_data):

        _access = self.emu_eng.mem_access.get(access)

        if _access == common.INVALID_MEM_READ:
            p = self.get_current_process()
            pld = p.get_peb_ldr()
            if address > pld.address and address < (pld.address + pld.sizeof()):
                self.mem_map_reserve(pld.address)
                user_mods = self.get_user_modules()
                self.init_peb(user_mods)
                return True
        return super(Win32Emulator, self)._hook_mem_unmapped(emu, access, address, size,
                                                             value, user_data)

    def set_hooks(self):
        """Set the emulator callbacks"""

        super(Win32Emulator, self).set_hooks()

        if not self.builtin_hooks_set:
            self.add_mem_invalid_hook(cb=self._hook_mem_unmapped)
            self.add_interrupt_hook(cb=self._hook_interrupt)
            self.builtin_hooks_set = True

        self.set_mem_tracing_hooks()

    def stop(self):
        self.run_complete = True
        # self._unset_emu_hooks()
        # self.unset_hooks()
        super(Win32Emulator, self).stop()

    def on_emu_complete(self):
        """
        Called when all runs have completed emulation
        """
        if not self.emu_complete:
            self.emu_complete = True
            if self.do_strings and self.profiler:
                dec_ansi, dec_unicode = self.get_mem_strings()
                dec_ansi = [a[1] for a in dec_ansi if a not in self.profiler.strings['ansi']]
                dec_unicode = [u[1] for u in dec_unicode
                               if u not in self.profiler.strings['unicode']]
                self.profiler.decoded_strings['ansi'] = dec_ansi
                self.profiler.decoded_strings['unicode'] = dec_unicode
        self.stop()

    def on_run_complete(self):
        """
        Clean up after a run completes. This function will pop the
        next run from the run queue and emulate it.
        """
        self.run_complete = True
        self.curr_run.ret_val = self.get_return_val()
        if self.profiler:
            self.profiler.log_dropped_files(self.curr_run, self.get_dropped_files())

        return self._exec_next_run()

    def heap_alloc(self, size, heap='None'):
        """
        Allocate a memory chunk and add it to the "heap"
        """
        addr = self.mem_map(size, base=None, tag='api.heap.%s' % (heap))
        self.heap_allocs.append((addr, size, heap))
        return addr
