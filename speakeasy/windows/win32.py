# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
import hashlib
import ntpath
import os
import shlex
import zlib

import speakeasy.common as common
import speakeasy.windows.common as w32common
import speakeasy.windows.objman as objman
import speakeasy.winenv.arch as _arch
from speakeasy.errors import Win32EmuError
from speakeasy.profiler import Run
from speakeasy.windows.com import COM
from speakeasy.windows.loaders import (
    PeLoader,
    RuntimeModule,
)
from speakeasy.windows.sessman import SessionManager
from speakeasy.windows.winemu import WindowsEmulator
from speakeasy.winenv.api.winapi import WindowsApi

DLL_PROCESS_DETACH = 0
DLL_PROCESS_ATTACH = 1

MAX_EXPORTS_TO_EMULATE = 10


class Win32Emulator(WindowsEmulator):
    """
    User Mode Windows Emulator Class
    """

    def __init__(self, config, argv=[], debug=False, exit_event=None, gdb_port=None):
        super().__init__(config, debug=debug, exit_event=exit_event, gdb_port=gdb_port)

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
        argv0 = ""
        out = []

        if len(self.argv):
            for m in self.modules:
                if isinstance(m, RuntimeModule) and m.is_exe():
                    argv0 = m.get_emu_path()
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
        if handler not in self.veh_handlers:
            self.veh_handlers.append(handler)

    def remove_vectored_exception_handler(self, handler):
        """
        Remove a vectored exception handler
        """
        if handler in self.veh_handlers:
            self.veh_handlers.remove(handler)

    def get_processes(self):
        if len(self.processes) <= 1:
            self.init_processes(self.config.processes)
        return self.processes

    def init_processes(self, processes):
        """
        Initialize configured processes set in the emulator config
        """
        for proc in processes:
            p = objman.Process(self)
            self.add_object(p)

            p.name = proc.name
            if proc.pid is not None:
                p.pid = proc.pid

            base = proc.base_addr
            if isinstance(base, str):
                base = int(base, 16)
            p.base = base
            p.path = proc.path
            p.session = proc.session or 0
            p.image = ntpath.basename(p.path)

            self.processes.append(p)

    def load_module(self, path=None, data=None):
        self._init_name(path, data)

        if not data:
            assert path is not None
            with open(path, "rb") as f:
                data = f.read()

        emu_path = self._make_emu_path(path, data)
        self.fileman.add_existing_file(emu_path, data)

        self._set_input_metadata(path, data)

        loader = PeLoader(path=path, data=data)
        image = loader.make_image()
        image.name = self.mod_name
        image.emu_path = emu_path

        rtmod = self.load_image(image)
        self.set_func_args(self.stack_base, self.return_hook)

        return rtmod

    def _make_emu_path(self, path, data):
        cd = self.get_cd()
        if not cd.endswith("\\"):
            cd += "\\"
        return cd + os.path.basename(self.file_name)

    def _set_input_metadata(self, path, data):
        if not self.profiler:
            return
        from speakeasy.windows.common import _PeParser

        pe = _PeParser(path=path, data=data, fast_load=True)
        pe_type = "unknown"
        if pe.is_driver():
            pe_type = "driver"
        elif pe.is_dll():
            pe_type = "dll"
        elif pe.is_exe():
            pe_type = "exe"
        arch = "unknown"
        if pe.arch == _arch.ARCH_AMD64:
            arch = "x64"
        elif pe.arch == _arch.ARCH_X86:
            arch = "x86"
        self.input = {
            "path": pe.path,
            "sha256": pe.hash,
            "size": pe.file_size,
            "arch": arch,
            "filetype": pe_type,
            "emu_version": self.get_emu_version(),
            "os_run": self.get_osver_string(),
        }
        self.profiler.add_input_metadata(self.input)

    def prepare_module_for_emulation(self, module, all_entrypoints):
        if not module:
            self.stop()
            raise Win32EmuError("Module not found")

        # Check if any TLS callbacks exist, these run before the module's entry point
        tls = module.get_tls_callbacks()
        for i, cb_addr in enumerate(tls):
            base = module.get_base()
            if base < cb_addr < base + module.get_image_size():
                run = Run()
                run.start_addr = cb_addr
                run.type = f"tls_callback_{i}"
                run.args = [base, DLL_PROCESS_ATTACH, 0]
                self.add_run(run)

        ep = module.base + module.ep

        run = Run()
        run.start_addr = ep

        if not module.is_exe():
            run.args = [module.base, DLL_PROCESS_ATTACH, 0]
            run.type = "dll_entry.DLL_PROCESS_ATTACH"
            container = self.init_container_process()
            if container:
                self.processes.append(container)
                self.curr_process = container
        else:
            run.type = "module_entry"
            run.args = [self.mem_map(8, tag=f"emu.module_arg_{i}") for i in range(4)]

        self.add_run(run)

        if all_entrypoints:
            # Only emulate a subset of all the exported functions
            # There are some modules (such as the windows kernel) with
            # thousands of exports
            exports = [k for k in module.get_exports()[:MAX_EXPORTS_TO_EMULATE]]

            if exports:
                args = [self.mem_map(8, tag="emu.export_arg_%d" % (i), base=0x41420000) for i in range(4)]  # noqa
                for exp in exports:
                    if exp.name in ("DllMain",):
                        continue
                    run = Run()
                    if exp.name:
                        fn = exp.name
                    else:
                        fn = "no_name"

                    run.type = f"export.{fn}"
                    run.start_addr = exp.address
                    if exp.name == "ServiceMain":
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
                        svc_name = "IPRIP\x00".encode("utf-16le")
                        argc = 1
                        argv = self.mem_map(len(svc_name) + 0x10, tag="emu.export_ServiceMain_argv", base=0x41420000)

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
            pe_obj = getattr(module, "_pe", module)
            p = objman.Process(self, path=module.get_emu_path(), base=module.base, pe=pe_obj, cmdline=self.command_line)
            self.curr_process = p
            self.om.objects.update({p.address: p})  # type: ignore[union-attr]
            mm = self.get_address_map(module.base)
            if mm:
                mm.process = self.curr_process

        t = objman.Thread(self, stack_base=self.stack_base, stack_commit=module.stack_commit)

        self.om.objects.update({t.address: t})  # type: ignore[union-attr]
        self.curr_process.threads.append(t)  # type: ignore[union-attr]
        self.curr_thread = t

        if self.run_queue:
            self.run_queue[0].thread = t

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

            child.pe = self.load_module(data=child.pe_data)
            self.prepare_module_for_emulation(child.pe, all_entrypoints)

            self.command_line = child.cmdline

            self.curr_process = child
            self.curr_process.base = child.pe.base
            self.curr_thread = child.threads[0]

            self.om.objects.update({self.curr_thread.address: self.curr_thread})  # type: ignore[union-attr]

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
            mod_hash = mod_hash.hexdigest()  # type: ignore[assignment]
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
        from speakeasy.windows.loaders import ShellcodeLoader

        self._init_name(path, data)
        if arch == "x86":
            arch = _arch.ARCH_X86
        elif arch in ("x64", "amd64"):
            arch = _arch.ARCH_AMD64

        if data is None:
            with open(path, "rb") as f:
                data = f.read()

        sc_hash = hashlib.sha256(data).hexdigest()

        loader = ShellcodeLoader(data=data, arch=arch)
        image = loader.make_image()
        image.name = str(sc_hash)
        rtmod = self.load_image(image)
        sc_addr = rtmod.get_base()

        sc_arch = "unknown"
        if arch == _arch.ARCH_AMD64:
            sc_arch = "x64"
        elif arch == _arch.ARCH_X86:
            sc_arch = "x86"

        sc_tag = f"emu.shellcode.{sc_hash}"
        if self.profiler:
            self.input = {
                "path": path,
                "sha256": sc_hash,
                "size": len(data),
                "arch": sc_arch,
                "mem_tag": sc_tag,
                "emu_version": self.get_emu_version(),
                "os_run": self.get_osver_string(),
            }
            self.profiler.add_input_metadata(self.input)

        return sc_addr

    def run_shellcode(self, sc_addr, stack_commit=0x4000, offset=0):
        """
        Begin emulating position independent code (i.e. shellcode) to prepare for emulation
        """

        target = None
        for mod in self.modules:
            if isinstance(mod, RuntimeModule) and mod.get_base() == sc_addr:
                target = sc_addr
                break

        if not target:
            raise Win32EmuError("Invalid shellcode address")

        self.stack_base, stack_addr = self.alloc_stack(stack_commit)
        self.set_func_args(self.stack_base, self.return_hook, 0x7000)

        run = Run()
        run.type = "shellcode"
        run.start_addr = sc_addr + offset
        run.instr_cnt = 0
        args = [self.mem_map(1024, tag=f"emu.shellcode_arg_{i}", base=0x41420000 + i) for i in range(4)]
        run.args = args

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

        t = objman.Thread(self, stack_base=self.stack_base, stack_commit=stack_commit)
        self.om.objects.update({t.address: t})  # type: ignore[union-attr]
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
        self.mem_reserve(size, base=res, tag="emu.struct.PEB_LDR_DATA")
        proc.set_peb_ldr_address(res)

        peb = proc.get_peb()
        proc.is_peb_active = True
        peb.object.ImageBaseAddress = proc.base
        peb.object.OSMajorVersion = self.config.os_ver.major or 0
        peb.object.OSMinorVersion = self.config.os_ver.minor or 0
        peb.object.OSBuildNumber = self.config.os_ver.build or 0
        peb.write_back()

        self._ensure_core_dlls_loaded()
        self.mem_map_reserve(proc.get_peb_ldr().address)
        self.init_peb(self.get_peb_modules())

        return peb

    def _ensure_core_dlls_loaded(self):
        CORE_DLLS = ["ntdll", "kernel32", "kernelbase"]
        for dll in CORE_DLLS:
            if not self.get_mod_by_name(dll):
                self.init_module(name=dll, default_base=0x6F000000)

    def set_unhandled_exception_handler(self, handler_addr):
        """
        Establish a handler for unhandled exceptions that occur during emulation
        """
        self.unhandled_exception_filter = handler_addr

    def setup(self):
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

        for sl in self.config.symlinks:
            self.om.add_symlink(sl.name, sl.target)

        self.init_sys_modules(self.config.modules.system_modules)
        self._init_user_modules_from_config()

    def init_sys_modules(self, modules_config):
        """
        Get the system modules (e.g. drivers) that are loaded in the emulator
        """
        from speakeasy.windows.loaders import DecoyLoader, LoadedImage

        sys_mods = []

        for modconf in modules_config:
            mod = w32common.DecoyModule()
            mod.name = modconf.name
            base = modconf.base_addr
            if isinstance(base, str):
                base = int(base, 16)

            mod.decoy_base = base
            mod.decoy_path = modconf.path

            drv = modconf.driver
            if drv:
                devs = drv.devices
                for dev in devs:
                    name = dev.name or ""
                    do = self.new_object(objman.Device)
                    do.name = name

            sys_mods.append(mod)

            decoy_image = LoadedImage(
                arch=self.arch if self.arch else 0,
                module_type="decoy",
                name=modconf.name or "",
                emu_path=modconf.path or "",
                image_base=base or 0,
                image_size=0,
                regions=[],
                imports=[],
                exports=[],
                default_export_mode="intercepted",
                entry_points=[],
                visible_in_peb=True,
                loader=DecoyLoader(
                    name=modconf.name or "",
                    base=base or 0,
                    emu_path=modconf.path or "",
                    image_size=0,
                ),
            )
            rtmod = RuntimeModule(decoy_image)
            rtmod._pe = mod
            self.modules.append(rtmod)
        return sys_mods

    def init_container_process(self):
        """
        Create a process to be used to host shellcode or DLLs
        """
        for p in self.config.processes:
            if p.is_main_exe:
                name = p.name or ""
                emu_path = p.path or ""
                base = p.base_addr or 0
                if isinstance(base, str):
                    base = int(base, 0)
                cmd_line = p.command_line or ""

                proc = objman.Process(self, name=name, path=emu_path, base=base, cmdline=cmd_line)
                return proc
        return None

    def _init_user_modules_from_config(self):
        proc_mod = None
        for p in self.config.processes:
            if p.is_main_exe:
                proc_mod = p
                break

        if proc_mod:
            all_user_mods = [proc_mod] + list(self.config.modules.user_modules)
        else:
            all_user_mods = list(self.config.modules.user_modules)

        self.init_user_modules(all_user_mods)

    def exit_process(self):
        """
        An emulated binary is attempted to terminate its current process.
        Signal that the run has finished.
        """
        self.enable_code_hook()
        self.run_complete = True

    def _hook_mem_unmapped(self, emu, access, address, size, value, ctx):
        _access = self.emu_eng.mem_access.get(access)  # type: ignore[union-attr]

        if _access == common.INVALID_MEM_READ:
            p = self.get_current_process()
            pld = p.get_peb_ldr()
            if address > pld.address and address < (pld.address + pld.sizeof()):
                self.mem_map_reserve(pld.address)
                self.init_peb(self.get_peb_modules())
                return True
        return super()._hook_mem_unmapped(emu, access, address, size, value, ctx)

    def set_hooks(self):
        """Set the emulator callbacks"""

        super().set_hooks()

        if not self.builtin_hooks_set:
            self.add_mem_invalid_hook(cb=self._hook_mem_unmapped)
            self.add_interrupt_hook(cb=self._hook_interrupt)
            self.builtin_hooks_set = True

        self.set_mem_tracing_hooks()
        self.set_coverage_hooks()
        self.set_debug_hooks()

    def stop(self):
        self.run_complete = True
        # self._unset_emu_hooks()
        # self.unset_hooks()
        super().stop()

    def on_emu_complete(self):
        """
        Called when all runs have completed emulation
        """
        if not self.emu_complete:
            self.emu_complete = True
            if self.config.analysis.strings and self.profiler:
                dec_ansi, dec_unicode = self.get_mem_strings()
                dec_ansi = [a[1] for a in dec_ansi if a not in self.profiler.strings["ansi"]]
                dec_unicode = [u[1] for u in dec_unicode if u not in self.profiler.strings["unicode"]]
                self.profiler.decoded_strings["ansi"] = dec_ansi
                self.profiler.decoded_strings["unicode"] = dec_unicode
        self.stop()

    def on_run_complete(self):
        """
        Clean up after a run completes. This function will pop the
        next run from the run queue and emulate it.
        """
        self.run_complete = True
        self.curr_run.ret_val = self.get_return_val()  # type: ignore[union-attr]
        if self.profiler:
            self.profiler.record_dropped_files_event(self.curr_run, self.get_dropped_files())
            self._capture_memory_layout()

        return self._exec_next_run()

    def _capture_memory_layout(self):
        """
        Capture current memory layout and loaded modules for the run report.
        """
        EXCLUDED_TAG_PREFIXES = ("emu.stack", "api.heap", "emu.process_heap")

        prot_map = {
            common.PERM_MEM_NONE: "---",
            common.PERM_MEM_READ: "r--",
            common.PERM_MEM_WRITE: "-w-",
            common.PERM_MEM_EXEC: "--x",
            common.PERM_MEM_READ | common.PERM_MEM_WRITE: "rw-",
            common.PERM_MEM_READ | common.PERM_MEM_EXEC: "r-x",
            common.PERM_MEM_WRITE | common.PERM_MEM_EXEC: "-wx",
            common.PERM_MEM_RWX: "rwx",
        }

        capture_dumps = getattr(self.config, "capture_memory_dumps", False)

        for mm in self.get_mem_maps():
            prot = prot_map.get(mm.get_prot(), "???")
            access_stats = None
            has_writes = False
            if mm in self.curr_run.mem_access:  # type: ignore[union-attr]
                ma = self.curr_run.mem_access[mm]  # type: ignore[union-attr]
                access_stats = {"reads": ma.reads, "writes": ma.writes, "execs": ma.execs}
                has_writes = ma.writes > 0

            tag = mm.get_tag() or ""
            region_dict: dict = {
                "tag": tag,
                "address": mm.get_base(),
                "size": mm.get_size(),
                "prot": prot,
                "is_free": mm.is_free(),
                "accesses": access_stats,
            }

            if capture_dumps and has_writes and not tag.startswith(EXCLUDED_TAG_PREFIXES):
                try:
                    data = self.mem_read(mm.get_base(), mm.get_size())
                    compressed = zlib.compress(data)
                    region_dict["data"] = base64.b64encode(compressed).decode()
                except Exception:
                    pass  # Skip if mem_read fails (e.g., freed memory)

            self.curr_run.memory_regions.append(region_dict)  # type: ignore[union-attr]

        for m in self.modules:
            if m.image_size == 0:
                continue
            mod_name = ntpath.basename(m.get_emu_path()) or "unknown"
            segments = []
            pe = getattr(m, "_pe", None)
            if pe and hasattr(pe, "sections"):
                for section in pe.sections:
                    name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                    addr = section.VirtualAddress + m.base
                    size = section.Misc_VirtualSize
                    chars = section.Characteristics
                    r = chars & w32common.ImageSectionCharacteristics.IMAGE_SCN_MEM_READ
                    w = chars & w32common.ImageSectionCharacteristics.IMAGE_SCN_MEM_WRITE
                    x = chars & w32common.ImageSectionCharacteristics.IMAGE_SCN_MEM_EXECUTE
                    prot = ""
                    prot += "r" if r else "-"
                    prot += "w" if w else "-"
                    prot += "x" if x else "-"
                    segments.append({"name": name, "address": addr, "size": size, "prot": prot})
            self.curr_run.loaded_modules.append(  # type: ignore[union-attr]
                {
                    "name": mod_name,
                    "path": m.get_emu_path(),
                    "base": m.base,
                    "size": m.image_size,
                    "segments": segments,
                }
            )

    def heap_alloc(self, size, heap="None"):
        """
        Allocate a memory chunk and add it to the "heap"
        """
        addr = self.mem_map(size, base=None, tag=f"api.heap.{heap}")
        self.heap_allocs.append((addr, size, heap))
        return addr
