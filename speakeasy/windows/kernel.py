# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import hashlib
import ntpath
import os

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
from speakeasy import common
from speakeasy.errors import KernelEmuError
from speakeasy.profiler import Run
from speakeasy.report import EntryPointType
from speakeasy.windows import objman
from speakeasy.windows.handles import HandleTable
from speakeasy.windows.loaders import PeLoader, RuntimeModule
from speakeasy.windows.winemu import MAX_EXPORTS_TO_EMULATE, WindowsEmulator
from speakeasy.winenv.defs.enums import REG_VALUE_TYPE
from speakeasy.winenv.defs.nt import ddk


class WinKernelEmulator(WindowsEmulator):
    """Emulate a Windows driver in kernel mode."""

    ssdt_ptr: int

    def __init__(self, config, *, debug=False, exit_event=None, gdb_port=None, gdb_host=None):
        super().__init__(config, debug=debug, exit_event=exit_event, gdb_port=gdb_port, gdb_host=gdb_host)

        self.drivers: list[objman.Driver] = []
        self.pool_allocs: list[tuple[int, int, int, str]] = []
        self.all_entrypoints: bool = False
        self.is_kernel_mode: bool = True
        self.irql: int = ddk.PASSIVE_LEVEL
        self.delayed_runs: list[Run] = []
        self.ktypes = ntos

    def get_system_process(self):
        """Get the process object for the system process (PID 4)."""
        for proc in self.processes:
            if proc.pid == 4:
                return proc

    def get_current_irql(self):
        """Get the current interrupt request level."""
        return self.irql

    def set_current_irql(self, irql):
        """Set the current interrupt request level."""
        self.irql = irql

    def create_driver_object(self, pe, name=None):
        """Create a driver object for a loaded driver image."""
        drv = objman.Driver(emu=self)
        drv.init_driver_object(name, pe)

        self.add_object(drv)

        self.drivers.append(drv)
        return drv

    def init_machine_structures(self):
        self.om = objman.ObjectManager(emu=self)
        self.init_processes(self.config.processes)
        self._setup_gdt(self.get_arch())
        self.init_sys_modules(self.config.modules.system_modules)
        self.setup_kernel_mode()
        self.setup_user_shared_data()

    def load_module(self, path=None, data=None, filename=None) -> RuntimeModule:
        if filename:
            file_name = ntpath.basename(filename)
            mod_name = os.path.splitext(file_name)[0]
            if not data:
                assert path is not None
                with open(path, "rb") as f:
                    data = f.read()
        elif not data:
            assert path is not None
            file_name = os.path.basename(path)
            mod_name = os.path.splitext(file_name)[0]
            with open(path, "rb") as f:
                data = f.read()
        else:
            mod_name = hashlib.sha256(data).hexdigest()
            file_name = f"{mod_name}.sys"

        self._set_input_metadata(path, data)

        emu_path = f"{self.get_system_root()}drivers\\{file_name}"

        image = PeLoader(path=path, data=data).make_image()
        image.name = mod_name
        image.emu_path = emu_path

        rtmod = self.load_image(image, is_input=True)

        if self.input is not None:
            self.input["image_base"] = rtmod.base

        return rtmod

    def pool_alloc(self, pooltype, size, tag="None"):
        """Map a pool allocation in the System process, and tag it with the pool type and ``tag``."""
        if pooltype == ddk.POOL_TYPE.NonPagedPool:
            pt = "NonPagedPool"
        elif pooltype == ddk.POOL_TYPE.PagedPool:
            pt = "PagedPool"
        elif pooltype == ddk.POOL_TYPE.NonPagedPoolNx:
            pt = "NonPagedPoolNx"
        else:
            pt = "unk"

        system_proc = self.get_system_process()

        addr = self.mem_map(size, base=None, tag=f"api.pool.{pt}.{tag}", process=system_proc)
        self.pool_allocs.append((addr, pooltype, size, tag))
        return addr

    def init_sys_modules(self, modules_config):
        sysmods = super().init_sys_modules(modules_config)

        for mc in modules_config:
            drv = mc.driver
            if drv:
                mod = [m for m in sysmods if m.name == mc.name]
                if not mod:
                    continue
                mod = mod[0]
                driver = self.create_driver_object(name=drv.name, pe=mod)
                for dev in drv.devices:
                    self.create_device_object(dev.name, driver, 0, 0, 0)

        return sysmods

    def init_processes(self, processes):
        for proc in processes:
            p = objman.Process(self)
            self.add_object(p)
            p.name = proc.name
            p.pid = proc.pid

            if p.name.lower() == "system":
                p.pid = 4
                p.path = "System"

            if not p.pid:
                p.pid = self.get_object_manager("process id allocation").new_id()
            p.base = proc.base_addr
            if not p.path:
                p.path = proc.path
            p.image = ntpath.basename(p.path)

            t = objman.Thread(self)
            self.add_object(t)
            t.process = p
            p.threads.append(t)
            self.processes.append(p)

        # The System process is the current process at start.
        sp = [p for p in self.processes if p.name.lower() == "system"]
        if sp:
            sp = sp[0]
            self.set_current_process(sp)

    def alloc_peb(self, proc):
        """Map the loader data of the PEB of a process if it is not mapped, and return the PEB."""
        ldr = proc.peb_ldr_data
        if not ldr.address:
            size = ldr.sizeof()
            res, size = self.get_valid_ranges(size)
            base = self.mem_map(size, base=res, tag="emu.struct.PEB_LDR_DATA")
            proc.set_peb_ldr_address(base)
        return proc.peb

    def get_process_peb(self, process):
        """Get the PEB of a process, with the loaded modules in its loader lists."""
        self.alloc_peb(process)
        process.init_peb(self.get_peb_modules())
        return process.peb

    def set_current_process(self, process):
        """Set the current process."""
        self.curr_process = process

    def get_current_process(self):
        """Get the current process."""
        self.get_object_manager("kernel current-process resolution")
        return self.curr_process

    def get_handle_table(self) -> HandleTable:
        """Get the handle table of the emulator. The kernel emulator keeps all handles in one table."""
        return self.handles

    def _get_process_state(self) -> WindowsEmulator:
        """
        Get the emulator for the state that each process has.

        A driver runs in the context of any process, and KeStackAttachProcess changes the current process. The
        function tables, heap blocks, current directory and environment of the kernel do not change with it.
        """
        return self

    def run_module(self, module, *, all_entrypoints=False, entry_point=None) -> None:
        """
        Add a DriverEntry run for a loaded driver, and run the queue.

        If ``all_entrypoints`` is true, the emulator also runs the exports, the IRP handlers and the unload
        routine of the driver.
        """
        self.all_entrypoints = all_entrypoints

        # Create the service key for the driver
        drv = self.create_driver_object(pe=module)
        svc_key = self.regman.create_key(drv.reg_path)
        svc_key.create_value("ImagePath", REG_VALUE_TYPE.REG_EXPAND_SZ, module.emu_path)
        svc_key.create_value("Type", REG_VALUE_TYPE.REG_DWORD, 0x1)  # SERVICE_KERNEL_DRIVER
        svc_key.create_value("Start", REG_VALUE_TYPE.REG_DWORD, 0x3)  # SERVICE_DEMAND_START
        svc_key.create_value("ErrorControl", REG_VALUE_TYPE.REG_DWORD, 0x1)  # SERVICE_ERROR_NORMAL

        self.regman.create_key(drv.reg_path + "\\Parameters")

        if entry_point is not None:
            ep = module.base + entry_point
        else:
            ep = module.get_ep()

        if entry_point is not None or module.ep > 0:
            run = Run()
            run.type = EntryPointType.DRIVER_ENTRY
            run.start_addr = ep
            run.instr_cnt = 0
            run.args = [drv.address, drv.reg_path_ptr]
            self.add_run(run)

        if self.all_entrypoints:
            # Limit the number of export runs, because some modules, such as the Windows kernel, have
            # thousands of exports.
            exports = [k for k in module.get_exports()[:MAX_EXPORTS_TO_EMULATE]]

            if exports:
                args = [self.mem_map(8, tag=f"emu.export_arg_{i}") for i in range(4)]
                for exp in exports:
                    run = Run()
                    run.type = EntryPointType.EXPORT
                    run.name = exp.name or None
                    run.start_addr = exp.address
                    # Each export gets the same placeholder arguments.
                    run.args = args
                    # The export runs wait in delayed_runs until the run queue is empty after DriverEntry,
                    # because an export can depend on the state that DriverEntry sets up.
                    self.delayed_runs.append(run)

        self.start()

    def create_device_object(self, name="", drv=0, ext_size=0, devtype=0, chars=0, tag=""):
        """Create a device object and add it to the device list of ``drv``."""
        dev = objman.Device(self)

        alloc_size = ext_size + dev.sizeof()

        if not name:
            devname = rf"\Device\{dev.id:x}"
            if not tag:
                tag = "emu.device.autogen"
            name = f"{tag}.{devname}"
        else:
            devname = name
            if not tag:
                tag = "emu.object"
            name = f"{tag}.{devname}"

        dev.address = self.mem_map(alloc_size, tag=name)
        dev.name = devname

        # Create a FILE_OBJECT for the device
        fobj = objman.FileObject(self)
        dev.object.DeviceObject = dev.address
        dev.file_object = fobj

        self.add_object(dev)

        if drv:
            drv.read_back()
            dev.object.DriverObject = drv.address
            dev.driver = drv

            if not drv.object.DeviceObject:
                drv.object.DeviceObject = dev.address
                drv.write_back()
            else:
                next_dev = self.get_object_from_addr(drv.object.DeviceObject)
                while next_dev:
                    if next_dev.object.NextDevice:
                        next_dev = self.get_object_from_addr(next_dev.object.NextDevice)
                    else:
                        next_dev.object.NextDevice = dev.address
                        next_dev.write_back()
                        break

            drv.devices.append(dev)

        dev.object.Characteristics = chars
        dev.object.DeviceType = devtype
        if ext_size > 0:
            dev.object.DeviceExtension = dev.address + dev.sizeof()

        dev.write_back()

        return dev

    def add_symlink(self, symlink, devname):
        """Add a symlink for a device."""
        self.get_object_manager("symlink creation").add_symlink(symlink, devname)

    def _call_driver_dispatch(self, func, dev_addr, irp_addr):
        """Set the arguments and the pc for a call to a dispatch function with an IRP."""
        stk_ptr = self.get_stack_ptr()
        self.set_func_args(stk_ptr, self.return_hook, dev_addr, irp_addr, conv=_arch.CALL_CONV_STDCALL)
        self.set_pc(func)

    def new_irp(self):
        """Create a new IRP."""
        return objman.Irp(emu=self)

    def irp_mj_create(self, func, dev):
        irp = self.new_irp()

        self._call_driver_dispatch(func, dev.address, irp.address)
        return irp

    def irp_mj_close(self, func, dev):
        irp = self.new_irp()
        self._call_driver_dispatch(func, dev.address, irp.address)
        return irp

    def irp_mj_dev_io(self, func, dev):
        irp = self.new_irp()

        ios = irp.get_curr_stack_loc()
        ios.object.MajorFunction = ddk.IRP_MJ_DEVICE_CONTROL
        ios.object.Parameters.DeviceIoControl.IoControlCode = 0x5D5D5D5D

        ios.write_back()
        irp.write_back()

        self._call_driver_dispatch(func, dev.address, irp.address)
        return irp

    def irp_mj_read(self, func, dev):
        irp = self.new_irp()

        self._call_driver_dispatch(func, dev.address, irp.address)
        return irp

    def irp_mj_write(self, func, dev):
        irp = self.new_irp()

        self._call_driver_dispatch(func, dev.address, irp.address)
        return irp

    def irp_mj_cleanup(self, func, dev):
        irp = self.new_irp()

        self._call_driver_dispatch(func, dev.address, irp.address)
        return irp

    def driver_unload(self, drv):
        """Add a run for the unload routine of a driver. If there is none, or it ran, end the emulation."""
        if not drv.on_unload or drv.unload_called:
            self.on_emu_complete()
            return

        stk_ptr = self.get_stack_ptr()
        self.set_func_args(stk_ptr, self.exit_hook, drv.address, conv=_arch.CALL_CONV_STDCALL)
        self.set_pc(drv.on_unload)

        run = Run()
        run.type = EntryPointType.DRIVER_UNLOAD
        run.start_addr = drv.on_unload
        run.instr_cnt = 0
        run.args = (drv.address,)
        run.return_value = None
        self.add_run(run)
        drv.unload_called = True

    def next_driver_func(self, drv):
        func_addr = None
        func_handler = None

        if self.curr_run is not None and self.curr_run.type is not None:
            self.curr_run.return_value = self.get_return_val()

        if len(self.run_queue):
            return

        if not self.all_entrypoints:
            return

        # TODO: send the IRPs to each device, not only the first device.
        dev = None
        if len(drv.devices):
            dev = drv.devices[0]

        # Find the first IRP major function that has no run yet.
        for hdlr, major, irp_name in (
            (self.irp_mj_create, ddk.IRP_MJ_CREATE, "IRP_MJ_CREATE"),
            (self.irp_mj_dev_io, ddk.IRP_MJ_DEVICE_CONTROL, "IRP_MJ_DEVICE_CONTROL"),
            (self.irp_mj_read, ddk.IRP_MJ_READ, "IRP_MJ_READ"),
            (self.irp_mj_write, ddk.IRP_MJ_WRITE, "IRP_MJ_WRITE"),
            (self.irp_mj_close, ddk.IRP_MJ_CLOSE, "IRP_MJ_CLOSE"),
            (self.irp_mj_cleanup, ddk.IRP_MJ_CLEANUP, "IRP_MJ_CLEANUP"),
        ):
            if not any(r.type == EntryPointType.IRP and r.name == irp_name for r in self.runs):
                func_handler = hdlr
                func_addr = int(drv.mj_funcs[major])

                if not func_addr:
                    continue
                break

        if len(self.delayed_runs):
            [self.add_run(r) for r in self.delayed_runs]
            self.delayed_runs = []

        if not func_addr or not dev or func_handler is None:
            # No IRP handler is left, so run the unload routine.
            self.driver_unload(drv)
            return

        irp = func_handler(func_addr, dev)

        run = Run()
        run.type = EntryPointType.IRP
        run.name = irp_name
        run.start_addr = func_addr
        run.instr_cnt = 0
        run.args = (dev.address, irp.address)
        self.add_run(run)

    def on_run_complete(self):
        if self.curr_run is not None:
            self.curr_run.return_value = self.get_return_val()

        for drv in self.drivers:
            drv.read_back()
            if drv.pe == self.curr_mod:
                self.next_driver_func(drv)

        return self._prepare_next_run()

    def on_emu_complete(self):
        if not self.is_emu_complete:
            self.is_emu_complete = True

            if self.config.analysis.strings and self.profiler:
                dec_ansi, dec_unicode = self.get_mem_strings()
                static_ansi = set(self.profiler.strings["ansi"])
                static_unicode = set(self.profiler.strings["unicode"])
                dec_ansi = list(dict.fromkeys(s for _, s in dec_ansi if s not in static_ansi))
                dec_unicode = list(dict.fromkeys(s for _, s in dec_unicode if s not in static_unicode))
                self.profiler.decoded_strings["ansi"] = dec_ansi
                self.profiler.decoded_strings["unicode"] = dec_unicode
        self.stop()

    def set_hooks(self):
        """Add the hooks of the kernel emulator, then the tracing, coverage and debug hooks."""
        super().set_hooks()

        if not self.has_builtin_hooks:
            self.add_mem_invalid_hook(cb=self._hook_mem_unmapped)
            self.add_interrupt_hook(cb=self._hook_interrupt)
            self.add_invalid_instruction_hook(cb=self._hook_invalid_instruction)
            self.has_builtin_hooks = True

        self.set_mem_tracing_hooks()
        self.set_coverage_hooks()
        self.set_debug_hooks()

    def get_kernel_base(self):
        """Get the base address of the kernel image (ntoskrnl.exe)."""
        kern = self.get_kernel_mod()
        return kern.base

    def get_kernel_mod(self):
        """
        Get the module of the kernel image.

        Raises:
            KernelEmuError: if ``ntoskrnl`` is not loaded.
        """
        mod = self.get_mod_by_name("ntoskrnl")
        if mod:
            return mod
        raise KernelEmuError("Failed to get kernel base")

    def get_ssdt_ptr(self):
        return self.ssdt_ptr

    def setup_kernel_mode(self):
        idt = objman.IDT(self)
        idt.init_descriptors()

        # Unicorn takes the IDTR as (selector, base, limit, flags).
        self.reg_write(_arch.X86_REG_IDTR, (0, idt.object.Descriptors, idt.object.Limit, 0))

        # Set up the SSDT.
        ssdt = self.ktypes.SSDT(self.get_ptr_size())
        size = self.get_ptr_size() * 256

        self.ssdt_ptr = self.get_proc("ntoskrnl", "KeServiceDescriptorTable")
        ssdt.NumberOfServices = 256
        ssdt.pServiceTable = self.mem_map(size, base=None, tag="api.struct.SSDT.services")
        self.mem_write(self.ssdt_ptr, self.get_bytes(ssdt))

        self.setup_msrs()

        for sl in self.config.symlinks:
            self.get_object_manager("symlink creation").add_symlink(sl.name, sl.target)

    def setup_msrs(self):
        """On x64, map a ``KiSystemCall64`` stub next to the kernel and point the LSTAR MSR to it."""
        km = self.get_kernel_mod()

        if self.get_arch() == _arch.ARCH_AMD64 and km.image_size > 0:
            sdt_entry = km.get_export_by_name("KeServiceDescriptorTable")
            sdt_addr = sdt_entry.address if sdt_entry else None
            if sdt_addr:
                for i in range(0x20):
                    self.symbols.update({sdt_addr + i: (km.get_base_name(), "KeServiceDescriptorTable")})
                self.symbols.update({sdt_addr: (km.get_base_name(), "KeServiceDescriptorTable.pServiceTable")})
                self.symbols.update(
                    {sdt_addr + 0x10: (km.get_base_name(), "KeServiceDescriptorTable.NumberOfServices")}
                )

                # Map the compatibility stub next to the kernel image so that its
                # 32-bit relative offsets reach the SSDT.
                ksc64_addr = self.mem_map(
                    self.page_size,
                    base=km.base + km.image_size,
                    perms=common.PERM_MEM_RX,
                    tag="emu.KiSystemCall64",
                )
                self.symbols.update({ksc64_addr: (km.get_base_name(), "KiSystemCall64")})
                self.reg_write(_arch.X86_REG_MSR, (_arch.LSTAR, ksc64_addr))
                sdt_offset = sdt_addr - ksc64_addr - 7
                data = b"\x90\x90\xc3" + sdt_offset.to_bytes(4, "little", signed=True)
                second_offset = sdt_addr - ksc64_addr - 14
                data += b"\x90\x90\xc3" + second_offset.to_bytes(4, "little", signed=True)
                data += b"\x90\x90\x90\x90\x90\x90\xc3"
                self.mem_write(ksc64_addr, data)
