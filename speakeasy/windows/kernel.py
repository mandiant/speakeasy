# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import ntpath
import hashlib

from speakeasy.profiler import Run
from speakeasy.windows.winemu import WindowsEmulator
from speakeasy.windows.ioman import IoManager

import speakeasy.winenv.arch as _arch
import speakeasy.windows.common as w32common
import speakeasy.windows.objman as objman

from speakeasy.winenv.api.winapi import WindowsApi

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.registry.reg as regdefs

from speakeasy.errors import KernelEmuError

import speakeasy.winenv.defs.nt.ntoskrnl as ntos

import capstone as cs

EP_DRIVER_ENTRY = ddk.IRP_MJ_MAXIMUM_FUNCTION
EP_DRIVER_UNLOAD = ddk.IRP_MJ_MAXIMUM_FUNCTION + 1

MAX_EXPORTS_TO_EMULATE = 10

SYSTEM_TIME_START = 131911108955110000


class WinKernelEmulator(WindowsEmulator, IoManager):
    """
    Class used to emulate Windows drivers
    """
    def __init__(self, config, debug=False, logger=None, exit_event=None):
        super(WinKernelEmulator, self).__init__(config, debug=debug, logger=logger,
                                                exit_event=exit_event)

        self.disasm_eng = None
        self.curr_mod = None
        self.debug = debug
        self.drivers = []
        self.pool_allocs = []
        self.all_entrypoints = False
        self.kernel_mode = True
        self.irql = ddk.PASSIVE_LEVEL
        self.delayed_runs = []
        self.system_time = SYSTEM_TIME_START
        self.ktypes = ntos

    def get_system_time(self):
        return self.system_time

    def get_system_process(self):
        """
        Get the process object for the system process (PID 4)
        """
        for proc in self.processes:
            if proc.get_pid() == 4:
                return proc

    def get_current_irql(self):
        """
        Get the current interrupt request level
        """
        return self.irql

    def set_current_irql(self, irql):
        """
        Set the current interrupt request level
        """
        self.irql = irql

    def create_driver_object(self, name=None, pe=None):
        """
        Create a driver object for the driver that is going to be emulated
        """

        drv = objman.Driver(emu=self)

        # If no PE was supplied, assign a dummy driver
        if not pe:
            # Get the path for the dummy driver
            default_path = self.get_native_module_path('default_sys')

            pe = w32common.DecoyModule(path=default_path)
            if name:
                bn = ntpath.basename(name)
            else:
                bn = 'none'
            pe.decoy_path = ('%sdrivers\\%s.sys' %
                             (self.get_system_root(), os.path.basename(bn)))
            pe.decoy_base = pe.get_base()

        else:
            if not name:
                bn = pe.path
                path = '%sdrivers\\%s' % (self.get_system_root(),
                                          os.path.basename(bn))
                pe.decoy_path = path
                pe.decoy_base = pe.base

        drv.init_driver_object(name, pe, is_decoy=False)

        self.add_object(drv)

        self.drivers.append(drv)
        return drv

    def load_module(self, path=None, data=None):
        """
        Load the kernel module to be emulated
        """
        pe = self.load_pe(path, data=data, imp_id=w32common.IMPORT_HOOK_ADDR)

        if pe.arch == _arch.ARCH_X86:
            disasm_mode = cs.CS_MODE_32
        elif pe.arch == _arch.ARCH_AMD64:
            disasm_mode = cs.CS_MODE_64
        else:
            raise KernelEmuError('Unsupported architecture: %s', pe.arch)

        if not self.arch:
            self.arch = pe.arch
            self.set_ptr_size(self.arch)

        self.emu_eng.init_engine(_arch.ARCH_X86, pe.arch)

        if not self.disasm_eng:
            self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, disasm_mode)

        self.api = WindowsApi(self)

        self.om = objman.ObjectManager(emu=self)

        if not data:
            file_name = os.path.basename(path)
            mod_name = os.path.splitext(file_name)[0]
        else:
            drv_hash = hashlib.sha256()
            drv_hash.update(data)
            drv_hash = drv_hash.hexdigest()
            mod_name = drv_hash
            file_name = '%s.sys' % (mod_name)
        emu_path = '%sdrivers\\%s' % (self.get_system_root(), file_name)
        pe.emu_path = emu_path
        self.map_pe(pe, mod_name=mod_name, emu_path=emu_path)
        self.mem_write(pe.base, pe.mapped_image)

        # Strings the initial buffer so that we can detect decoded strings later on
        if self.profiler and self.do_strings:

            astrs = [a[1] for a in self.get_ansi_strings(pe.mapped_image)]
            wstrs = [u[1] for u in self.get_unicode_strings(pe.mapped_image)]

            for s in astrs:
                if s not in self.profiler.strings['ansi']:
                    self.profiler.strings['ansi'].append(s)

            for s in wstrs:
                if s not in self.profiler.strings['unicode']:
                    self.profiler.strings['unicode'].append(s)

        # Set the emulator to run in protected mode
        self._setup_gdt(self.get_arch())

        self.setup_kernel_mode()

        self.setup_user_shared_data()

        if not self.stack_base:
            self.stack_base, stack_ptr = self.alloc_stack(pe.stack_commit)

        # Init imported data
        for addr, imp in pe.imports.items():
            mn, fn = imp
            mod, eh = self.api.get_data_export_handler(mn, fn)
            if eh:
                data_ptr = self.handle_import_data(mn, fn)
                sym = "%s.%s" % (mn, fn)
                self.global_data.update({addr: [sym, data_ptr]})
                self.mem_write(addr,
                               data_ptr.to_bytes(self.get_ptr_size(),
                                                 'little'))

        return pe

    def pool_alloc(self, pooltype, size, tag='None'):
        """
        Allocate memory in the emulated "pool"
        """

        if pooltype == ddk.POOL_TYPE.NonPagedPool:
            pt = 'NonPagedPool'
        elif pooltype == ddk.POOL_TYPE.PagedPool:
            pt = 'PagedPool'
        elif pooltype == ddk.POOL_TYPE.NonPagedPoolNx:
            pt = 'NonPagedPoolNx'
        else:
            pt = 'unk'

        system_proc = self.get_system_process()

        addr = self.mem_map(size, base=None, tag='api.pool.%s.%s' % (pt, tag), process=system_proc)
        self.pool_allocs.append((addr, pooltype, size, tag))
        return addr

    def init_sys_modules(self, modules_config):
        """
        Initialize kernel mode modules that may be accessed by emulated modules
        """
        sysmods = super(WinKernelEmulator, self).init_sys_modules(modules_config)

        # Initalize any DRIVER_OBJECTs needed by the module
        for mc in modules_config:
            drv = mc.get('driver')
            if drv:
                mod = [m for m in sysmods if m.name == mc.get('name')]
                if not mod:
                    continue

                mod = mod[0]

                driver = self.create_driver_object(name=drv.get('name'),
                                                   pe=mod)
                devs = drv.get('devices')
                for dev in devs:
                    name = dev.get('name', '')
                    ext_size = dev.get('ext_size', 0)
                    devtype = dev.get('devtype', 0)
                    chars = dev.get('chars', 0)
                    self.create_device_object(name, driver, ext_size,
                                              devtype, chars)

        for m in self.modules:
            mod = m[0]
            sysmods.append(mod)

        return sysmods

    def get_processes(self):
        """
        Get processes that exist in the emulation space
        """
        if not self.processes:
            self.init_processes(self.config_processes)
        return self.processes

    def init_processes(self, processes):
        for proc in processes:
            p = objman.Process(self)
            self.add_object(p)
            p.name = proc.get('name', '')
            p.pid = proc.get('pid')

            if p.name.lower() == 'system':
                p.pid = 4
                p.path = 'System'

            if not p.pid:
                p.pid = self.om.new_id()
            base = proc.get('base_addr')

            if isinstance(base, str):
                base = int(base, 16)
            p.base = base
            if not p.path:
                p.path = proc.get('path')
            p.image = ntpath.basename(p.path)

            # Create an initial thread for each process
            t = objman.Thread(self)
            self.add_object(t)
            t.process = p
            p.threads.append(t)
            self.processes.append(p)

        # The SYSTEM process should be the starting context
        sp = [p for p in self.processes if p.name.lower() == 'system']
        if sp:
            sp = sp[0]
            self.set_current_process(sp)

    def alloc_peb(self, proc):
        """
        Allocate PEB and related substructures for a given process
        """
        ldr = proc.get_peb_ldr()
        if not ldr.address:
            size = ldr.sizeof()
            res, size = self.get_valid_ranges(size)
            base = self.mem_map(size, base=res, tag='emu.struct.PEB_LDR_DATA')
            proc.set_peb_ldr_address(base)
        return proc.get_peb()

    def get_process_peb(self, process):
        """
        Retrieve the PEB for the supplied process
        """
        self.alloc_peb(process)
        user_mods = self.get_user_modules()
        process.init_peb(user_mods)
        return process.peb

    def set_current_process(self, process):
        """
        Set the current process context
        """
        self.curr_process = process

    def get_current_process(self):
        """
        Get the current process context
        """
        if not self.processes:
            self.processes = self.get_processes()
        return self.curr_process

    def run_module(self, module, all_entrypoints=False):
        """
        Begin emulation fo a previously loaded kernel module
        """

        self.all_entrypoints = all_entrypoints

        # Create the service key for the driver
        drv = self.create_driver_object(pe=module)
        svc_key = self.regman.create_key(drv.get_reg_path())
        # Create the values for the service key
        svc_key.create_value('ImagePath', regdefs.REG_EXPAND_SZ, module.get_emu_path())
        svc_key.create_value('Type', regdefs.REG_DWORD, 0x1)  # SERVICE_KERNEL_DRIVER
        svc_key.create_value('Start', regdefs.REG_DWORD, 0x3)  # SERVICE_DEMAND_START
        svc_key.create_value('ErrorControl', regdefs.REG_DWORD, 0x1)  # SERVICE_ERROR_NORMAL

        # Create the parameters subkey
        self.regman.create_key(drv.get_reg_path() + '\\Parameters')

        if module.ep > 0:

            ep = module.base + module.ep

            run = Run()
            run.type = EP_DRIVER_ENTRY
            run.start_addr = ep
            run.instr_cnt = 0
            run.args = [drv.address, drv.reg_path_ptr]
            self.add_run(run)

        if self.all_entrypoints:
            # Only emulate a subset of all the exported functions
            # There are some modules (such as the windows kernel) with thousands of exports
            exports = [k for k in module.get_exports()[: MAX_EXPORTS_TO_EMULATE]]

            if exports:
                args = [self.mem_map(8, tag='emu.export_arg_%d' % (i)) for i in range(4)]
                for exp in exports:
                    run = Run()
                    if exp.name:
                        fn = exp.name
                    else:
                        fn = 'no_name'
                    run.type = 'export.%s' % (fn)
                    run.start_addr = exp.address
                    # Here we set dummy args to pass into the export function
                    run.args = args
                    # Store these runs and only queue them before the unload routine
                    # this is because some exports may not be ready to be called yet
                    self.delayed_runs.append(run)

        self.start()

    def create_device_object(self, name='', drv=0, ext_size=0,
                             devtype=0, chars=0, tag=''):
        """
        Create a device object to use for kernel emulation
        """
        dev = objman.Device(self)

        alloc_size = ext_size + dev.sizeof()

        if not name:
            devname = r'\Device\%x' % (dev.get_id())
            if not tag:
                tag = 'emu.device.autogen'
            name = '%s.%s' % (tag, devname)
        else:
            devname = name
            if not tag:
                tag = 'emu.object'
            name = '%s.%s' % (tag, devname)

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
                        next_dev = \
                            self.get_object_from_addr(drv.object.NextDevice)
                    else:
                        # This is the last in the list, add our new device
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
        """
        Add a symlink for a device
        """
        self.om.add_symlink(symlink, devname)

    def _call_driver_dispatch(self, func, dev_addr, irp_addr):
        """
        Call a WDM driver dispatch function with a supplied IRP
        """
        stk_ptr = self.get_stack_ptr()
        self.set_func_args(stk_ptr, self.return_hook, dev_addr, irp_addr)
        self.set_pc(func)

    def new_irp(self):
        """
        Create a new IRP
        """
        return objman.Irp(emu=self)

    def irp_mj_create(self, func, dev):

        # Generate an IRP for the create request
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
        ios.object.Parameters.DeviceIoControl.IoControlCode = 0x5d5d5d5d

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
        """
        Call the unload routine for a driver
        """

        if not drv.on_unload or drv.unload_called:
            self.on_emu_complete()
            return

        stk_ptr = self.get_stack_ptr()
        self.set_func_args(stk_ptr, self.exit_hook, drv.address)
        self.set_pc(drv.on_unload)

        run = Run()
        run.type = EP_DRIVER_UNLOAD
        run.start_addr = drv.on_unload
        run.instr_cnt = 0
        run.args = (drv.address,)
        run.ret_val = None
        self.add_run(run)
        drv.unload_called = True

    def next_driver_func(self, drv):

        func_addr = None
        func_handler = None

        if self.curr_run.type is not None:
            self.curr_run.ret_val = self.get_return_val()

        # Check if theres anything in the run queue
        if len(self.run_queue):
            return

        if not self.all_entrypoints:
            return

        # TODO right now just use the first device object that was created
        dev = None
        if len(drv.devices):
            dev = drv.devices[0]

        # Run any remaining IRP handlers
        for hdlr, i in ((self.irp_mj_create, ddk.IRP_MJ_CREATE),
                        (self.irp_mj_dev_io, ddk.IRP_MJ_DEVICE_CONTROL),
                        (self.irp_mj_read, ddk.IRP_MJ_READ),
                        (self.irp_mj_write, ddk.IRP_MJ_WRITE),
                        (self.irp_mj_close, ddk.IRP_MJ_CLOSE),
                        (self.irp_mj_cleanup, ddk.IRP_MJ_CLEANUP)
                        ):

            # Did we run this mj func yet?
            if i not in [r.type for r in self.runs]:
                func_handler = hdlr
                func_addr = int(drv.mj_funcs[i])

                if not func_addr:
                    continue
                break

        if len(self.delayed_runs):
            [self.add_run(r) for r in self.delayed_runs]
            self.delayed_runs = []

        if not func_addr or not dev:
            # We are done here, call the unload routine
            self.driver_unload(drv)
            return

        irp = func_handler(func_addr, dev)

        run = Run()
        run.type = i
        run.start_addr = func_addr
        run.instr_cnt = 0
        run.args = (dev.address, irp.address)
        self.add_run(run)

    def on_run_complete(self):

        self.curr_run.ret_val = self.get_return_val()

        for drv in self.drivers:
            drv.read_back()
            if drv.pe == self.curr_mod:
                self.next_driver_func(drv)

        # Dispatch the next run
        return self._exec_next_run()

    def on_emu_complete(self):
        if not self.emu_complete:
            self.emu_complete = True

            if self.do_strings and self.profiler:
                dec_ansi, dec_unicode = self.get_mem_strings()
                dec_ansi = [a for a in dec_ansi if a not in self.profiler.strings['ansi']]
                dec_unicode = [u for u in dec_unicode if u not in self.profiler.strings['unicode']]
                self.profiler.decoded_strings['ansi'] = dec_ansi
                self.profiler.decoded_strings['unicode'] = dec_unicode
        self.stop()

    def set_hooks(self):
        """Set the emulator callbacks"""

        super(WinKernelEmulator, self).set_hooks()

        if not self.builtin_hooks_set:
            self.add_mem_invalid_hook(cb=self._hook_mem_unmapped)
            self.add_interrupt_hook(cb=self._hook_interrupt)
            self.builtin_hooks_set = True

        self.set_mem_tracing_hooks()

    def get_kernel_base(self):
        """
        Get the base address of the kernel image (ntoskrnl.exe)
        """
        # Get kernel base address
        kern = self.get_kernel_mod()
        return kern.get_base()

    def get_kernel_mod(self):
        """
        Get the kernel image module
        """
        sys_mods = self.get_sys_modules()
        for mod in sys_mods:
            if mod.name.lower() == 'ntoskrnl':
                return mod
        raise KernelEmuError('Failed to get kernel base')

    def _set_entry_point_names(self):
        run_types = {ddk.IRP_MJ_CREATE: 'irp_mj_create',
                     ddk.IRP_MJ_DEVICE_CONTROL: 'irp_mj_device_control',
                     ddk.IRP_MJ_READ: 'irp_mj_read',
                     ddk.IRP_MJ_WRITE: 'irp_mj_write',
                     ddk.IRP_MJ_CLOSE: 'irp_mj_close',
                     ddk.IRP_MJ_CLEANUP: 'irp_mj_cleanup',
                     EP_DRIVER_ENTRY: 'entry_point',
                     EP_DRIVER_UNLOAD: 'driver_unload'}
        for r in self.runs:
            if not r.type or run_types.get(r.type):
                r.type = run_types.get(r.type, 'unk')

    def get_report(self):
        """ Retrieve the execution profile for the emulator """
        self._set_entry_point_names()
        return super(WinKernelEmulator, self).get_report()

    def get_json_report(self):
        self._set_entry_point_names()
        return super(WinKernelEmulator, self).get_json_report()

    def get_ssdt_ptr(self):
        return self.ssdt_ptr

    def setup_kernel_mode(self):

        idt = objman.IDT(self)
        idt.init_descriptors()

        # selector, base, limit, flags
        self.reg_write(_arch.X86_REG_IDTR,
                       (0, idt.object.Descriptors, idt.object.Limit, 0))

        # Setup the SSDT
        ssdt = self.ktypes.SSDT(self.get_ptr_size())
        size = self.get_ptr_size() * 256

        self.ssdt_ptr = self.mem_map(size, base=None, tag='api.struct.SSDT')
        ssdt.NumberOfServices = 256
        ssdt.pServiceTable = self.ssdt_ptr + self.sizeof(ssdt)
        self.mem_write(self.ssdt_ptr, self.get_bytes(ssdt))

        self.get_sys_modules()

        self.setup_msrs()

        for sl in self.symlinks:
            self.om.add_symlink(sl['name'], sl['target'])

    def setup_msrs(self):
        """
        Setup machine specific registers for kernel emulation
        """
        # Initalize the LSTAR on amd64 with the address of KiSystemCall64
        km = self.get_kernel_mod()

        if self.get_arch() == _arch.ARCH_AMD64:
            ksc64_off = km.find_bytes(b'\x00' * 100, 0)
            if ksc64_off != -1:
                self.map_decoy(km)
                sdt = km.get_export_by_name('KeServiceDescriptorTable')
                if sdt:
                    kbase = km.get_base()
                    sdt_addr = kbase + sdt
                    # Set the symbols up
                    for i in range(0x20):
                        self.symbols.update({sdt_addr + i:
                                            (km.get_base_name(), 'KeServiceDescriptorTable')})
                    self.symbols.update({sdt_addr:
                                        (km.get_base_name(),
                                         'KeServiceDescriptorTable.pServiceTable')})
                    self.symbols.update({sdt_addr + 0x10:
                                        (km.get_base_name(),
                                         'KeServiceDescriptorTable.NumberOfServices')})
                    ksc64_off += 5

                    ksc64_addr = kbase + ksc64_off
                    self.symbols.update({ksc64_addr:
                                        (km.get_base_name(), 'KiSystemCall64')})

                    # Write the address of our fake KiSystemCall64 to the LSTAR register
                    self.reg_write(_arch.X86_REG_MSR, (_arch.LSTAR, ksc64_addr))
                    # ssdt load:
                    # KeServiceDescriptorTable
                    sdt_offset = (sdt_addr - ksc64_addr) - 7
                    data = b'\x90\x90\xc3' + sdt_offset.to_bytes(4, 'little')
                    self.mem_write(kbase+ksc64_off, data)
                    ksc64_off += 7
                    # shadow_ssdt_load:
                    # KeServiceDescriptorTableShadow
                    sdt_offset = sdt_addr - (kbase + ksc64_off)
                    data = b'\x90\x90\xc3' + sdt_offset.to_bytes(4, 'little')
                    km.set_bytes(ksc64_off, data)
                    ksc64_off += 7
                    data = b'\x90\x90\x90\x90\x90\x90\xc3'
                    km.set_bytes(ksc64_off, data)
