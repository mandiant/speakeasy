# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import ntpath

import speakeasy.winenv.defs.nt.ntoskrnl as ntoskrnl
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windef


class Console(object):
    """
    Represents a console window object
    """
    curr_handle = 0x340

    def __init__(self):
        self.handle = self.get_handle()
        self.window = 0

    def get_handle(self):
        tmp = Console.curr_handle
        Console.curr_handle += 4
        return tmp

    def set_window(self, window):
        self.window = window

    def get_window(self):
        return self.window


class SEH(object):
    """
    Implements the structures needed to support SEH handling during emulation
    """
    class ScopeRecord(object):
        def __init__(self, record):
            self.record = record
            self.filter_called = False
            self.handler_called = False

    class Frame(object):

        def __init__(self, entry, scope_table, scope_records):
            self.entry = entry
            self.scope_table = scope_table
            self.scope_records = []
            for rec in scope_records:
                SEH.ScopeRecord(rec)
                self.scope_records.append(SEH.ScopeRecord(rec))
            self.searched = False

    def __init__(self):
        self.context = None
        self.context_address = 0
        self.record = None
        self.frames = []
        self.last_func = 0
        self.last_exception_code = 0
        self.exception_ptrs = 0
        self.handler_ret_val = None

    def set_context(self, context, address=0):
        self.context = context
        self.context_address = address

    def get_context(self):
        return self.context

    def set_last_func(self, func):
        self.last_func = func

    def set_record(self, record, address=0):
        self.record = record

    def set_current_frame(self, frame):
        self.frame = frame

    def get_frames(self):
        return self.frames

    def clear_frames(self):
        self.frames = []

    def add_frame(self, entry, scope_table, records):
        frame = SEH.Frame(entry, scope_table, records)
        self.frames.append(frame)


class KernelObject(object):
    """
    Base class for Kernel objects managed by the object manager
    """
    curr_handle = 0x220
    curr_id = 0x400

    def __init__(self, emu):
        self.emu = emu
        self.address = None
        self.name = ''
        self.object = 0
        self.ref_cnt = 0
        self.handles = []
        self.arch = emu.get_arch()
        self.id = KernelObject.curr_id
        KernelObject.curr_id += 4

        self.nt_types = ntoskrnl
        self.win_types = windef

    def sizeof(self, obj=None):
        if obj:
            return obj.sizeof()
        return self.object.sizeof()

    def get_bytes(self, obj=None):
        if obj:
            return obj.get_bytes()
        return self.object.get_bytes()

    def read_back(self):
        data = self.emu.mem_read(self.address, self.sizeof())
        self.object.cast(data)
        return self

    def write_back(self):
        data = self.get_bytes()
        if data and self.address:
            self.emu.mem_write(self.address, data)

    def get_id(self):
        return self.id

    def set_id(self, oid):
        self.id = oid

    def get_class_name(self):
        if self.object:
            return self.object.__class__.__name__

    def get_mem_tag(self):
        return 'emu.struct.%s' % (self.get_class_name())

    def get_handle(self):
        tmp = KernelObject.curr_handle
        KernelObject.curr_handle += 4
        self.handles.append(tmp)
        return tmp


class Driver(KernelObject):

    """
    Class that represents DRIVER_OBJECTs created by the Windows kernel
    """

    ldr_entries = []

    def __init__(self, emu):
        super(Driver, self).__init__(emu=emu)
        self.pe = None
        self.devices = []
        self.mj_funcs = [None] * (ddk.IRP_MJ_MAXIMUM_FUNCTION + 1)
        self.on_unload = None
        self.unload_called = False
        self.reg_path_ptr = 0
        self.reg_path = ''
        self.name = ''
        self.basename = ''
        self.object = self.nt_types.DRIVER_OBJECT(emu.get_ptr_size())

    def create_reg_path(self, name):
        """
        Create the service path in the registry for the created driver
        """
        self.reg_path = '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s\x00' % (name) # noqa
        buf = self.reg_path.encode('utf-16le')
        self.reg_path = self.reg_path.strip('\x00')

        us = self.nt_types.UNICODE_STRING(self.emu.get_ptr_size())
        size = self.sizeof(us) + len(buf)
        addr = self.emu.mem_map(size, tag='emu.object.%s.reg_path' % self.name)
        us.Length = len(buf) - 2
        us.MaximumLength = len(buf)
        us.Buffer = addr + self.sizeof(us)

        self.emu.mem_write(addr, self.get_bytes(us))
        self.emu.mem_write(us.Buffer, buf)

        self.reg_path_ptr = addr

    def get_basename(self):
        return self.basename.lower()

    def get_reg_path(self):
        return self.reg_path

    def init_driver_section(self):
        """
        Create the driver section for the driver. This is a linked list that
        links together driver objects
        """
        tag = 'emu.object.%s.DriverSection' % self.name
        mod = self.pe

        if mod and mod.get_emu_path():
            mod_name = mod.get_emu_path()
        else:
            mod_name = 'None'

        ldte = LdrDataTableEntry(self.emu, mod_name, tag=tag)
        first = None
        last = None
        if len(self.ldr_entries):
            first = self.ldr_entries[0]
            last = self.ldr_entries[-1]
        self.ldr_entries.append(ldte)

        ldte.object.DllBase = mod.get_base()

        dllname = mod.get_emu_path().encode('utf-16le')
        name_addr = ldte.address + ldte.sizeof()
        self.emu.mem_write(name_addr, dllname)

        # Set the dll full name
        ldte.object.FullDllName.Length = len(dllname)
        ldte.object.FullDllName.MaximumLength = len(dllname)
        ldte.object.FullDllName.Buffer = name_addr

        # Set the dll base name
        dllname = ntpath.basename(mod.get_emu_path()).encode('utf-16le')
        ldte.object.BaseDllName.Length = len(dllname)
        ldte.object.BaseDllName.MaximumLength = len(dllname)
        ldte.object.BaseDllName.Buffer = name_addr + \
            (ldte.object.FullDllName.Length - len(dllname))

        if not last:
            ldte.object.InLoadOrderLinks.Flink = ldte.address
            ldte.object.InLoadOrderLinks.Flink = ldte.address
            ldte.object.InLoadOrderLinks.Blink = ldte.address
            ldte.object.InMemoryOrderLinks.Blink = ldte.address
        else:
            ldte.object.InLoadOrderLinks.Flink = \
                last.object.InLoadOrderLinks.Flink
            ldte.object.InMemoryOrderLinks.Flink = \
                last.object.InMemoryOrderLinks.Flink
            ldte.object.InLoadOrderLinks.Blink = last.address
            ldte.object.InMemoryOrderLinks.Blink = last.address

            last.object.InLoadOrderLinks.Flink = ldte.address
            last.object.InMemoryOrderLinks.Flink = ldte.address
            first.object.InLoadOrderLinks.Blink = ldte.address
            first.object.InMemoryOrderLinks.Blink = ldte.address

            last.write_back()
        ldte.write_back()
        return ldte

    def init_driver_object(self, name=None, pe=None, is_decoy=True):
        """
        Initialize the DRIVER_OBJECT
        """
        self.pe = pe
        drvobj = self.object

        drvobj.Type = 4
        drvobj.Size = self.sizeof()
        drvobj.DeviceObject = 0
        drvobj.Flags = 2
        us = ''
        if pe:
            drvobj.DriverStart = pe.get_base()
            drvobj.DriverSize = pe.image_size
            drvobj.DriverInit = pe.get_base() + pe.ep

            if is_decoy:
                ep = pe.get_base() + pe.ep
                drvobj.MajorFunction[ddk.IRP_MJ_CREATE] = ep + 1
                drvobj.MajorFunction[ddk.IRP_MJ_READ] = ep + 2
                drvobj.MajorFunction[ddk.IRP_MJ_WRITE] = ep + 3
                drvobj.MajorFunction[ddk.IRP_MJ_DEVICE_CONTROL] = ep + 4
                drvobj.MajorFunction[ddk.IRP_MJ_PNP] = ep + 5
                drvobj.MajorFunction[ddk.IRP_MJ_INTERNAL_DEVICE_CONTROL] = ep+6

            if not name:
                drvname = os.path.splitext(pe.path)[0]
                drvname = os.path.basename(drvname)
                self.name = r'\Driver\%s' % (drvname)
                us = ('\\Driver\\%s\x00' % (drvname)).encode('utf-16le')
                name = self.name

        if name:
            us = name.encode('utf-16le')
            self.name = name

        if not pe and not self.name:
            name = 'none'

        # Allocate the driver object
        addr = self.emu.mem_map(drvobj.Size + len(us),
                                tag='emu.object.%s' % name)

        drvobj.DriverName.Length = len(us)
        drvobj.DriverName.MaximumLength = len(us)
        drvobj.DriverName.Buffer = addr + drvobj.Size

        name = self.name
        idx = name.rfind('\\')
        if idx >= 0 and idx != len(name) - 1:
            name = self.name[idx+1:]
        else:
            name = 'None'

        self.basename = name
        self.create_reg_path(name)

        drv_sect = self.init_driver_section()
        drvobj.DriverSection = drv_sect.address

        self.address = addr
        self.emu.mem_write(addr, self.get_bytes() + us)

    def read_back(self):
        super(Driver, self).read_back()

        for i, func in enumerate(self.mj_funcs):
            self.mj_funcs[i] = self.object.MajorFunction[i]

        self.on_unload = self.object.DriverUnload


class Device(KernelObject):
    """
    Represents a DEVICE_OBJECT created by the windows kernel
    """

    def __init__(self, emu):
        super(Device, self).__init__(emu=emu)
        devobj = self.nt_types.DEVICE_OBJECT(emu.get_ptr_size())

        devobj.Type = 0x3
        devobj.Size = self.sizeof(devobj)
        devobj.ReferenceCount = 1

        self.file_object = None
        self.object = devobj
        self.driver = None

    def get_parent_driver(self):
        return self.driver


class FileObject(KernelObject):
    """
    Represents a FILE_OBJECT created by the windows kernel
    """
    def __init__(self, emu):
        super(FileObject, self).__init__(emu=emu)
        fileobj = self.nt_types.FILE_OBJECT(emu.get_ptr_size())

        fileobj.Type = 0x5
        fileobj.Size = self.sizeof(fileobj)
        self.object = fileobj
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class IoStackLocation(KernelObject):
    """
    Represents a IO_STACK_LOCATION struct that is part of
    an IRP.
    """
    def __init__(self, emu):
        super(IoStackLocation, self).__init__(emu=emu)

        self.object = self.nt_types.IO_STACK_LOCATION(emu.get_ptr_size())
        # Allocate two stack locations for now to handle IoGetNextIrpStackLocation calls
        self.address = emu.mem_map(self.sizeof() * 2, tag=self.get_mem_tag())


class Irp(KernelObject):
    """
    I/O request packet used when performing device input/output
    """
    def __init__(self, emu):
        super(Irp, self).__init__(emu=emu)
        self.object = self.nt_types.IRP(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())
        self.stack_locations = []

        ios = IoStackLocation(emu=emu)
        ios.write_back()

        self.object.Tail.Overlay.CurrentStackLocation = ios.address + ios.sizeof()

        self.stack_locations.append(ios)

        self.object.Type = 0x6
        self.object.Size = self.sizeof()
        self.write_back()

    def get_curr_stack_loc(self):
        return self.stack_locations[0]


class Thread(KernelObject):
    """
    Represents a Windows ETHREAD object that describes a
    an OS level thread
    """
    def __init__(self, emu, stack_base=0, stack_commit=0):
        super(Thread, self).__init__(emu=emu)
        self.emu = emu
        self.object = self.nt_types.ETHREAD(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())
        self.object.Data = b'\xFF' * self.sizeof()
        self.tid = self.get_id()
        self.modified_pc = False
        self.teb = None
        self.seh = SEH()
        self.tls = []
        self.message_queue = []
        self.ctx = self.emu.get_thread_context()
        self.fls = []
        self.suspend_count = 0
        self.token = Token(self.emu)
        self.last_error = 0
        self.stack_base = stack_base
        self.stack_commit = stack_commit

        self.write_back()
        self.process = None

    def queue_message(self, msg):
        """
        Add a GUI message to the thread's message queue
        """
        self.message_queue.append(msg)

    def get_seh(self):
        return self.seh

    def get_context(self):
        if self.ctx:
            return self.ctx
        return self.emu.get_thread_context()

    def set_context(self, ctx):
        if self.ctx:
            if self.emu.get_arch() == _arch.ARCH_X86:
                if ctx.Eip != self.ctx.Eip:
                    self.modified_pc = True
        self.ctx = ctx

    def init_teb(self, teb_addr, peb_addr):
        if not self.teb:
            self.teb = TEB(emu=self.emu, address=teb_addr)

        self.teb.object.NtTib.StackBase = self.stack_base
        self.teb.object.NtTib.Self = teb_addr
        self.teb.object.NtTib.StackLimit = self.stack_commit
        self.teb.object.ProcessEnvironmentBlock = peb_addr
        self.teb.write_back()

    def get_teb(self):
        return self.teb.read_back()

    def set_last_error(self, code):
        self.last_error = code

    def get_last_error(self):
        return self.last_error

    def get_tls(self):
        return self.tls

    def set_tls(self, tls):
        self.tls = tls

    def get_fls(self):
        return self.fls

    def set_fls(self, fls):
        self.fls = fls

    def get_token(self):
        return self.token

    def init_tls(self, tls_dir, modname):
        ptrsz = self.emu.get_ptr_size()

        tls_dirp = self.emu.mem_map(ptrsz, tag='emu.tls.%s' % (modname))

        self.emu.mem_write(tls_dirp, tls_dir)

        self.teb.object.ThreadLocalStoragePointer = tls_dirp
        self.teb.write_back()

        return

class Token(KernelObject):
    """
    Represents a TOKEN object
    """
    def __init__(self, emu):
        super(Token, self).__init__(emu=emu)


class Process(KernelObject):

    """
    An EPROCESS object used by the Windows kernel to represent a process
    """
    ldr_entries = []

    def __init__(self, emu, pe=None, user_modules=[],
                 name='', path='', cmdline='', base=0, session=0):
        super(Process, self).__init__(emu=emu)
        # TODO: For now just allocate a blank opaque struct for an EPROCESS
        self.object = self.nt_types.EPROCESS(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag(), perms=1, base=0xe0000000)
        self.name = name
        self.base = base
        self.pid = self.get_id()
        self.modules = user_modules
        self.threads = []
        self.console = None
        self.curr_thread = None
        self.cmdline = cmdline
        self.session = session
        self.token = Token(self.emu)
        emu.add_object(self.token)
        self.pe = pe
        self.pe_data = None

        self.stdin = (0xf000) + 1
        self.stdout = (0xf000) + 2
        self.stderr = (0xf000) + 3

        # Initialize the process PEB
        self.peb = PEB(emu=emu)
        self.peb_ldr_data = PebLdrData(self.emu)
        self.is_peb_active = False
        self.path = path
        self.set_process_parameters(emu)
        self.image = ''
        self.title = ''

        if pe and pe.OPTIONAL_HEADER.Subsystem & ddk.WINDOWS_CONSOLE:
            self.alloc_console()

    def get_peb(self):
        return self.peb

    def set_peb_ldr_address(self, addr):
        self.peb.object.Ldr = addr
        self.peb.write_back()
        self.peb_ldr_data.address = addr

    def set_process_parameters(self, emu):
        process_parameters = RTL_USER_PROCESS_PARAMETERS(emu=emu, proc=self)
        self.peb.object.ProcessParameters = process_parameters.address
        self.peb.write_back()

    def get_peb_ldr(self):
        return self.peb_ldr_data

    def alloc_console(self):

        if not self.console:
            self.console = Console()
        sm = self.emu.get_session_manager()
        desk = sm.get_current_desktop()
        self.console.set_window(desk.new_window())

    def get_desktop_name(self):
        sm = self.emu.get_session_manager()
        stat = sm.get_current_station()
        stat_name = stat.get_name()

        desk = sm.get_current_desktop()
        desk_name = desk.get_name()

        name = '%s\\%s' % (stat_name, desk_name)

        return name

    def get_token(self):
        """
        Get the token associated with the process
        """
        return self.token

    def get_std_handle(self, dev):
        STD_INPUT_HANDLE = 0xfffffff6
        STD_OUTPUT_HANDLE = 0xfffffff5
        STD_ERROR_HANDLE = 0xfffffff4

        for k, v in ((STD_INPUT_HANDLE, self.stdin),
                     (STD_OUTPUT_HANDLE, self.stdout),
                     (STD_ERROR_HANDLE, self.stderr),
                     ):

            if k == dev:
                return v
        return 0

    def get_title_name(self):
        return self.title

    def get_module(self):
        return self.pe

    def get_ep(self):
        if self.pe:
            return self.pe.get_ep()

    def get_console(self):
        return self.console

    def get_session_id(self):
        return self.session

    def get_pid(self):
        return self.pid

    def get_process_path(self):
        return self.path

    def get_command_line(self):
        return self.cmdline

    def set_user_modules(self, mods):
        self.modules = mods

    def new_thread(self):
        thr = Thread(self.emu)
        self.threads.append(thr)

    def add_module_to_peb(self, module):
        pld = self.peb_ldr_data
        list_type = self.nt_types.LIST_ENTRY(self.emu.get_ptr_size())

        # Initialize the LDTE
        ldte = LdrDataTableEntry(self.emu, module.get_emu_path())
        if not self.ldr_entries:
            prev = ldte
        else:
            prev = self.ldr_entries[-1]

        self.ldr_entries.append(ldte)
        first = self.ldr_entries[0]

        ldte.object.InLoadOrderLinks.Flink = first.address
        ldte.object.InMemoryOrderLinks.Flink = first.address + self.sizeof(list_type)
        ldte.object.InInitializationOrderLinks.Flink = first.address + self.sizeof(list_type) * 2

        ldte.object.DllBase = module.get_base()
        dllname = (module.get_emu_path() + '\x00').encode('utf-16le')
        name_addr = ldte.address + ldte.sizeof()
        self.emu.mem_write(name_addr, dllname)

        # Set the dll full name
        ldte.object.FullDllName.Length = len(dllname) - 2
        ldte.object.FullDllName.MaximumLength = len(dllname)
        ldte.object.FullDllName.Buffer = name_addr

        # Set the dll base name
        dllname = (ntpath.basename(module.get_emu_path()) +
                   '\x00').encode('utf-16le')

        ldte.object.BaseDllName.Length = len(dllname) - 2
        ldte.object.BaseDllName.MaximumLength = len(dllname)
        ldte.object.BaseDllName.Buffer = name_addr + \
            (ldte.object.FullDllName.MaximumLength - len(dllname))
        ldte.write_back()

        prev.object.InLoadOrderLinks.Flink = ldte.address
        prev.object.InMemoryOrderLinks.Flink = ldte.address + \
            self.sizeof(list_type)

        if first is ldte:
            prev.object.InInitializationOrderLinks.Flink = 0
        else:
            imol = prev.object.InMemoryOrderLinks.Flink
            prev.object.InInitializationOrderLinks.Flink = imol + \
                self.sizeof(list_type)

        ldte.object.InLoadOrderLinks.Blink = prev.address
        ldte.object.InMemoryOrderLinks.Blink = prev.address + \
            self.sizeof(list_type)

        if first is ldte:
            ldte.object.InInitializationOrderLinks.Blink = 0
        else:
            imol = ldte.object.InMemoryOrderLinks.Blink
            ldte.object.InInitializationOrderLinks.Blink = imol + \
                self.sizeof(list_type)

        prev.write_back()
        ldte.write_back()

        first.object.InLoadOrderLinks.Blink = prev.address
        first.object.InMemoryOrderLinks.Blink = prev.address
        if first is not ldte:
            first.object.InInitializationOrderLinks.Blink = prev.address

        first.write_back()

        pld.object.InLoadOrderModuleList.Flink = first.address
        pld.object.InMemoryOrderModuleList.Flink = \
            pld.object.InLoadOrderModuleList.Flink + \
            self.sizeof(list_type)

        # Lets just copy InMemoryOrderModuleList but skip the main EXE module
        head = pld.object.InMemoryOrderModuleList.Flink
        le = self.emu.mem_cast(ntoskrnl.LIST_ENTRY(self.emu.get_ptr_size()),
                               head)

        pld.object.InInitializationOrderModuleList.Flink = le.Flink + self.sizeof(list_type)

        pld.object.InLoadOrderModuleList.Blink = prev.address
        pld.object.InMemoryOrderModuleList.Blink = \
            pld.object.InLoadOrderModuleList.Blink + \
            self.sizeof(list_type)

        pld.object.InInitializationOrderModuleList.Blink = \
            pld.object.InMemoryOrderModuleList.Blink + \
            self.sizeof(list_type)

        pld.write_back()

        self.peb.object.Ldr = pld.address
        self.peb.write_back()

    def init_peb(self, modules):
        # Add an entry for each module in the module list
        for mod in modules:
            self.add_module_to_peb(mod)


class RTL_USER_PROCESS_PARAMETERS(KernelObject):
    def __init__(self, emu, proc):
        super(RTL_USER_PROCESS_PARAMETERS, self).__init__(emu=emu)

        self.object = self.nt_types.RTL_USER_PROCESS_PARAMETERS(emu.get_ptr_size())
        proc_path = (proc.path + '\x00').encode('utf-16le')
        proc_cmdline = (proc.cmdline + '\x00').encode('utf-16le')
        size = self.sizeof()
        size += len(proc_path)
        size += len(proc_cmdline)
        self.address = emu.mem_map(size,
                                   tag=proc.get_mem_tag() + '.ProcessParameters')
        emu.mem_write(self.address + self.sizeof(), proc_path)
        emu.mem_write(self.address + self.sizeof() + len(proc_path), proc_cmdline)

        self.object.ImagePathName.Length = len(proc_path) - 2
        self.object.ImagePathName.MaxLength = len(proc_path)
        self.object.ImagePathName.Buffer = self.address + self.sizeof()

        self.object.CommandLine.Length = len(proc_cmdline) - 2
        self.object.CommandLine.MaxLength = len(proc_cmdline)
        self.object.CommandLine.Buffer = self.address + self.sizeof() + len(proc_path)
        self.write_back()


class PEB(KernelObject):
    """
    Represents the process environment block. This structure contains a large amount of
    fields that are used internally by Windows. Shellcode may parse this structure in
    order to resolve exported functions.
    """
    def __init__(self, emu, address=None):
        super(PEB, self).__init__(emu=emu)

        self.object = self.nt_types.PEB(emu.get_ptr_size())
        if not address:
            self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())
        else:
            self.address = address


class TEB(KernelObject):
    """
    Represents the thread environment block. This structure contains a large amount of
    fields that are used internally by Windows.
    """
    def __init__(self, emu, address=0):
        super(TEB, self).__init__(emu=emu)

        self.object = self.nt_types.TEB(emu.get_ptr_size())
        if address:
            self.address = address
        else:
            self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class PebLdrData(KernelObject):

    def __init__(self, emu):
        super(PebLdrData, self).__init__(emu=emu)
        self.object = self.nt_types.PEB_LDR_DATA(emu.get_ptr_size())
        self.address = 0


class LdrDataTableEntry(KernelObject):
    def __init__(self, emu, dllname, tag=''):
        super(LdrDataTableEntry, self).__init__(emu=emu)
        self.object = self.nt_types.LDR_DATA_TABLE_ENTRY(emu.get_ptr_size())

        size = self.sizeof()
        size += len((dllname + '\x00').encode('utf-16le'))

        if not tag:
            tag = self.get_mem_tag()

        self.address = emu.mem_map(size, tag=tag)


class IDT(KernelObject):
    """
    Represents the Interrupt descriptor table. This is currently a dummy structure and
    only exists to detect if samples read or write to it.
    """
    def __init__(self, emu):
        super(IDT, self).__init__(emu=emu)

        self.object = self.nt_types.IDT(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())

    def init_descriptors(self):
        tbl = self.nt_types.DESCRIPTOR_TABLE(self.emu.get_ptr_size())

        kbase = self.emu.get_kernel_base()

        descs = self.emu.mem_map(self.sizeof(tbl),
                                 tag=self.get_mem_tag() + '.idt_entries')
        self.object.Limit = 0xFFF
        self.object.Descriptors = descs

        if self.emu.get_arch() == _arch.ARCH_X86:
            for i, entry in enumerate(tbl.Table):
                entry.OffsetLow = 0 + (4 * i)
                entry.Base = kbase
        elif self.emu.get_arch() == _arch.ARCH_AMD64:
            for i, entry in enumerate(tbl.Table):
                entry.OffsetLow = 0xFFFF & kbase
                entry.OffsetMiddle = (0xFFFF0000 & kbase) >> 16
                entry.OffsetHigh = (0xFFFFFFFF00000000 & kbase) >> 32

        self.emu.mem_write(descs, self.get_bytes(tbl))

        self.write_back()


class Event(KernelObject):
    """
    Describes event objects used by Windows for synchronization
    """

    def __init__(self, emu):
        super(Event, self).__init__(emu=emu)
        self.object = self.nt_types.KEVENT(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class Mutant(KernelObject):
    """
    Describes mutant objects used by Windows for synchronization
    """

    def __init__(self, emu):
        super(Mutant, self).__init__(emu=emu)
        self.object = self.nt_types.MUTANT(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class ObjectManager(object):
    """
    Class that manages kernel objects during emulation
    """
    def __init__(self, emu):
        super(ObjectManager, self).__init__()
        self.emu = emu
        self.objects = {}
        self.symlinks = []

    def add_symlink(self, link, dev):
        self.symlinks.append((link, dev))

    def new_object(self, obj_type):

        obj = obj_type(emu=self.emu)
        obj.set_id(self.new_id())
        return self.add_object(obj)

    def add_object(self, obj):
        if not self.get_object_from_addr(obj.address):
            self.objects.update({obj.address: obj})
        if not obj.id:
            obj.id = self.new_id()
        obj.ref_cnt += 1
        return obj

    def remove_object(self, obj):
        """
        Remove an object from the object manager
        """
        addr = None
        for a, o in self.objects.items():
            if o == obj:
                addr = a
                break
        if addr:
            self.objects.pop(addr)

    def dec_ref(self, obj):
        """
        Dereferece an object and remove it from the object manager when its reference count is 0
        """
        if hasattr(obj, 'ref_cnt'):
            obj.ref_cnt -= 1
            if obj.ref_cnt <= 0:
                self.remove_object(obj)
            return obj.ref_cnt

    def get_handle(self, obj):
        tmp = KernelObject.curr_handle
        KernelObject.curr_handle += 4
        obj.handles.append(tmp)
        return tmp

    def new_id(self):
        _id = KernelObject.curr_id
        KernelObject.curr_id += 4
        return _id

    def get_object_from_addr(self, addr):
        return self.objects.get(addr)

    def get_object_from_id(self, id):
        for a, o in self.objects.items():
            if o.get_id() == id:
                return o

    def get_object_from_name(self, name, check_symlinks=True):

        if not name:
            return None
        name = name.rstrip('\\')
        for a, o in self.objects.items():
            if not o.name:
                continue
            if o.name.lower() == name.lower():
                return o
        if check_symlinks:
            m = [sl[1] for sl in self.symlinks
                 if name.lower() == sl[0].lower()]
            if m:
                name = m[0]
            return self.get_object_from_name(name, False)

    def get_object_from_handle(self, handle):
        for a, o in self.objects.items():
            if handle in o.handles:
                return o
