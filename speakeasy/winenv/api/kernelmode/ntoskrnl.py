# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid
import ntpath

import lznt1

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.registry.reg as regdefs
import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
from speakeasy.const import FILE_OPEN, FILE_WRITE, FILE_READ, MEM_WRITE
from speakeasy.errors import ApiEmuError
from speakeasy.winenv.api import api


class Ntoskrnl(api.ApiHandler):
    """
    Implements functions exported by the Windows kernel. Zw*/Nt* are folded together as the same
    function since we aren't concerned with PreviousMode implications here.
    """

    name = 'ntoskrnl'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ntoskrnl, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.emu = emu

        self.win = ntos

        super(Ntoskrnl, self).__get_hook_attrs__(self)

    def get_current_irql(self):
        return self.emu.get_current_irql()

    def set_current_irql(self, irql):
        return self.emu.set_current_irql(irql)

    @impdata('IoDriverObjectType')
    def IoDriverObjectType(self, ptr=0):
        """
        Type object used for Driver objects exported by ntoskrnl
        """
        drv_type = ptr
        if not ptr:
            drv_type = self.mem_alloc(0x100,
                                      base=None, tag='api.ntoskrnl.IoDriverObjectType')
        return drv_type

    @impdata('KeTickCount')
    def KeTickCount(self, ptr=0):
        """Tick count exported by ntoskrnl"""
        ksystime = self.win.KSYSTEM_TIME(self.emu.get_ptr_size())
        kst = ptr

        if not ptr:
            kst = self.mem_alloc(self.sizeof(ksystime),
                                 base=None, tag='api.ntoskrnl.KeTickCount')
        return kst

    @impdata('KeServiceDescriptorTable')
    def KeServiceDescriptorTable(self, ptr=0):
        """Kernel table containing SSDT"""
        return self.emu.get_ssdt_ptr()

    @impdata('KdDebuggerEnabled')
    def KdDebuggerEnabled(self, ptr=0):
        if not ptr:
            return self.mem_alloc(8, base=None, tag='emu.struct.KdDebuggerEnabled')
        return ptr

    @apihook('ObfDereferenceObject', argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ObfDereferenceObject(self, emu, argv, ctx={}):
        """
        void ObfDereferenceObject(a);
        """
        Object = argv[0]

        obj = self.get_object_from_addr(Object)
        if obj:
            obj.ref_cnt -= 1

    @apihook('ZwClose', argc=1)
    def ZwClose(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS ZwClose(
        HANDLE Handle
        );
        """
        rv = ddk.STATUS_SUCCESS

        # For now, just leave the handle open so we can reference it later
        return rv

    @apihook('DbgPrint', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def DbgPrint(self, emu, argv, ctx={}):
        """
        ULONG DbgPrint(
        PCSTR Format,
        ...
        );
        """

        fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 1)[0]
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        _argv = emu.get_func_argv(_arch.CALL_CONV_CDECL, 1 + fmt_cnt)[1:]
        fin = self.do_str_format(fmt_str, _argv)
        argv.clear()
        argv.append(fin)

        return len(fin)

    @apihook('DbgPrintEx', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def DbgPrintEx(self, emu, argv, ctx={}):
        """
        NTSYSAPI ULONG DbgPrintEx(
          ULONG ComponentId,
          ULONG Level,
          PCSTR Format,
          ...
        );
        """

        cid, level, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)

        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        _argv = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]

        fin = self.do_str_format(fmt_str, _argv)

        argv.clear()
        argv.append(cid)
        argv.append(level)
        argv.append(fin)

        return len(fin)

    @apihook('_vsnprintf', argc=4, conv=_arch.CALL_CONV_CDECL)
    def _vsnprintf(self, emu, argv, ctx={}):
        """
        int _vsnprintf(
            char *buffer,
            size_t count,
            const char *format,
            va_list argptr
        );
        """
        buffer, count, _format, argptr = argv
        rv = 0

        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        fin = fin[:count] + '\x00'

        rv = len(fin)
        self.mem_write(buffer, fin.encode('utf-8'))
        argv[0] = fin.replace('\x00', '')
        argv[1] = fmt_str

        return rv

    @apihook('vsprintf_s', argc=4, conv=_arch.CALL_CONV_CDECL)
    def vsprintf_s(self, emu, argv, ctx={}):
        return self._vsnprintf(emu, argv, ctx)

    @apihook('RtlAnsiStringToUnicodeString', argc=3)
    def RtlAnsiStringToUnicodeString(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(
            PUNICODE_STRING DestinationString,
            PCANSI_STRING   SourceString,
            BOOLEAN         AllocateDestinationString
        );
        """

        dest, src, do_alloc = argv
        nts = ddk.STATUS_SUCCESS

        ansi_str = self.read_ansi_string(src)

        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        us = self.mem_cast(us, dest)

        ansi = self.win.STRING(emu.get_ptr_size())
        ansi = self.mem_cast(ansi, src)

        size = len(ansi_str) * 2

        if do_alloc:
            us.Length = size
            us.MaximumLength = size
            ptr = self.mem_alloc(size, tag='api.struct.STRING.%s' % (ansi_str))
            us.Buffer = ptr
        else:
            if us.MaximumLength < size:
                nts = ddk.STATUS_UNSUCCESSFUL

        if nts == ddk.STATUS_SUCCESS:
            us.Length = size
            us.MaximumLength = size
            self.mem_write(us.Buffer, ansi_str.encode('utf-16le'))

            data = self.get_bytes(us)
            self.mem_write(dest, data)

        argv[1] = ansi_str

        return nts

    @apihook('RtlInitAnsiString', argc=2)
    def RtlInitAnsiString(self, emu, argv, ctx={}):
        """
        NTSYSAPI VOID RtlInitAnsiString(
            PANSI_STRING DestinationString,
            PCSZ SourceString
        );
        """
        ansi = self.win.STRING(emu.get_ptr_size())

        dest, src = argv
        ansi_str = self.read_string(src)

        size = len(ansi_str)
        ansi.Length = size
        ansi.MaximumLength = size
        ansi.Buffer = src

        data = self.get_bytes(ansi)
        self.mem_write(dest, data)

        argv[1] = ansi_str

    @apihook('RtlInitUnicodeString', argc=2)
    def RtlInitUnicodeString(self, emu, argv, ctx={}):
        """
        NTSYSAPI VOID RtlInitUnicodeString(
            PUNICODE_STRING DestinationString,
            PCWSTR SourceString
            );
        """
        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        dest, src = argv
        uni_str = self.read_wide_string(src)

        size = len(uni_str) * 2
        us.Length = size
        us.MaximumLength = size
        us.Buffer = src

        data = self.get_bytes(us)
        self.mem_write(dest, data)

        argv[1] = uni_str

    @apihook('RtlFreeUnicodeString', argc=1)
    def RtlFreeUnicodeString(self, emu, argv, ctx={}):
        """
        NTSYSAPI VOID RtlFreeUnicodeString(
            PUNICODE_STRING UnicodeString
        );
        """
        UnicodeString, = argv

        us_str = self.read_unicode_string(UnicodeString)
        argv[0] = us_str

        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        us = self.mem_cast(us, UnicodeString)
        self.mem_free(us.Buffer)

    @apihook('ExAllocatePoolWithTag', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def ExAllocatePoolWithTag(self, emu, argv, ctx={}):
        """
        NTKERNELAPI PVOID ExAllocatePoolWithTag(
           POOL_TYPE PoolType,
           SIZE_T NumberOfBytes,
           ULONG Tag
        );
        """

        PoolType, NumberOfBytes, Tag = argv

        if Tag:
            try:
                Tag = Tag.to_bytes(4, 'little').decode('utf-8')
            except Exception as e:
                emu.log_exception(str(e))
            argv[2] = Tag

        chunk = self.pool_alloc(PoolType, NumberOfBytes, Tag)
        return chunk

    @apihook('ExFreePoolWithTag', argc=2)
    def ExFreePoolWithTag(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID ExFreePoolWithTag(
            PVOID P,
            ULONG Tag
            );
        """
        P, Tag = argv

        if Tag:
            try:
                Tag = Tag.to_bytes(4, 'little').decode('utf-8')
            except Exception as e:
                emu.log_exception(str(e))
            argv[1] = Tag
        self.mem_free(P)

    @apihook('ExAllocatePool', argc=2)
    def ExAllocatePool(self, emu, argv, ctx={}):
        """
        NTKERNELAPI PVOID ExAllocatePool(
            POOL_TYPE PoolType,
            SIZE_T NumberOfBytes
            );
        """
        PoolType, NumberOfBytes = argv

        chunk = self.pool_alloc(PoolType, NumberOfBytes, 'None')
        return chunk

    @apihook('ExFreePool', argc=1)
    def ExFreePool(self, emu, argv, ctx={}):
        """
        void ExFreePool(
            addr
        );
        """
        addr, = argv
        self.mem_free(addr)

    @apihook('memmove', argc=3)
    def memmove(self, emu, argv, ctx={}):
        """
        void *memmove(
            void *dest,
            const void *src,
            size_t count
        );
        """
        dest, src, count = argv

        data = self.mem_read(src, count)
        self.mem_write(dest, data)
        return dest

    @apihook('IoDeleteDriver', argc=1)
    def IoDeleteDriver(self, emu, argv, ctx={}):
        """
        VOID IoDeleteDriver(PDRIVER_OBJECT DriverObject)
        """
        drv, = argv

        return

    @apihook('IoCreateDevice', argc=7)
    def IoCreateDevice(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS IoCreateDevice(
            PDRIVER_OBJECT  DriverObject,
            ULONG           DeviceExtensionSize,
            PUNICODE_STRING DeviceName,
            DEVICE_TYPE     DeviceType,
            ULONG           DeviceCharacteristics,
            BOOLEAN         Exclusive,
            PDEVICE_OBJECT  *DeviceObject
            );
        """

        nts = ddk.STATUS_SUCCESS
        drv, ext_size, name, devtype, chars, exclusive, out_addr = argv

        if name:
            name = self.read_unicode_string(name).replace('\x00', '')

        driver_obj = self.get_object_from_addr(drv)
        if not driver_obj:
            return ddk.STATUS_INVALID_PARAMETER

        dev = emu.create_device_object(name, driver_obj, ext_size, devtype,
                                       chars, tag='api.object')

        self.mem_write(out_addr, dev.address.to_bytes(self.get_ptr_size(),
                       byteorder='little'))

        argv[2] = name
        return nts

    @apihook('IoCreateDeviceSecure', argc=9)
    def IoCreateDeviceSecure(self, emu, argv, ctx={}):
        """
        NTSTATUS IoCreateDeviceSecure(
            _In_     PDRIVER_OBJECT   DriverObject,
            _In_     ULONG            DeviceExtensionSize,
            _In_opt_ PUNICODE_STRING  DeviceName,
            _In_     DEVICE_TYPE      DeviceType,
            _In_     ULONG            DeviceCharacteristics,
            _In_     BOOLEAN          Exclusive,
            _In_     PCUNICODE_STRING DefaultSDDLString,
            _In_opt_ LPCGUID          DeviceClassGuid,
            _Out_    PDEVICE_OBJECT   *DeviceObject
        );
        """

        nts = ddk.STATUS_SUCCESS
        drv, ext_size, name, devtype, chars, exclusive, sddl, guid, out_addr = argv

        if name:
            name = self.read_unicode_string(name).replace('\x00', '')

        driver_obj = self.get_object_from_addr(drv)

        dev = emu.create_device_object(name, driver_obj, ext_size, devtype,
                                       chars, tag='api.object')

        self.mem_write(out_addr, dev.address.to_bytes(self.get_ptr_size(),
                       byteorder='little'))

        argv[2] = name
        return nts

    @apihook('IoCreateSymbolicLink', argc=2)
    def IoCreateSymbolicLink(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS IoCreateSymbolicLink(
            PUNICODE_STRING SymbolicLinkName,
            PUNICODE_STRING DeviceName
            );
        """
        SymbolicLinkName, DeviceName = argv
        link_name = \
            self.read_unicode_string(SymbolicLinkName).replace('\x00', '')
        dev_name = \
            self.read_unicode_string(DeviceName).replace('\x00', '')
        emu.add_symlink(link_name, dev_name)

        nts = ddk.STATUS_SUCCESS
        argv[0] = link_name
        argv[1] = dev_name

        return nts

    @apihook('IofCompleteRequest', argc=2, conv=_arch.CALL_CONV_FASTCALL)
    def IofCompleteRequest(self, emu, argv, ctx={}):
        """
        VOID IoCompleteRequest(
            _In_ PIRP  Irp,
            _In_ CCHAR PriorityBoost
            );
        """
        pIrp, boost = argv

        argv[1] = 0xFF & argv[1]
        return

    @apihook('IoDeleteSymbolicLink', argc=1)
    def IoDeleteSymbolicLink(self, emu, argv, ctx={}):
        """
        NTSTATUS IoDeleteSymbolicLink(
        PUNICODE_STRING SymbolicLinkName
        );
        """
        nts = ddk.STATUS_SUCCESS

        SymbolicLinkName = argv[0]
        link_name = \
            self.read_unicode_string(SymbolicLinkName).replace('\x00', '')
        argv[0] = link_name
        return nts

    @apihook('KeInitializeMutex', argc=2)
    def KeInitializeMutex(self, emu, argv, ctx={}):
        return

    @apihook('IoDeleteDevice', argc=1)
    def IoDeleteDevice(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID IoDeleteDevice(
            __drv_freesMem(Mem)PDEVICE_OBJECT DeviceObject
            );
        """
        nts = ddk.STATUS_SUCCESS
        # devobj = argv[0]

        return nts

    @apihook('MmIsAddressValid', argc=1)
    def MmIsAddressValid(self, emu, argv, ctx={}):
        """
        BOOLEAN MmIsAddressValid(
        PVOID VirtualAddress
        );
        """
        rv = 0

        addr, = argv

        rv = emu.is_address_valid(addr)
        return rv

    @apihook('ZwQuerySystemInformation', argc=4)
    def ZwQuerySystemInformation(self, emu, argv, ctx={}):
        """
        NTSTATUS WINAPI ZwQuerySystemInformation(
            _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
            _Inout_   PVOID                    SystemInformation,
            _In_      ULONG                    SystemInformationLength,
            _Out_opt_ PULONG                   ReturnLength
            );
        """
        sysclass, sysinfo, syslen, retlen = argv

        size = 0
        nts = ddk.STATUS_INFO_LENGTH_MISMATCH
        buf_ptr = 0

        if sysclass == ddk.SYSTEM_INFORMATION_CLASS.SystemModuleInformation:
            mods = emu.get_sys_modules()
            mod_count = len(mods)
            size = mod_count * self.sizeof(self.win.SYSTEM_MODULE(emu.get_ptr_size()))
            size += self.ptr_size

            if size <= syslen and syslen != 0:

                buf_ptr = sysinfo
                # Write the number of mods
                self.mem_write(buf_ptr,
                               mod_count.to_bytes(self.ptr_size, 'little'))
                buf_ptr += self.ptr_size

                for i, mod in enumerate(mods):
                    sm = self.win.SYSTEM_MODULE(emu.get_ptr_size())
                    sm.Base = mod.get_base()
                    sm.Size = mod.get_image_size()
                    sm.ImageName = b'\\??\\' + mod.get_emu_path().encode('utf-8')
                    sm.LoadCount = 1
                    sm.Index = i
                    sm.ModuleNameOffset = bytes(sm.ImageName)[:].rfind(b'\\') + 1
                    self.mem_write(buf_ptr, self.get_bytes(sm))
                    buf_ptr += self.sizeof(sm)
                nts = ddk.STATUS_SUCCESS

        elif sysclass == ddk.SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation:
            tod = self.win.SYSTEM_TIMEOFDAY_INFORMATION(emu.get_ptr_size())
            tod.BootTime = 0x100000
            tod.CurrentTime = 0x200000
            tod.TimeZoneBias = 0
            tod.TimeZoneId = 0
            tod.Reserved = 0
            tod.BootTimeBias = 0
            tod.SleepTimeBias = 0

            size = self.sizeof(tod)
            if size <= syslen and syslen != 0:
                self.mem_write(sysinfo, self.get_bytes(tod))
            nts = ddk.STATUS_SUCCESS

        elif sysclass == ddk.SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation:
            if sysinfo and syslen >= 2:
                out = b'\x00\x01'
                size = len(out)
                self.mem_write(sysinfo, out)
                nts = ddk.STATUS_SUCCESS

        elif sysclass == ddk.SYSTEM_INFORMATION_CLASS.SystemProcessInformation:
            procs = emu.get_processes()
            for proc in procs:
                threads = proc.threads
                spi = self.win.SYSTEM_PROCESS_INFORMATION(emu.get_ptr_size())
                sti = self.win.SYSTEM_THREAD_INFORMATION(emu.get_ptr_size())
                size += self.sizeof(spi)
                size += len((proc.image + '\x00').encode('utf-16le'))
                size += (len(threads) * self.sizeof(sti))

            if size <= syslen:
                buf_ptr = sysinfo

                for i, proc in enumerate(procs):
                    tis = []
                    rel_offset = 0

                    spi = self.win.SYSTEM_PROCESS_INFORMATION(emu.get_ptr_size())

                    spi.NumberOfThreads = len(proc.threads)
                    spi.UniqueProcessId = proc.get_id()
                    rel_offset += self.sizeof(spi)

                    for thread in proc.threads:
                        sti = self.win.SYSTEM_THREAD_INFORMATION(emu.get_ptr_size())
                        sti.ClientId.UniqueProcess = proc.get_id()
                        sti.ClientId.UniqueThread = thread.get_id()
                        tis.append(sti)
                        rel_offset += self.sizeof(sti)

                    # Add the string data after the SI structs
                    iname = (proc.image + '\x00').encode('utf-16le')
                    spi.ImageName.Length = len(iname)
                    spi.ImageName.MaximumLength = len(iname)
                    spi.ImageName.Buffer = buf_ptr + rel_offset

                    rel_offset += len(iname)

                    spi.NextEntryOffset = rel_offset

                    # Mark the last process
                    if i == (len(procs) - 1):
                        spi.NextEntryOffset = 0

                    data = self.get_bytes(spi)
                    data += b''.join([self.get_bytes(d) for d in tis])
                    data += iname

                    self.mem_write(buf_ptr, data)
                    buf_ptr += len(data)

                nts = ddk.STATUS_SUCCESS

        else:
            raise ApiEmuError('Unsupported information class: 0x%x'
                              % (sysclass))

        if retlen:
            self.mem_write(retlen, size.to_bytes(4, 'little'))

        return nts

    @apihook('_allshl', argc=2, conv=_arch.CALL_CONV_CDECL)
    def _allshl(self, emu, argv, ctx={}):
        """
        LONGLONG _allshl
        (
        LONGLONG a,
        LONG     b
        )
        """
        a, b = argv
        rv = 0xFFFFFFFFFFFFFFFF & a << (0xFFFFFFFF & b)

        return rv

    @apihook('wcscpy', argc=2, conv=_arch.CALL_CONV_CDECL)
    def wcscpy(self, emu, argv, ctx={}):
        """
        wchar_t *wcscpy(
                        wchar_t *strDestination,
                        const wchar_t *strSource
                        );
        """
        dest, src = argv
        ws = self.read_wide_string(src)

        self.write_wide_string(ws, dest)
        argv[1] = ws

        return len(ws)

    @apihook('wcsncpy', argc=3, conv=_arch.CALL_CONV_CDECL)
    def wcsncpy(self, emu, argv, ctx={}):
        """
        wchar_t *wcsncpy(
            wchar_t *strDest,
            const wchar_t *strSource,
            size_t count
            );
        """
        dest, src, count = argv
        ws = self.read_wide_string(src)

        self.write_wide_string(ws, dest)
        argv[1] = ws
        return len(ws)

    @apihook('RtlMoveMemory', argc=3)
    def RtlMoveMemory(self, emu, argv, ctx={}):
        """
        void RtlMoveMemory(
            void*       Destination,
            const void* Source,
            size_t      Length
        );
        """
        self.memcpy(emu, argv)

    @apihook('memcpy', argc=3, conv=_arch.CALL_CONV_CDECL)
    def memcpy(self, emu, argv, ctx={}):
        """
        void *memcpy(
            void *dest,
            const void *src,
            size_t count
            );
        """
        dest, src, count = argv

        data = self.mem_read(src, count)
        self.mem_write(dest, data)
        return dest

    @apihook('memset', argc=3, conv=_arch.CALL_CONV_CDECL)
    def memset(self, emu, argv, ctx={}):
        """
        void *memset(
            void *dest,
            int c,
            size_t count
            );
        """
        dest, c, count = argv

        data = c.to_bytes(1, 'little')
        self.mem_write(dest, data * count)
        return dest

    @apihook('sprintf', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def sprintf(self, emu, argv, ctx={}):
        """
        int sprintf(
            char *buffer,
            const char *format [,
            argument] ...
            );
        """
        buf, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        if not fmt_cnt:
            self.write_string(fmt_str, buf)
            return len(fmt_str)

        _argv = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook('_snprintf', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def _snprintf(self, emu, argv, ctx={}):
        """
        int _snprintf(
            char *buffer,
            size_t count,
            const char *format [,
            argument] ...
            );
        """
        buf, cnt, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        if not fmt_cnt:
            self.write_string(fmt_str[:cnt - 1], buf)
            return len(fmt_str)

        _argv = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook('wcslen', argc=1, conv=_arch.CALL_CONV_CDECL)
    def wcslen(self, emu, argv, ctx={}):
        """
        size_t wcslen(
            const wchar_t *str
            );
        """

        string = argv[0]
        ws = self.read_wide_string(string)
        if isinstance(ws, str):
            argv[0] = ws
            slen = len(ws)
        else:
            slen = int(len(ws) / 2)

        return slen

    @apihook('wcschr', argc=2, conv=_arch.CALL_CONV_CDECL)
    def wcschr(self, emu, argv, ctx={}):
        """
        wchar_t *wcschr(
                const wchar_t *str,
                wchar_t c
                );
        """
        wstr, c = argv
        ws = self.read_wide_string(wstr)
        hay = ws.encode('utf-16le')
        needle = c.to_bytes(2, 'little')

        offset = hay.find(needle)
        if offset < 0:
            rv = 0
        else:
            rv = wstr + offset

        argv[0] = ws
        argv[1] = needle.decode('utf-16le')

        return rv

    @apihook('wcscat', argc=2, conv=_arch.CALL_CONV_CDECL)
    def wcscat(self, emu, argv, ctx={}):
        """
        wchar_t *wcscat(
            wchar_t *strDestination,
            const wchar_t *strSource
            );
        """
        dest, src = argv
        sws = self.read_wide_string(src)
        dws = self.read_wide_string(dest)

        if dws.endswith('\x00'):
            dws = dws[:-1]
        if sws.endswith('\x00'):
            sws = sws[:-1]

        new = (dws + sws).encode('utf-16le')
        self.mem_write(dest, new)
        argv[0] = dws
        argv[1] = sws
        return dest

    @apihook('strrchr', argc=2, conv=_arch.CALL_CONV_CDECL)
    def strrchr(self, emu, argv, ctx={}):
        """
        char *strrchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        cs = self.read_string(cstr)
        hay = cs.encode('utf-8')
        needle = c.to_bytes(1, 'little')

        offset = hay.rfind(needle)
        if offset < 0:
            rv = 0
        else:
            rv = cstr + offset

        argv[0] = cs
        argv[1] = needle.decode('utf-8')

        return rv

    @apihook('strchr', argc=2, conv=_arch.CALL_CONV_CDECL)
    def strchr(self, emu, argv, ctx={}):
        """
        char *strchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        cs = self.read_string(cstr)
        hay = cs.encode('utf-8')
        needle = c.to_bytes(1, 'little')

        offset = hay.find(needle)
        if offset < 0:
            rv = 0
        else:
            rv = cstr + offset

        argv[0] = cs
        argv[1] = needle.decode('utf-8')

        return rv

    @apihook('_wcsnicmp', argc=3, conv=_arch.CALL_CONV_CDECL)
    def _wcsnicmp(self, emu, argv, ctx={}):
        """
        int _wcsnicmp(
        const wchar_t *string1,
        const wchar_t *string2,
        size_t count
        );
        """
        string1, string2, count = argv
        rv = 1

        ws1 = self.read_wide_string(string1, max_chars=count)
        ws2 = self.read_wide_string(string2, max_chars=count)

        argv[0] = ws1
        argv[1] = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    @apihook('_stricmp', argc=2, conv=_arch.CALL_CONV_CDECL)
    def _stricmp(self, emu, argv, ctx={}):
        """
        int _stricmp(
                const char *string1,
                const char *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_string(string1)
        cs2 = self.read_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook('_wcsicmp', argc=2, conv=_arch.CALL_CONV_CDECL)
    def _wcsicmp(self, emu, argv, ctx={}):
        """
        int _wcsicmp(
            const wchar_t *string1,
            const wchar_t *string2
            );
        """
        string1, string2 = argv
        rv = 1

        ws1 = self.read_wide_string(string1)
        ws2 = self.read_wide_string(string2)

        argv[0] = ws1
        argv[1] = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    @apihook('PsCreateSystemThread', argc=7)
    def PsCreateSystemThread(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS PsCreateSystemThread(
            PHANDLE            ThreadHandle,
            ULONG              DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            HANDLE             ProcessHandle,
            PCLIENT_ID         ClientId,
            PKSTART_ROUTINE    StartRoutine,
            PVOID              StartContext
            );
        """
        hThrd, access, objattr, hProc, client_id, start, startctx = argv

        rv = ddk.STATUS_SUCCESS

        cid = self.win.CLIENT_ID(emu.get_ptr_size())
        proc_obj = self.get_object_from_handle(hProc)

        handle, obj = self.create_thread(start, startctx, proc_obj,
                                         thread_type='system_thread')

        self.mem_write(hThrd, handle.to_bytes(4, 'little'))

        if client_id:
            if not hProc:
                cid.UniqueProcess = 4
            cid.UniqueThread = obj.tid
            self.mem_write(client_id, self.get_bytes(cid))

        return rv

    @apihook('RtlCopyUnicodeString', argc=2)
    def RtlCopyUnicodeString(self, emu, argv, ctx={}):
        """
        NTSYSAPI VOID RtlCopyUnicodeString(
            PUNICODE_STRING  DestinationString,
            PCUNICODE_STRING SourceString
            );
        """
        dest_str, src_str = argv

        dest = self.win.UNICODE_STRING(emu.get_ptr_size())
        dest = self.mem_cast(dest, dest_str)

        src = self.win.UNICODE_STRING(emu.get_ptr_size())
        src = self.mem_cast(src, src_str)

        if src.Buffer == 0 or dest.Buffer == 0:
            dest.Length = 0
            self.mem_write(src_str, self.get_bytes(src))
        else:

            if src.Length > dest.MaximumLength:
                to_copy = dest.MaximumLength
            else:
                to_copy = src.Length

            data = self.mem_read(src.Buffer, to_copy)
            argv[1] = data.decode('utf-16le')
            self.mem_write(dest.Buffer, data)

            self.mem_write(dest_str, self.get_bytes(dest))

        return

    @apihook('RtlEqualUnicodeString', argc=3)
    def RtlEqualUnicodeString(self, emu, argv, ctx={}):
        """
        NTSYSAPI BOOLEAN RtlEqualUnicodeString(
            PCUNICODE_STRING String1,
            PCUNICODE_STRING String2,
            BOOLEAN          CaseInSensitive
            );
        """
        str1, str2, ci = argv

        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        us = self.mem_cast(us, str1)

        s1 = self.read_unicode_string(str1).replace('\x00', '')
        s2 = self.read_unicode_string(str2).replace('\x00', '')

        if ci:
            rv = (s1.lower() == s2.lower())
        else:
            rv = (s1 == s2)

        argv[0] = s1
        argv[1] = s2
        return int(rv)

    @apihook('IoAllocateIrp', argc=2)
    def IoAllocateIrp(self, emu, argv, ctx={}):
        """
        PIRP IoAllocateIrp(
          CCHAR   StackSize,
          BOOLEAN ChargeQuota
        );
        """
        StackSize, ChargeQuota = argv

        StackSize = StackSize & 0xFF

        irp = emu.new_irp()
        rv = irp.address

        argv[0] = StackSize

        return rv

    @apihook('IoFreeIrp', argc=1)
    def IoFreeIrp(self, emu, argv, ctx={}):
        """
        void IoFreeIrp(
          PIRP Irp
        );
        """
        Irp, = argv

        return

    @apihook('IoReuseIrp', argc=2)
    def IoReuseIrp(self, emu, argv, ctx={}):
        """
        void IoReuseIrp(
          PIRP     Irp,
          NTSTATUS Iostatus
        );
        """

        Irp, Iostatus = argv
        return

    @apihook('IoAllocateMdl', argc=5)
    def IoAllocateMdl(self, emu, argv, ctx={}):
        """
        PMDL IoAllocateMdl(
          __drv_aliasesMem PVOID VirtualAddress,
          ULONG                  Length,
          BOOLEAN                SecondaryBuffer,
          BOOLEAN                ChargeQuota,
          PIRP                   Irp
        );
        """
        va, length, sec_buf, quota, irp = argv

        mdl = self.win.MDL(emu.get_ptr_size())
        size = self.sizeof(mdl)

        mdl.Size = 0x56
        mdl.Flags = 0x8
        mdl.StartVa = va & 0xFFFFFFFFFFFF000
        mdl.ByteCount = length
        mdl.ByteOffset = (va - mdl.StartVa)

        ptr = self.mem_alloc(size, tag='api.MDL.0x%x' % (va))
        self.mem_write(ptr, self.get_bytes(mdl))

        return ptr

    @apihook('MmProbeAndLockPages', argc=3)
    def MmProbeAndLockPages(self, emu, argv, ctx={}):
        """
        void MmProbeAndLockPages(
          PMDL            MemoryDescriptorList,
          KPROCESSOR_MODE AccessMode,
          LOCK_OPERATION  Operation
        );
        """
        return

    @apihook('KeDelayExecutionThread', argc=3)
    def KeDelayExecutionThread(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS KeDelayExecutionThread(
              KPROCESSOR_MODE WaitMode,
              BOOLEAN         Alertable,
              PLARGE_INTEGER  Interval
            );
        """
        mode, alert, interval = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('KeSetEvent', argc=3)
    def KeSetEvent(self, emu, argv, ctx={}):
        """
        LONG KeSetEvent(
        PRKEVENT  Event,
        KPRIORITY Increment,
        BOOLEAN   Wait
        );
        """
        Event, Increment, Wait = argv
        rv = 0

        return rv

    @apihook('IoCreateSynchronizationEvent', argc=2)
    def IoCreateSynchronizationEvent(self, emu, argv, ctx={}):
        """
        NTKERNELAPI PKEVENT IoCreateSynchronizationEvent(
            PUNICODE_STRING EventName,
            PHANDLE         EventHandle
            );
        """
        EventName, EventHandle = argv

        name = self.read_unicode_string(EventName)

        hnd, evt = emu.create_event(name)

        if EventHandle:
            self.mem_write(EventHandle, hnd.to_bytes(4, 'little'))

        argv[0] = name
        return evt.address

    @apihook('KeInitializeEvent', argc=3)
    def KeInitializeEvent(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID KeInitializeEvent(
            PRKEVENT   Event,
            EVENT_TYPE Type,
            BOOLEAN    State
            );
        """

        return

    @apihook('KeResetEvent', argc=1)
    def KeResetEvent(self, emu, argv, ctx={}):
        """
        NTKERNELAPI LONG KeResetEvent(
            PRKEVENT Event
            );
        """
        rv = 0

        return rv

    @apihook('KeClearEvent', argc=1)
    def KeClearEvent(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID KeClearEvent(
            PRKEVENT Event
            );
        """
        return

    @apihook('KeInitializeTimer', argc=1)
    def KeInitializeTimer(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID KeInitializeTimer(
            PKTIMER Timer
            );
        """
        return

    @apihook('KeSetTimer', argc=3)
    def KeSetTimer(self, emu, argv, ctx={}):
        """
        NTKERNELAPI BOOLEAN KeSetTimer(
            PKTIMER       Timer,
            LARGE_INTEGER DueTime,
            PKDPC         Dpc
            );
        """
        return True

    @apihook('PsLookupProcessByProcessId', argc=2)
    def PsLookupProcessByProcessId(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
            HANDLE    ProcessId,
            PEPROCESS *Process
            );
        """
        ProcessId, Process = argv
        rv = ddk.STATUS_SUCCESS

        if ProcessId == 4:
            proc = emu.get_system_process()
            proc.ref_cnt += 1
            self.mem_write(Process, proc.address.to_bytes(self.get_ptr_size(), 'little')) # noqa
            return rv

        proc = self.get_object_from_id(ProcessId)
        if not proc:
            rv = ddk.STATUS_INVALID_CID
        else:
            proc.ref_cnt += 1
            self.mem_write(Process, proc.address.to_bytes(self.get_ptr_size(), 'little')) # noqa

        return rv

    @apihook('ObOpenObjectByPointer', argc=7)
    def ObOpenObjectByPointer(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
                PVOID           Object,
                ULONG           HandleAttributes,
                PACCESS_STATE   PassedAccessState,
                ACCESS_MASK     DesiredAccess,
                POBJECT_TYPE    ObjectType,
                KPROCESSOR_MODE AccessMode,
                PHANDLE         Handle
                );
        """
        Object, HandleAttributes, pAccess, dAccess,\
            ObjectType, AccessMode, Handle = argv
        rv = ddk.STATUS_SUCCESS

        obj = self.get_object_from_addr(Object)
        obj.ref_cnt += 1

        hnd = self.get_object_handle(obj)
        self.mem_write(Handle,
                       hnd.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('PsGetProcessPeb', argc=1)
    def PsGetProcessPeb(self, emu, argv, ctx={}):
        """
        NTKERNELAPI PPEB PsGetProcessPeb(
            PEPROCESS           Object,
        );
        """
        Object = argv[0]

        proc = self.get_object_from_addr(Object)
        peb = emu.get_process_peb(proc)
        return peb.address

    @apihook('KeStackAttachProcess', argc=2)
    def KeStackAttachProcess(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID KeStackAttachProcess(
            PRKPROCESS   PROCESS,
            PRKAPC_STATE ApcState
            );
        """

        Process, ApcState = argv

        proc = self.get_object_from_addr(Process)
        emu.set_current_process(proc)

    @apihook('KeUnstackDetachProcess', argc=1)
    def KeUnstackDetachProcess(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID KeUnstackDetachProcess(
            PRKAPC_STATE ApcState
            );
        """
        # ApcState = argv[0]
        return

    @apihook('ZwProtectVirtualMemory', argc=5)
    def ZwProtectVirtualMemory(self, emu, argv, ctx={}):
        """
        NTSTATUS ZwProtectVirtualMemory(
            IN HANDLE ProcessHandle,
            IN_OUT PVOID* BaseAddress,
            IN SIZE_T* NumberOfBytesToProtect,
            IN ULONG NewAccessProtection,
            OUT PULONG OldAccessProtection
            )
        """
        hnd, base, byte_len, new_prot, old_prot = argv

        if base:
            addr = self.mem_read(base, emu.get_ptr_size())
            addr = int.from_bytes(addr, 'little')
            argv[1] = addr
        if byte_len:
            size = self.mem_read(byte_len, emu.get_ptr_size())
            size = int.from_bytes(size, 'little')
            argv[2] = size
        rv = ddk.STATUS_SUCCESS
        return rv

    @apihook('ZwWriteVirtualMemory', argc=5)
    def ZwWriteVirtualMemory(self, emu, argv, ctx={}):
        """
        ZwWriteVirtualMemory(
            HANDLE ProcessHandle,
            PVOID BaseAddress,
            PVOID Buffer,
            ULONG NumberOfBytesToWrite,
            PULONG NumberOfBytesWritten);
        """
        rv = ddk.STATUS_SUCCESS
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten = argv
        rv = False

        if hProcess == self.get_max_int():
            obj = emu.get_current_process()
        else:
            obj = self.get_object_from_handle(hProcess)

        proc_path = obj.get_process_path()
        argv[0] = proc_path

        data = b''
        if lpBuffer and lpBaseAddress:
            data = self.mem_read(lpBuffer, nSize)
            self.mem_write(lpBaseAddress, data)
            if lpNumberOfBytesWritten:
                bw = (len(data)).to_bytes(self.get_ptr_size(), 'little')
                self.mem_write(lpNumberOfBytesWritten, bw)
        else:
            rv = ddk.STATUS_INVALID_PARAMETER

        self.log_process_event(obj, MEM_WRITE, base=lpBaseAddress,
                               size=nSize, data=data)

        return rv

    @apihook('ZwAllocateVirtualMemory', argc=6)
    def ZwAllocateVirtualMemory(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS ZwAllocateVirtualMemory(
            HANDLE    ProcessHandle,
            PVOID     *BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T   RegionSize,
            ULONG     AllocationType,
            ULONG     Protect
            );
        """
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, Type, Protect = argv
        rv = ddk.STATUS_SUCCESS

        if ProcessHandle == self.get_max_int():
            obj = emu.get_current_process()
        else:
            obj = self.get_object_from_handle(ProcessHandle)

        size = int.from_bytes(self.mem_read(RegionSize,
                                            self.get_ptr_size()), 'little')

        base = self.mem_read(BaseAddress, emu.get_ptr_size())
        base = int.from_bytes(base, 'little')
        argv[1] = '0x%x->0x%x' % (BaseAddress, base)
        base = self.mem_alloc(size, tag='api.virtalloc.%s' % obj.image, process=obj)

        emu._set_dyn_code_hook(base, size)

        self.mem_write(BaseAddress,
                       base.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('PsLookupThreadByThreadId', argc=2)
    def PsLookupThreadByThreadId(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
            HANDLE   ThreadId,
            PETHREAD *Thread
            );
        """
        ThreadId, pThread = argv
        rv = ddk.STATUS_INVALID_PARAMETER

        ethread_addr = 0

        obj = self.get_object_from_id(ThreadId)
        if obj:
            obj.ref_cnt += 1
            rv = ddk.STATUS_SUCCESS
            ethread_addr = obj.address
        self.mem_write(pThread,
                       ethread_addr.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('RtlGetVersion', argc=1)
    def RtlGetVersion(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlGetVersion(
            PRTL_OSVERSIONINFOW lpVersionInformation
            );
        """
        lpVersionInformation = argv[0]

        rv = ddk.STATUS_SUCCESS

        osver = emu.get_os_version()
        size = int.from_bytes(self.mem_read(lpVersionInformation, 4),
                              'little')

        if size == self.sizeof(self.win.RTL_OSVERSIONINFOW(emu.get_ptr_size())):
            verinfo = self.win.RTL_OSVERSIONINFOW(emu.get_ptr_size())
        else:
            verinfo = self.win.RTL_OSVERSIONINFOEXW(emu.get_ptr_size())

        vi = self.mem_cast(verinfo, lpVersionInformation)
        vi.dwMajorVersion = osver['major']
        vi.dwMinorVersion = osver['minor']
        vi.dwBuildNumber = osver['build']

        self.mem_write(lpVersionInformation, self.get_bytes(vi))

        return rv

    @apihook('KeWaitForSingleObject', argc=5)
    def KeWaitForSingleObject(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS KeWaitForSingleObject(
            PVOID Object,
            _Strict_type_match_ KWAIT_REASON WaitReason,
            KPROCESSOR_MODE WaitMode,
            BOOLEAN Alertable,
            PLARGE_INTEGER Timeout
            );
        """
        Object, WaitReason, WaitMode, Alertable, Timeout = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('KeInitializeApc', argc=8)
    def KeInitializeApc(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID KeInitializeApc(
                    PKAPC Apc,
                    PKTHREAD Thread,
                    KAPC_ENVIRONMENT Environment,
                    PKKERNEL_ROUTINE KernelRoutine,
                    PKRUNDOWN_ROUTINE RundownRoutine,
                    PKNORMAL_ROUTINE NormalRoutine,
                    KPROCESSOR_MODE ProcessorMode,
                    PVOID NormalContext
                );
        """
        pApc, Thread, env, KernelRoutine, rundown, \
            NormalRoutine, procmode, ctx = argv

        apc = self.win.KAPC(emu.get_ptr_size())
        apc.Type = 0x12
        apc.Thread = Thread
        apc.ApcStateIndex = env
        apc.KernelRoutine = KernelRoutine
        apc.RundownRoutine = rundown
        apc.NormalRoutine = NormalRoutine

        if NormalRoutine:
            apc.ApcMode = procmode
            apc.NormalContext = ctx

    @apihook('MmMapLockedPagesSpecifyCache', argc=6)
    def MmMapLockedPagesSpecifyCache(self, emu, argv, ctx={}):
        """
        PVOID MmMapLockedPagesSpecifyCache(
            PMDL MemoryDescriptorList,
            KPROCESSOR_MODE AccessMode,
            MEMORY_CACHING_TYPE CacheType,
            PVOID RequestedAddress,
            ULONG BugCheckOnFailure,
            ULONG Priority
            );
        """
        p_mdl, am, ctype, addr, bugcheck, priority = argv
        rv = 0

        mdl = self.win.MDL(emu.get_ptr_size())
        mdl = self.mem_cast(mdl, p_mdl)

        rv = self.mem_alloc(mdl.ByteCount, tag='api.mapped_pages.0x%x' % (mdl.StartVa))
        return rv

    @apihook('KeInsertQueueApc', argc=4)
    def KeInsertQueueApc(self, emu, argv, ctx={}):
        """
        NTKERNELAPI BOOLEAN KeInsertQueueApc(
                PKAPC Apc,
                PVOID SystemArgument1,
                PVOID SystemArgument2,
                KPRIORITY PriorityBoost)
        """
        Apc, SystemArgument1, SystemArgument2, PriorityBoost = argv
        rv = True

        return rv

    @apihook('KeInitializeDpc', argc=3)
    def KeInitializeDpc(self, emu, argv, ctx={}):
        """
        void KeInitializeDpc(
        __drv_aliasesMem PRKDPC Dpc,
        PKDEFERRED_ROUTINE      DeferredRoutine,
        __drv_aliasesMem PVOID  DeferredContext
        );
        """
        Dpc, DeferredRoutine, DeferredContext = argv

        return

    @apihook('ObReferenceObjectByName', argc=8)
    def ObReferenceObjectByName(self, emu, argv, ctx={}):
        """
        NTSTATUS
            NTAPI
            ObReferenceObjectByName(
                PUNICODE_STRING ObjectName,
                ULONG Attributes,
                PACCESS_STATE Passed,
                ACCESS_MASK DesiredAccess,
                POBJECT_TYPE ObjectType,
                KPROCESSOR_MODE Access,
                PVOID ParseContext,
                PVOID* ObjectPtr
                );
        """
        ObjectName, Attributes, Passed, DesiredAccess,\
            objtype, Access, ParseContext, objptr = argv
        rv = ddk.STATUS_INVALID_PARAMETER
        obj = None

        if not ObjectName:
            rv = ddk.STATUS_INVALID_PARAMETER
        else:
            name = self.read_unicode_string(ObjectName)
            name = name.replace('\x00', '')
            argv[0] = name

            obj = self.get_object_from_name(name)
            if not obj:
                # Is this a driver?
                if name.lower().startswith(r"\driver"):
                    obj = emu.create_driver_object(name)
                else:
                    rv = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        if obj:
            rv = ddk.STATUS_SUCCESS
            self.mem_write(objptr,
                           obj.address.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('IoGetDeviceObjectPointer', argc=4)
    def IoGetDeviceObjectPointer(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS IoGetDeviceObjectPointer(
            PUNICODE_STRING ObjectName,
            ACCESS_MASK     DesiredAccess,
            PFILE_OBJECT    *FileObject,
            PDEVICE_OBJECT  *DeviceObject
            );
        """
        ObjectName, DesiredAccess, pFileObject, pDeviceObject = argv
        rv = ddk.STATUS_INVALID_PARAMETER

        s1 = self.read_unicode_string(ObjectName).replace('\x00', '')
        argv[0] = s1

        obj = self.get_object_from_name(s1)
        if obj:
            if obj.file_object:
                self.mem_write(pFileObject,
                            obj.file_object.address.to_bytes(self.get_ptr_size(), 'little')) # noqa
            self.mem_write(pDeviceObject,
                           obj.address.to_bytes(self.get_ptr_size(), 'little'))
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('PsTerminateSystemThread', argc=1)
    def PsTerminateSystemThread(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS PsTerminateSystemThread(
            NTSTATUS ExitStatus
            );
        """
        # ExitStatus = argv[0]

        rv = ddk.STATUS_SUCCESS
        return rv

    @apihook('IoRegisterBootDriverReinitialization', argc=3)
    def IoRegisterBootDriverReinitialization(self, emu, argv, ctx={}):
        """
        void IoRegisterBootDriverReinitialization(
            PDRIVER_OBJECT       DriverObject,
            PDRIVER_REINITIALIZE DriverReinitializationRoutine,
            PVOID                Context
            );
        """

        DriverObject, routine, context = argv

        self.queue_run('driver_reinit', routine, (DriverObject, context, 1))

        return

    @apihook('KdDisableDebugger', argc=0)
    def KdDisableDebugger(self, emu, argv, ctx={}):
        """NTKERNELAPI NTSTATUS KdDisableDebugger();"""

        rv = ddk.STATUS_DEBUGGER_INACTIVE
        return rv

    @apihook('KdChangeOption', argc=0)
    def KdChangeOption(self, emu, argv, ctx={}):
        """
        NTSTATUS KdChangeOption(
          KD_OPTION Option,
          ULONG     InBufferBytes,
          PVOID     InBuffer,
          ULONG     OutBufferBytes,
          PVOID     OutBuffer,
          PULONG    OutBufferNeeded
        );
        """

        rv = ddk.STATUS_DEBUGGER_INACTIVE
        return rv

    @apihook('MmGetSystemRoutineAddress', argc=1)
    def MmGetSystemRoutineAddress(self, emu, argv, ctx={}):
        """
        DECLSPEC_IMPORT PVOID MmGetSystemRoutineAddress(
            PUNICODE_STRING SystemRoutineName
            );
        """
        SystemRoutineName, = argv
        fn = self.read_unicode_string(SystemRoutineName)

        addr = emu.get_proc('ntoskrnl', fn)
        argv[0] = fn
        return addr

    @apihook('KeQuerySystemTime', argc=1)
    def KeQuerySystemTime(self, emu, argv, ctx={}):
        """
        void KeQuerySystemTime(
            PLARGE_INTEGER CurrentTime
        );
        """
        CurrentTime, = argv
        data = emu.get_system_time()
        data = data.to_bytes(8, 'little')
        self.mem_write(CurrentTime, data)

    @apihook('RtlTimeToTimeFields', argc=2)
    def RtlTimeToTimeFields(self, emu, argv, ctx={}):
        """
        NTSYSAPI VOID RtlTimeToTimeFields(
            PLARGE_INTEGER Time,
            PTIME_FIELDS   TimeFields
        );
        """
        Time, TimeFields = argv

        sys_time = self.mem_read(Time, 8)
        sys_time

    @apihook('ExSystemTimeToLocalTime', argc=2)
    def ExSystemTimeToLocalTime(self, emu, argv, ctx={}):
        """
        void ExSystemTimeToLocalTime(
            PLARGE_INTEGER SystemTime,
            PLARGE_INTEGER LocalTime
        );
        """
        SystemTime, LocalTime = argv

        sys_time = self.mem_read(SystemTime, 8)
        int_sys_time = int.from_bytes(sys_time, 'little')
        self.mem_write(LocalTime, int_sys_time.to_bytes(8, 'little'))

    @apihook('CmRegisterCallbackEx', argc=6)
    def CmRegisterCallbackEx(self, emu, argv, ctx={}):
        """
        NTSTATUS CmRegisterCallbackEx(
            PEX_CALLBACK_FUNCTION Function,
            PCUNICODE_STRING      Altitude,
            PVOID                 Driver,
            PVOID                 Context,
            PLARGE_INTEGER        Cookie,
            PVOID                 Reserved
        );
        """
        # TODO: Emulate the callback routine
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('CmRegisterCallback', argc=3)
    def CmRegisterCallback(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS CmRegisterCallback(
            PEX_CALLBACK_FUNCTION Function,
            PVOID                 Context,
            PLARGE_INTEGER        Cookie
        );
        """
        # TODO: Emulate the callback routine
        Function, Context, Cookie = argv

        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('CmUnRegisterCallback', argc=1)
    def CmUnRegisterCallback(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS CmUnRegisterCallback(
            LARGE_INTEGER Cookie
            );
        """
        Cookie, = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('EtwRegister', argc=4)
    def EtwRegister(self, emu, argv, ctx={}):
        """
        NTSTATUS EtwRegister(
            LPCGUID            ProviderId,
            PETWENABLECALLBACK EnableCallback,
            PVOID              CallbackContext,
            PREGHANDLE         RegHandle
            );
        """
        ProviderId, EnableCallback, CallbackContext, RegHandle = argv
        rv = ddk.STATUS_SUCCESS

        guid = self.mem_read(ProviderId, 16)
        guid = uuid.UUID(bytes_le=guid)

        argv[0] = str(guid)

        return rv

    @apihook('RtlImageDirectoryEntryToData', argc=4)
    def RtlImageDirectoryEntryToData(self, emu, argv, ctx={}):
        """
        PVOID IMAGEAPI ImageDirectoryEntryToData(
            PVOID   Base,
            BOOLEAN MappedAsImage,
            USHORT  DirectoryEntry,
            PULONG  Size
            );
        """
        Base, MappedAsImage, DirectoryEntry, Size = argv

        MappedAsImage &= 0xFF
        argv[1] = MappedAsImage

        rv = 0

        # mod = emu.get_mod_from_addr(Base)
        raise Exception('Unimplemented')
        return rv

    @apihook('ZwOpenEvent', argc=3)
    def ZwOpenEvent(self, emu, argv, ctx={}):
        """
        NTSYSCALLAPI NTSTATUS ZwOpenEvent(
        PHANDLE            EventHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
        );
        """
        EventHandle, DesiredAccess, ObjectAttributes = argv

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, ObjectAttributes)
        name = self.read_unicode_string(oa.ObjectName)

        obj = self.get_object_from_name(name)
        if not obj:
            rv = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        else:
            if EventHandle:
                hnd = obj.get_handle()
                self.mem_write(EventHandle,
                               hnd.to_bytes(self.ptr_size, 'little'))
            rv = ddk.STATUS_SUCCESS

        argv[2] = name
        return rv

    @apihook('ZwCreateEvent', argc=5)
    def ZwCreateEvent(self, emu, argv, ctx={}):
        """ NTSYSAPI NTSTATUS ZwCreateEvent(
        PHANDLE            EventHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        EVENT_TYPE         EventType,
        BOOLEAN            InitialState
        );
        """

        EventHandle, access, objattr, evttype, state = argv

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, objattr)
        name = self.read_unicode_string(oa.ObjectName)

        hnd, evt = emu.create_event(name)
        if EventHandle:
            self.mem_write(EventHandle,
                           hnd.to_bytes(self.ptr_size, 'little'))
        rv = ddk.STATUS_SUCCESS

        argv[2] = name
        argv[4] = 0xFF & state

        return rv

    @apihook('ExInitializeResourceLite', argc=1)
    def ExInitializeResourceLite(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS ExInitializeResourceLite(
            PERESOURCE Resource
            );
        """
        Resource, = argv

        return ddk.STATUS_SUCCESS

    @apihook('KeEnterCriticalRegion', argc=0)
    def KeEnterCriticalRegion(self, emu, argv, ctx={}):
        """NTKERNELAPI VOID KeEnterCriticalRegion();"""

        return

    @apihook('ExAcquireResourceExclusiveLite', argc=2)
    def ExAcquireResourceExclusiveLite(self, emu, argv, ctx={}):
        """
        BOOLEAN ExAcquireResourceExclusiveLite(
            PERESOURCE Resource,
            BOOLEAN    Wait
            );
        """
        rv = True
        return rv

    @apihook('ExAcquireResourceSharedLite', argc=2)
    def ExAcquireResourceSharedLite(self, emu, argv, ctx={}):
        """
        BOOLEAN ExAcquireResourceSharedLite(
            _Inout_ PERESOURCE Resource,
            _In_    BOOLEAN    Wait
        );
        """
        rv = True
        return rv

    @apihook('ExReleaseResourceLite', argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExReleaseResourceLite(self, emu, argv, ctx={}):
        """
        VOID ExReleaseResourceLite(
            _Inout_ PERESOURCE Resource
        );
        """
        return

    @apihook('ExAcquireFastMutex', argc=1)
    def ExAcquireFastMutex(self, emu, argv, ctx={}):
        """
        VOID ExAcquireFastMutex(
            _Inout_ PFAST_MUTEX FastMutex
            );
        """
        FastMutex, = argv

        return

    @apihook('ExReleaseFastMutex', argc=1)
    def ExReleaseFastMutex(self, emu, argv, ctx={}):
        """
        VOID ExReleaseFastMutex(
            _Inout_ PFAST_MUTEX FastMutex
            );
        """
        FastMutex, = argv

        return

    @apihook('ObfReferenceObject', argc=1)
    def ObfReferenceObject(self, emu, argv, ctx={}):
        """
        NTKERNELAPI LONG_PTR ObfReferenceObject(
            PVOID Object
            );
        """
        return 0

    @apihook('RtlLengthRequiredSid', argc=1)
    def RtlLengthRequiredSid(self, emu, argv, ctx={}):
        """
        NTSYSAPI ULONG RtlLengthRequiredSid(
            ULONG SubAuthorityCount
        );
        """
        count, = argv
        rv = count * 16

        return rv

    @apihook('RtlInitializeSid', argc=3)
    def RtlInitializeSid(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlInitializeSid(
            PSID                      Sid,
            PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
            UCHAR                     SubAuthorityCount
        );
        """
        # TODO, unimplemented
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('RtlSubAuthoritySid', argc=2)
    def RtlSubAuthoritySid(self, emu, argv, ctx={}):
        """
        NTSYSAPI PULONG RtlSubAuthoritySid(
            PSID  Sid,
            ULONG SubAuthority
        );
        """
        # TODO, unimplemented
        sid, sub_auth = argv

        return sid

    @apihook('RtlCreateAcl', argc=3)
    def RtlCreateAcl(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlCreateAcl(
            PACL  Acl,
            ULONG AclLength,
            ULONG AclRevision
        );
        """
        # TODO, unimplemented
        acl, acl_len, acl_rev = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('RtlSetDaclSecurityDescriptor', argc=4)
    def RtlSetDaclSecurityDescriptor(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlSetDaclSecurityDescriptor(
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            BOOLEAN              DaclPresent,
            PACL                 Dacl,
            BOOLEAN              DaclDefaulted
        );
        """
        # TODO, unimplemented
        sec_desc, dacl_present, dacl, dacl_default = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('ObSetSecurityObjectByPointer', argc=3)
    def ObSetSecurityObjectByPointer(self, emu, argv, ctx={}):
        """
        ObSetSecurityObjectByPointer(IN PVOID Object,
                              IN SECURITY_INFORMATION SecurityInformation,
                              IN PSECURITY_DESCRIPTOR SecurityDescriptor)
        );
        """
        # TODO, unimplemented
        Object, SecurityInformation, SecurityDescriptor = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('RtlCreateSecurityDescriptor', argc=2)
    def RtlCreateSecurityDescriptor(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlCreateSecurityDescriptor(
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            ULONG                Revision
        );
        """
        # TODO, unimplemented
        sec_desc, rev = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('RtlAddAccessAllowedAce', argc=4)
    def RtlAddAccessAllowedAce(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlAddAccessAllowedAce(
            PACL        Acl,
            ULONG       AceRevision,
            ACCESS_MASK AccessMask,
            PSID        Sid
        );
        """
        # TODO, unimplemented
        acl, acl_rev, access, sid = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('PoDeletePowerRequest', argc=1)
    def PoDeletePowerRequest(self, emu, argv, ctx={}):
        """
        void PoDeletePowerRequest(
            PVOID PowerRequest
        );
        """
        return

    @apihook('IoWMIRegistrationControl', argc=2)
    def IoWMIRegistrationControl(self, emu, argv, ctx={}):
        """
        NTSTATUS IoWMIRegistrationControl(
            PDEVICE_OBJECT DeviceObject,
            ULONG          Action
        );
        """
        rv = ddk.STATUS_INVALID_PARAMETER

        dev, action = argv
        if dev:
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('ObMakeTemporaryObject', argc=1)
    def ObMakeTemporaryObject(self, emu, argv, ctx={}):
        """
        NTKERNELAPI VOID ObMakeTemporaryObject(
            PVOID Object
            );
        """
        return None

    @apihook('RtlGetCompressionWorkSpaceSize', argc=3)
    def RtlGetCompressionWorkSpaceSize(self, emu, argv, ctx={}):
        """
        NT_RTL_COMPRESS_API NTSTATUS RtlGetCompressionWorkSpaceSize(
            USHORT CompressionFormatAndEngine,
            PULONG CompressBufferWorkSpaceSize,
            PULONG CompressFragmentWorkSpaceSize
        );
        """
        engine, buffer_workspace, frag_workspace = argv
        if buffer_workspace:
            self.mem_write(buffer_workspace, 0x1000.to_bytes(4, 'little'))
        if frag_workspace:
            self.mem_write(frag_workspace, 0x1000.to_bytes(4, 'little'))
        return ddk.STATUS_SUCCESS

    @apihook('RtlDecompressBuffer', argc=6)
    def RtlDecompressBuffer(self, emu, argv, ctx={}):
        """
        NT_RTL_COMPRESS_API NTSTATUS RtlDecompressBuffer(
            USHORT CompressionFormat,
            PUCHAR UncompressedBuffer,
            ULONG  UncompressedBufferSize,
            PUCHAR CompressedBuffer,
            ULONG  CompressedBufferSize,
            PULONG FinalUncompressedSize
            );
        """

        fmt, uncomp_buf, uncomp_buf_size, comp_buf,\
            comp_buf_size, final_size = argv

        if fmt not in (ddk.COMPRESSION_FORMAT_LZNT1, ddk.COMPRESSION_FORMAT_XPRESS): # noqa
            nts = ddk.STATUS_UNSUPPORTED_COMPRESSION
            return nts

        data = self.mem_read(comp_buf, comp_buf_size)

        dec = lznt1.decompress(data)

        if uncomp_buf_size < len(dec):
            nts = ddk.STATUS_BAD_COMPRESSION_BUFFER
            return nts

        self.mem_write(final_size, len(dec).to_bytes(4, 'little'))
        self.mem_write(uncomp_buf, dec)
        nts = ddk.STATUS_SUCCESS

        return nts

    @apihook('FsRtlAllocatePool', argc=2)
    def FsRtlAllocatePool(self, emu, argv, ctx={}):
        """
        void FsRtlAllocatePool(
            PoolType,
            NumberOfBytes);
        """
        PoolType, NumberOfBytes = argv

        chunk = self.pool_alloc(PoolType, NumberOfBytes, 'None')
        return chunk

    @apihook('IofCallDriver', argc=2, conv=_arch.CALL_CONV_FASTCALL)
    def IofCallDriver(self, emu, argv, ctx={}):
        """
        NTSTATUS IofCallDriver(
          PDEVICE_OBJECT        DeviceObject,
          __drv_aliasesMem PIRP Irp
        );
        """
        DeviceObject, pIrp = argv
        rv = ddk.STATUS_SUCCESS

        _irp = self.win.IRP(emu.get_ptr_size())
        _irp = self.mem_cast(_irp, pIrp)

        _irp.IoStatus.Status = 0
        self.mem_write(pIrp, _irp.get_bytes())

        return rv

    @apihook('IoSetCompletionRoutineEx', argc=7)
    def IoSetCompletionRoutineEx(self, emu, argv, ctx={}):
        """
        NTSTATUS IoSetCompletionRoutineEx(
          PDEVICE_OBJECT         DeviceObject,
          PIRP                   Irp,
          PIO_COMPLETION_ROUTINE CompletionRoutine,
          PVOID                  Context,
          BOOLEAN                InvokeOnSuccess,
          BOOLEAN                InvokeOnError,
          BOOLEAN                InvokeOnCancel
        );
        """
        DeviceObject, Irp, CompletionRoutine, Context, on_success, on_error, on_cancel = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('ExQueueWorkItem', argc=2)
    def ExQueueWorkItem(self, emu, argv, ctx={}):
        """
        DECLSPEC_DEPRECATED_DDK NTKERNELAPI VOID ExQueueWorkItem(
        __drv_aliasesMem PWORK_QUEUE_ITEM WorkItem,
        WORK_QUEUE_TYPE                   QueueType
        );
        """
        WorkItem, QueueType = argv

        return

    @apihook('ZwDeviceIoControlFile', argc=10)
    def ZwDeviceIoControlFile(self, emu, argv, ctx={}):

        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtDeviceIoControlFile(
            HANDLE           FileHandle,
            HANDLE           Event,
            PIO_APC_ROUTINE  ApcRoutine,
            PVOID            ApcContext,
            PIO_STATUS_BLOCK IoStatusBlock,
            ULONG            IoControlCode,
            PVOID            InputBuffer,
            ULONG            InputBufferLength,
            PVOID            OutputBuffer,
            ULONG            OutputBufferLength
            );
        """

        hnd, evt, apc_func, apc_ctx, isb, ioctl, InputBuffer, in_len, out_buf, out_len = argv # noqa
        nts = ddk.STATUS_SUCCESS

        obj = self.get_object_from_handle(hnd)

        in_buf = b''
        if InputBuffer:
            in_buf = self.mem_read(InputBuffer, in_len)

        nts, outbuf = emu.dev_ioctl(emu.get_ptr_size(), obj, ioctl, in_buf)

        if out_buf:
            if out_len < len(outbuf):
                nts = ddk.STATUS_BUFFER_TOO_SMALL
            else:
                self.mem_write(out_buf, outbuf)

        return nts

    @apihook('_snwprintf', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def _snwprintf(self, emu, argv, ctx={}):
        """
        int _snwprintf(
            wchar_t *buffer,
            size_t count,
            const wchar_t *format [,
            argument] ...
            );
        """
        buf, cnt, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)
        fmt_str = self.read_wide_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        if not fmt_cnt:
            self.write_wide_string(fmt_str, buf)
            return len(fmt_str)

        argv = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, argv)

        self.write_wide_string(fin, buf)

        argv = [buf, cnt, fmt] + argv
        argv[2] = fmt_str
        return len(fin)

    @apihook('ObReferenceObjectByHandle', argc=6)
    def ObReferenceObjectByHandle(self, emu, argv, ctx={}):
        """
        NTKERNELAPI NTSTATUS ObReferenceObjectByHandle(
            HANDLE                     Handle,
            ACCESS_MASK                DesiredAccess,
            POBJECT_TYPE               ObjectType,
            KPROCESSOR_MODE            AccessMode,
            PVOID                      *Object,
            POBJECT_HANDLE_INFORMATION HandleInformation
            );
        """
        hnd, access, obtype, mode, Object, ohi = argv

        nts = ddk.STATUS_SUCCESS

        obj = self.get_object_from_handle(hnd)
        if obj:
            if Object:
                self.mem_write(Object,
                               obj.address.to_bytes(self.get_ptr_size(), 'little')) # noqa
        else:
            nts = ddk.STATUS_INVALID_HANDLE

        return nts

    @apihook('ObGetFilterVersion', argc=0)
    def ObGetFilterVersion(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        USHORT
        ObGetFilterVersion (
            VOID
            );
        """
        return 256

    @apihook('ObRegisterCallbacks', argc=2)
    def ObRegisterCallbacks(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        NTSTATUS
        ObRegisterCallbacks (
            _In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
            _Outptr_ PVOID *RegistrationHandle
            );
        """
        CallbackRegistration, RegistrationHandle = argv
        nts = ddk.STATUS_SUCCESS

        return nts

    @apihook('ZwDeleteKey', argc=1)
    def ZwDeleteKey(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS ZwDeleteKey(
            HANDLE KeyHandle
            );
        """
        KeyHandle, = argv
        nts = ddk.STATUS_SUCCESS

        return nts

    @apihook('ZwQueryInformationProcess', argc=5)
    def ZwQueryInformationProcess(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSTATUS ZwQueryInformationProcess(
            IN HANDLE               ProcessHandle,
            IN PROCESSINFOCLASS     ProcessInformationClass,
            OUT PVOID               ProcessInformation,
            IN ULONG                ProcessInformationLength,
            OUT PULONG ReturnLength OPTIONAL
            );
        """
        hnd, info_class, proc_info, proc_info_len, retlen = argv

        nts = ddk.STATUS_OBJECT_TYPE_MISMATCH

        # Caller wants the current process
        if hnd == self.get_max_int():
            obj = emu.get_current_process()
        else:
            obj = self.get_object_from_handle(hnd)

        ptr_size = self.get_ptr_size()

        if obj:
            if info_class == ddk.PROCESSINFOCLASS.ProcessWow64Information:
                if proc_info_len < self.get_ptr_size():
                    nts = ddk.STATUS_INFO_LENGTH_MISMATCH
                    if retlen:
                        self.mem_write(retlen, ptr_size.to_bytes(ptr_size, 'little'))
                        nts = ddk.STATUS_SUCCESS
                else:
                    if retlen:
                        self.mem_write(retlen, ptr_size.to_bytes(ptr_size, 'little'))
                    # Send back that we are not in WOW64
                    self.mem_write(proc_info, (0).to_bytes(ptr_size, 'little'))
                    nts = ddk.STATUS_SUCCESS
            elif info_class == ddk.PROCESSINFOCLASS.ProcessDebugObjectHandle:
                nts = ddk.STATUS_PORT_NOT_SET

        return nts

    @apihook('IoGetCurrentProcess', argc=0)
    def IoGetCurrentProcess(self, emu, argv, ctx={}):
        """NTKERNELAPI PEPROCESS IoGetCurrentProcess();"""

        p = emu.get_current_process()
        return p.address

    @apihook('NtSetInformationThread', argc=4)
    def NtSetInformationThread(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtSetInformationThread(
            HANDLE          ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID           ThreadInformation,
            ULONG           ThreadInformationLength
        );
        """

        nts = ddk.STATUS_SUCCESS
        return nts

    @apihook('wcsnlen', argc=2)
    def wcsnlen(self, emu, argv, ctx={}):
        """s
        ize_t wcsnlen(
           const wchar_t *str,
           size_t numberOfElements
        );
        """

        src, num_elements = argv
        ws = self.read_wide_string(src)

        argv[0] = ws

        return len(ws)

    @apihook('IoRegisterShutdownNotification', argc=1)
    def IoRegisterShutdownNotification(self, emu, argv, ctx={}):
        """
        NTSTATUS IoRegisterShutdownNotification(
          PDEVICE_OBJECT DeviceObject
        );
        """
        DeviceObject, = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('IoUnregisterShutdownNotification', argc=1)
    def IoUnregisterShutdownNotification(self, emu, argv, ctx={}):
        """
        NTSTATUS IoRegisterShutdownNotification(
          PDEVICE_OBJECT DeviceObject
        );
        """
        DeviceObject, = argv
        return ddk.STATUS_SUCCESS

    @apihook('KeAcquireSpinLockRaiseToDpc', argc=1)
    def KeAcquireSpinLockRaiseToDpc(self, emu, argv, ctx={}):
        """
        KIRQL KeAcquireSpinLockRaiseToDpc(
        _Inout_ PKSPIN_LOCK SpinLock
        );
        """
        spinlock, = argv
        irql = self.get_current_irql()
        self.set_current_irql(ddk.DISPATCH_LEVEL)
        return irql

    @apihook('MmUnlockPages', argc=1)
    def MmUnlockPages(self, emu, argv, ctx={}):
        """
        void MmUnlockPages(
        PMDL MemoryDescriptorList
        );
        """
        mdl, = argv
        return

    @apihook('IoFreeMdl', argc=1)
    def IoFreeMdl(self, emu, argv, ctx={}):
        """
        void IoFreeMdl(
        PMDL Mdl
        );
        """
        mdl, = argv
        return

    @apihook('KeCancelTimer', argc=1)
    def KeCancelTimer(self, emu, argv, ctx={}):
        """
        BOOLEAN KeCancelTimer(
        PKTIMER Arg1
        );
        """
        rv = 1
        return rv

    @apihook('PsGetVersion', argc=4)
    def PsGetVersion(self, emu, argv, ctx={}):
        """
        BOOLEAN PsGetVersion(
            PULONG          MajorVersion,
            PULONG          MinorVersion,
            PULONG          BuildNumber,
            PUNICODE_STRING CSDVersion
        );
        """
        pmaj, pmin, bn, csdv = argv

        ver = self.get_os_version()
        major, minor, build = ver['major'], ver['minor'], ver['build']

        if pmaj:
            self.mem_write(pmaj, major.to_bytes(4, 'little'))

        if pmin:
            self.mem_write(pmin, minor.to_bytes(4, 'little'))

        if bn:
            self.mem_write(bn, build.to_bytes(4, 'little'))

        return 0

    @apihook('PsSetCreateProcessNotifyRoutineEx', argc=2)
    def PsSetCreateProcessNotifyRoutineEx(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        NTSTATUS
        PsSetCreateProcessNotifyRoutineEx (
            _In_ PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
            _In_ BOOLEAN Remove
            );
        """
        NotifyRoutine, Remove = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('PsSetLoadImageNotifyRoutine', argc=1)
    def PsSetLoadImageNotifyRoutine(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        NTSTATUS
        PsSetLoadImageNotifyRoutine(
            _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
            );
        """
        NotifyRoutine = argv # noqa
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('PsRemoveLoadImageNotifyRoutine', argc=1)
    def PsRemoveLoadImageNotifyRoutine(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        NTSTATUS
        PsRemoveLoadImageNotifyRoutine(
            _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
            );
        """
        NotifyRoutine = argv # noqa
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('PsSetCreateThreadNotifyRoutine', argc=1)
    def PsSetCreateThreadNotifyRoutine(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        NTSTATUS
        PsSetCreateThreadNotifyRoutine (
            _In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
            );
        """
        NotifyRoutine = argv # noqa
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('PsRemoveCreateThreadNotifyRoutine', argc=1)
    def PsRemoveCreateThreadNotifyRoutine(self, emu, argv, ctx={}):
        """
        NTKERNELAPI
        NTSTATUS
        PsRemoveCreateThreadNotifyRoutine (
            _In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
            );
        """
        NotifyRoutine = argv # noqa
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('mbstowcs', argc=3)
    def mbstowcs(self, emu, argv, ctx={}):
        """
        size_t mbstowcs(
        wchar_t *wcstr,
        const char *mbstr,
        size_t count
        );
        """
        wcstr, mbstr, count = argv

        rv = 0

        mb = self.read_string(mbstr)
        argv[1] = mb
        wide = mb.encode('utf-16le')
        if not wcstr:
            rv = len(mb)
        else:
            self.mem_write(wcstr, wide)
            rv = len(mb)

        return rv

    @apihook('ZwOpenKey', argc=3)
    def ZwOpenKey(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS ZwOpenKey(
        PHANDLE            KeyHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
        );
        """
        phnd, access, objattr = argv
        rv = ddk.STATUS_SUCCESS

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, objattr)
        name = self.read_unicode_string(oa.ObjectName)

        argv[2] = name

        hnd = self.reg_open_key(name, create=False)
        if not hnd:
            rv = ddk.STATUS_INVALID_HANDLE

        if phnd:
            self.mem_write(phnd, hnd.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('ZwQueryValueKey', argc=6)
    def ZwQueryValueKey(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS ZwQueryValueKey(
        HANDLE                      KeyHandle,
        PUNICODE_STRING             ValueName,
        KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        PVOID                       KeyValueInformation,
        ULONG                       Length,
        PULONG                      ResultLength
        );
        """

        hnd, val, info_class, val_info, length, ret_len = argv
        rv = ddk.STATUS_INVALID_HANDLE

        if val:
            name = self.read_unicode_string(val)

        argv[1] = name

        key = self.reg_get_key(hnd)
        if key:
            val = key.get_value(name)
            if val:
                data = val.get_data()
                output = b''
                if info_class == regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation:
                    vi = regdefs.KEY_VALUE_PARTIAL_INFORMATION(emu.get_ptr_size())
                    vi.Type = val.get_type()
                    vi.DataLength = len(data)
                    output = self.get_bytes(vi) + data
                elif info_class == regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation:
                    vi = regdefs.KEY_VALUE_FULL_INFORMATION(emu.get_ptr_size())
                    vi.Type = val.get_type()
                    val_name = val.get_name().encode('utf-16le') + b'\x00\x00'
                    vi.NameLength = len(val_name)
                    vi.DataOffset = self.sizeof(vi) + vi.NameLength
                    vi.DataLength = len(data)
                    output = self.get_bytes(vi) + val_name + data
                else:
                    raise ApiEmuError('Unsupported information class: 0x%x'
                                      % (info_class))
                self.mem_write(ret_len, len(output).to_bytes(4, 'little'))
                if len(output) > length:
                    rv = ddk.STATUS_BUFFER_TOO_SMALL
                else:
                    self.mem_write(val_info, output)
                    rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('ZwCreateFile', argc=11)
    def ZwCreateFile(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtCreateFile(
            PHANDLE            FileHandle,
            ACCESS_MASK        DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            PIO_STATUS_BLOCK   IoStatusBlock,
            PLARGE_INTEGER     AllocationSize,
            ULONG              FileAttributes,
            ULONG              ShareAccess,
            ULONG              CreateDisposition,
            ULONG              CreateOptions,
            PVOID              EaBuffer,
            ULONG              EaLength
        );
        """
        pHndl, access, objattr, statblock, alloc_size, file_attrs, share, \
            create_disp, create_opts, ea_buf, ea_len = argv

        nts = ddk.STATUS_SUCCESS

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, objattr)
        name = self.read_unicode_string(oa.ObjectName)

        create_disp = 0xFFFFFFFF & create_disp

        argv[3] = name
        cd = ddk.get_create_disposition(create_disp)
        if cd:
            argv[7] = cd

        ad = ddk.get_file_access_defines(access)
        if ad:
            argv[1] = ' | '.join(ad)

        npath = name
        if name.startswith('\\??\\'):
            npath = name.strip('\\??\\')
        npath = npath.rstrip('\\')

        obj = self.get_object_from_name(name)
        if obj:
            hnd = self.get_object_handle(obj)
            self.mem_write(pHndl, hnd.to_bytes(self.ptr_size, 'little'))
            self.log_file_access(name, FILE_OPEN, disposition=cd, access=ad)

        else:

            hfile = 0
            # Does the file being opened exist in our emulation space?
            if self.does_file_exist(npath):
                if create_disp == ddk.FILE_SUPERSEDE:
                    hfile = self.file_open(npath, create=True)
                elif create_disp == ddk.FILE_CREATE:
                    nts = ddk.STATUS_UNSUCCESSFUL
                elif create_disp == ddk.FILE_OPEN:
                    hfile = self.file_open(npath, create=False)
                elif create_disp == ddk.FILE_OPEN_IF:
                    hfile = self.file_open(npath, create=False)
                elif create_disp == ddk.FILE_OVERWRITE:
                    hfile = self.file_open(npath, create=True)
                elif create_disp == ddk.FILE_OVERWRITE_IF:
                    hfile = self.file_open(npath, create=True)
            else:
                if create_disp == ddk.FILE_SUPERSEDE:
                    hfile = self.file_open(npath, create=True)
                elif create_disp == ddk.FILE_CREATE:
                    hfile = self.file_open(npath, create=True)
                elif create_disp == ddk.FILE_OPEN:
                    nts = ddk.STATUS_UNSUCCESSFUL
                elif create_disp == ddk.FILE_OPEN_IF:
                    hfile = self.file_open(npath, create=True)
                elif create_disp == ddk.FILE_OVERWRITE:
                    nts = ddk.STATUS_UNSUCCESSFUL
                elif create_disp == ddk.FILE_OVERWRITE_IF:
                    hfile = self.file_open(npath, create=True)

            self.mem_write(pHndl, hfile.to_bytes(self.ptr_size, 'little'))
            self.log_file_access(npath, FILE_OPEN, disposition=cd, access=ad)

        return nts

    @apihook('ZwOpenFile', argc=6)
    def ZwOpenFile(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtOpenFile(
          PHANDLE            FileHandle,
          ACCESS_MASK        DesiredAccess,
          POBJECT_ATTRIBUTES ObjectAttributes,
          PIO_STATUS_BLOCK   IoStatusBlock,
          ULONG              ShareAccess,
          ULONG              OpenOptions
        );
        """
        pHndl, access, objattr, statblock, share, open_opts = argv

        nts = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        hfile = None

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, objattr)
        path = self.read_unicode_string(oa.ObjectName)

        argv[3] = path
        ad = ddk.get_file_access_defines(access)
        if ad:
            argv[1] = ' | '.join(ad)

        obj = self.get_object_from_name(path)
        if obj:
            nts = ddk.STATUS_SUCCESS
            hfile = self.get_object_handle(obj)
        else:
            # Is a file being opened?
            npath = path
            if path.startswith('\\??\\'):
                npath = path.strip('\\??\\')
            npath = npath.rstrip('\\')
            hfile = emu.file_open(npath)
            if hfile:
                nts = ddk.STATUS_SUCCESS

        self.log_file_access(path, FILE_OPEN, disposition=None, access=ad)

        if hfile:
            self.mem_write(pHndl, hfile.to_bytes(self.ptr_size, 'little'))

        return nts

    @apihook('ZwQueryInformationFile', argc=5)
    def ZwQueryInformationFile(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtQueryInformationFile(
            HANDLE                 FileHandle,
            PIO_STATUS_BLOCK       IoStatusBlock,
            PVOID                  FileInformation,
            ULONG                  Length,
            FILE_INFORMATION_CLASS FileInformationClass
        );
        """
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass = argv

        nts = ddk.STATUS_INVALID_PARAMETER
        _file = self.file_get(FileHandle)

        if _file and FileInformation:
            if FileInformationClass == ddk.FILE_INFORMATION_CLASS.FileStandardInformation:
                fsi = self.win.FILE_STANDARD_INFORMATION(emu.get_ptr_size())
                if Length >= self.sizeof(fsi):
                    nts = ddk.STATUS_SUCCESS
                    fsi.AllocationSize.LowPart = 512 - (_file.get_size() % 512)
                    fsi.EndOfFile.LowPart = _file.get_size()
                    self.mem_write(FileInformation, self.get_bytes(fsi))

                else:
                    nts = ddk.STATUS_INFO_LENGTH_MISMATCH

        return nts

    @apihook('RtlCompareMemory', argc=3)
    def RtlCompareMemory(self, emu, argv, ctx={}):
        """
        NTSYSAPI SIZE_T RtlCompareMemory(
          const VOID *Source1,
          const VOID *Source2,
          SIZE_T     Length
        );
        """

        s1, s2, Length = argv

        s1 = self.mem_read(s1, Length)
        s2 = self.mem_read(s2, Length)
        i = 0
        for i in range(Length):
            if s1[i] != s2[i]:
                break
        i += 1

        return i

    @apihook('RtlQueryRegistryValuesEx', argc=5)
    def RtlQueryRegistryValuesEx(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS RtlQueryRegistryValuesEx(
          ULONG                     RelativeTo,
          PCWSTR                    Path,
          PRTL_QUERY_REGISTRY_TABLE QueryTable,
          PVOID                     Context,
          PVOID                     Environment
        );
        """

        rv = ddk.STATUS_SUCCESS
        # TODO: complete this api handler
        RelativeTo, Path, QueryTable, Context, Environment = argv
        relatives = {regdefs.RTL_REGISTRY_ABSOLUTE: '',  # noqa
                     regdefs.RTL_REGISTRY_SERVICES: '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\', # noqa
                     regdefs.RTL_REGISTRY_CONTROL: '\\Registry\\Machine\\System\\CurrentControlSet\\Control\\', # noqa
                     regdefs.RTL_REGISTRY_WINDOWS_NT: '\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\', # noqa
                     regdefs.RTL_REGISTRY_DEVICEMAP: '\\Registry\\Machine\\Hardware\\DeviceMap\\', # noqa
                     regdefs.RTL_REGISTRY_USER: '\\Registry\\User\\CurrentUser\\'}

        path_str = self.read_wide_string(Path)
        argv[1] = path_str

        return rv

    @apihook('ZwWriteFile', argc=9)
    def ZwWriteFile(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtWriteFile(
            HANDLE           FileHandle,
            HANDLE           Event,
            PIO_APC_ROUTINE  ApcRoutine,
            PVOID            ApcContext,
            PIO_STATUS_BLOCK IoStatusBlock,
            PVOID            Buffer,
            ULONG            Length,
            PLARGE_INTEGER   ByteOffset,
            PULONG           Key
        );
        """
        FileHandle, evt, apc, apc_ctx, ios, buf, length, offset, key = argv
        length = length & 0xFFFFFFFF

        nts = ddk.STATUS_INVALID_PARAMETER
        _file = self.file_get(FileHandle)

        if _file and buf and length:
            path = _file.get_path()
            argv[0] = path

            data = self.mem_read(buf, length)
            if data:
                _file.add_data(data)
                # Log the file event
                self.log_file_access(path, FILE_WRITE, data=data, size=length)

                # Is it ascii?
                try:
                    data = data.decode('utf-8')
                except UnicodeDecodeError:
                    data = data.hex()
                argv[6] = data[:0x10]
                nts = ddk.STATUS_SUCCESS

        return nts

    @apihook('ZwReadFile', argc=9)
    def ZwReadFile(self, emu, argv, ctx={}):
        """
        __kernel_entry NTSYSCALLAPI NTSTATUS NtReadFile(
            HANDLE           FileHandle,
            HANDLE           Event,
            PIO_APC_ROUTINE  ApcRoutine,
            PVOID            ApcContext,
            PIO_STATUS_BLOCK IoStatusBlock,
            PVOID            Buffer,
            ULONG            Length,
            PLARGE_INTEGER   ByteOffset,
            PULONG           Key
        );
        """
        FileHandle, evt, apc, apc_ctx, ios, buf, length, offset, key = argv

        nts = ddk.STATUS_INVALID_PARAMETER
        _file = self.file_get(FileHandle)

        if _file and buf:
            path = _file.get_path()
            argv[0] = path

            data = _file.get_data()

            if buf:
                self.mem_write(buf, data[:length])

            # Log the file event
            self.log_file_access(path, FILE_READ, buffer=buf, size=length)

            nts = ddk.STATUS_SUCCESS

        return nts

    @apihook('MmIsDriverVerifying', argc=1)
    def MmIsDriverVerifying(self, emu, argv, ctx={}):
        """
        LOGICAL MmIsDriverVerifying(
          _DRIVER_OBJECT *DriverObject
        );
        """

        DriverObject, = argv
        rv = False

        return rv

    @apihook('ZwCreateSection', argc=7)
    def ZwCreateSection(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS ZwCreateSection(
            PHANDLE            SectionHandle,
            ACCESS_MASK        DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            PLARGE_INTEGER     MaximumSize,
            ULONG              SectionPageProtection,
            ULONG              AllocationAttributes,
            HANDLE             FileHandle
        );
        """

        (SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
         SectionPageProtection, AllocationAttributes, FileHandle) = argv

        fm = emu.get_file_manager()

        if not SectionHandle:
            return ddk.STATUS_INVALID_PARAMETER

        name = None
        if ObjectAttributes:
            oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
            oa = self.mem_cast(oa, ObjectAttributes)
            if oa.ObjectName:
                name = self.read_unicode_string(oa.ObjectName)
                argv[2] = name

        size = 0
        if MaximumSize:
            size = self.mem_read(MaximumSize, 8)
            size = int.from_bytes(size, 'little')
        hmap = fm.file_create_mapping(FileHandle, name, size, SectionPageProtection)
        self.mem_write(SectionHandle, hmap.to_bytes(self.get_ptr_size(), byteorder='little'))
        argv[0] = hmap

        return ddk.STATUS_SUCCESS

    @apihook('ZwUnmapViewOfSection', argc=2)
    def ZwUnmapViewOfSection(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS ZwUnmapViewOfSection(
            HANDLE ProcessHandle,
            PVOID  BaseAddress
        );
        """
        ProcessHandle, BaseAddress = argv
        return 0

    @apihook('ZwMapViewOfSection', argc=10)
    def ZwMapViewOfSection(self, emu, argv, ctx={}):
        """
        NTSYSAPI NTSTATUS ZwMapViewOfSection(
            HANDLE          SectionHandle,
            HANDLE          ProcessHandle,
            PVOID           *BaseAddress,
            ULONG_PTR       ZeroBits,
            SIZE_T          CommitSize,
            PLARGE_INTEGER  SectionOffset,
            PSIZE_T         ViewSize,
            SECTION_INHERIT InheritDisposition,
            ULONG           AllocationType,
            ULONG           Win32Protect
        );
        """

        (SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
         SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect) = argv

        fman = emu.get_file_manager()

        sect = fman.get_mapping_from_handle(SectionHandle)
        if ProcessHandle == self.get_max_int():
            proc_obj = emu.get_current_process()
        else:
            proc_obj = self.get_object_from_handle(ProcessHandle)

        full_offset = 0
        if SectionOffset:
            full_offset = int.from_bytes(self.mem_read(SectionOffset, 8), 'little')

        if ViewSize:
            bytes_to_map = int.from_bytes(self.mem_read(ViewSize, emu.get_ptr_size()),
                                          'little')

        pref_address = int.from_bytes(self.mem_read(BaseAddress, emu.get_ptr_size()),
                                      'little')

        tag_prefix = 'api.ZwMapViewOfSection'
        access = Win32Protect
        if sect:
            buf = None
            size = 0
            f = sect.get_backed_file()
            if f and not pref_address:
                data = f.get_data()

                if bytes_to_map != 0:
                    data = data[full_offset: full_offset + bytes_to_map]

                base, size = emu.get_valid_ranges(len(data))
                while base and base & 0xFFF:
                    base, size = emu.get_valid_ranges(size)

                buf = self.mem_alloc(base=base, size=size, perms=access, shared=True, tag='api',
                                     process=proc_obj)
                sect.add_view(buf, full_offset, size, access)
                mm = emu.get_address_map(buf)
                fname = ntpath.basename(f.get_path())
                fname = fname.replace('.', '_')
                mm.update_tag('%s.%s.0x%x' % (tag_prefix, fname, buf))
                self.mem_write(buf, data)
                if ViewSize:
                    self.mem_write(ViewSize, size.to_bytes(self.get_ptr_size(), 'little'))
                argv[2] = buf
                argv[6] = size
            elif not pref_address:
                if bytes_to_map == 0:
                    bytes_to_map = sect.size
                base, size = emu.get_valid_ranges(bytes_to_map)
                buf = self.mem_alloc(base=base, size=size, perms=access, shared=True,
                                     process=proc_obj)
                mm = emu.get_address_map(buf)
                mm.update_tag('%s.0x%x' % (tag_prefix, buf))
                if ViewSize:
                    self.mem_write(ViewSize, size.to_bytes(self.get_ptr_size(), 'little'))
                argv[2] = buf
                argv[6] = size
                sect.add_view(buf, full_offset, size, access)
            else:
                buf = pref_address

            if BaseAddress and buf:
                rv = ddk.STATUS_SUCCESS
                self.mem_write(BaseAddress, buf.to_bytes(emu.get_ptr_size(), 'little'))

            for base, view in sect.views.items():
                if base != buf and view.size == size and full_offset == view.offset:
                    data = self.mem_read(base, size)
                    self.mem_write(buf, data)

        return rv

    @apihook('RtlAllocateHeap', argc=3)
    def RtlAllocateHeap(self, emu, argv, ctx={}):
        '''
        NTSYSAPI PVOID RtlAllocateHeap(
            PVOID  HeapHandle,
            ULONG  Flags,
            SIZE_T Size
        );
        '''
        heap, flags, size = argv

        block = self.heap_alloc(size, heap='RtlAllocateHeap')

        return block

    @apihook('ZwGetContextThread', argc=2)
    def ZwGetContextThread(self, emu, argv, ctx={}):
        '''
        BOOL ZwGetContextThread(
            HANDLE    hThread,
            LPCONTEXT lpContext
        );
        '''
        hThread, lpContext = argv

        obj = self.get_object_from_handle(hThread)
        if not obj:
            return False

        context = obj.get_context()

        self.mem_write(lpContext, context.get_bytes())

        return True

    @apihook('ZwSetContextThread', argc=2)
    def ZwSetContextThread(self, emu, argv, ctx={}):
        '''
        BOOL ZwSetContextThread(
            HANDLE    hThread,
            LPCONTEXT lpContext
        );
        '''
        hThread, lpContext = argv

        obj = self.get_object_from_handle(hThread)
        if not obj:
            return False

        context = windefs.CONTEXT(emu.get_ptr_size())
        if lpContext:
            _context = self.mem_cast(context, lpContext)
            obj.set_context(_context)

        return True

    @apihook('RtlFreeHeap', argc=3)
    def RtlFreeHeap(self, emu, argv, ctx={}):
        '''
        NTSYSAPI RtlFreeHeap(
            PVOID HeapHandle,
            ULONG Flags,
            PVOID BaseAddress
        );
        '''
        rv = 1
        hHeap, dwFlags, lpMem = argv

        self.mem_free(lpMem)
        return rv
