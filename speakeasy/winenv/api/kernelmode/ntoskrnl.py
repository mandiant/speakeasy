# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import datetime
import io
import logging
import ntpath
import struct
import uuid
from typing import TYPE_CHECKING

import lznt1
import pefile

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
import speakeasy.winenv.defs.registry.reg as regdefs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.errors import ApiEmuError
from speakeasy.profiler_events import EventType
from speakeasy.report import EntryPointType, ErrorType
from speakeasy.windows import objman
from speakeasy.windows.guest_callbacks import get_first_unmapped
from speakeasy.winenv.api import api
from speakeasy.winenv.api.compare import ANSI_UPPER_TABLE, Fold, get_string_order
from speakeasy.winenv.api.token import query_token_information
from speakeasy.winenv.api.usermode.kernel32 import PROCESSOR_COUNT
from speakeasy.winenv.codepage import decode_ansi, encode_ansi
from speakeasy.winenv.defs.enums import (
    FILE_ACCESS_FLAGS,
    NT_CREATE_FILE_DISPOSITION,
    PAGE_PROTECTION_FLAGS,
    REG_VALUE_TYPE,
)
from speakeasy.winenv.defs.lookup import decode, decode_flags
from speakeasy.winenv.defs.nt import ddk

if TYPE_CHECKING:
    from speakeasy.windows.kernel import WinKernelEmulator
    from speakeasy.windows.winemu import WindowsEmulator

logger = logging.getLogger(__name__)


class Ntoskrnl(api.ApiHandler):
    """
    Implements functions exported by the Windows kernel. Zw*/Nt* are folded together as the same
    function since we aren't concerned with PreviousMode implications here.
    """

    name = "ntoskrnl"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata
    emu: "WindowsEmulator"

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.emu = emu

        self.win = ntos

        super().__get_hook_attrs__(self)

    @impdata("IoDriverObjectType")
    def IoDriverObjectType(self, ptr):
        """
        POBJECT_TYPE *IoDriverObjectType;

        Type object used for Driver objects exported by ntoskrnl.
        """
        return ptr

    @impdata("KeTickCount")
    def KeTickCount(self, ptr):
        """
        volatile KSYSTEM_TIME KeTickCount;

        Tick count exported by ntoskrnl.
        """
        return ptr

    @impdata("KeServiceDescriptorTable")
    def KeServiceDescriptorTable(self, ptr):
        """
        KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable[4];

        Kernel table containing SSDT.
        """
        return ptr

    @impdata("KdDebuggerEnabled")
    def KdDebuggerEnabled(self, ptr):
        """
        BOOLEAN *KdDebuggerEnabled;
        """
        return ptr

    def _read_object_name(self, objattr):
        """
        Read the ObjectName of an OBJECT_ATTRIBUTES. Both the attributes and
        the name are optional, so return None when either is NULL.
        """
        if not objattr:
            return None
        oa = self.win.OBJECT_ATTRIBUTES(self.emu.get_ptr_size())
        oa = self.mem_cast(oa, objattr)
        if not oa.ObjectName:
            return None
        return self.read_unicode_string(oa.ObjectName)

    def _new_mdl(self, va: int, length: int) -> int:
        """Allocate an MDL that describes ``length`` bytes at ``va``."""
        start = va & ~0xFFF
        mdl = self.win.MDL(self.emu.get_ptr_size())
        mdl.Size = 0x56
        mdl.MdlFlags = 0x8
        mdl.StartVa = start
        mdl.ByteCount = length
        mdl.ByteOffset = va - start

        ptr: int = self.mem_alloc(self.sizeof(mdl), tag=f"api.MDL.0x{va:x}")
        self.mem_write(ptr, self.get_bytes(mdl))
        return ptr

    def _append_to_unicode_string(self, dest_addr: int, data: bytes) -> int:
        """
        Append ``data`` to the UNICODE_STRING at ``dest_addr``, and end the
        buffer with a NUL when there is room.
        """
        dest = self.mem_cast(self.win.UNICODE_STRING(self.emu.get_ptr_size()), dest_addr)
        if not data:
            return ddk.STATUS_SUCCESS
        if dest.Length + len(data) > dest.MaximumLength:
            return ddk.STATUS_BUFFER_TOO_SMALL
        self.mem_write(dest.Buffer + dest.Length, data)
        dest.Length += len(data)
        if dest.Length + 2 <= dest.MaximumLength:
            self.mem_write(dest.Buffer + dest.Length, b"\x00\x00")
        self.mem_write(dest_addr, self.get_bytes(dest))
        return ddk.STATUS_SUCCESS

    def _write_secure_counted_string(self, string, buf, size, count):
        """
        Write ``string`` the way _snprintf_s does: the buffer always ends
        with a NUL, a ``count`` of _TRUNCATE truncates to the buffer size,
        and a string that does not fit in the buffer leaves it empty.
        """
        if not buf or not size:
            return -1
        truncate = count == (1 << (self.emu.get_ptr_size() * 8)) - 1
        limit = size - 1 if truncate else min(count, size - 1)
        if len(string) <= limit:
            self.write_string(string, buf)
            return len(string)
        if truncate or count < size:
            self.write_string(string[:limit], buf)
        else:
            self.mem_write(buf, b"\x00")
        return -1

    @apihook("ObfDereferenceObject", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ObfDereferenceObject(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR ObfDereferenceObject(
            PVOID Object
        );

        Speakeasy counts only the references of the object manager and of handles, so the count does not change.
        """
        return 0

    @apihook("ZwClose", argc=1)
    def ZwClose(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwClose(
            HANDLE Handle
        );
        """
        (Handle,) = argv
        if not emu.get_handle_table().close(Handle):
            return ddk.STATUS_INVALID_HANDLE
        return ddk.STATUS_SUCCESS

    @apihook("DbgPrint", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def DbgPrint(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
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
        ctx.args.clear()
        ctx.args.append(fin)

        return len(fin)

    @apihook("DbgPrintEx", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def DbgPrintEx(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONG DbgPrintEx(
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

        ctx.args.clear()
        ctx.args.append(hex(cid))
        ctx.args.append(hex(level))
        ctx.args.append(fin)

        return len(fin)

    @apihook("vDbgPrintEx", argc=4, conv=_arch.CALL_CONV_CDECL)
    def vDbgPrintEx(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONG vDbgPrintEx(
            ULONG ComponentId,
            ULONG Level,
            PCCH Format,
            va_list arglist
        );
        """
        ComponentId, Level, Format, arglist = argv
        fmt_str = self.read_string(Format)
        vargs = self.va_args(arglist, self.get_va_arg_count(fmt_str))
        ctx.args[2].display = self.do_str_format(fmt_str, vargs)
        return ddk.STATUS_SUCCESS

    @apihook("vDbgPrintExWithPrefix", argc=5, conv=_arch.CALL_CONV_CDECL)
    def vDbgPrintExWithPrefix(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONG vDbgPrintExWithPrefix(
            PCCH Prefix,
            ULONG ComponentId,
            ULONG Level,
            PCCH Format,
            va_list arglist
        );
        """
        Prefix, ComponentId, Level, Format, arglist = argv
        fmt_str = self.read_string(Format)
        vargs = self.va_args(arglist, self.get_va_arg_count(fmt_str))
        ctx.args[3].display = self.read_string(Prefix) + self.do_str_format(fmt_str, vargs)
        return ddk.STATUS_SUCCESS

    @apihook("RtlAnsiStringToUnicodeString", argc=3)
    def RtlAnsiStringToUnicodeString(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlAnsiStringToUnicodeString(
            PUNICODE_STRING DestinationString,
            PCANSI_STRING SourceString,
            BOOLEAN AllocateDestinationString
        );
        """
        DestinationString, SourceString, AllocateDestinationString = argv
        nts = ddk.STATUS_SUCCESS

        ansi_str = self.read_ansi_string(SourceString)

        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        us = self.mem_cast(us, DestinationString)

        ansi = self.win.STRING(emu.get_ptr_size())
        ansi = self.mem_cast(ansi, SourceString)

        size = len(ansi_str) * 2

        if AllocateDestinationString:
            us.MaximumLength = size
            ptr = self.mem_alloc(size, tag=f"api.struct.STRING.{ansi_str}")
            us.Buffer = ptr
        elif us.MaximumLength < size:
            nts = ddk.STATUS_UNSUCCESSFUL

        if nts == ddk.STATUS_SUCCESS:
            us.Length = size
            self.mem_write(us.Buffer, ansi_str.encode("utf-16le"))

            data = self.get_bytes(us)
            self.mem_write(DestinationString, data)

        ctx.args["SourceString"].display = ansi_str

        return nts

    @apihook("RtlInitAnsiString", argc=2)
    def RtlInitAnsiString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlInitAnsiString(
            PANSI_STRING DestinationString,
            PCSZ SourceString
        );
        """
        ansi = self.win.STRING(emu.get_ptr_size())

        DestinationString, SourceString = argv
        if SourceString:
            ansi_str = self.read_string(SourceString)
            size = len(ansi_str)
            ansi.Length = size
            ansi.MaximumLength = size
            ansi.Buffer = SourceString
        else:
            ansi_str = ""
            ansi.Length = 0
            ansi.MaximumLength = 0
            ansi.Buffer = 0

        data = self.get_bytes(ansi)
        self.mem_write(DestinationString, data)

        ctx.args["SourceString"].display = ansi_str

    @apihook("RtlInitUnicodeString", argc=2)
    def RtlInitUnicodeString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlInitUnicodeString(
            PUNICODE_STRING DestinationString,
            PCWSTR SourceString
        );
        """
        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        DestinationString, SourceString = argv

        if SourceString:
            uni_str = self.read_wide_string(SourceString)
            size = len(uni_str) * 2
            us.Length = size
            us.MaximumLength = size
            us.Buffer = SourceString
        else:
            uni_str = ""
            us.Length = 0
            us.MaximumLength = 0
            us.Buffer = 0

        data = self.get_bytes(us)
        self.mem_write(DestinationString, data)

        ctx.args["SourceString"].display = uni_str

    @apihook("RtlDuplicateUnicodeString", argc=3)
    def RtlDuplicateUnicodeString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlDuplicateUnicodeString(
            ULONG Flags,
            PCUNICODE_STRING StringIn,
            PUNICODE_STRING StringOut
        );
        """
        NULL_TERMINATE, ALLOCATE_NULL_STRING = 1, 2
        Flags, StringIn, StringOut = argv
        if not StringIn or not StringOut or Flags == ALLOCATE_NULL_STRING or Flags > 3:
            return ddk.STATUS_INVALID_PARAMETER

        src = self.mem_cast(self.win.UNICODE_STRING(emu.get_ptr_size()), StringIn)
        if src.Length > src.MaximumLength or (src.Length and not src.Buffer):
            return ddk.STATUS_INVALID_PARAMETER

        data = self.mem_read(src.Buffer, src.Length) if src.Length else b""
        ctx.args["StringIn"].display = data.decode("utf-16le", "replace")

        dest = self.win.UNICODE_STRING(emu.get_ptr_size())
        if data or Flags == NULL_TERMINATE | ALLOCATE_NULL_STRING:
            if Flags & NULL_TERMINATE:
                data += b"\x00\x00"
            dest.Buffer = self.mem_alloc(len(data), tag="api.struct.UNICODE_STRING")
            self.mem_write(dest.Buffer, data)
            dest.Length = src.Length
            dest.MaximumLength = len(data)
        self.mem_write(StringOut, self.get_bytes(dest))
        return ddk.STATUS_SUCCESS

    @apihook("RtlFreeUnicodeString", argc=1)
    def RtlFreeUnicodeString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlFreeUnicodeString(
            PUNICODE_STRING UnicodeString
        );
        """
        (UnicodeString,) = argv

        us_str = self.read_unicode_string(UnicodeString)
        ctx.args["UnicodeString"].display = us_str

        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        us = self.mem_cast(us, UnicodeString)
        self.mem_free(us.Buffer)

    @apihook("ExAllocatePoolWithTag", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def ExAllocatePoolWithTag(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID ExAllocatePoolWithTag(
            POOL_TYPE PoolType,
            SIZE_T NumberOfBytes,
            ULONG Tag
        );
        """
        PoolType, NumberOfBytes, Tag = argv

        tag: int | str = Tag
        if Tag:
            try:
                tag = Tag.to_bytes(4, "little").decode("utf-8")
                ctx.args[2].display = tag
            except Exception as e:
                logger.exception(str(e))

        chunk = self.pool_alloc(PoolType, NumberOfBytes, tag)
        return chunk

    @apihook("ExFreePoolWithTag", argc=2)
    def ExFreePoolWithTag(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExFreePoolWithTag(
            PVOID P,
            ULONG Tag
        );
        """
        P, Tag = argv

        if Tag:
            try:
                ctx.args[1].display = Tag.to_bytes(4, "little").decode("utf-8")
            except Exception as e:
                logger.exception(str(e))
        self.mem_free(P)

    @apihook("IoAllocateWorkItem", argc=1)
    def IoAllocateWorkItem(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PIO_WORKITEM IoAllocateWorkItem(
            PDEVICE_OBJECT DeviceObject
        );
        """
        (DeviceObject,) = argv
        ptr_size = emu.get_ptr_size()
        item = self.pool_alloc(0, ptr_size * 8, "IoWk")
        self.write_ptr(item, DeviceObject)
        return item

    @apihook("IoQueueWorkItem", argc=4)
    def IoQueueWorkItem(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoQueueWorkItem(
            PIO_WORKITEM IoWorkItem,
            PIO_WORKITEM_ROUTINE WorkerRoutine,
            WORK_QUEUE_TYPE QueueType,
            PVOID Context
        );
        """
        IoWorkItem, WorkerRoutine, QueueType, Context = argv
        device = self.read_ptr(IoWorkItem)
        self.setup_callback(WorkerRoutine, (device, Context))

    @apihook("IoFreeWorkItem", argc=1)
    def IoFreeWorkItem(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoFreeWorkItem(
            PIO_WORKITEM IoWorkItem
        );
        """
        self.mem_free(argv[0])

    @apihook("ExAllocatePool", argc=2)
    def ExAllocatePool(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID ExAllocatePool(
            POOL_TYPE PoolType,
            SIZE_T NumberOfBytes
        );
        """
        PoolType, NumberOfBytes = argv

        chunk = self.pool_alloc(PoolType, NumberOfBytes, "None")
        return chunk

    @apihook("ExAllocatePool2", argc=4)
    def ExAllocatePool2(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID ExAllocatePool2(
            POOL_FLAGS Flags,
            SIZE_T NumberOfBytes,
            ULONG Tag
        );

        POOL_FLAGS is a ULONG64 passed by value: two stack slots on x86, one
        register on x64. argc=4 covers the x86 layout; on x64 the fourth slot
        is unused.
        """
        if emu.get_ptr_size() == 4:
            lo, hi, Size, Tag = argv
            Flags = (hi << 32) | lo
            tag_slot = 3
        else:
            Flags, Size, Tag = argv[:3]
            tag_slot = 2

        tag: int | str = Tag
        if Tag:
            try:
                tag = Tag.to_bytes(4, "little").decode("utf-8")
                ctx.args[tag_slot].display = tag
            except Exception as e:
                logger.exception(str(e))

        if not Size:
            return 0

        pool_flag_paged = 0x100
        pool_type = ddk.POOL_TYPE.PagedPool if Flags & pool_flag_paged else ddk.POOL_TYPE.NonPagedPool

        chunk = self.pool_alloc(pool_type, Size, tag)
        return chunk

    @apihook("ExFreePool", argc=1)
    def ExFreePool(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExFreePool(
            PVOID P
        );
        """
        (P,) = argv
        self.mem_free(P)

    @apihook("IoDeleteDriver", argc=1)
    def IoDeleteDriver(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoDeleteDriver(
            PDRIVER_OBJECT DriverObject
        );
        """
        (DriverObject,) = argv

    @apihook("IoCreateDevice", argc=7)
    def IoCreateDevice(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoCreateDevice(
            PDRIVER_OBJECT DriverObject,
            ULONG DeviceExtensionSize,
            PUNICODE_STRING DeviceName,
            DEVICE_TYPE DeviceType,
            ULONG DeviceCharacteristics,
            BOOLEAN Exclusive,
            PDEVICE_OBJECT *DeviceObject
        );
        """
        nts = ddk.STATUS_SUCCESS
        DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject = argv

        if DeviceName:
            DeviceName = self.read_unicode_string(DeviceName).replace("\x00", "")
            ctx.args[2].display = DeviceName

        driver_obj = self.get_object_from_addr(DriverObject)
        if not driver_obj:
            return ddk.STATUS_INVALID_PARAMETER

        dev = emu.create_device_object(
            DeviceName, driver_obj, DeviceExtensionSize, DeviceType, DeviceCharacteristics, tag="api.object"
        )

        self.write_ptr(DeviceObject, dev.address)

        return nts

    @apihook("IoCreateDeviceSecure", argc=9)
    def IoCreateDeviceSecure(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoCreateDeviceSecure(
            PDRIVER_OBJECT DriverObject,
            ULONG DeviceExtensionSize,
            PUNICODE_STRING DeviceName,
            DEVICE_TYPE DeviceType,
            ULONG DeviceCharacteristics,
            BOOLEAN Exclusive,
            PCUNICODE_STRING DefaultSDDLString,
            LPCGUID DeviceClassGuid,
            PDEVICE_OBJECT *DeviceObject
        );
        """
        nts = ddk.STATUS_SUCCESS
        (
            DriverObject,
            DeviceExtensionSize,
            DeviceName,
            DeviceType,
            DeviceCharacteristics,
            Exclusive,
            DefaultSDDLString,
            DeviceClassGuid,
            DeviceObject,
        ) = argv

        if DeviceName:
            DeviceName = self.read_unicode_string(DeviceName).replace("\x00", "")
            ctx.args[2].display = DeviceName

        driver_obj = self.get_object_from_addr(DriverObject)
        if not driver_obj:
            return ddk.STATUS_INVALID_PARAMETER

        dev = emu.create_device_object(
            DeviceName, driver_obj, DeviceExtensionSize, DeviceType, DeviceCharacteristics, tag="api.object"
        )

        self.write_ptr(DeviceObject, dev.address)

        return nts

    @apihook("IoCreateSymbolicLink", argc=2)
    def IoCreateSymbolicLink(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoCreateSymbolicLink(
            PUNICODE_STRING SymbolicLinkName,
            PUNICODE_STRING DeviceName
        );
        """
        SymbolicLinkName, DeviceName = argv
        link_name = self.read_unicode_string(SymbolicLinkName).replace("\x00", "")
        dev_name = self.read_unicode_string(DeviceName).replace("\x00", "")
        emu.add_symlink(link_name, dev_name)

        nts = ddk.STATUS_SUCCESS
        ctx.args[0].display = link_name
        ctx.args[1].display = dev_name

        return nts

    @apihook("IofCompleteRequest", argc=2, conv=_arch.CALL_CONV_FASTCALL)
    def IofCompleteRequest(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IofCompleteRequest(
            PIRP Irp,
            CCHAR PriorityBoost
        );
        """
        Irp, PriorityBoost = argv

        ctx.args[1].display = hex(0xFF & PriorityBoost)

    @apihook("IoDeleteSymbolicLink", argc=1)
    def IoDeleteSymbolicLink(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoDeleteSymbolicLink(
            PUNICODE_STRING SymbolicLinkName
        );
        """
        nts = ddk.STATUS_SUCCESS

        (SymbolicLinkName,) = argv
        link_name = self.read_unicode_string(SymbolicLinkName).replace("\x00", "")
        ctx.args[0].display = link_name
        return nts

    @apihook("KeInitializeMutex", argc=2)
    def KeInitializeMutex(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeInitializeMutex(
            PRKMUTEX Mutex,
            ULONG Level
        );
        """
        return

    @apihook("IoDeleteDevice", argc=1)
    def IoDeleteDevice(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoDeleteDevice(
            PDEVICE_OBJECT DeviceObject
        );
        """
        nts = ddk.STATUS_SUCCESS
        # devobj = argv[0]

        return nts

    @apihook("MmIsAddressValid", argc=1)
    def MmIsAddressValid(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN MmIsAddressValid(
            PVOID VirtualAddress
        );
        """
        rv = 0

        (VirtualAddress,) = argv

        rv = emu.is_address_valid(VirtualAddress)
        return rv

    @apihook("ZwQuerySystemInformation", argc=4)
    def ZwQuerySystemInformation(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
        """
        SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength = argv

        size = 0
        nts = ddk.STATUS_INFO_LENGTH_MISMATCH
        buf_ptr = 0

        if SystemInformationClass == ddk.SYSTEM_INFORMATION_CLASS.SystemModuleInformation:
            mods = emu.get_peb_modules()
            mod_count = len(mods)
            size = mod_count * self.sizeof(self.win.SYSTEM_MODULE(emu.get_ptr_size()))
            size += self.ptr_size

            if size <= SystemInformationLength and SystemInformationLength != 0:
                buf_ptr = SystemInformation
                # Write the number of mods
                self.write_ptr(buf_ptr, mod_count)
                buf_ptr += self.ptr_size

                for i, mod in enumerate(mods):
                    sm = self.win.SYSTEM_MODULE(emu.get_ptr_size())
                    sm.Base = mod.base
                    sm.Size = mod.image_size
                    image_name = encode_ansi("\\??\\" + mod.emu_path)
                    sm.ImageName = image_name
                    sm.LoadCount = 1
                    sm.Index = i
                    sm.ModuleNameOffset = image_name.rfind(b"\\") + 1
                    self.mem_write(buf_ptr, self.get_bytes(sm))
                    buf_ptr += self.sizeof(sm)
                nts = ddk.STATUS_SUCCESS

        elif SystemInformationClass == ddk.SYSTEM_INFORMATION_CLASS.SystemBasicInformation:
            k32 = emu.api.load_api_handler("kernel32")
            sbi = self.win.SYSTEM_BASIC_INFORMATION(emu.get_ptr_size())
            sbi.TimerResolution = 156250
            sbi.PageSize = 0x1000
            sbi.NumberOfPhysicalPages = 0x200000
            sbi.LowestPhysicalPageNumber = 1
            sbi.HighestPhysicalPageNumber = 0x200000
            sbi.AllocationGranularity = 0x10000
            sbi.MinimumUserModeAddress = 0x10000
            sbi.MaximumUserModeAddress = k32.get_max_application_address(emu)
            sbi.ActiveProcessorsAffinityMask = (1 << PROCESSOR_COUNT) - 1
            sbi.NumberOfProcessors = PROCESSOR_COUNT

            size = self.sizeof(sbi)
            if SystemInformationLength == size:
                self.mem_write(SystemInformation, self.get_bytes(sbi))
                nts = ddk.STATUS_SUCCESS

        elif SystemInformationClass == ddk.SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation:
            k32 = emu.api.load_api_handler("kernel32")
            tod = self.win.SYSTEM_TIMEOFDAY_INFORMATION(emu.get_ptr_size())
            tod.BootTime = k32.boot_time
            tod.CurrentTime = k32.get_system_time()
            tod.TimeZoneBias = 0
            tod.TimeZoneId = 0
            tod.Reserved = 0
            tod.BootTimeBias = 0
            tod.SleepTimeBias = 0

            if SystemInformationLength > self.sizeof(tod):
                return ddk.STATUS_INFO_LENGTH_MISMATCH
            size = SystemInformationLength
            self.mem_write(SystemInformation, self.get_bytes(tod)[:size])
            nts = ddk.STATUS_SUCCESS

        elif SystemInformationClass == ddk.SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation:
            if SystemInformation and SystemInformationLength >= 2:
                out = b"\x00\x01"
                size = len(out)
                self.mem_write(SystemInformation, out)
                nts = ddk.STATUS_SUCCESS

        elif SystemInformationClass == ddk.SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation:
            if SystemInformation and SystemInformationLength >= 8:
                class_len = (8).to_bytes(4, "little")
                flags = (1).to_bytes(4, "little")
                self.mem_write(SystemInformation, class_len + flags)
                nts = ddk.STATUS_SUCCESS

        elif SystemInformationClass == ddk.SYSTEM_INFORMATION_CLASS.SystemProcessInformation:
            procs = emu.get_processes()
            for proc in procs:
                threads = proc.threads
                spi = self.win.SYSTEM_PROCESS_INFORMATION(emu.get_ptr_size())
                sti = self.win.SYSTEM_THREAD_INFORMATION(emu.get_ptr_size())
                size += self.sizeof(spi)
                size += len((proc.image + "\x00").encode("utf-16le"))
                size += len(threads) * self.sizeof(sti)

            if size <= SystemInformationLength:
                buf_ptr = SystemInformation

                for i, proc in enumerate(procs):
                    tis = []
                    rel_offset = 0

                    spi = self.win.SYSTEM_PROCESS_INFORMATION(emu.get_ptr_size())

                    spi.NumberOfThreads = len(proc.threads)
                    spi.UniqueProcessId = proc.id
                    rel_offset += self.sizeof(spi)

                    for thread in proc.threads:
                        sti = self.win.SYSTEM_THREAD_INFORMATION(emu.get_ptr_size())
                        sti.ClientId.UniqueProcess = proc.id
                        sti.ClientId.UniqueThread = thread.id
                        tis.append(sti)
                        rel_offset += self.sizeof(sti)

                    # Add the string data after the SI structs
                    iname = (proc.image + "\x00").encode("utf-16le")
                    spi.ImageName.Length = len(iname)
                    spi.ImageName.MaximumLength = len(iname)
                    spi.ImageName.Buffer = buf_ptr + rel_offset

                    rel_offset += len(iname)

                    spi.NextEntryOffset = rel_offset

                    # Mark the last process
                    if i == (len(procs) - 1):
                        spi.NextEntryOffset = 0

                    data = self.get_bytes(spi)
                    data += b"".join([self.get_bytes(d) for d in tis])
                    data += iname

                    self.mem_write(buf_ptr, data)
                    buf_ptr += len(data)

                nts = ddk.STATUS_SUCCESS

        else:
            return ddk.STATUS_INVALID_INFO_CLASS

        if ReturnLength:
            self.write_dword(ReturnLength, size)

        return nts

    @apihook("_allshl", argc=0, conv=_arch.CALL_CONV_CDECL)
    def _allshl(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONGLONG _allshl(
            LONGLONG a,
            LONG b
        );

        The x86 compiler helper takes the value in EDX:EAX and the count in
        CL, and returns the result in EDX:EAX.
        """
        a = emu.reg_read(_arch.X86_REG_EDX) << 32 | emu.reg_read(_arch.X86_REG_EAX)
        b = emu.reg_read(_arch.X86_REG_ECX) & 0xFF
        rv = 0xFFFFFFFFFFFFFFFF & a << b

        emu.reg_write(_arch.X86_REG_EDX, rv >> 32)
        return rv & 0xFFFFFFFF

    @apihook("RtlMoveMemory", argc=3)
    def RtlMoveMemory(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void RtlMoveMemory(
            void *Destination,
            const void *Source,
            size_t Length
        );
        """
        Destination, Source, Length = argv
        self.mem_write(Destination, self.mem_read(Source, Length))

    @apihook("_vsnprintf_s", argc=5, conv=_arch.CALL_CONV_CDECL)
    def _vsnprintf_s(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _vsnprintf_s(
            char *buffer,
            size_t sizeOfBuffer,
            size_t count,
            const char *format,
            va_list argptr
        );
        """
        buffer, sizeOfBuffer, count, format, argptr = argv
        fmt_str = self.read_mem_string(format, 1)
        vargs = self.va_args(argptr, self.get_va_arg_count(fmt_str))
        fin = self.do_str_format(fmt_str, vargs)
        ctx.args[3].display = fmt_str
        return self._write_secure_counted_string(fin, buffer, sizeOfBuffer, count)

    @apihook("PsCreateSystemThread", argc=7)
    def PsCreateSystemThread(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS PsCreateSystemThread(
            PHANDLE ThreadHandle,
            ULONG DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            HANDLE ProcessHandle,
            PCLIENT_ID ClientId,
            PKSTART_ROUTINE StartRoutine,
            PVOID StartContext
        );
        """
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, StartContext = argv

        rv = ddk.STATUS_SUCCESS

        ptr_size = emu.get_ptr_size()
        proc_obj = emu.get_handle_table().get(ProcessHandle, objman.Process) if ProcessHandle else None
        if ProcessHandle and not proc_obj:
            return ddk.STATUS_INVALID_HANDLE

        handle, obj = self.create_thread(StartRoutine, StartContext, proc_obj)

        self.write_ptr(ThreadHandle, handle)

        if ClientId:
            cid = self.win.CLIENT_ID(ptr_size)
            cid.UniqueProcess = 4 if not ProcessHandle else 0
            cid.UniqueThread = obj.tid
            self.mem_write(ClientId, self.get_bytes(cid))

        return rv

    @apihook("RtlCopyUnicodeString", argc=2)
    def RtlCopyUnicodeString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlCopyUnicodeString(
            PUNICODE_STRING DestinationString,
            PCUNICODE_STRING SourceString
        );
        """
        DestinationString, SourceString = argv

        dest = self.win.UNICODE_STRING(emu.get_ptr_size())
        dest = self.mem_cast(dest, DestinationString)

        src = None
        if SourceString:
            src = self.win.UNICODE_STRING(emu.get_ptr_size())
            src = self.mem_cast(src, SourceString)

        if src is None or src.Buffer == 0 or dest.Buffer == 0:
            dest.Length = 0
        else:
            to_copy = min(src.Length, dest.MaximumLength)

            data = self.mem_read(src.Buffer, to_copy)
            ctx.args["SourceString"].display = data.decode("utf-16le", "replace")
            self.mem_write(dest.Buffer, data)
            dest.Length = to_copy

        self.mem_write(DestinationString, self.get_bytes(dest))

    @apihook("RtlEqualUnicodeString", argc=3)
    def RtlEqualUnicodeString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN RtlEqualUnicodeString(
            PCUNICODE_STRING String1,
            PCUNICODE_STRING String2,
            BOOLEAN CaseInSensitive
        );
        """
        String1, String2, CaseInSensitive = argv

        us = self.win.UNICODE_STRING(emu.get_ptr_size())
        us = self.mem_cast(us, String1)

        s1 = self.read_unicode_string(String1).replace("\x00", "")
        s2 = self.read_unicode_string(String2).replace("\x00", "")

        if CaseInSensitive:
            rv = s1.lower() == s2.lower()
        else:
            rv = s1 == s2

        ctx.args["String1"].display = s1
        ctx.args["String2"].display = s2
        return int(rv)

    @apihook("RtlCompareString", argc=3)
    def RtlCompareString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG RtlCompareString(
            const STRING *String1,
            const STRING *String2,
            BOOLEAN CaseInSensitive
        );
        """
        str1, str2, ci = argv
        texts = []
        for i, addr in enumerate((str1, str2)):
            ans = self.mem_cast(self.win.STRING(emu.get_ptr_size()), addr)
            data = self.mem_read(ans.Buffer, ans.Length)
            ctx.args[i].display = decode_ansi(data)
            if ci & 0xFF:
                data = data.translate(ANSI_UPPER_TABLE)
            # Latin-1 keeps the byte order of the compare.
            texts.append(data.decode("latin-1"))
        return get_string_order(texts[0], texts[1], Fold.NONE)

    @apihook("RtlCompareUnicodeString", argc=3)
    def RtlCompareUnicodeString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG RtlCompareUnicodeString(
            PCUNICODE_STRING String1,
            PCUNICODE_STRING String2,
            BOOLEAN CaseInSensitive
        );
        """
        str1, str2, ci = argv
        texts = []
        for i, addr in enumerate((str1, str2)):
            us = self.mem_cast(self.win.UNICODE_STRING(emu.get_ptr_size()), addr)
            # Length is in bytes, and the compare uses whole characters.
            data = self.mem_read(us.Buffer, us.Length // 2 * 2)
            ctx.args[i].display = data.decode("utf-16le", "replace")
            texts.append(data.decode("utf-16le", "surrogatepass"))
        return get_string_order(texts[0], texts[1], Fold.UPPER if ci & 0xFF else Fold.NONE)

    @apihook("IoAllocateIrp", argc=2)
    def IoAllocateIrp(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PIRP IoAllocateIrp(
            CCHAR StackSize,
            BOOLEAN ChargeQuota
        );
        """
        StackSize, ChargeQuota = argv

        StackSize = StackSize & 0xFF

        irp = emu.new_irp()
        rv = irp.address

        ctx.args[0].display = hex(StackSize)

        return rv

    @apihook("IoFreeIrp", argc=1)
    def IoFreeIrp(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoFreeIrp(
            PIRP Irp
        );
        """
        (Irp,) = argv

    @apihook("IoReuseIrp", argc=2)
    def IoReuseIrp(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoReuseIrp(
            PIRP Irp,
            NTSTATUS Iostatus
        );
        """
        Irp, Iostatus = argv

    @apihook("IoAllocateMdl", argc=5)
    def IoAllocateMdl(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PMDL IoAllocateMdl(
            PVOID VirtualAddress,
            ULONG Length,
            BOOLEAN SecondaryBuffer,
            BOOLEAN ChargeQuota,
            PIRP Irp
        );
        """
        VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp = argv
        return self._new_mdl(VirtualAddress, Length)

    @apihook("MmProbeAndLockPages", argc=3)
    def MmProbeAndLockPages(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID MmProbeAndLockPages(
            PMDL MemoryDescriptorList,
            KPROCESSOR_MODE AccessMode,
            LOCK_OPERATION Operation
        );
        """
        return

    @apihook("KeDelayExecutionThread", argc=3)
    def KeDelayExecutionThread(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS KeDelayExecutionThread(
            KPROCESSOR_MODE WaitMode,
            BOOLEAN Alertable,
            PLARGE_INTEGER Interval
        );
        """
        WaitMode, Alertable, Interval = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("KeSetEvent", argc=3)
    def KeSetEvent(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG KeSetEvent(
            PRKEVENT Event,
            KPRIORITY Increment,
            BOOLEAN Wait
        );

        Speakeasy does not model kernel events, so the event does not change.
        """
        Event, Increment, Wait = argv
        rv = 0

        return rv

    @apihook("IoCreateSynchronizationEvent", argc=2)
    def IoCreateSynchronizationEvent(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        PKEVENT IoCreateSynchronizationEvent(
            PUNICODE_STRING EventName,
            PHANDLE EventHandle
        );
        """
        EventName, EventHandle = argv

        name = self.read_unicode_string(EventName)

        hnd, evt = emu.create_event(name)

        if EventHandle:
            self.write_ptr(EventHandle, hnd)

        ctx.args[0].display = name
        return evt.address

    @apihook("KeInitializeEvent", argc=3)
    def KeInitializeEvent(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeInitializeEvent(
            PRKEVENT Event,
            EVENT_TYPE Type,
            BOOLEAN State
        );
        """
        return

    @apihook("KeResetEvent", argc=1)
    def KeResetEvent(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG KeResetEvent(
            PRKEVENT Event
        );
        """
        rv = 0

        return rv

    @apihook("KeClearEvent", argc=1)
    def KeClearEvent(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeClearEvent(
            PRKEVENT Event
        );
        """
        return

    @apihook("KeInitializeTimer", argc=1)
    def KeInitializeTimer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeInitializeTimer(
            PKTIMER Timer
        );
        """
        return

    @apihook("KeSetTimer", argc=4)
    def KeSetTimer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN KeSetTimer(
            PKTIMER Timer,
            LARGE_INTEGER DueTime,
            PKDPC Dpc
        );

        DueTime is passed by value: two stack slots on x86, one register on
        x64. argc=4 covers the x86 layout; on x64 the fourth slot is unused.

        Speakeasy does not model kernel timers, so the DPC of the timer does not run.
        """
        return True

    @apihook("PsLookupProcessByProcessId", argc=2)
    def PsLookupProcessByProcessId(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS PsLookupProcessByProcessId(
            HANDLE ProcessId,
            PEPROCESS *Process
        );
        """
        ProcessId, Process = argv
        rv = ddk.STATUS_SUCCESS

        if ProcessId == 4:
            proc = emu.get_system_process()
            self.write_ptr(Process, proc.address)
            return rv

        proc = self.get_object_from_id(ProcessId)
        if not proc:
            rv = ddk.STATUS_INVALID_CID
        else:
            self.write_ptr(Process, proc.address)

        return rv

    @apihook("ObOpenObjectByPointer", argc=7)
    def ObOpenObjectByPointer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ObOpenObjectByPointer(
            PVOID Object,
            ULONG HandleAttributes,
            PACCESS_STATE PassedAccessState,
            ACCESS_MASK DesiredAccess,
            POBJECT_TYPE ObjectType,
            KPROCESSOR_MODE AccessMode,
            PHANDLE Handle
        );
        """
        Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, Handle = argv
        rv = ddk.STATUS_SUCCESS

        obj = self.get_object_from_addr(Object)
        if not obj:
            return ddk.STATUS_INVALID_PARAMETER

        hnd = self.get_object_handle(obj)
        self.write_ptr(Handle, hnd)

        return rv

    @apihook("ZwOpenProcess", argc=4)
    def ZwOpenProcess(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwOpenProcess(
            PHANDLE ProcessHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            PCLIENT_ID ClientId
        );
        """
        ProcessHandle, DesiredAccess, ObjectAttributes, ClientId = argv

        if not ClientId:
            return ddk.STATUS_INVALID_PARAMETER_MIX

        hnd = emu.open_process(self.read_ptr(ClientId))
        if not hnd:
            return ddk.STATUS_INVALID_CID

        self.write_ptr(ProcessHandle, hnd)
        return ddk.STATUS_SUCCESS

    @apihook("ZwOpenProcessToken", argc=3)
    def ZwOpenProcessToken(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwOpenProcessToken(
            HANDLE ProcessHandle,
            ACCESS_MASK DesiredAccess,
            PHANDLE TokenHandle
        );
        """
        ProcessHandle, DesiredAccess, TokenHandle = argv

        proc = emu.get_handle_table().get(ProcessHandle, objman.Process)
        if not proc:
            return ddk.STATUS_INVALID_HANDLE

        self.write_ptr(TokenHandle, emu.get_handle_table().new_handle(proc.token))
        return ddk.STATUS_SUCCESS

    @apihook("ZwQueryInformationToken", argc=5)
    def ZwQueryInformationToken(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwQueryInformationToken(
            HANDLE TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            PVOID TokenInformation,
            ULONG TokenInformationLength,
            PULONG ReturnLength
        );
        """
        TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength = argv

        if not emu.get_handle_table().get(TokenHandle, objman.Token):
            return ddk.STATUS_INVALID_HANDLE

        status, size = query_token_information(
            self, emu, TokenInformationClass, TokenInformation, TokenInformationLength
        )
        if ReturnLength:
            self.write_dword(ReturnLength, size)
        return status

    @apihook("PsGetProcessPeb", argc=1)
    def PsGetProcessPeb(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PPEB PsGetProcessPeb(
            PEPROCESS Process
        );
        """
        (Process,) = argv

        proc = self.get_object_from_addr(Process)
        peb = emu.get_process_peb(proc)
        return peb.address

    @apihook("KeStackAttachProcess", argc=2)
    def KeStackAttachProcess(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeStackAttachProcess(
            PRKPROCESS PROCESS,
            PRKAPC_STATE ApcState
        );
        """
        PROCESS, ApcState = argv

        proc = self.get_object_from_addr(PROCESS)
        emu.set_current_process(proc)

    @apihook("KeUnstackDetachProcess", argc=1)
    def KeUnstackDetachProcess(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeUnstackDetachProcess(
            PRKAPC_STATE ApcState
        );

        Speakeasy does not save the process that KeStackAttachProcess replaced, so the attached process stays current.
        """
        # ApcState = argv[0]
        return

    @apihook("ZwProtectVirtualMemory", argc=5)
    def ZwProtectVirtualMemory(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwProtectVirtualMemory(
            HANDLE ProcessHandle,
            PVOID *BaseAddress,
            PSIZE_T RegionSize,
            ULONG NewProtection,
            PULONG OldProtection
        );

        Speakeasy does not check that the range is in one allocation.
        """
        ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection = argv

        proc = emu.get_handle_table().get(ProcessHandle, objman.Process)
        if not proc:
            return ddk.STATUS_INVALID_HANDLE

        addr = self.read_ptr(BaseAddress)
        size = self.read_ptr(RegionSize)
        ctx.args["BaseAddress"].display = hex(addr)
        ctx.args["RegionSize"].display = hex(size)
        prot_def = decode_flags(PAGE_PROTECTION_FLAGS, NewProtection)
        ctx.args["NewProtection"].display = "|".join(prot_def)
        if not size:
            return ddk.STATUS_INVALID_PARAMETER

        # Windows changes whole pages, and returns the page-aligned range to the caller.
        page_mask = emu.page_size - 1
        base = addr & ~page_mask
        region_size = ((addr + size + page_mask) & ~page_mask) - base
        # get_first_unmapped also returns the start of the range when the first page is unmapped.
        perms = next((p for start, end, p in emu.get_mem_regions() if start <= base <= end), None)
        if perms is None or get_first_unmapped(emu, base, region_size) != base:
            return ddk.STATUS_CONFLICTING_ADDRESSES

        # Windows returns the protection of the first page.
        if base in emu.guard_pages:
            old = self.emu_perms_to_win_perms(emu.guard_pages[base]) | PAGE_PROTECTION_FLAGS.PAGE_GUARD
        else:
            uc_to_perms = {v: k for k, v in emu.emu_eng.perms.items()}
            old = self.emu_perms_to_win_perms(uc_to_perms[perms])

        new = self.win_perms_to_emu_perms(NewProtection)
        emu.mem_protect(base, region_size, new)
        emu.clear_guard_pages(base, region_size)
        if NewProtection & PAGE_PROTECTION_FLAGS.PAGE_GUARD:
            emu.set_guard_pages(base, region_size, new)

        self.write_ptr(BaseAddress, base)
        self.write_ptr(RegionSize, region_size)
        if OldProtection:
            self.write_dword(OldProtection, old)

        self.record_process_event(proc, EventType.MEM_PROTECT, base=addr, size=size, protect=prot_def or None)
        return ddk.STATUS_SUCCESS

    @apihook("ZwWriteVirtualMemory", argc=5)
    def ZwWriteVirtualMemory(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwWriteVirtualMemory(
            HANDLE ProcessHandle,
            PVOID BaseAddress,
            PVOID Buffer,
            SIZE_T NumberOfBytesToWrite,
            PSIZE_T NumberOfBytesWritten
        );
        """
        ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten = argv
        rv = ddk.STATUS_SUCCESS

        obj = emu.get_handle_table().get(ProcessHandle, objman.Process)
        if not obj:
            return ddk.STATUS_INVALID_HANDLE

        ctx.args["ProcessHandle"].display = obj.path

        data = b""
        if Buffer and BaseAddress:
            data = self.mem_read(Buffer, NumberOfBytesToWrite)
            self.mem_write(BaseAddress, data)
            if NumberOfBytesWritten:
                bw = (len(data)).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(NumberOfBytesWritten, bw)
            obj.is_modified = True
        else:
            rv = ddk.STATUS_INVALID_PARAMETER

        self.record_process_event(obj, EventType.MEM_WRITE, base=BaseAddress, size=NumberOfBytesToWrite, data=data)

        return rv

    @apihook("ZwAllocateVirtualMemory", argc=6)
    def ZwAllocateVirtualMemory(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwAllocateVirtualMemory(
            HANDLE ProcessHandle,
            PVOID *BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T RegionSize,
            ULONG AllocationType,
            ULONG PageProtection
        );
        """
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, PageProtection = argv
        rv = ddk.STATUS_SUCCESS

        obj = emu.get_handle_table().get(ProcessHandle, objman.Process)
        if not obj:
            return ddk.STATUS_INVALID_HANDLE

        size = self.read_ptr(RegionSize)

        base = self.mem_read(BaseAddress, emu.get_ptr_size())
        base = int.from_bytes(base, "little")
        base = self.mem_alloc(size, tag=f"api.ZwAllocateVirtualMemory.{obj.image}", process=obj)

        emu._set_dyn_code_hook(base, size)

        self.write_ptr(BaseAddress, base)

        return rv

    @apihook("PsLookupThreadByThreadId", argc=2)
    def PsLookupThreadByThreadId(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS PsLookupThreadByThreadId(
            HANDLE ThreadId,
            PETHREAD *Thread
        );
        """
        ThreadId, Thread = argv
        rv = ddk.STATUS_INVALID_PARAMETER

        ethread_addr = 0

        obj = self.get_object_from_id(ThreadId)
        if obj:
            rv = ddk.STATUS_SUCCESS
            ethread_addr = obj.address
        self.write_ptr(Thread, ethread_addr)

        return rv

    @apihook("RtlGetVersion", argc=1)
    def RtlGetVersion(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlGetVersion(
            PRTL_OSVERSIONINFOW VersionInformation
        );
        """
        (VersionInformation,) = argv

        rv = ddk.STATUS_SUCCESS

        osver = emu.config.os_ver
        size = self.read_dword(VersionInformation)

        # Windows writes the extended fields only when the caller gives the size of RTL_OSVERSIONINFOEXW.
        vi: ntos.RTL_OSVERSIONINFOW | ntos.RTL_OSVERSIONINFOEXW = self.win.RTL_OSVERSIONINFOEXW(emu.get_ptr_size())
        if size != self.sizeof(vi):
            vi = self.win.RTL_OSVERSIONINFOW(emu.get_ptr_size())

        # Windows writes each field of the structure. The fields that the handler does not set, such as
        # szCSDVersion (no service pack), are zero and not the old bytes of the guest buffer.
        vi.dwOSVersionInfoSize = size
        vi.dwMajorVersion = osver.major or 0
        vi.dwMinorVersion = osver.minor or 0
        vi.dwBuildNumber = osver.build or 0
        vi.dwPlatformId = windefs.VER_PLATFORM_WIN32_NT
        if isinstance(vi, ntos.RTL_OSVERSIONINFOEXW):
            vi.wProductType = windefs.VER_NT_WORKSTATION

        self.mem_write(VersionInformation, self.get_bytes(vi))

        return rv

    @apihook("KeWaitForSingleObject", argc=5)
    def KeWaitForSingleObject(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS KeWaitForSingleObject(
            PVOID Object,
            KWAIT_REASON WaitReason,
            KPROCESSOR_MODE WaitMode,
            BOOLEAN Alertable,
            PLARGE_INTEGER Timeout
        );
        """
        Object, WaitReason, WaitMode, Alertable, Timeout = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("KeInitializeApc", argc=8)
    def KeInitializeApc(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeInitializeApc(
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
        Apc, Thread, Environment, KernelRoutine, RundownRoutine, NormalRoutine, ProcessorMode, NormalContext = argv

        apc = self.win.KAPC(emu.get_ptr_size())
        apc.Type = 0x12
        apc.Thread = Thread
        apc.ApcStateIndex = Environment
        apc.KernelRoutine = KernelRoutine
        apc.RundownRoutine = RundownRoutine
        apc.NormalRoutine = NormalRoutine

        if NormalRoutine:
            apc.ApcMode = ProcessorMode
            apc.NormalContext = NormalContext

    @apihook("MmMapLockedPagesSpecifyCache", argc=6)
    def MmMapLockedPagesSpecifyCache(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
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
        MemoryDescriptorList, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority = argv

        mdl = self.win.MDL(emu.get_ptr_size())
        mdl = self.mem_cast(mdl, MemoryDescriptorList)

        return mdl.StartVa + mdl.ByteOffset

    @apihook("KeInsertQueueApc", argc=4)
    def KeInsertQueueApc(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN KeInsertQueueApc(
            PKAPC Apc,
            PVOID SystemArgument1,
            PVOID SystemArgument2,
            KPRIORITY PriorityBoost
        );
        """
        Apc, SystemArgument1, SystemArgument2, PriorityBoost = argv
        rv = True

        return rv

    @apihook("KeInitializeDpc", argc=3)
    def KeInitializeDpc(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeInitializeDpc(
            PRKDPC Dpc,
            PKDEFERRED_ROUTINE DeferredRoutine,
            PVOID DeferredContext
        );
        """
        Dpc, DeferredRoutine, DeferredContext = argv

    @apihook("ObReferenceObjectByName", argc=8)
    def ObReferenceObjectByName(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ObReferenceObjectByName(
            PUNICODE_STRING ObjectName,
            ULONG Attributes,
            PACCESS_STATE PassedAccessState,
            ACCESS_MASK DesiredAccess,
            POBJECT_TYPE ObjectType,
            KPROCESSOR_MODE AccessMode,
            PVOID ParseContext,
            PVOID *Object
        );
        """
        ObjectName, Attributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, ParseContext, Object = argv
        rv = ddk.STATUS_INVALID_PARAMETER
        obj = None

        if not ObjectName:
            rv = ddk.STATUS_INVALID_PARAMETER
        else:
            name = self.read_unicode_string(ObjectName)
            name = name.replace("\x00", "")
            ctx.args[0].display = name

            obj = self.get_object_from_name(name)
            if not obj:
                rv = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        if obj:
            rv = ddk.STATUS_SUCCESS
            self.write_ptr(Object, obj.address)

        return rv

    @apihook("IoGetDeviceObjectPointer", argc=4)
    def IoGetDeviceObjectPointer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoGetDeviceObjectPointer(
            PUNICODE_STRING ObjectName,
            ACCESS_MASK DesiredAccess,
            PFILE_OBJECT *FileObject,
            PDEVICE_OBJECT *DeviceObject
        );
        """
        ObjectName, DesiredAccess, FileObject, DeviceObject = argv
        rv = ddk.STATUS_INVALID_PARAMETER

        s1 = self.read_unicode_string(ObjectName).replace("\x00", "")
        ctx.args[0].display = s1

        obj = self.get_object_from_name(s1)
        if obj:
            if obj.file_object:
                self.write_ptr(FileObject, obj.file_object.address)
            self.write_ptr(DeviceObject, obj.address)
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("PsTerminateSystemThread", argc=1)
    def PsTerminateSystemThread(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS PsTerminateSystemThread(
            NTSTATUS ExitStatus
        );
        """
        # ExitStatus = argv[0]

        rv = ddk.STATUS_SUCCESS
        return rv

    @apihook("IoRegisterBootDriverReinitialization", argc=3)
    def IoRegisterBootDriverReinitialization(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        VOID IoRegisterBootDriverReinitialization(
            PDRIVER_OBJECT DriverObject,
            PDRIVER_REINITIALIZE DriverReinitializationRoutine,
            PVOID Context
        );
        """
        DriverObject, DriverReinitializationRoutine, Context = argv

        self.queue_run(EntryPointType.DRIVER_REINIT, DriverReinitializationRoutine, (DriverObject, Context, 1))

    @apihook("KdDisableDebugger", argc=0)
    def KdDisableDebugger(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS KdDisableDebugger();
        """
        rv = ddk.STATUS_DEBUGGER_INACTIVE
        return rv

    @apihook("KdChangeOption", argc=6)
    def KdChangeOption(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS KdChangeOption(
            KD_OPTION Option,
            ULONG InBufferBytes,
            PVOID InBuffer,
            ULONG OutBufferBytes,
            PVOID OutBuffer,
            PULONG OutBufferNeeded
        );
        """
        rv = ddk.STATUS_DEBUGGER_INACTIVE
        return rv

    @apihook("MmGetSystemRoutineAddress", argc=1)
    def MmGetSystemRoutineAddress(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID MmGetSystemRoutineAddress(
            PUNICODE_STRING SystemRoutineName
        );
        """
        (SystemRoutineName,) = argv
        fn = self.read_unicode_string(SystemRoutineName)

        addr = 0
        for name in ("ntoskrnl", "hal"):
            module = emu.get_mod_by_name(name)
            if module is not None:
                addr = emu.resolve_export(module, fn)
                if addr:
                    break
        ctx.args[0].display = fn
        return addr

    @apihook("KeQuerySystemTime", argc=1)
    def KeQuerySystemTime(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeQuerySystemTime(
            PLARGE_INTEGER CurrentTime
        );
        """
        (CurrentTime,) = argv
        data = emu.api.load_api_handler("kernel32").get_system_time()
        data = data.to_bytes(8, "little")
        self.mem_write(CurrentTime, data)

    @apihook("KeQuerySystemTimePrecise", argc=1)
    def KeQuerySystemTimePrecise(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeQuerySystemTimePrecise(
            PLARGE_INTEGER CurrentTime
        );
        """
        self.KeQuerySystemTime(emu, argv, ctx)

    @apihook("RtlTimeToTimeFields", argc=2)
    def RtlTimeToTimeFields(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlTimeToTimeFields(
            PLARGE_INTEGER Time,
            PTIME_FIELDS TimeFields
        );
        """
        Time, TimeFields = argv

        quad = int.from_bytes(self.mem_read(Time, 8), "little")
        try:
            dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=quad // 10)
        except OverflowError:
            # datetime cannot hold a time after the year 9999
            return
        tf = ntos.TIME_FIELDS(emu.get_ptr_size())
        tf.Year = dt.year
        tf.Month = dt.month
        tf.Day = dt.day
        tf.Hour = dt.hour
        tf.Minute = dt.minute
        tf.Second = dt.second
        tf.Milliseconds = quad // 10000 % 1000
        tf.Weekday = dt.isoweekday() % 7
        self.mem_write(TimeFields, self.get_bytes(tf))

    @apihook("ExSystemTimeToLocalTime", argc=2)
    def ExSystemTimeToLocalTime(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExSystemTimeToLocalTime(
            PLARGE_INTEGER SystemTime,
            PLARGE_INTEGER LocalTime
        );
        """
        SystemTime, LocalTime = argv

        sys_time = self.mem_read(SystemTime, 8)
        int_sys_time = int.from_bytes(sys_time, "little")
        self.write_qword(LocalTime, int_sys_time)

    @apihook("CmRegisterCallbackEx", argc=6)
    def CmRegisterCallbackEx(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS CmRegisterCallbackEx(
            PEX_CALLBACK_FUNCTION Function,
            PCUNICODE_STRING Altitude,
            PVOID Driver,
            PVOID Context,
            PLARGE_INTEGER Cookie,
            PVOID Reserved
        );
        """
        # TODO: Emulate the callback routine
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("CmRegisterCallback", argc=3)
    def CmRegisterCallback(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS CmRegisterCallback(
            PEX_CALLBACK_FUNCTION Function,
            PVOID Context,
            PLARGE_INTEGER Cookie
        );
        """
        # TODO: Emulate the callback routine
        Function, Context, Cookie = argv

        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("CmUnRegisterCallback", argc=2)
    def CmUnRegisterCallback(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS CmUnRegisterCallback(
            LARGE_INTEGER Cookie
        );

        Cookie is passed by value: two stack slots on x86, one register on
        x64. argc=2 covers the x86 layout; on x64 the second slot is unused.
        """
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("EtwRegister", argc=4)
    def EtwRegister(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS EtwRegister(
            LPCGUID ProviderId,
            PETWENABLECALLBACK EnableCallback,
            PVOID CallbackContext,
            PREGHANDLE RegHandle
        );
        """
        ProviderId, EnableCallback, CallbackContext, RegHandle = argv
        rv = ddk.STATUS_SUCCESS

        guid = self.mem_read(ProviderId, 16)
        guid = uuid.UUID(bytes_le=guid)

        ctx.args[0].display = str(guid)

        return rv

    @apihook("RtlImageDirectoryEntryToData", argc=4)
    def RtlImageDirectoryEntryToData(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        PVOID RtlImageDirectoryEntryToData(
            PVOID BaseOfImage,
            BOOLEAN MappedAsImage,
            USHORT DirectoryEntry,
            PULONG Size
        );
        """
        BaseOfImage, MappedAsImage, DirectoryEntry, Size = argv

        MappedAsImage &= 0xFF
        DirectoryEntry &= 0xFFFF
        ctx.args["MappedAsImage"].display = hex(MappedAsImage)

        mm = emu.get_address_map(BaseOfImage)
        if not mm:
            return 0
        try:
            pe = pefile.PE(
                data=self.mem_read(BaseOfImage, min(0x1000, mm.base + mm.size - BaseOfImage)), fast_load=True
            )
        except pefile.PEFormatError:
            return 0
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if DirectoryEntry >= len(directories) or not directories[DirectoryEntry].VirtualAddress:
            return 0
        rva = directories[DirectoryEntry].VirtualAddress
        self.write_dword(Size, directories[DirectoryEntry].Size)
        if MappedAsImage or rva < pe.OPTIONAL_HEADER.SizeOfHeaders:
            return BaseOfImage + rva
        try:
            return BaseOfImage + pe.get_offset_from_rva(rva)
        except pefile.PEFormatError:
            return 0

    @apihook("ZwOpenEvent", argc=3)
    def ZwOpenEvent(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwOpenEvent(
            PHANDLE EventHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes
        );
        """
        EventHandle, DesiredAccess, ObjectAttributes = argv

        name = self._read_object_name(ObjectAttributes)

        obj = self.get_object_from_name(name)
        if not obj:
            rv = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        else:
            if EventHandle:
                hnd = emu.get_object_handle(obj)
                self.write_ptr(EventHandle, hnd)
            rv = ddk.STATUS_SUCCESS

        if name:
            ctx.args["ObjectAttributes"].display = name
        return rv

    @apihook("ZwCreateEvent", argc=5)
    def ZwCreateEvent(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwCreateEvent(
            PHANDLE EventHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            EVENT_TYPE EventType,
            BOOLEAN InitialState
        );
        """
        EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState = argv

        name = self._read_object_name(ObjectAttributes)

        hnd, evt = emu.create_event(name)
        if EventHandle:
            self.write_ptr(EventHandle, hnd)
        rv = ddk.STATUS_SUCCESS

        if name:
            ctx.args["ObjectAttributes"].display = name
        ctx.args["InitialState"].display = hex(0xFF & InitialState)

        return rv

    @apihook("ExInitializeResourceLite", argc=1)
    def ExInitializeResourceLite(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ExInitializeResourceLite(
            PERESOURCE Resource
        );
        """
        (Resource,) = argv

        return ddk.STATUS_SUCCESS

    @apihook("KeEnterCriticalRegion", argc=0)
    def KeEnterCriticalRegion(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeEnterCriticalRegion();
        """
        return

    @apihook("ExAcquireResourceExclusiveLite", argc=2)
    def ExAcquireResourceExclusiveLite(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOLEAN ExAcquireResourceExclusiveLite(
            PERESOURCE Resource,
            BOOLEAN Wait
        );
        """
        rv = True
        return rv

    @apihook("ExAcquireResourceSharedLite", argc=2)
    def ExAcquireResourceSharedLite(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOLEAN ExAcquireResourceSharedLite(
            PERESOURCE Resource,
            BOOLEAN Wait
        );
        """
        rv = True
        return rv

    @apihook("ExReleaseResourceLite", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExReleaseResourceLite(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExReleaseResourceLite(
            PERESOURCE Resource
        );
        """
        return

    @apihook("ExAcquireFastMutex", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExAcquireFastMutex(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExAcquireFastMutex(
            PFAST_MUTEX FastMutex
        );
        """
        (FastMutex,) = argv

    @apihook("ExReleaseFastMutex", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExReleaseFastMutex(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExReleaseFastMutex(
            PFAST_MUTEX FastMutex
        );
        """
        (FastMutex,) = argv

    @apihook("ObfReferenceObject", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ObfReferenceObject(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR ObfReferenceObject(
            PVOID Object
        );

        Speakeasy counts only the references of the object manager and of handles, so the count does not change.
        """
        return 0

    @apihook("RtlLengthRequiredSid", argc=1)
    def RtlLengthRequiredSid(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONG RtlLengthRequiredSid(
            ULONG SubAuthorityCount
        );
        """
        (SubAuthorityCount,) = argv
        header = windefs.SID(emu.get_ptr_size(), 0)
        return self.sizeof(header) + 4 * SubAuthorityCount

    @apihook("RtlInitializeSid", argc=3)
    def RtlInitializeSid(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlInitializeSid(
            PSID Sid,
            PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
            UCHAR SubAuthorityCount
        );
        """
        Sid, IdentifierAuthority, SubAuthorityCount = argv
        SubAuthorityCount &= 0xFF
        if SubAuthorityCount > 15:
            return ddk.STATUS_INVALID_PARAMETER
        header = windefs.SID(emu.get_ptr_size(), 0)
        header.Revision = 1
        header.SubAuthorityCount = SubAuthorityCount
        header.IdentifierAuthority = self.mem_read(IdentifierAuthority, 6)
        # Windows writes the header and does not change SubAuthority.
        self.mem_write(Sid, self.get_bytes(header))
        return ddk.STATUS_SUCCESS

    @apihook("RtlSubAuthoritySid", argc=2)
    def RtlSubAuthoritySid(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PULONG RtlSubAuthoritySid(
            PSID Sid,
            ULONG SubAuthority
        );
        """
        Sid, SubAuthority = argv
        header = windefs.SID(emu.get_ptr_size(), 0)
        return Sid + self.sizeof(header) + 4 * SubAuthority

    @apihook("RtlCreateAcl", argc=3)
    def RtlCreateAcl(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlCreateAcl(
            PACL Acl,
            ULONG AclLength,
            ULONG AclRevision
        );
        """
        # TODO, unimplemented
        Acl, AclLength, AclRevision = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("RtlSetDaclSecurityDescriptor", argc=4)
    def RtlSetDaclSecurityDescriptor(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlSetDaclSecurityDescriptor(
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            BOOLEAN DaclPresent,
            PACL Dacl,
            BOOLEAN DaclDefaulted
        );
        """
        # TODO, unimplemented
        SecurityDescriptor, DaclPresent, Dacl, DaclDefaulted = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("ObSetSecurityObjectByPointer", argc=3)
    def ObSetSecurityObjectByPointer(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS ObSetSecurityObjectByPointer(
            PVOID Object,
            SECURITY_INFORMATION SecurityInformation,
            PSECURITY_DESCRIPTOR SecurityDescriptor
        );
        """
        # TODO, unimplemented
        Object, SecurityInformation, SecurityDescriptor = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("RtlCreateSecurityDescriptor", argc=2)
    def RtlCreateSecurityDescriptor(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlCreateSecurityDescriptor(
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            ULONG Revision
        );
        """
        # TODO, unimplemented
        SecurityDescriptor, Revision = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("RtlAddAccessAllowedAce", argc=4)
    def RtlAddAccessAllowedAce(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlAddAccessAllowedAce(
            PACL Acl,
            ULONG AceRevision,
            ACCESS_MASK AccessMask,
            PSID Sid
        );
        """
        # TODO, unimplemented
        Acl, AceRevision, AccessMask, Sid = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("PoDeletePowerRequest", argc=1)
    def PoDeletePowerRequest(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID PoDeletePowerRequest(
            PVOID PowerRequest
        );
        """
        return

    @apihook("IoWMIRegistrationControl", argc=2)
    def IoWMIRegistrationControl(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoWMIRegistrationControl(
            PDEVICE_OBJECT DeviceObject,
            ULONG Action
        );
        """
        rv = ddk.STATUS_INVALID_PARAMETER

        DeviceObject, Action = argv
        if DeviceObject:
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("ObMakeTemporaryObject", argc=1)
    def ObMakeTemporaryObject(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ObMakeTemporaryObject(
            PVOID Object
        );
        """
        return

    @apihook("RtlGetCompressionWorkSpaceSize", argc=3)
    def RtlGetCompressionWorkSpaceSize(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlGetCompressionWorkSpaceSize(
            USHORT CompressionFormatAndEngine,
            PULONG CompressBufferWorkSpaceSize,
            PULONG CompressFragmentWorkSpaceSize
        );
        """
        CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize = argv
        if CompressBufferWorkSpaceSize:
            self.write_dword(CompressBufferWorkSpaceSize, 0x1000)
        if CompressFragmentWorkSpaceSize:
            self.write_dword(CompressFragmentWorkSpaceSize, 0x1000)
        return ddk.STATUS_SUCCESS

    @apihook("RtlCompressBuffer", argc=8)
    def RtlCompressBuffer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlCompressBuffer(
            USHORT CompressionFormatAndEngine,
            PUCHAR UncompressedBuffer,
            ULONG UncompressedBufferSize,
            PUCHAR CompressedBuffer,
            ULONG CompressedBufferSize,
            ULONG UncompressedChunkSize,
            PULONG FinalCompressedSize,
            PVOID WorkSpace
        );

        The output is valid LZNT1, but its bytes can differ from the output of Windows.
        """
        (
            CompressionFormatAndEngine,
            UncompressedBuffer,
            UncompressedBufferSize,
            CompressedBuffer,
            CompressedBufferSize,
            UncompressedChunkSize,
            FinalCompressedSize,
            WorkSpace,
        ) = argv

        algorithm = CompressionFormatAndEngine & 0xFF
        if algorithm in (ddk.COMPRESSION_FORMAT_NONE, ddk.COMPRESSION_FORMAT_DEFAULT):
            return ddk.STATUS_INVALID_PARAMETER
        if algorithm != ddk.COMPRESSION_FORMAT_LZNT1:
            return ddk.STATUS_UNSUPPORTED_COMPRESSION
        if CompressionFormatAndEngine & 0xFF00 not in (ddk.COMPRESSION_ENGINE_STANDARD, ddk.COMPRESSION_ENGINE_MAXIMUM):
            return ddk.STATUS_NOT_SUPPORTED

        data = self.mem_read(UncompressedBuffer, UncompressedBufferSize & 0xFFFFFFFF)
        comp = lznt1.compress(data)
        if len(comp) > CompressedBufferSize & 0xFFFFFFFF:
            return ddk.STATUS_BUFFER_TOO_SMALL

        self.mem_write(CompressedBuffer, comp)
        self.write_dword(FinalCompressedSize, len(comp))
        return ddk.STATUS_SUCCESS

    @apihook("RtlDecompressBuffer", argc=6)
    def RtlDecompressBuffer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlDecompressBuffer(
            USHORT CompressionFormat,
            PUCHAR UncompressedBuffer,
            ULONG UncompressedBufferSize,
            PUCHAR CompressedBuffer,
            ULONG CompressedBufferSize,
            PULONG FinalUncompressedSize
        );
        """
        (
            CompressionFormat,
            UncompressedBuffer,
            UncompressedBufferSize,
            CompressedBuffer,
            CompressedBufferSize,
            FinalUncompressedSize,
        ) = argv

        algorithm = CompressionFormat & 0xFF
        if algorithm != ddk.COMPRESSION_FORMAT_LZNT1:
            nts = ddk.STATUS_UNSUPPORTED_COMPRESSION
            return nts

        CompressedBufferSize &= 0xFFFFFFFF
        UncompressedBufferSize &= 0xFFFFFFFF

        data = self.mem_read(CompressedBuffer, CompressedBufferSize)

        try:
            dec = lznt1.decompress(data)
        except (ValueError, ZeroDivisionError, struct.error):
            return ddk.STATUS_BAD_COMPRESSION_BUFFER

        if UncompressedBufferSize < len(dec):
            nts = ddk.STATUS_BAD_COMPRESSION_BUFFER
            return nts

        self.write_dword(FinalUncompressedSize, len(dec))
        self.mem_write(UncompressedBuffer, dec)
        nts = ddk.STATUS_SUCCESS

        return nts

    @apihook("FsRtlAllocatePool", argc=2)
    def FsRtlAllocatePool(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID FsRtlAllocatePool(
            POOL_TYPE PoolType,
            ULONG NumberOfBytes
        );
        """
        PoolType, NumberOfBytes = argv

        chunk = self.pool_alloc(PoolType, NumberOfBytes, "None")
        return chunk

    @apihook("IofCallDriver", argc=2, conv=_arch.CALL_CONV_FASTCALL)
    def IofCallDriver(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IofCallDriver(
            PDEVICE_OBJECT DeviceObject,
            PIRP Irp
        );

        Speakeasy does not call the dispatch routine of the target driver or the completion routines. The IRP completes
        with STATUS_SUCCESS.
        """
        DeviceObject, Irp = argv
        rv = ddk.STATUS_SUCCESS

        _irp = self.win.IRP(emu.get_ptr_size())
        _irp = self.mem_cast(_irp, Irp)

        _irp.IoStatus.Status = 0
        self.mem_write(Irp, _irp.get_bytes())
        if _irp.UserIosb:
            self.mem_write(_irp.UserIosb, self.get_bytes(_irp.IoStatus))

        return rv

    @apihook("IoSetCompletionRoutineEx", argc=7)
    def IoSetCompletionRoutineEx(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS IoSetCompletionRoutineEx(
            PDEVICE_OBJECT DeviceObject,
            PIRP Irp,
            PIO_COMPLETION_ROUTINE CompletionRoutine,
            PVOID Context,
            BOOLEAN InvokeOnSuccess,
            BOOLEAN InvokeOnError,
            BOOLEAN InvokeOnCancel
        );
        """
        DeviceObject, Irp, CompletionRoutine, Context, InvokeOnSuccess, InvokeOnError, InvokeOnCancel = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("ExQueueWorkItem", argc=2)
    def ExQueueWorkItem(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExQueueWorkItem(
            PWORK_QUEUE_ITEM WorkItem,
            WORK_QUEUE_TYPE QueueType
        );

        Speakeasy does not run the work item.
        """
        WorkItem, QueueType = argv

    @apihook("ZwDeviceIoControlFile", argc=10)
    def ZwDeviceIoControlFile(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwDeviceIoControlFile(
            HANDLE FileHandle,
            HANDLE Event,
            PIO_APC_ROUTINE ApcRoutine,
            PVOID ApcContext,
            PIO_STATUS_BLOCK IoStatusBlock,
            ULONG IoControlCode,
            PVOID InputBuffer,
            ULONG InputBufferLength,
            PVOID OutputBuffer,
            ULONG OutputBufferLength
        );
        """
        (
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength,
        ) = argv
        nts = ddk.STATUS_SUCCESS

        obj = emu.get_handle_table().get(FileHandle)
        if obj is None:
            return ddk.STATUS_INVALID_HANDLE

        in_buf = b""
        if InputBuffer:
            in_buf = self.mem_read(InputBuffer, InputBufferLength)

        nts, outbuf = emu.dev_ioctl(emu.get_ptr_size(), obj, IoControlCode, in_buf)

        if OutputBuffer:
            if OutputBufferLength < len(outbuf):
                nts = ddk.STATUS_BUFFER_TOO_SMALL
            else:
                self.mem_write(OutputBuffer, outbuf)

        return nts

    @apihook("ObReferenceObjectByHandle", argc=6)
    def ObReferenceObjectByHandle(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ObReferenceObjectByHandle(
            HANDLE Handle,
            ACCESS_MASK DesiredAccess,
            POBJECT_TYPE ObjectType,
            KPROCESSOR_MODE AccessMode,
            PVOID *Object,
            POBJECT_HANDLE_INFORMATION HandleInformation
        );
        """
        Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation = argv

        nts = ddk.STATUS_SUCCESS

        obj = emu.get_handle_table().get(Handle, objman.KernelObject)
        if obj:
            if Object:
                self.write_ptr(Object, obj.address or 0)
        else:
            nts = ddk.STATUS_INVALID_HANDLE

        return nts

    @apihook("ObGetFilterVersion", argc=0)
    def ObGetFilterVersion(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        USHORT ObGetFilterVersion();
        """
        return 256

    @apihook("ObRegisterCallbacks", argc=2)
    def ObRegisterCallbacks(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ObRegisterCallbacks(
            POB_CALLBACK_REGISTRATION CallbackRegistration,
            PVOID *RegistrationHandle
        );
        """
        CallbackRegistration, RegistrationHandle = argv
        nts = ddk.STATUS_SUCCESS

        return nts

    @apihook("ZwDeleteKey", argc=1)
    def ZwDeleteKey(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwDeleteKey(
            HANDLE KeyHandle
        );
        """
        (KeyHandle,) = argv

        if not emu.regman.delete_key(KeyHandle):
            return ddk.STATUS_INVALID_HANDLE
        return ddk.STATUS_SUCCESS

    @apihook("ZwQueryInformationProcess", argc=5)
    def ZwQueryInformationProcess(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwQueryInformationProcess(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );
        """
        ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength = argv

        nts = ddk.STATUS_OBJECT_TYPE_MISMATCH

        obj = emu.get_handle_table().get(ProcessHandle, objman.Process)

        ptr_size = self.get_ptr_size()

        if obj:
            if ProcessInformationClass == ddk.PROCESSINFOCLASS.ProcessWow64Information:
                if ProcessInformationLength < self.get_ptr_size():
                    nts = ddk.STATUS_INFO_LENGTH_MISMATCH
                    if ReturnLength:
                        self.write_dword(ReturnLength, ptr_size)
                else:
                    if ReturnLength:
                        self.write_dword(ReturnLength, ptr_size)
                    # Send back that we are not in WOW64
                    self.write_ptr(ProcessInformation, 0)
                    nts = ddk.STATUS_SUCCESS
            elif ProcessInformationClass == ddk.PROCESSINFOCLASS.ProcessBasicInformation:
                size = 6 * ptr_size
                if ProcessInformationLength < size:
                    nts = ddk.STATUS_INFO_LENGTH_MISMATCH
                else:
                    peb = getattr(getattr(obj, "peb", None), "address", 0)
                    parent = next((p.pid for p in emu.get_processes() if p.name.lower() == "explorer"), 0)
                    fields = (ddk.STATUS_PENDING, peb, 1, 8, obj.pid, parent)
                    self.mem_write(ProcessInformation, b"".join(f.to_bytes(ptr_size, "little") for f in fields))
                    if ReturnLength:
                        self.write_dword(ReturnLength, size)
                    nts = ddk.STATUS_SUCCESS
            elif ProcessInformationClass == ddk.PROCESSINFOCLASS.ProcessDebugPort:
                # No debugger is attached
                nts = self.write_process_info(ProcessInformation, ProcessInformationLength, ReturnLength, 0, ptr_size)
            elif ProcessInformationClass == ddk.PROCESSINFOCLASS.ProcessDebugFlags:
                nts = self.write_process_info(ProcessInformation, ProcessInformationLength, ReturnLength, 1, 4)
            elif ProcessInformationClass == ddk.PROCESSINFOCLASS.ProcessDebugObjectHandle:
                nts = self.write_process_info(ProcessInformation, ProcessInformationLength, ReturnLength, 0, ptr_size)
                if nts == ddk.STATUS_SUCCESS:
                    nts = ddk.STATUS_PORT_NOT_SET
        else:
            nts = ddk.STATUS_INVALID_HANDLE

        return nts

    def write_process_info(self, proc_info, proc_info_len, retlen, value, size):
        """
        Write a fixed-size ZwQueryInformationProcess result. Windows requires
        the exact length for these classes.
        """
        if proc_info_len != size:
            return ddk.STATUS_INFO_LENGTH_MISMATCH
        self.mem_write(proc_info, value.to_bytes(size, "little"))
        if retlen:
            self.write_dword(retlen, size)
        return ddk.STATUS_SUCCESS

    @apihook("IoGetCurrentProcess", argc=0)
    def IoGetCurrentProcess(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PEPROCESS IoGetCurrentProcess();
        """
        p = emu.get_current_process()
        return p.address

    @apihook("PsGetCurrentProcessId", argc=0)
    def PsGetCurrentProcessId(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE PsGetCurrentProcessId();
        """
        p = emu.get_current_process()
        pid = getattr(p, "pid", None)
        return pid if pid is not None else 4

    @apihook("PsGetProcessId", argc=1)
    def PsGetProcessId(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE PsGetProcessId(
            PEPROCESS Process
        );
        """
        (Process,) = argv
        proc = self.get_object_from_addr(Process)
        return getattr(proc, "pid", 0)

    @apihook("NtSetInformationThread", argc=4)
    def NtSetInformationThread(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS NtSetInformationThread(
            HANDLE ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID ThreadInformation,
            ULONG ThreadInformationLength
        );
        """
        ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength = argv

        if ThreadInformationClass == ddk.THREADINFOCLASS.ThreadHideFromDebugger:
            if ThreadInformationLength:
                return ddk.STATUS_INFO_LENGTH_MISMATCH
            if not emu.get_handle_table().get(ThreadHandle, objman.Thread):
                return ddk.STATUS_INVALID_HANDLE

        return ddk.STATUS_SUCCESS

    @apihook("IoRegisterShutdownNotification", argc=1)
    def IoRegisterShutdownNotification(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS IoRegisterShutdownNotification(
            PDEVICE_OBJECT DeviceObject
        );
        """
        (DeviceObject,) = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("IoRegisterLastChanceShutdownNotification", argc=1)
    def IoRegisterLastChanceShutdownNotification(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS IoRegisterLastChanceShutdownNotification(
            PDEVICE_OBJECT DeviceObject
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("IoUnregisterShutdownNotification", argc=1)
    def IoUnregisterShutdownNotification(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        VOID IoUnregisterShutdownNotification(
            PDEVICE_OBJECT DeviceObject
        );
        """
        (DeviceObject,) = argv
        return ddk.STATUS_SUCCESS

    @apihook("KeGetCurrentIrql", argc=0)
    def KeGetCurrentIrql(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        KIRQL KeGetCurrentIrql();
        """
        return emu.get_current_irql()

    @apihook("KeAcquireSpinLockRaiseToDpc", argc=1)
    def KeAcquireSpinLockRaiseToDpc(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        KIRQL KeAcquireSpinLockRaiseToDpc(
            PKSPIN_LOCK SpinLock
        );
        """
        (SpinLock,) = argv
        irql = emu.get_current_irql()
        emu.set_current_irql(ddk.DISPATCH_LEVEL)
        return irql

    @apihook("KeInitializeSpinLock", argc=1)
    def KeInitializeSpinLock(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeInitializeSpinLock(
            PKSPIN_LOCK SpinLock
        );
        """
        (SpinLock,) = argv
        if SpinLock:
            self.mem_write(SpinLock, b"\x00" * emu.get_ptr_size())

    @apihook("KeAcquireSpinLock", argc=2)
    def KeAcquireSpinLock(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeAcquireSpinLock(
            PKSPIN_LOCK SpinLock,
            PKIRQL OldIrql
        );
        """
        SpinLock, OldIrql = argv
        irql = emu.get_current_irql()
        if OldIrql:
            self.mem_write(OldIrql, bytes([irql]))
        emu.set_current_irql(ddk.DISPATCH_LEVEL)

    @apihook("KeReleaseSpinLock", argc=2)
    def KeReleaseSpinLock(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeReleaseSpinLock(
            PKSPIN_LOCK SpinLock,
            KIRQL NewIrql
        );
        """
        SpinLock, NewIrql = argv
        if NewIrql:
            emu.set_current_irql(NewIrql & 0xFF)
        else:
            emu.set_current_irql(ddk.PASSIVE_LEVEL)

    @apihook("MmUnlockPages", argc=1)
    def MmUnlockPages(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID MmUnlockPages(
            PMDL MemoryDescriptorList
        );
        """
        (MemoryDescriptorList,) = argv

    @apihook("IoFreeMdl", argc=1)
    def IoFreeMdl(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID IoFreeMdl(
            PMDL Mdl
        );
        """
        (Mdl,) = argv

    @apihook("KeCancelTimer", argc=1)
    def KeCancelTimer(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN KeCancelTimer(
            PKTIMER unnamedParam1
        );
        """
        rv = 1
        return rv

    @apihook("PsGetVersion", argc=4)
    def PsGetVersion(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN PsGetVersion(
            PULONG MajorVersion,
            PULONG MinorVersion,
            PULONG BuildNumber,
            PUNICODE_STRING CSDVersion
        );
        """
        MajorVersion, MinorVersion, BuildNumber, CSDVersion = argv

        ver = self.emu.config.os_ver

        if MajorVersion:
            self.write_dword(MajorVersion, ver.major or 0)

        if MinorVersion:
            self.write_dword(MinorVersion, ver.minor or 0)

        if BuildNumber:
            self.write_dword(BuildNumber, ver.build or 0)

        return 0

    @apihook("PsSetCreateProcessNotifyRoutineEx", argc=2)
    def PsSetCreateProcessNotifyRoutineEx(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS PsSetCreateProcessNotifyRoutineEx(
            PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
            BOOLEAN Remove
        );
        """
        NotifyRoutine, Remove = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("PsSetLoadImageNotifyRoutine", argc=1)
    def PsSetLoadImageNotifyRoutine(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS PsSetLoadImageNotifyRoutine(
            PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
        );
        """
        (NotifyRoutine,) = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("PsRemoveLoadImageNotifyRoutine", argc=1)
    def PsRemoveLoadImageNotifyRoutine(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS PsRemoveLoadImageNotifyRoutine(
            PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
        );
        """
        (NotifyRoutine,) = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("PsSetCreateThreadNotifyRoutine", argc=1)
    def PsSetCreateThreadNotifyRoutine(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS PsSetCreateThreadNotifyRoutine(
            PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
        );
        """
        (NotifyRoutine,) = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("PsRemoveCreateThreadNotifyRoutine", argc=1)
    def PsRemoveCreateThreadNotifyRoutine(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS PsRemoveCreateThreadNotifyRoutine(
            PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
        );
        """
        (NotifyRoutine,) = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("ZwOpenKey", argc=3)
    def ZwOpenKey(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwOpenKey(
            PHANDLE KeyHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes
        );
        """
        KeyHandle, DesiredAccess, ObjectAttributes = argv
        rv = ddk.STATUS_SUCCESS

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, ObjectAttributes)
        name = self.read_unicode_string(oa.ObjectName)

        ctx.args["ObjectAttributes"].display = name

        hnd = self.reg_open_key(name, create=False, access=DesiredAccess)
        if not hnd:
            return ddk.STATUS_OBJECT_NAME_NOT_FOUND

        if KeyHandle:
            self.write_ptr(KeyHandle, hnd)

        return rv

    @apihook("ZwQueryValueKey", argc=6)
    def ZwQueryValueKey(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwQueryValueKey(
            HANDLE KeyHandle,
            PUNICODE_STRING ValueName,
            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            PVOID KeyValueInformation,
            ULONG Length,
            PULONG ResultLength
        );
        """
        KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength = argv
        rv = ddk.STATUS_INVALID_HANDLE

        name = ""
        if ValueName:
            name = self.read_unicode_string(ValueName)
            ctx.args["ValueName"].display = name

        key = self.get_reg_key(KeyHandle)
        if key:
            ValueName = emu.regman.read_value(key, name, 2, handle=KeyHandle, buffer=KeyValueInformation, size=Length)
            if ValueName:
                data = ValueName.get_bytes(2)
                output = b""
                if KeyValueInformationClass == regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation:
                    partial = regdefs.KEY_VALUE_PARTIAL_INFORMATION(emu.get_ptr_size())
                    partial.Type = ValueName.get_type()
                    partial.DataLength = len(data)
                    output = self.get_bytes(partial) + data
                elif KeyValueInformationClass in (
                    regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation,
                    regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformationAlign64,
                ):
                    vi = regdefs.KEY_VALUE_FULL_INFORMATION(emu.get_ptr_size())
                    vi.Type = ValueName.get_type()
                    val_name = ValueName.get_name().encode("utf-16le")
                    vi.NameLength = len(val_name)
                    vi.DataLength = len(data)
                    padding = b""
                    if data:
                        align = 4
                        if (
                            emu.get_ptr_size() == 8
                            or KeyValueInformationClass
                            == regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformationAlign64
                        ):
                            align = 8
                        name_end = self.sizeof(vi) + len(val_name)
                        vi.DataOffset = (name_end + align - 1) & ~(align - 1)
                        padding = b"\x00" * (vi.DataOffset - name_end)
                    else:
                        vi.DataOffset = 0xFFFFFFFF
                    output = self.get_bytes(vi) + val_name + padding + data
                else:
                    raise ApiEmuError(f"Unsupported information class: 0x{KeyValueInformationClass:x}")
                self.write_dword(ResultLength, len(output))
                if len(output) > Length:
                    rv = ddk.STATUS_BUFFER_TOO_SMALL
                else:
                    self.mem_write(KeyValueInformation, output)
                    rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("ZwCreateKey", argc=7)
    def ZwCreateKey(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwCreateKey(
            PHANDLE KeyHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            ULONG TitleIndex,
            PUNICODE_STRING Class,
            ULONG CreateOptions,
            PULONG Disposition
        );
        """
        KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition = argv

        oa = self.mem_cast(self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size()), ObjectAttributes)
        path = self.read_unicode_string(oa.ObjectName) if oa.ObjectName else ""
        if oa.RootDirectory:
            root = self.get_reg_key(oa.RootDirectory)
            if not root:
                return ddk.STATUS_INVALID_HANDLE
            path = f"{root.get_path()}\\{path}" if path else root.get_path()
        ctx.args["ObjectAttributes"].display = path

        existing = emu.reg_get_key(path=path)
        disp = regdefs.REG_OPENED_EXISTING_KEY if existing else regdefs.REG_CREATED_NEW_KEY
        hnd = self.reg_open_key(path, create=True, disposition=disp, access=DesiredAccess)
        key = self.get_reg_key(hnd)
        if not hnd or not key:
            return ddk.STATUS_OBJECT_NAME_NOT_FOUND

        if KeyHandle:
            self.write_ptr(KeyHandle, hnd)
        if Disposition:
            self.write_dword(Disposition, disp)

        return ddk.STATUS_SUCCESS

    @apihook("ZwSetValueKey", argc=6)
    def ZwSetValueKey(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwSetValueKey(
            HANDLE KeyHandle,
            PUNICODE_STRING ValueName,
            ULONG TitleIndex,
            ULONG Type,
            PVOID Data,
            ULONG DataSize
        );
        """
        KeyHandle, ValueName, TitleIndex, Type, Data, DataSize = argv
        Type &= 0xFFFFFFFF
        DataSize &= 0xFFFFFFFF

        key = self.get_reg_key(KeyHandle)
        if not key:
            return ddk.STATUS_INVALID_HANDLE

        name = self.read_unicode_string(ValueName) if ValueName else ""
        ctx.args["ValueName"].display = name

        raw = self.mem_read(Data, DataSize) if Data and DataSize else b""
        value_data: str | int | bytes
        if Type in (REG_VALUE_TYPE.REG_SZ, REG_VALUE_TYPE.REG_EXPAND_SZ, REG_VALUE_TYPE.REG_MULTI_SZ):
            value_data = raw.decode("utf-16le", errors="replace").rstrip("\x00")
            ctx.args["Data"].display = value_data
        elif Type == REG_VALUE_TYPE.REG_DWORD:
            value_data = int.from_bytes(raw[:4].ljust(4, b"\x00"), "little")
        elif Type == REG_VALUE_TYPE.REG_QWORD:
            value_data = int.from_bytes(raw[:8].ljust(8, b"\x00"), "little")
        else:
            value_data = raw

        emu.regman.write_value(key, name, Type, value_data, raw=raw, handle=KeyHandle, buffer=Data)
        return ddk.STATUS_SUCCESS

    @apihook("ZwCreateFile", argc=11)
    def ZwCreateFile(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwCreateFile(
            PHANDLE FileHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            PIO_STATUS_BLOCK IoStatusBlock,
            PLARGE_INTEGER AllocationSize,
            ULONG FileAttributes,
            ULONG ShareAccess,
            ULONG CreateDisposition,
            ULONG CreateOptions,
            PVOID EaBuffer,
            ULONG EaLength
        );
        """
        (
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength,
        ) = argv

        nts = ddk.STATUS_SUCCESS

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, ObjectAttributes)
        name = self.read_unicode_string(oa.ObjectName)

        CreateDisposition = 0xFFFFFFFF & CreateDisposition

        ctx.args["ObjectAttributes"].display = name
        cd = decode(NT_CREATE_FILE_DISPOSITION, CreateDisposition)
        ctx.args["CreateDisposition"].display = cd

        ad = decode_flags(FILE_ACCESS_FLAGS, DesiredAccess) if DesiredAccess else None
        ctx.args["DesiredAccess"].display = decode(FILE_ACCESS_FLAGS, DesiredAccess)

        npath = name
        if name.startswith("\\??\\"):
            npath = name.removeprefix("\\??\\")
        npath = npath.rstrip("\\")

        open_flags = {"disposition": cd, "access": ad}
        obj = self.get_object_from_name(name)
        if obj:
            hnd = self.get_object_handle(obj)
            self.write_ptr(FileHandle, hnd)
            emu.get_file_manager().record_open(name, handle=hnd, **open_flags)

        else:
            hfile = 0
            # Does the file being opened exist in our emulation space?
            if self.does_file_exist(npath):
                if CreateDisposition == NT_CREATE_FILE_DISPOSITION.FILE_SUPERSEDE:
                    hfile = self.file_open(npath, create=True, **open_flags)
                elif CreateDisposition == NT_CREATE_FILE_DISPOSITION.FILE_CREATE:
                    nts = ddk.STATUS_UNSUCCESSFUL
                    emu.get_file_manager().record_open(npath, **open_flags)
                elif CreateDisposition in (
                    NT_CREATE_FILE_DISPOSITION.FILE_OPEN,
                    NT_CREATE_FILE_DISPOSITION.FILE_OPEN_IF,
                ):
                    hfile = self.file_open(npath, create=False, **open_flags)
                elif CreateDisposition in (
                    NT_CREATE_FILE_DISPOSITION.FILE_OVERWRITE,
                    NT_CREATE_FILE_DISPOSITION.FILE_OVERWRITE_IF,
                ):
                    hfile = self.file_open(npath, create=True, **open_flags)
            elif CreateDisposition in (
                NT_CREATE_FILE_DISPOSITION.FILE_SUPERSEDE,
                NT_CREATE_FILE_DISPOSITION.FILE_CREATE,
            ):
                hfile = self.file_open(npath, create=True, **open_flags)
            elif CreateDisposition in (
                NT_CREATE_FILE_DISPOSITION.FILE_OPEN,
                NT_CREATE_FILE_DISPOSITION.FILE_OVERWRITE,
            ):
                nts = ddk.STATUS_UNSUCCESSFUL
                emu.get_file_manager().record_open(npath, **open_flags)
            elif CreateDisposition in (
                NT_CREATE_FILE_DISPOSITION.FILE_OPEN_IF,
                NT_CREATE_FILE_DISPOSITION.FILE_OVERWRITE_IF,
            ):
                hfile = self.file_open(npath, create=True, **open_flags)

            self.write_ptr(FileHandle, hfile)

        return nts

    @apihook("ZwOpenFile", argc=6)
    def ZwOpenFile(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwOpenFile(
            PHANDLE FileHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            PIO_STATUS_BLOCK IoStatusBlock,
            ULONG ShareAccess,
            ULONG OpenOptions
        );
        """
        FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions = argv

        nts = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        hfile = None

        oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
        oa = self.mem_cast(oa, ObjectAttributes)
        path = self.read_unicode_string(oa.ObjectName)

        ctx.args["ObjectAttributes"].display = path
        ad = decode_flags(FILE_ACCESS_FLAGS, DesiredAccess) if DesiredAccess else None
        ctx.args["DesiredAccess"].display = decode(FILE_ACCESS_FLAGS, DesiredAccess)

        obj = self.get_object_from_name(path)
        if obj:
            nts = ddk.STATUS_SUCCESS
            hfile = self.get_object_handle(obj)
            emu.get_file_manager().record_open(path, handle=hfile, access=ad)
        else:
            # Is a file being opened?
            npath = path
            if path.startswith("\\??\\"):
                npath = path.removeprefix("\\??\\")
            npath = npath.rstrip("\\")
            hfile = emu.file_open(npath, access=ad)
            if hfile:
                nts = ddk.STATUS_SUCCESS

        if hfile:
            self.write_ptr(FileHandle, hfile)

        return nts

    @apihook("ZwQueryInformationFile", argc=5)
    def ZwQueryInformationFile(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwQueryInformationFile(
            HANDLE FileHandle,
            PIO_STATUS_BLOCK IoStatusBlock,
            PVOID FileInformation,
            ULONG Length,
            FILE_INFORMATION_CLASS FileInformationClass
        );
        """
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass = argv

        nts = ddk.STATUS_INVALID_PARAMETER
        _file = self.get_file(FileHandle)
        if not _file:
            return ddk.STATUS_INVALID_HANDLE

        if FileInformation:
            if FileInformationClass == ddk.FILE_INFORMATION_CLASS.FileStandardInformation:
                fsi = self.win.FILE_STANDARD_INFORMATION(emu.get_ptr_size())
                if Length >= self.sizeof(fsi):
                    nts = ddk.STATUS_SUCCESS
                    fsi.AllocationSize.QuadPart = 512 - (_file.get_size() % 512)
                    fsi.EndOfFile.QuadPart = _file.get_size()
                    self.mem_write(FileInformation, self.get_bytes(fsi))

                else:
                    nts = ddk.STATUS_INFO_LENGTH_MISMATCH

        return nts

    @apihook("RtlCompareMemory", argc=3)
    def RtlCompareMemory(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SIZE_T RtlCompareMemory(
            const VOID *Source1,
            const VOID *Source2,
            SIZE_T Length
        );
        """
        Source1, Source2, Length = argv

        Source1 = self.mem_read(Source1, Length)
        Source2 = self.mem_read(Source2, Length)
        for i in range(Length):
            if Source1[i] != Source2[i]:
                return i

        return Length

    @apihook("RtlQueryRegistryValuesEx", argc=5)
    def RtlQueryRegistryValuesEx(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlQueryRegistryValuesEx(
            ULONG RelativeTo,
            PCWSTR Path,
            PRTL_QUERY_REGISTRY_TABLE QueryTable,
            PVOID Context,
            PVOID Environment
        );
        """
        rv = ddk.STATUS_SUCCESS
        # TODO: complete this api handler
        RelativeTo, Path, QueryTable, Context, Environment = argv
        _relatives = {
            regdefs.RTL_REGISTRY_ABSOLUTE: "",
            regdefs.RTL_REGISTRY_SERVICES: "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
            regdefs.RTL_REGISTRY_CONTROL: "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\",
            regdefs.RTL_REGISTRY_WINDOWS_NT: "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\",
            regdefs.RTL_REGISTRY_DEVICEMAP: "\\Registry\\Machine\\Hardware\\DeviceMap\\",
            regdefs.RTL_REGISTRY_USER: "\\Registry\\User\\CurrentUser\\",
        }

        path_str = self.read_wide_string(Path)
        ctx.args["Path"].display = path_str

        return rv

    @apihook("ZwWriteFile", argc=9)
    def ZwWriteFile(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwWriteFile(
            HANDLE FileHandle,
            HANDLE Event,
            PIO_APC_ROUTINE ApcRoutine,
            PVOID ApcContext,
            PIO_STATUS_BLOCK IoStatusBlock,
            PVOID Buffer,
            ULONG Length,
            PLARGE_INTEGER ByteOffset,
            PULONG Key
        );
        """
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key = argv
        Length = Length & 0xFFFFFFFF

        nts = ddk.STATUS_INVALID_PARAMETER
        _file = self.get_file(FileHandle)
        if not _file:
            return ddk.STATUS_INVALID_HANDLE

        if Buffer and Length:
            path = _file.path
            ctx.args["FileHandle"].display = path

            data = self.mem_read(Buffer, Length)
            if data:
                self.seek_to_byte_offset(_file, ByteOffset)
                emu.get_file_manager().write_file(_file, data, buffer=Buffer)

                # Is it ascii?
                try:
                    data = data.decode("utf-8")
                except UnicodeDecodeError:
                    data = data.hex()
                ctx.args["Buffer"].display = data[:0x10]
                nts = ddk.STATUS_SUCCESS
                self.write_io_status(IoStatusBlock, nts, Length)

        return nts

    @apihook("ZwReadFile", argc=9)
    def ZwReadFile(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwReadFile(
            HANDLE FileHandle,
            HANDLE Event,
            PIO_APC_ROUTINE ApcRoutine,
            PVOID ApcContext,
            PIO_STATUS_BLOCK IoStatusBlock,
            PVOID Buffer,
            ULONG Length,
            PLARGE_INTEGER ByteOffset,
            PULONG Key
        );
        """
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key = argv

        Length = Length & 0xFFFFFFFF

        nts = ddk.STATUS_INVALID_PARAMETER
        _file = self.get_file(FileHandle)
        if not _file:
            return ddk.STATUS_INVALID_HANDLE

        if Buffer:
            path = _file.path
            ctx.args["FileHandle"].display = path

            self.seek_to_byte_offset(_file, ByteOffset)
            data = emu.get_file_manager().read_file(_file, Length, buffer=Buffer)
            self.mem_write(Buffer, data)

            nts = ddk.STATUS_SUCCESS if data or not Length else ddk.STATUS_END_OF_FILE
            self.write_io_status(IoStatusBlock, nts, len(data))

        return nts

    def seek_to_byte_offset(self, _file, offset):
        """
        Move the file pointer to the LARGE_INTEGER at ``offset``. A NULL pointer
        or a negative value keeps the current file pointer.
        """
        if not offset:
            return
        pos = int.from_bytes(self.mem_read(offset, 8), "little", signed=True)
        if pos >= 0:
            _file.seek(pos, io.SEEK_SET)

    def write_io_status(self, ios, status, information):
        if ios:
            ptr_size = self.get_ptr_size()
            self.mem_write(ios, status.to_bytes(ptr_size, "little") + information.to_bytes(ptr_size, "little"))

    @apihook("MmIsDriverVerifying", argc=1)
    def MmIsDriverVerifying(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LOGICAL MmIsDriverVerifying(
            struct _DRIVER_OBJECT *DriverObject
        );
        """
        (DriverObject,) = argv
        rv = False

        return rv

    @apihook("ZwCreateSection", argc=7)
    def ZwCreateSection(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwCreateSection(
            PHANDLE SectionHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            PLARGE_INTEGER MaximumSize,
            ULONG SectionPageProtection,
            ULONG AllocationAttributes,
            HANDLE FileHandle
        );
        """
        (
            SectionHandle,
            DesiredAccess,
            ObjectAttributes,
            MaximumSize,
            SectionPageProtection,
            AllocationAttributes,
            FileHandle,
        ) = argv

        fm = emu.get_file_manager()

        if not SectionHandle:
            return ddk.STATUS_INVALID_PARAMETER

        name = None
        if ObjectAttributes:
            oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
            oa = self.mem_cast(oa, ObjectAttributes)
            if oa.ObjectName:
                name = self.read_unicode_string(oa.ObjectName)
                ctx.args["ObjectAttributes"].display = name

        size = 0
        if MaximumSize:
            size = self.mem_read(MaximumSize, 8)
            size = int.from_bytes(size, "little")
        hmap = fm.file_create_mapping(FileHandle, name, size, SectionPageProtection)
        if hmap is None:
            return ddk.STATUS_INVALID_HANDLE
        self.write_ptr(SectionHandle, hmap)
        ctx.args["SectionHandle"].display = hex(hmap)

        return ddk.STATUS_SUCCESS

    @apihook("ZwOpenSection", argc=3)
    def ZwOpenSection(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwOpenSection(
            PHANDLE SectionHandle,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes
        );
        """
        SectionHandle, DesiredAccess, ObjectAttributes = argv
        if not SectionHandle or not ObjectAttributes:
            return ddk.STATUS_INVALID_PARAMETER

        oa = self.mem_cast(self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size()), ObjectAttributes)
        name = self.read_unicode_string(oa.ObjectName) if oa.ObjectName else ""
        ctx.args["ObjectAttributes"].display = name
        if name.lower() == "\\device\\physicalmemory":
            return ddk.STATUS_ACCESS_DENIED

        hmap = emu.get_file_manager().open_mapping(name)
        if hmap is None:
            return ddk.STATUS_OBJECT_NAME_NOT_FOUND
        self.write_ptr(SectionHandle, hmap)
        ctx.args["SectionHandle"].display = hex(hmap)
        return ddk.STATUS_SUCCESS

    @apihook("ZwUnmapViewOfSection", argc=2)
    def ZwUnmapViewOfSection(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwUnmapViewOfSection(
            HANDLE ProcessHandle,
            PVOID BaseAddress
        );
        """
        ProcessHandle, BaseAddress = argv
        proc = emu.get_handle_table().get(ProcessHandle, objman.Process)
        if not proc:
            return ddk.STATUS_INVALID_HANDLE
        if proc is not emu.get_current_process():
            return ddk.STATUS_SUCCESS
        mm = emu.get_address_map(BaseAddress)
        if not mm:
            return ddk.STATUS_NOT_MAPPED_VIEW
        self.mem_free(mm.base)
        return ddk.STATUS_SUCCESS

    @apihook("ZwMapViewOfSection", argc=10)
    def ZwMapViewOfSection(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwMapViewOfSection(
            HANDLE SectionHandle,
            HANDLE ProcessHandle,
            PVOID *BaseAddress,
            ULONG_PTR ZeroBits,
            SIZE_T CommitSize,
            PLARGE_INTEGER SectionOffset,
            PSIZE_T ViewSize,
            SECTION_INHERIT InheritDisposition,
            ULONG AllocationType,
            ULONG PageProtection
        );
        """
        (
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            CommitSize,
            SectionOffset,
            ViewSize,
            InheritDisposition,
            AllocationType,
            PageProtection,
        ) = argv

        rv = ddk.STATUS_INVALID_HANDLE
        fman = emu.get_file_manager()

        sect = fman.get_mapping(SectionHandle)
        proc_obj = emu.get_handle_table().get(ProcessHandle, objman.Process)
        if not proc_obj:
            return rv

        full_offset = 0
        if SectionOffset:
            full_offset = int.from_bytes(self.mem_read(SectionOffset, 8), "little")

        bytes_to_map = 0
        if ViewSize:
            bytes_to_map = self.read_ptr(ViewSize)

        pref_address = self.read_ptr(BaseAddress)

        tag_prefix = "api.ZwMapViewOfSection"
        access = self.win_perms_to_emu_perms(PageProtection)
        if sect:
            buf = None
            size = 0
            f = sect.backed_file
            if f and not pref_address:
                data = f.get_contents()

                if bytes_to_map != 0:
                    data = data[full_offset : full_offset + bytes_to_map]

                base, size = emu.get_valid_ranges(len(data))
                while base and base & 0xFFF:
                    base, size = emu.get_valid_ranges(size)

                buf = self.mem_alloc(base=base, size=size, perms=access, shared=True, tag="api", process=proc_obj)
                sect.add_view(buf, full_offset, size, access)
                mm = emu.get_address_map(buf)
                fname = ntpath.basename(f.path)
                fname = fname.replace(".", "_")
                mm.tag = f"{tag_prefix}.{fname}.0x{buf:x}"
                self.mem_write(buf, data)
                if ViewSize:
                    self.write_ptr(ViewSize, size)
                ctx.args["BaseAddress"].display = hex(buf)
                ctx.args["ViewSize"].display = hex(size)
            elif not pref_address:
                if bytes_to_map == 0:
                    bytes_to_map = sect.size
                base, size = emu.get_valid_ranges(bytes_to_map)
                buf = self.mem_alloc(base=base, size=size, perms=access, shared=True, process=proc_obj)
                mm = emu.get_address_map(buf)
                mm.tag = f"{tag_prefix}.0x{buf:x}"
                if ViewSize:
                    self.write_ptr(ViewSize, size)
                ctx.args["BaseAddress"].display = hex(buf)
                ctx.args["ViewSize"].display = hex(size)
                sect.add_view(buf, full_offset, size, access)
            else:
                buf = pref_address

            if BaseAddress and buf:
                rv = ddk.STATUS_SUCCESS
                self.write_ptr(BaseAddress, buf)
                if proc_obj and proc_obj is not emu.get_current_process():
                    proc_obj.is_modified = True

            for base, view in sect.views.items():
                if base != buf and view.size == size and full_offset == view.offset:
                    data = self.mem_read(base, size)
                    self.mem_write(buf, data)

        return rv

    @apihook("RtlCreateHeap", argc=6)
    def RtlCreateHeap(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID RtlCreateHeap(
            ULONG Flags,
            PVOID HeapBase,
            SIZE_T ReserveSize,
            SIZE_T CommitSize,
            PVOID Lock,
            PRTL_HEAP_PARAMETERS Parameters
        );
        """
        Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters = argv

        return self.create_heap(emu)

    @apihook("RtlDestroyHeap", argc=1)
    def RtlDestroyHeap(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID RtlDestroyHeap(
            PVOID HeapHandle
        );

        RtlDestroyHeap returns NULL on success and the heap handle on failure.
        """
        (HeapHandle,) = argv

        return 0

    @apihook("RtlAllocateHeap", argc=3)
    def RtlAllocateHeap(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID RtlAllocateHeap(
            PVOID HeapHandle,
            ULONG Flags,
            SIZE_T Size
        );
        """
        HeapHandle, Flags, Size = argv

        block = self.heap_alloc(Size, heap="RtlAllocateHeap")

        return block

    @apihook("ZwGetContextThread", argc=2)
    def ZwGetContextThread(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwGetContextThread(
            HANDLE ThreadHandle,
            PCONTEXT ThreadContext
        );
        """
        ThreadHandle, ThreadContext = argv

        obj = emu.get_handle_table().get(ThreadHandle, objman.Thread)
        if not obj:
            return ddk.STATUS_INVALID_HANDLE

        context = obj.get_context()

        self.mem_write(ThreadContext, context.get_bytes())

        return ddk.STATUS_SUCCESS

    @apihook("ZwSetContextThread", argc=2)
    def ZwSetContextThread(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS ZwSetContextThread(
            HANDLE ThreadHandle,
            PCONTEXT ThreadContext
        );
        """
        ThreadHandle, ThreadContext = argv

        obj = emu.get_handle_table().get(ThreadHandle, objman.Thread)
        if not obj:
            return ddk.STATUS_INVALID_HANDLE

        context: windefs.CONTEXT | windefs.CONTEXT64
        if emu.get_arch() == _arch.ARCH_AMD64:
            context = windefs.CONTEXT64(emu.get_ptr_size())
        else:
            context = windefs.CONTEXT(emu.get_ptr_size())
        if ThreadContext:
            _context = self.mem_cast(context, ThreadContext)
            obj.set_context(_context)
            if obj.process:
                obj.process.is_modified = True

        return ddk.STATUS_SUCCESS

    @apihook("RtlFreeHeap", argc=3)
    def RtlFreeHeap(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN RtlFreeHeap(
            PVOID HeapHandle,
            ULONG Flags,
            PVOID BaseAddress
        );
        """
        HeapHandle, Flags, BaseAddress = argv

        if BaseAddress and not self.heap_free(BaseAddress):
            return 0
        return 1

    @apihook("KeBugCheckEx", argc=5)
    def KeBugCheckEx(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID KeBugCheckEx(
            ULONG BugCheckCode,
            ULONG_PTR BugCheckParameter1,
            ULONG_PTR BugCheckParameter2,
            ULONG_PTR BugCheckParameter3,
            ULONG_PTR BugCheckParameter4
        );
        """
        BugCheckCode, *params = argv
        reason = f"bug check 0x{BugCheckCode & 0xFFFFFFFF:x} ({', '.join(hex(p) for p in params)})"
        logger.error("%s: %s", ctx.func_name, reason)

        error = emu.get_error_info(ErrorType.BUG_CHECK, emu.get_ret_address(), api_name=ctx.func_name)
        error.api_name = ctx.func_name
        error.context_summary = f"{error.context_summary}: {reason}"
        emu.end_run(error)

    @apihook("IoBuildDeviceIoControlRequest", argc=9)
    def IoBuildDeviceIoControlRequest(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        PIRP IoBuildDeviceIoControlRequest(
            ULONG IoControlCode,
            PDEVICE_OBJECT DeviceObject,
            PVOID InputBuffer,
            ULONG InputBufferLength,
            PVOID OutputBuffer,
            ULONG OutputBufferLength,
            BOOLEAN InternalDeviceIoControl,
            PKEVENT Event,
            PIO_STATUS_BLOCK IoStatusBlock
        );
        """
        (
            IoControlCode,
            DeviceObject,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength,
            InternalDeviceIoControl,
            Event,
            IoStatusBlock,
        ) = argv
        IoControlCode &= 0xFFFFFFFF
        InputBufferLength &= 0xFFFFFFFF
        OutputBufferLength &= 0xFFFFFFFF

        irp = emu.new_irp()
        ios = irp.get_next_stack_loc()
        ios.object.MajorFunction = (
            ddk.IRP_MJ_INTERNAL_DEVICE_CONTROL if InternalDeviceIoControl & 0xFF else ddk.IRP_MJ_DEVICE_CONTROL
        )
        params = ios.object.Parameters.DeviceIoControl
        params.IoControlCode = IoControlCode
        params.InputBufferLength = InputBufferLength
        params.OutputBufferLength = OutputBufferLength

        method = IoControlCode & 3
        if method == ddk.METHOD_NEITHER:
            params.Type3InputBuffer = InputBuffer
        else:
            sys_len = max(InputBufferLength, OutputBufferLength) if method == ddk.METHOD_BUFFERED else InputBufferLength
            if sys_len:
                sys_buf = self.pool_alloc(ddk.POOL_TYPE.NonPagedPool, sys_len, "IoBuildDeviceIoControlRequest")
                data = self.mem_read(InputBuffer, InputBufferLength) if InputBuffer and InputBufferLength else b""
                self.mem_write(sys_buf, data.ljust(sys_len, b"\x00"))
                irp.object.AssociatedIrp = sys_buf
                irp.object.Flags = ddk.IRP_BUFFERED_IO | ddk.IRP_DEALLOCATE_BUFFER
                if method == ddk.METHOD_BUFFERED and OutputBufferLength:
                    irp.object.Flags |= ddk.IRP_INPUT_OPERATION
            if method != ddk.METHOD_BUFFERED and OutputBuffer and OutputBufferLength:
                irp.object.MdlAddress = self._new_mdl(OutputBuffer, OutputBufferLength)

        irp.object.UserBuffer = OutputBuffer
        irp.object.UserIosb = IoStatusBlock
        irp.object.UserEvent = Event
        ios.write_back()
        irp.write_back()

        ctx.args[0].display = hex(IoControlCode)
        return irp.address

    @apihook("ProbeForRead", argc=3)
    def ProbeForRead(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ProbeForRead(
            const volatile VOID *Address,
            SIZE_T Length,
            ULONG Alignment
        );
        """
        return

    @apihook("ProbeForWrite", argc=3)
    def ProbeForWrite(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ProbeForWrite(
            volatile VOID *Address,
            SIZE_T Length,
            ULONG Alignment
        );
        """
        return

    @apihook("MmMapIoSpace", argc=4)
    def MmMapIoSpace(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID MmMapIoSpace(
            PHYSICAL_ADDRESS PhysicalAddress,
            SIZE_T NumberOfBytes,
            MEMORY_CACHING_TYPE CacheType
        );

        PhysicalAddress is passed by value: two stack slots on x86, one
        register on x64. argc=4 covers the x86 layout.
        """
        if emu.get_ptr_size() == 4:
            lo, hi, size, _cache = argv
            phys = hi << 32 | lo
        else:
            phys, size, _cache = argv[:3]
        if not size:
            return 0

        offset = phys & 0xFFF
        base = self.mem_alloc((offset + size + 0xFFF) & ~0xFFF, tag=f"api.MmMapIoSpace.0x{phys:x}")
        ctx.args[0].display = hex(phys)
        return base + offset

    @apihook("MmUnmapIoSpace", argc=2)
    def MmUnmapIoSpace(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID MmUnmapIoSpace(
            PVOID BaseAddress,
            SIZE_T NumberOfBytes
        );
        """
        BaseAddress, NumberOfBytes = argv
        if BaseAddress:
            self.mem_free(BaseAddress)

    @apihook("_wcsnset", argc=3, conv=_arch.CALL_CONV_CDECL)
    def _wcsnset(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *_wcsnset(
            wchar_t *str,
            wchar_t c,
            size_t count
        );
        """
        str, c, count = argv
        n = min(self.mem_string_len(str, 2), count)
        self.mem_write(str, (c & 0xFFFF).to_bytes(2, "little") * n)
        return str

    @apihook("RtlAppendUnicodeToString", argc=2)
    def RtlAppendUnicodeToString(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlAppendUnicodeToString(
            PUNICODE_STRING Destination,
            PCWSTR Source
        );
        """
        Destination, Source = argv
        if not Source:
            return ddk.STATUS_SUCCESS
        ctx.args["Source"].display = self.read_wide_string(Source)
        return self._append_to_unicode_string(Destination, self.mem_read(Source, self.mem_string_len(Source, 2) * 2))

    @apihook("RtlAppendUnicodeStringToString", argc=2)
    def RtlAppendUnicodeStringToString(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlAppendUnicodeStringToString(
            PUNICODE_STRING Destination,
            PCUNICODE_STRING Source
        );
        """
        Destination, Source = argv
        us = self.mem_cast(self.win.UNICODE_STRING(emu.get_ptr_size()), Source)
        data = self.mem_read(us.Buffer, us.Length) if us.Buffer and us.Length else b""
        ctx.args["Source"].display = data.decode("utf-16le", "replace")
        return self._append_to_unicode_string(Destination, data)

    @apihook("RtlQueryFeatureConfiguration", argc=4)
    def RtlQueryFeatureConfiguration(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlQueryFeatureConfiguration(
            RTL_FEATURE_ID FeatureId,
            RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
            PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
            PRTL_FEATURE_CONFIGURATION FeatureConfiguration
        );

        No feature has a configuration, so drivers use their defaults.
        """
        return ddk.STATUS_NOT_FOUND

    @apihook("RtlQueryFeatureConfigurationChangeStamp", argc=0)
    def RtlQueryFeatureConfigurationChangeStamp(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        RTL_FEATURE_CHANGE_STAMP RtlQueryFeatureConfigurationChangeStamp();
        """
        if emu.get_ptr_size() == 4:
            emu.reg_write(_arch.X86_REG_EDX, 0)
        return 1

    @apihook("RtlRegisterFeatureConfigurationChangeNotification", argc=4)
    def RtlRegisterFeatureConfigurationChangeNotification(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlRegisterFeatureConfigurationChangeNotification(
            PRTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK Callback,
            PVOID Context,
            PRTL_FEATURE_CHANGE_STAMP ObservedChangeStamp,
            PRTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle
        );
        """
        Callback, Context, ObservedChangeStamp, RegistrationHandle = argv
        if RegistrationHandle:
            self.write_ptr(RegistrationHandle, emu.get_object_manager(ctx.func_name).allocate_handle())
        return ddk.STATUS_SUCCESS

    @apihook("RtlUnregisterFeatureConfigurationChangeNotification", argc=1)
    def RtlUnregisterFeatureConfigurationChangeNotification(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlUnregisterFeatureConfigurationChangeNotification(
            RTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("RtlRegisterFeatureUsageProvider", argc=3)
    def RtlRegisterFeatureUsageProvider(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlRegisterFeatureUsageProvider(
            PVOID Callback,
            PVOID Descriptor,
            PHANDLE ProviderHandle
        );
        """
        Callback, Descriptor, ProviderHandle = argv
        if ProviderHandle:
            self.write_ptr(ProviderHandle, emu.get_object_manager(ctx.func_name).allocate_handle())
        return ddk.STATUS_SUCCESS

    @apihook("RtlUnregisterFeatureUsageProvider", argc=1)
    def RtlUnregisterFeatureUsageProvider(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlUnregisterFeatureUsageProvider(
            HANDLE ProviderHandle
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("RtlArmFeatureUsageProviderFlushNotification", argc=2)
    def RtlArmFeatureUsageProviderFlushNotification(
        self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS RtlArmFeatureUsageProviderFlushNotification(
            HANDLE ProviderHandle,
            ULONG Flags
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("RtlRecordFeatureUsage", argc=2)
    def RtlRecordFeatureUsage(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlRecordFeatureUsage(
            PVOID Record,
            ULONG Flags
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("RtlNotifyFeatureUsage", argc=1)
    def RtlNotifyFeatureUsage(self, emu: "WindowsEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS RtlNotifyFeatureUsage(
            PRTL_FEATURE_USAGE_REPORT FeatureUsageReport
        );
        """
        return ddk.STATUS_SUCCESS
