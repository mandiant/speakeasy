"""
Exception and unwind APIs that ntdll implements and kernel32 forwards to ntdll.

The kernel32 and ntdll API handlers both inherit ExceptionApis. Most of these
APIs exist only on x64, where the exception dispatch uses the unwind data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows import seh, seh32, seh64
from speakeasy.winenv.api import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator
    from speakeasy.windows.winemu import WindowsEmulator

    _ApiHandlerBase = api.ApiHandler
else:
    _ApiHandlerBase = object

apihook = api.ApiHandler.apihook


def is_amd64(emu: WindowsEmulator) -> bool:
    return emu.get_arch() == e_arch.ARCH_AMD64


def c_specific_handler(emu, argv):
    """__C_specific_handler, which the C runtimes also export."""
    if not is_amd64(emu):
        return windefs.ExceptionContinueSearch
    return seh64.c_specific_handler(emu, *argv)


class ExceptionApis(_ApiHandlerBase):
    @apihook("RtlUnwind", argc=4)
    def RtlUnwind(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlUnwind(
            PVOID TargetFrame,
            PVOID TargetIp,
            PEXCEPTION_RECORD ExceptionRecord,
            PVOID ReturnValue
        );
        """
        if is_amd64(emu):
            return seh64.rtl_unwind_ex(emu, *argv)
        return seh32.rtl_unwind(emu, *argv)

    @apihook("RtlUnwindEx", argc=6)
    def RtlUnwindEx(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlUnwindEx(
            PVOID TargetFrame,
            PVOID TargetIp,
            PEXCEPTION_RECORD ExceptionRecord,
            PVOID ReturnValue,
            PCONTEXT ContextRecord,
            PUNWIND_HISTORY_TABLE HistoryTable
        );
        """
        if is_amd64(emu):
            return seh64.rtl_unwind_ex(emu, *argv[:4])

    @apihook("__C_specific_handler", argc=4)
    def __C_specific_handler(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        EXCEPTION_DISPOSITION __C_specific_handler(
            struct _EXCEPTION_RECORD *ExceptionRecord,
            void *EstablisherFrame,
            struct _CONTEXT *ContextRecord,
            struct _DISPATCHER_CONTEXT *DispatcherContext
        );
        """
        return c_specific_handler(emu, argv)

    @apihook("RtlCaptureContext", argc=1)
    def RtlCaptureContext(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlCaptureContext(
            PCONTEXT ContextRecord
        );
        """
        if argv[0]:
            seh.capture_context(emu, argv[0])

    @apihook("RtlRestoreContext", argc=2)
    def RtlRestoreContext(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlRestoreContext(
            PCONTEXT ContextRecord,
            struct _EXCEPTION_RECORD *ExceptionRecord
        );
        """
        if is_amd64(emu):
            return seh.restore_context(emu, argv[0])

    @apihook("RtlAddFunctionTable", argc=3)
    def RtlAddFunctionTable(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN RtlAddFunctionTable(
            PRUNTIME_FUNCTION FunctionTable,
            DWORD EntryCount,
            DWORD64 BaseAddress
        );
        """
        return is_amd64(emu) and seh64.add_function_table(emu, *argv)

    @apihook("RtlInstallFunctionTableCallback", argc=6)
    def RtlInstallFunctionTableCallback(
        self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOLEAN RtlInstallFunctionTableCallback(
            DWORD64 TableIdentifier,
            DWORD64 BaseAddress,
            DWORD Length,
            PGET_RUNTIME_FUNCTION_CALLBACK Callback,
            PVOID Context,
            PCWSTR OutOfProcessCallbackDll
        );
        """
        return is_amd64(emu) and seh64.install_function_table_callback(emu, *argv[:4])

    @apihook("RtlDeleteFunctionTable", argc=1)
    def RtlDeleteFunctionTable(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN RtlDeleteFunctionTable(
            PRUNTIME_FUNCTION FunctionTable
        );
        """
        return is_amd64(emu) and seh64.delete_function_table(emu, argv[0])

    @apihook("RtlPcToFileHeader", argc=2)
    def RtlPcToFileHeader(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID RtlPcToFileHeader(
            PVOID PcValue,
            PVOID *BaseOfImage
        );
        """
        PcValue, BaseOfImage = argv
        mod = emu.get_mod_from_addr(PcValue)
        base = mod.base if mod else 0
        self.write_ptr(BaseOfImage, base)
        return base

    @apihook("RtlLookupFunctionEntry", argc=3)
    def RtlLookupFunctionEntry(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PRUNTIME_FUNCTION RtlLookupFunctionEntry(
            DWORD64 ControlPc,
            PDWORD64 ImageBase,
            PUNWIND_HISTORY_TABLE HistoryTable
        );
        """
        if not is_amd64(emu):
            return 0
        return seh64.lookup_function_entry(emu, *argv[:2])

    @apihook("RtlVirtualUnwind", argc=8)
    def RtlVirtualUnwind(self, emu: Win32Emulator, argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PEXCEPTION_ROUTINE RtlVirtualUnwind(
            DWORD HandlerType,
            DWORD64 ImageBase,
            DWORD64 ControlPc,
            PRUNTIME_FUNCTION FunctionEntry,
            PCONTEXT ContextRecord,
            PVOID *HandlerData,
            PDWORD64 EstablisherFrame,
            PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
        );
        """
        if not is_amd64(emu):
            return 0
        return seh64.virtual_unwind(emu, *argv[:7])
