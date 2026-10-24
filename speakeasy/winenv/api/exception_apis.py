"""
Exception and unwind APIs that ntdll implements and kernel32 forwards to it.

ExceptionApis is a mixin of the kernel32 and ntdll API handlers. Most of these
APIs exist only on x64, where exceptions are dispatched from unwind data.
"""

import speakeasy.windows.seh as seh
import speakeasy.windows.seh32 as seh32
import speakeasy.windows.seh64 as seh64
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.api import api

apihook = api.ApiHandler.apihook


def is_amd64(emu) -> bool:
    return emu.get_arch() == e_arch.ARCH_AMD64


def c_specific_handler(emu, argv):
    """__C_specific_handler, which the C runtimes also export."""
    if not is_amd64(emu):
        return windefs.ExceptionContinueSearch
    return seh64.c_specific_handler(emu, *argv)


class ExceptionApis:
    @apihook("RtlUnwind", argc=4)
    def RtlUnwind(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
    def RtlUnwindEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
    def __C_specific_handler(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        EXCEPTION_DISPOSITION __C_specific_handler(
          PEXCEPTION_RECORD ExceptionRecord,
          PVOID EstablisherFrame,
          PCONTEXT ContextRecord,
          PDISPATCHER_CONTEXT DispatcherContext
        );
        """
        return c_specific_handler(emu, argv)

    @apihook("RtlCaptureContext", argc=1)
    def RtlCaptureContext(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlCaptureContext(
          PCONTEXT ContextRecord
        );
        """
        if argv[0]:
            seh.capture_context(emu, argv[0])

    @apihook("RtlRestoreContext", argc=2)
    def RtlRestoreContext(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RtlRestoreContext(
          PCONTEXT ContextRecord,
          _EXCEPTION_RECORD *ExceptionRecord
        );
        """
        if is_amd64(emu):
            return seh.restore_context(emu, argv[0])

    @apihook("RtlAddFunctionTable", argc=3)
    def RtlAddFunctionTable(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN RtlAddFunctionTable(
          PRUNTIME_FUNCTION FunctionTable,
          DWORD EntryCount,
          DWORD64 BaseAddress
        );
        """
        return is_amd64(emu) and seh64.add_function_table(emu, *argv)

    @apihook("RtlInstallFunctionTableCallback", argc=6)
    def RtlInstallFunctionTableCallback(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
    def RtlDeleteFunctionTable(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN RtlDeleteFunctionTable(
          PRUNTIME_FUNCTION FunctionTable
        );
        """
        return is_amd64(emu) and seh64.delete_function_table(emu, argv[0])

    @apihook("RtlLookupFunctionEntry", argc=3)
    def RtlLookupFunctionEntry(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
    def RtlVirtualUnwind(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
