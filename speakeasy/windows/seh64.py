"""
x64 exception dispatch, after ntdll's RtlDispatchException and RtlUnwindEx: handlers
come from the unwind data of the frames on the stack.

The entry points are dispatch_fault, for CPU exceptions, and the API handlers
raise_exception, rtl_unwind_ex and c_specific_handler. These are generator
handlers (see guest_callbacks.py): they yield a GuestCall for each vectored
handler, language handler, filter and __finally block they run, and are sent
back its return value. What x86 shares is in seh.py.

Data that guest handlers see (EXCEPTION_RECORD, CONTEXT, DISPATCHER_CONTEXT)
lives on the guest stack below the handler's frame, as it does on Windows.

See https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
"""

import struct
from collections import namedtuple
from collections.abc import Iterator

import unicorn as uc

import speakeasy.windows.common as winemu
import speakeasy.windows.guest_callbacks as guest_callbacks
import speakeasy.windows.seh as seh
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows import unwind
from speakeasy.windows.cpu_exceptions import CpuException
from speakeasy.windows.guest_callbacks import GeneratorHandler, GuestCall
from speakeasy.windows.seh import (
    EXCEPTION_EXECUTE_HANDLER,
    EXCEPTION_EXIT_UNWIND,
    EXCEPTION_RECORD64,
    EXCEPTION_TARGET_UNWIND,
    EXCEPTION_UNWINDING,
    STATUS_UNWIND,
    UNWINDING,
    UnhandledException,
    as_long,
    read_context,
    resume_at,
)

STATUS_INVALID_UNWIND_TARGET = 0xC0000029

DISPATCHER_CONTEXT = struct.Struct("<9QII")
DispatcherContext = namedtuple(
    "DispatcherContext",
    "ControlPc ImageBase FunctionEntry EstablisherFrame TargetIp ContextRecord "
    "LanguageHandler HandlerData HistoryTable ScopeIndex Fill0",
)
SCOPE_INDEX_OFFSET = 9 * 8


def copy_context(ctx):
    return windefs.CONTEXT64(8).cast(ctx.get_bytes())


def find_function(emu, pc: int) -> unwind.RuntimeFunction | None:
    """
    RtlLookupFunctionEntry: the unwind data of the function at pc, from a loaded image,
    else from a table registered at runtime. Callback tables are not called: their
    functions unwind as leaf functions.
    """
    module = emu.get_module_from_addr(pc)
    fn = module and unwind.lookup_function_entry(emu.mem_read, module.base, pc)
    if fn:
        return fn
    for table in emu.function_tables:
        if table.begin <= pc < table.end and not table.callback:
            return unwind.search_function_table(emu.mem_read, table, pc)
    return None


def walk_frames(emu, ctx, handler_type: int) -> Iterator[tuple[object, unwind.RuntimeFunction, unwind.FrameInfo]]:
    """
    Unwind ctx in place, yielding (frame context, function, frame info) for each frame with unwind data.

    Frames of the emulator itself (a generator handler's call into the guest) are unwound to
    the guest state they interrupted, so a walk from a handler continues into the
    frames that raised the exception, as it does through KiUserExceptionDispatcher.
    """
    for _ in range(seh.MAX_FRAMES):
        pc = ctx.Rip
        if pc == winemu.GUEST_CALLBACK_RETURN_ADDR:
            guest_callbacks.unwind_frame(emu, ctx)
            continue
        if not pc or winemu.EMU_RESERVED <= pc < winemu.EMU_RESERVED_END:
            return
        frame_ctx = copy_context(ctx)
        try:
            fn = find_function(emu, pc)
            if not fn:
                unwind.unwind_leaf(emu.mem_read, ctx)
                continue
            info = unwind.virtual_unwind(emu.mem_read, fn, pc, ctx, handler_type)
        except uc.UcError:
            return  # a corrupt stack or unwind data ends the walk
        yield frame_ctx, fn, info


def _dispatcher_context(fn, frame_ctx, info, context: int, target_ip: int = 0) -> bytes:
    dc = DispatcherContext(
        ControlPc=frame_ctx.Rip,
        ImageBase=fn.image_base,
        FunctionEntry=fn.address,
        EstablisherFrame=info.establisher_frame,
        TargetIp=target_ip,
        ContextRecord=context,
        LanguageHandler=info.handler,
        HandlerData=info.handler_data,
        HistoryTable=0,
        ScopeIndex=0,
        Fill0=0,
    )
    return DISPATCHER_CONTEXT.pack(*dc)


def dispatch_fault(emu, exception: CpuException) -> bool:
    return seh.dispatch_fault(emu, exception, dispatch_exception)


def raise_exception(emu, code: int, flags: int = 0, params=()) -> GeneratorHandler:
    """RaiseException"""
    return seh.raise_exception(emu, code, flags, params, dispatch_exception)


def rtl_raise_exception(emu, record: int) -> GeneratorHandler:
    """RtlRaiseException"""
    return seh.rtl_raise_exception(emu, record, dispatch_exception)


def rtl_unwind_ex(emu, target_frame: int, target_ip: int, record: int, return_value: int) -> GeneratorHandler:
    """RtlUnwindEx, called by the guest: unwind from its caller."""
    return (
        yield from unwind_to(emu, guest_callbacks.caller_context(emu), target_frame, target_ip, record, return_value)
    )


def dispatch_exception(emu, record: int, context: int) -> GeneratorHandler:
    """RtlDispatchException: offer the exception to vectored, then frame-based handlers."""
    exception = seh.Dispatch(emu, record, context)
    if (yield from exception.vectored()):
        return exception.resume()

    ctx = read_context(emu, context)
    unwound = guest_callbacks.alloca(emu, ctx.get_bytes())
    dispatcher_context = guest_callbacks.alloca(emu, bytes(DISPATCHER_CONTEXT.size))
    for frame_ctx, fn, info in walk_frames(emu, ctx, unwind.UNW_FLAG_EHANDLER):
        if not info.handler:
            continue
        emu.mem_write(unwound, ctx.get_bytes())
        emu.mem_write(dispatcher_context, _dispatcher_context(fn, frame_ctx, info, unwound))
        exception.offer(info.handler)
        disposition = yield GuestCall(info.handler, (record, info.establisher_frame, context, dispatcher_context))
        if disposition == windefs.ExceptionContinueExecution:
            return exception.resume()
        # ExceptionContinueSearch; nested and collided unwinds are not distinguished
    return (yield from exception.unhandled())


def unwind_to(emu, ctx, target_frame: int, target_ip: int, record: int, return_value: int) -> GeneratorHandler:
    """
    RtlUnwindEx: walk up from ctx calling termination handlers, then resume the
    target frame at target_ip with return_value in rax.
    """
    if record:
        fields = seh.read_record(emu, record)
    else:
        fields = [STATUS_UNWIND, 0, 0, ctx.Rip, 0] + [0] * 15
    fields[1] |= EXCEPTION_UNWINDING if target_frame else EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND
    record = guest_callbacks.alloca(emu, EXCEPTION_RECORD64.pack(*fields))
    unwound = guest_callbacks.alloca(emu, ctx.get_bytes())
    dispatcher_context = guest_callbacks.alloca(emu, bytes(DISPATCHER_CONTEXT.size))

    for frame_ctx, fn, info in walk_frames(emu, ctx, unwind.UNW_FLAG_UHANDLER):
        is_target = info.establisher_frame == target_frame
        if info.handler:
            if is_target:
                fields[1] |= EXCEPTION_TARGET_UNWIND
                emu.mem_write(record, EXCEPTION_RECORD64.pack(*fields))
            emu.mem_write(unwound, frame_ctx.get_bytes())
            emu.mem_write(dispatcher_context, _dispatcher_context(fn, frame_ctx, info, unwound, target_ip))
            yield GuestCall(info.handler, (record, info.establisher_frame, unwound, dispatcher_context))
        if is_target:
            frame_ctx.Rip, frame_ctx.Rax = target_ip, return_value
            return resume_at(emu, frame_ctx)
    raise UnhandledException(STATUS_INVALID_UNWIND_TARGET, target_ip)


def c_specific_handler(
    emu, record: int, establisher_frame: int, context: int, dispatcher_context: int
) -> GeneratorHandler:
    """__C_specific_handler: the language handler for MSVC __try/__except/__finally."""
    caller = guest_callbacks.caller_context(emu)  # where an unwind starts; read before the first guest call
    code, flags = struct.unpack("<II", emu.mem_read(record, 8))
    dc = DispatcherContext._make(DISPATCHER_CONTEXT.unpack(emu.mem_read(dispatcher_context, DISPATCHER_CONTEXT.size)))
    image_base = dc.ImageBase
    count = struct.unpack("<I", emu.mem_read(dc.HandlerData, 4))[0]
    # SCOPE_TABLE records: BeginAddress, EndAddress, HandlerAddress (filter or __finally), JumpTarget
    scopes = list(struct.iter_unpack("<IIII", emu.mem_read(dc.HandlerData + 4, 16 * count)))
    pc = dc.ControlPc - image_base

    if not flags & UNWINDING:
        pointers = guest_callbacks.alloca(emu, struct.pack("<QQ", record, context))
        for begin, end, filter_rva, target in scopes[dc.ScopeIndex :]:
            if not (begin <= pc < end and target):
                continue
            if filter_rva == EXCEPTION_EXECUTE_HANDLER:
                verdict = EXCEPTION_EXECUTE_HANDLER
            else:
                verdict = as_long((yield GuestCall(image_base + filter_rva, (pointers, establisher_frame))))
            if verdict < 0:
                return windefs.ExceptionContinueExecution
            if verdict > 0:
                return (yield from unwind_to(emu, caller, establisher_frame, image_base + target, record, code))
        return windefs.ExceptionContinueSearch

    target_pc = dc.TargetIp - image_base
    for index, (begin, end, handler, target) in enumerate(scopes[dc.ScopeIndex :], dc.ScopeIndex):
        if not begin <= pc < end:
            continue
        if flags & EXCEPTION_TARGET_UNWIND and any(
            b <= target_pc < e and h == handler and t == target for b, e, h, t in scopes
        ):
            break  # the scope also encloses the target: it is not being left
        if not target:  # __finally
            emu.mem_write(dispatcher_context + SCOPE_INDEX_OFFSET, struct.pack("<I", index + 1))
            yield GuestCall(image_base + handler, (1, establisher_frame))  # AbnormalTermination() is TRUE
    return windefs.ExceptionContinueSearch


# API implementations that kernel32 and ntdll share


def lookup_function_entry(emu, pc: int, image_base_out: int) -> int:
    """RtlLookupFunctionEntry"""
    fn = find_function(emu, pc)
    if not fn:
        return 0
    if image_base_out:
        emu.write_ptr(image_base_out, fn.image_base)
    return fn.address


def virtual_unwind(
    emu, handler_type: int, image_base: int, pc: int, entry: int, context: int, handler_data_out: int, frame_out: int
) -> int:
    """RtlVirtualUnwind: unwind the CONTEXT at context by one frame, and return the frame's handler."""
    fn = unwind.read_runtime_function(emu.mem_read, image_base, entry)
    ctx = read_context(emu, context)
    info = unwind.virtual_unwind(emu.mem_read, fn, pc, ctx, handler_type)
    emu.mem_write(context, ctx.get_bytes())
    emu.write_ptr(handler_data_out, info.handler_data)
    emu.write_ptr(frame_out, info.establisher_frame)
    return info.handler


def add_function_table(emu, table: int, count: int, base: int) -> bool:
    """RtlAddFunctionTable"""
    entries = list(struct.iter_unpack("<III", emu.mem_read(table, 12 * count))) if count else []
    if not entries:
        return False
    begin = base + min(b for b, _, _ in entries)
    end = base + max(e for _, e, _ in entries)
    emu.function_tables.append(unwind.FunctionTable(table, base, begin, end, count=count))
    return True


def install_function_table_callback(emu, identifier: int, base: int, length: int, callback: int) -> bool:
    """RtlInstallFunctionTableCallback"""
    if identifier & 3 != 3:  # the low bits mark a callback table
        return False
    emu.function_tables.append(unwind.FunctionTable(identifier, base, base, base + length, callback=callback))
    return True


def delete_function_table(emu, identifier: int) -> bool:
    """RtlDeleteFunctionTable"""
    for table in emu.function_tables:
        if table.identifier == identifier:
            emu.function_tables.remove(table)
            return True
    return False
