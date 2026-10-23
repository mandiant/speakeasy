"""
x64 exception dispatch, after ntdll's RtlDispatchException and RtlUnwindEx.

Everything x64 exception-specific lives here. The entry points are
dispatch_fault, for CPU exceptions, and the API handlers raise_exception,
rtl_unwind_ex and c_specific_handler. These are generator handlers (see guest_callbacks.py):
they yield a GuestCall for each vectored handler, language handler, filter and
__finally block they run, and are sent back its return value.

Data that guest handlers see (EXCEPTION_RECORD, CONTEXT, DISPATCHER_CONTEXT)
lives on the guest stack below the handler's frame, as it does on Windows.

See https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
"""

import ctypes as ct
import struct
from collections import namedtuple
from collections.abc import Iterator

import unicorn as uc

import speakeasy.windows.common as winemu
import speakeasy.windows.guest_callbacks as guest_callbacks
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.profiler import GuestCallbackFrame
from speakeasy.windows import unwind
from speakeasy.windows.guest_callbacks import GeneratorHandler, GuestCall, Resume

EXCEPTION_NONCONTINUABLE = 0x01
EXCEPTION_UNWINDING = 0x02
EXCEPTION_EXIT_UNWIND = 0x04
EXCEPTION_TARGET_UNWIND = 0x20

# Verdicts of exception filters and vectored handlers, as LONGs
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_EXECUTE_HANDLER = 1

STATUS_UNWIND = 0xC0000027
STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025
STATUS_INVALID_UNWIND_TARGET = 0xC0000029

# EXCEPTION_RECORD64: code, flags, nested record, address, parameter count, 15 parameters
EXCEPTION_RECORD = struct.Struct("<IIQQI4x15Q")
DISPATCHER_CONTEXT = struct.Struct("<9QII")
DispatcherContext = namedtuple(
    "DispatcherContext",
    "ControlPc ImageBase FunctionEntry EstablisherFrame TargetIp ContextRecord "
    "LanguageHandler HandlerData HistoryTable ScopeIndex Fill0",
)
SCOPE_INDEX_OFFSET = 9 * 8

MAX_FRAMES = 256


class UnhandledException(guest_callbacks.CallbackError):
    kind = "unhandled_exception"

    def __init__(self, code: int, address: int):
        super().__init__(f"unhandled exception 0x{code:x} at 0x{address:x}", address)
        self.code = code


def as_long(value: int) -> int:
    """A guest return value as a 32-bit LONG, e.g. an exception filter's verdict."""
    return ct.c_int32(value).value


def copy_context(ctx):
    return windefs.CONTEXT64(8).cast(ctx.get_bytes())


def read_context(emu, address: int):
    return emu.mem_cast(windefs.CONTEXT64(8), address)


def register_state(ctx) -> dict[str, str]:
    """The general purpose registers of ctx, formatted like the emulator's register state."""
    names = ("Rsp", "Rbp", "Rip", "Rsi", "Rdi", "Rax", "Rbx", "Rcx", "Rdx") + tuple(f"R{i}" for i in range(8, 16))
    return {name.lower(): f"{getattr(ctx, name):#018x}" for name in names}


def walk_frames(emu, ctx, handler_type: int) -> Iterator[tuple[object, unwind.RuntimeFunction, unwind.FrameInfo]]:
    """
    Unwind ctx in place, yielding (frame context, function, frame info) for each frame with unwind data.

    Frames of the emulator itself (a generator handler's call into the guest) are unwound to
    the guest state they interrupted, so a walk from a handler continues into the
    frames that raised the exception, as it does through KiUserExceptionDispatcher.
    """
    for _ in range(MAX_FRAMES):
        pc = ctx.Rip
        if pc == winemu.GUEST_CALLBACK_RETURN_ADDR:
            guest_callbacks.unwind_frame(emu, ctx)
            continue
        if not pc or winemu.EMU_RESERVED <= pc < winemu.EMU_RESERVED_END:
            return
        frame_ctx = copy_context(ctx)
        try:
            module = emu.get_module_from_addr(pc)
            fn = module and unwind.lookup_function_entry(emu.mem_read, module.base, pc)
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


def exception_record(code: int, flags: int, address: int, params=()) -> bytes:
    params = list(params)[:15]
    return EXCEPTION_RECORD.pack(code, flags, 0, address, len(params), *params, *[0] * (15 - len(params)))


def dispatch_fault(emu, code: int, faulting_address: int | None = None, access_type: str | None = None) -> bool:
    """
    Dispatch a CPU exception like KiUserExceptionDispatcher: on the stack of the
    faulting thread. Return False when no handler takes it.
    """
    ctx = emu.get_thread_context()
    if code == ddk.STATUS_BREAKPOINT:
        ctx.Rip -= 1  # Windows reports the address of the int3, Unicorn the one after it
    params = ()
    if code == ddk.STATUS_ACCESS_VIOLATION and faulting_address is not None:
        params = ({"read": 0, "write": 1, "fetch": 8}.get(access_type, 0), faulting_address)

    def dispatch() -> GeneratorHandler:
        context = guest_callbacks.alloca(emu, ctx.get_bytes())
        guest_callbacks.current(emu).context = context  # an unwind through this frame continues at the fault
        record = guest_callbacks.alloca(emu, exception_record(code, 0, ctx.Rip, params))
        return (yield from dispatch_exception(emu, record, context))

    frame = GuestCallbackFrame(stack_pointer=ctx.Rsp, return_address=0)
    try:
        guest_callbacks.start(emu, frame, dispatch())
    except UnhandledException:
        emu.get_current_run().guest_callbacks.remove(frame)
        return False
    return True


def raise_exception(emu, code: int, flags: int = 0, params=()) -> GeneratorHandler:
    """RaiseException: dispatch an exception raised by the caller of the API."""
    ctx = guest_callbacks.caller_context(emu)
    record = guest_callbacks.alloca(emu, exception_record(code, flags, ctx.Rip, params))
    return (yield from dispatch_exception(emu, record, guest_callbacks.alloca(emu, ctx.get_bytes())))


def rtl_unwind_ex(emu, target_frame: int, target_ip: int, record: int, return_value: int) -> GeneratorHandler:
    """RtlUnwindEx, called by the guest: unwind from its caller."""
    return (
        yield from unwind_to(emu, guest_callbacks.caller_context(emu), target_frame, target_ip, record, return_value)
    )


def dispatch_exception(emu, record: int, context: int) -> GeneratorHandler:
    """RtlDispatchException: offer the exception to vectored, then frame-based handlers."""
    code, flags, _, address, _, *information = EXCEPTION_RECORD.unpack(emu.mem_read(record, EXCEPTION_RECORD.size))
    pointers = guest_callbacks.alloca(emu, struct.pack("<QQ", record, context))
    recorded = False

    def offer(handler: int) -> None:
        """Report the exception once, when the first handler receives it."""
        nonlocal recorded
        if not recorded:
            # an access violation's parameters are the access type and the address
            faulting_address = information[1] if code == ddk.STATUS_ACCESS_VIOLATION else None
            emu.record_exception(code, address, handler, register_state(read_context(emu, context)), faulting_address)
            recorded = True

    def resume():
        if flags & EXCEPTION_NONCONTINUABLE:
            raise UnhandledException(STATUS_NONCONTINUABLE_EXCEPTION, address)
        return Resume(read_context(emu, context))

    for handler in list(emu.veh_handlers):
        offer(handler)
        if as_long((yield GuestCall(handler, (pointers,)))) == EXCEPTION_CONTINUE_EXECUTION:
            return resume()

    ctx = read_context(emu, context)
    unwound = guest_callbacks.alloca(emu, ctx.get_bytes())
    dispatcher_context = guest_callbacks.alloca(emu, bytes(DISPATCHER_CONTEXT.size))
    for frame_ctx, fn, info in walk_frames(emu, ctx, unwind.UNW_FLAG_EHANDLER):
        if not info.handler:
            continue
        emu.mem_write(unwound, ctx.get_bytes())
        emu.mem_write(dispatcher_context, _dispatcher_context(fn, frame_ctx, info, unwound))
        offer(info.handler)
        disposition = yield GuestCall(info.handler, (record, info.establisher_frame, context, dispatcher_context))
        if disposition == windefs.ExceptionContinueExecution:
            return resume()
        # ExceptionContinueSearch; nested and collided unwinds are not distinguished

    # The caller runs the top-level filter (SetUnhandledExceptionFilter), if any.
    raise UnhandledException(code, address)


def unwind_to(emu, ctx, target_frame: int, target_ip: int, record: int, return_value: int) -> GeneratorHandler:
    """
    RtlUnwindEx: walk up from ctx calling termination handlers, then resume the
    target frame at target_ip with return_value in rax.
    """
    if record:
        fields = list(EXCEPTION_RECORD.unpack(emu.mem_read(record, EXCEPTION_RECORD.size)))
    else:
        fields = [STATUS_UNWIND, 0, 0, ctx.Rip, 0] + [0] * 15
    fields[1] |= EXCEPTION_UNWINDING if target_frame else EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND
    record = guest_callbacks.alloca(emu, EXCEPTION_RECORD.pack(*fields))
    unwound = guest_callbacks.alloca(emu, ctx.get_bytes())
    dispatcher_context = guest_callbacks.alloca(emu, bytes(DISPATCHER_CONTEXT.size))

    for frame_ctx, fn, info in walk_frames(emu, ctx, unwind.UNW_FLAG_UHANDLER):
        is_target = info.establisher_frame == target_frame
        if info.handler:
            if is_target:
                fields[1] |= EXCEPTION_TARGET_UNWIND
                emu.mem_write(record, EXCEPTION_RECORD.pack(*fields))
            emu.mem_write(unwound, frame_ctx.get_bytes())
            emu.mem_write(dispatcher_context, _dispatcher_context(fn, frame_ctx, info, unwound, target_ip))
            yield GuestCall(info.handler, (record, info.establisher_frame, unwound, dispatcher_context))
        if is_target:
            frame_ctx.Rip, frame_ctx.Rax = target_ip, return_value
            return Resume(frame_ctx)
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

    if not flags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND):
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
