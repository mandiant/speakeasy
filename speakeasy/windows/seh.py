"""
What x64 (seh64.py) and x86 (seh32.py) exception dispatch share: exception
records, the vectored handlers that run before frame-based handlers, reporting,
and the entry points for CPU exceptions and RaiseException, which take the
architecture's dispatcher.

The functions here are generator handlers (see guest_callbacks.py).
"""

import ctypes as ct
import struct
from collections.abc import Callable

import speakeasy.windows.guest_callbacks as guest_callbacks
import speakeasy.windows.thread_context as thread_context
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.profiler import GuestCallbackFrame
from speakeasy.windows.cpu_exceptions import ACCESS_CODES, STATUS_GUARD_PAGE_VIOLATION, CpuException
from speakeasy.windows.guest_callbacks import GeneratorHandler, GuestCall, Resume

EXCEPTION_NONCONTINUABLE = 0x01
EXCEPTION_UNWINDING = 0x02
EXCEPTION_EXIT_UNWIND = 0x04
EXCEPTION_TARGET_UNWIND = 0x20
UNWINDING = EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND

# Verdicts of exception filters and vectored handlers, as LONGs
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_EXECUTE_HANDLER = 1

STATUS_UNWIND = 0xC0000027
STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025

TRAP_FLAG = 0x100

# Exceptions whose parameters are the access type and the address
MEMORY_FAULTS = (ddk.STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION)

# EXCEPTION_RECORD: code, flags, nested record, address, parameter count, 15 parameters
EXCEPTION_RECORD64 = struct.Struct("<IIQQI4x15Q")
EXCEPTION_RECORD32 = struct.Struct("<IIIII15I")

MAX_FRAMES = 256

ACCESS_TYPES = {code: name for name, code in ACCESS_CODES.items()}

Dispatcher = Callable[..., GeneratorHandler]


class UnhandledException(guest_callbacks.CallbackError):
    def __init__(self, code: int, address: int, information=()):
        if code == ddk.STATUS_ACCESS_VIOLATION and len(information) >= 2:
            # The error of the fault, as when no handler sees it
            access_type = ACCESS_TYPES.get(information[0])
            super().__init__(f"invalid_{access_type}", information[1], access_type, pc=address)
        else:
            super().__init__("unhandled_exception", address, pc=address)
        self.code = code


def as_long(value: int) -> int:
    """A guest return value as a 32-bit LONG, e.g. an exception filter's verdict."""
    return ct.c_int32(value).value


def record_struct(emu) -> struct.Struct:
    return EXCEPTION_RECORD64 if emu.get_ptr_size() == 8 else EXCEPTION_RECORD32


def exception_record(emu, code: int, flags: int, address: int, params=()) -> bytes:
    mask = (1 << 8 * emu.get_ptr_size()) - 1
    params = [param & mask for param in params][:15]
    return record_struct(emu).pack(code, flags, 0, address, len(params), *params, *[0] * (15 - len(params)))


def read_record(emu, address: int) -> list[int]:
    layout = record_struct(emu)
    return list(layout.unpack(emu.mem_read(address, layout.size)))


def read_context(emu, address: int):
    context = windefs.CONTEXT64(8) if emu.get_ptr_size() == 8 else windefs.CONTEXT(4)
    return emu.mem_cast(context, address)


def resume_at(emu, ctx) -> Resume:
    """Continue the guest at ctx once the exception is handled."""
    emu.note_seh_resume(thread_context.instruction_pointer(ctx))
    return Resume(ctx)


class Dispatch:
    """An exception being dispatched: its record and context, in guest memory."""

    def __init__(self, emu, record: int, context: int):
        self.emu = emu
        self.record = record
        self.context = context
        self.code, self.flags, _, self.address, _, *self.information = read_record(emu, record)
        pack = "<QQ" if emu.get_ptr_size() == 8 else "<II"
        self.pointers = guest_callbacks.alloca(emu, struct.pack(pack, record, context))
        self.reported = False

    def offer(self, handler: int) -> None:
        """Report the exception once, when the first handler receives it."""
        if self.reported:
            return
        faulting_address = self.information[1] if self.code in MEMORY_FAULTS else None
        registers = thread_context.register_state(read_context(self.emu, self.context))
        self.emu.record_exception(self.code, self.address, handler, registers, faulting_address)
        self.reported = True

    def vectored(self) -> GeneratorHandler:
        """Offer the exception to the vectored handlers; return whether one continues execution."""
        for handler in list(self.emu.veh_handlers):
            self.offer(handler)
            if as_long((yield GuestCall(handler, (self.pointers,)))) == EXCEPTION_CONTINUE_EXECUTION:
                return True
        return False

    def resume(self) -> Resume:
        """Continue at the context, which handlers may have changed."""
        if self.flags & EXCEPTION_NONCONTINUABLE:
            raise UnhandledException(STATUS_NONCONTINUABLE_EXCEPTION, self.address)
        return resume_at(self.emu, read_context(self.emu, self.context))

    def unhandled(self) -> GeneratorHandler:
        """
        No frame takes the exception: offer it to the top-level filter of
        SetUnhandledExceptionFilter, which Windows calls from the outermost frame of
        the thread, and continue if it says so. Otherwise the exception is unhandled.
        """
        top_level_filter = self.emu.unhandled_exception_filter
        if top_level_filter:
            self.offer(top_level_filter)
            if as_long((yield GuestCall(top_level_filter, (self.pointers,)))) == EXCEPTION_CONTINUE_EXECUTION:
                return self.resume()
        raise UnhandledException(self.code, self.address, self.information)


def dispatch_fault(
    emu, exception: CpuException, dispatch_exception: Dispatcher, error: guest_callbacks.CallbackError | None = None
) -> bool:
    """
    Dispatch a CPU exception like KiUserExceptionDispatcher: on the stack of the
    faulting thread. Return False when no handler takes it.

    error is how the run ends when no handler takes it, by default an UnhandledException.
    """
    ctx = emu.get_thread_context()
    thread_context.set_control(ctx, exception.pc, thread_context.stack_pointer(ctx))
    if exception.code == ddk.STATUS_SINGLE_STEP:
        ctx.EFlags &= ~TRAP_FLAG
    # Handlers run with the trap flag clear
    emu.reg_write(_arch.X86_REG_EFLAGS, emu.reg_read(_arch.X86_REG_EFLAGS) & ~TRAP_FLAG)

    def dispatch() -> GeneratorHandler:
        context = guest_callbacks.alloca(emu, ctx.get_bytes())
        guest_callbacks.current(emu).context = context  # an unwind through this frame continues at the fault
        record = exception_record(emu, exception.code, 0, exception.address, exception.params)
        try:
            return (yield from dispatch_exception(emu, guest_callbacks.alloca(emu, record), context))
        except UnhandledException:
            if error is None:
                raise
            raise error from None

    guest_callbacks.drop_abandoned(emu, thread_context.stack_pointer(ctx))
    frame = GuestCallbackFrame(stack_pointer=thread_context.stack_pointer(ctx), return_address=0)
    try:
        guest_callbacks.start(emu, frame, dispatch())
    except guest_callbacks.CallbackError:
        emu.get_current_run().guest_callbacks.remove(frame)
        return False
    return True


def raise_exception(emu, code: int, flags: int, params, dispatch_exception: Dispatcher) -> GeneratorHandler:
    """
    RaiseException: dispatch an exception raised by the caller of the API.

    Windows ends the process when no handler takes the exception. Here RaiseException
    returns instead, so that emulation goes on, unless the exception is not continuable.
    """
    try:
        return (yield from raise_in_caller(emu, code, flags, params, dispatch_exception))
    except UnhandledException:
        if flags & EXCEPTION_NONCONTINUABLE:
            raise
        return 0


def raise_in_caller(emu, code: int, flags: int, params, dispatch_exception: Dispatcher) -> GeneratorHandler:
    """Dispatch an exception at the caller of the API."""
    ctx = guest_callbacks.caller_context(emu)
    record = exception_record(emu, code, flags, thread_context.instruction_pointer(ctx), params)
    record = guest_callbacks.alloca(emu, record)
    return (yield from dispatch_exception(emu, record, guest_callbacks.alloca(emu, ctx.get_bytes())))


def rtl_raise_exception(emu, record: int, dispatch_exception: Dispatcher) -> GeneratorHandler:
    """RtlRaiseException: dispatch the caller's record, raised at the caller."""
    ctx = guest_callbacks.caller_context(emu)
    emu.write_ptr(record + 4 + 4 + emu.get_ptr_size(), thread_context.instruction_pointer(ctx))  # ExceptionAddress
    return (yield from dispatch_exception(emu, record, guest_callbacks.alloca(emu, ctx.get_bytes())))


def capture_context(emu, address: int) -> None:
    """RtlCaptureContext: the context of the caller, with CONTEXT_FULL (and segments on x64)."""
    context = guest_callbacks.caller_context(emu)
    if thread_context.is_amd64(context):
        context.ContextFlags = thread_context.CONTEXT_FULL_AMD64 | thread_context.CONTEXT_SEGMENTS
    else:
        context.ContextFlags = thread_context.CONTEXT_FULL_I386
    emu.mem_write(address, context.get_bytes())


def restore_context(emu, address: int) -> Resume:
    """RtlRestoreContext and NtContinue: continue at a context."""
    return resume_at(emu, read_context(emu, address))
