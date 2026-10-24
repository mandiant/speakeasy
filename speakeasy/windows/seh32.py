"""
x86 exception dispatch, after ntdll's RtlDispatchException and RtlUnwind: handlers
come from the chain of EXCEPTION_REGISTRATION_RECORDs at fs:[0].

The entry points are dispatch_fault, for CPU exceptions, and the API handlers
raise_exception, rtl_unwind, and the MSVC language handlers except_handler3 and
except_handler4_common. These are generator handlers (see guest_callbacks.py).
What x64 shares is in seh.py.

MSVC frames (_except_handler3 and the SEH4 of _except_handler4_common) extend the
registration record with a scope table and a try level, and keep the frame's
saved esp and exception pointers next to it. Filters and __finally blocks run
with the frame's ebp; an __except block is entered with the frame's ebp and esp.

See http://www.openrce.org/articles/full_view/21
"""

import struct
from collections.abc import Iterator

import unicorn as uc

import speakeasy.windows.guest_callbacks as guest_callbacks
import speakeasy.windows.seh as seh
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows.cpu_exceptions import CpuException
from speakeasy.windows.guest_callbacks import GeneratorHandler, GuestCall
from speakeasy.windows.seh import STATUS_UNWIND, UNWINDING, as_long, read_context, resume_at

END_OF_CHAIN = 0xFFFFFFFF

# An MSVC frame, by offset from its registration record of next, handler, scope
# table and try level, which is at ebp - 0x10
SAVED_ESP = -0x08
EXCEPTION_POINTERS = -0x04
SCOPE_TABLE = 0x08
TRY_LEVEL = 0x0C
FRAME_POINTER = 0x10

# Try levels out of every scope
TRYLEVEL_NONE_SEH3 = 0xFFFFFFFF  # -1
TRYLEVEL_NONE_SEH4 = 0xFFFFFFFE  # -2
# SEH4 scope tables start with GS and EH cookie offsets
SEH4_SCOPE_TABLE_HEADER = 0x10


def _u32(emu, address: int) -> int:
    return struct.unpack("<I", emu.mem_read(address, 4))[0]


def _write_u32(emu, address: int, value: int) -> None:
    emu.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))


def exception_list(emu) -> int:
    """The head of the thread's registration chain, at fs:[0]."""
    thread = emu.get_current_thread()
    return thread.get_teb().read_back().object.NtTib.ExceptionList if thread else 0


def registrations(emu) -> Iterator[tuple[int, int, int]]:
    """
    The registration, next registration and handler of each record on the chain at fs:[0].
    A record that cannot be read ends the chain, as one outside the stack does on Windows.
    """
    registration = exception_list(emu)
    for _ in range(seh.MAX_FRAMES):
        if registration in (0, END_OF_CHAIN):
            return
        try:
            next_registration, handler = struct.unpack("<II", emu.mem_read(registration, 8))
        except uc.UcError:
            return
        yield registration, next_registration, handler
        registration = next_registration


def set_exception_list(emu, registration: int) -> None:
    teb = emu.get_current_thread().get_teb()
    teb.object.NtTib.ExceptionList = registration
    teb.write_back()


def dispatch_fault(emu, exception: CpuException, error: guest_callbacks.CallbackError | None = None) -> bool:
    return seh.dispatch_fault(emu, exception, dispatch_exception, error)


def raise_exception(emu, code: int, flags: int = 0, params=()) -> GeneratorHandler:
    """RaiseException"""
    return seh.raise_exception(emu, code, flags, params, dispatch_exception)


def rtl_raise_exception(emu, record: int) -> GeneratorHandler:
    """RtlRaiseException"""
    return seh.rtl_raise_exception(emu, record, dispatch_exception)


def call_handler(emu, handler: int, record: int, registration: int, context: int, dispatcher_context: int) -> GuestCall:
    """
    A call of an exception handler from a frame like the one ExecuteHandler2 leaves at EBP:
    the saved EBP, a return address, then the arguments, which some handlers, such as
    Borland C++'s, read through EBP.
    """
    args = (record, registration, context, dispatcher_context)
    frame = guest_callbacks.alloca(emu, struct.pack("<6I", emu.reg_read(_arch.X86_REG_EBP), 0, *args))
    return GuestCall(handler, args, registers=((_arch.X86_REG_EBP, frame),))


def dispatch_exception(emu, record: int, context: int) -> GeneratorHandler:
    """RtlDispatchException: offer the exception to vectored handlers, then along the registration chain."""
    exception = seh.Dispatch(emu, record, context)
    if (yield from exception.vectored()):
        return exception.resume()

    dispatcher_context = guest_callbacks.alloca(emu, bytes(4))
    for registration, _, handler in registrations(emu):
        exception.offer(handler)
        disposition = yield call_handler(emu, handler, record, registration, context, dispatcher_context)
        if disposition == windefs.ExceptionContinueExecution:
            return exception.resume()
    return (yield from exception.unhandled())


def unwind_registrations(emu, target_frame: int, record: int = 0) -> GeneratorHandler:
    """
    Call the handlers of the registrations above target_frame to unwind, and unlink them.
    A target_frame of 0 unwinds them all.
    """
    if record:
        fields = seh.read_record(emu, record)
    else:
        fields = [STATUS_UNWIND, 0, 0, 0, 0] + [0] * 15
    fields[1] |= seh.EXCEPTION_UNWINDING if target_frame else UNWINDING
    record = guest_callbacks.alloca(emu, seh.EXCEPTION_RECORD32.pack(*fields))
    context = guest_callbacks.alloca(emu, emu.get_thread_context().get_bytes())
    dispatcher_context = guest_callbacks.alloca(emu, bytes(4))

    for registration, next_registration, handler in registrations(emu):
        # Registrations are in stack order: one above the target means it is not on the chain
        if registration == target_frame or target_frame and registration > target_frame:
            break
        yield call_handler(emu, handler, record, registration, context, dispatcher_context)
        set_exception_list(emu, next_registration)


def rtl_unwind(emu, target_frame: int, target_ip: int, record: int, return_value: int) -> GeneratorHandler:
    """
    RtlUnwind: unwind the registrations above target_frame, then return to the caller,
    a handler that takes the exception and continues in its frame.
    """
    caller = guest_callbacks.caller_context(emu)  # read before the first guest call
    yield from unwind_registrations(emu, target_frame, record)
    caller.Eax = return_value
    return resume_at(emu, caller)


class MsvcFrame:
    """The scopes of an MSVC frame, from its registration record."""

    def __init__(self, emu, registration: int, scope_table: int, header: int, none: int):
        self.emu = emu
        self.registration = registration
        self.ebp = registration + FRAME_POINTER
        self.scope_table = scope_table + header
        self.none = none

    @property
    def try_level(self) -> int:
        return _u32(self.emu, self.registration + TRY_LEVEL)

    @try_level.setter
    def try_level(self, level: int) -> None:
        _write_u32(self.emu, self.registration + TRY_LEVEL, level)

    def scope(self, level: int) -> tuple[int, int, int]:
        """The enclosing level, filter (0 for a __finally) and handler of a scope."""
        return struct.unpack("<III", self.emu.mem_read(self.scope_table + 12 * level, 12))

    def call(self, function: int) -> GuestCall:
        """A call of a filter or __finally block, which runs with the frame's ebp."""
        return GuestCall(function, registers=((_arch.X86_REG_EBP, self.ebp),))

    def local_unwind(self, stop: int) -> GeneratorHandler:
        """Leave the scopes inside the stop level, running their __finally blocks."""
        for _ in range(seh.MAX_FRAMES):  # a scope table may be corrupt
            if self.try_level in (self.none, stop):
                break
            enclosing, filter_function, handler = self.scope(self.try_level)
            self.try_level = enclosing
            if not filter_function:
                yield self.call(handler)


def msvc_handler(emu, frame: MsvcFrame, record: int, context: int) -> GeneratorHandler:
    """The language handler of MSVC frames: run filters, or __finally blocks when unwinding."""
    flags = _u32(emu, record + 4)
    if flags & UNWINDING:
        yield from frame.local_unwind(frame.none)
        return windefs.ExceptionContinueSearch

    pointers = guest_callbacks.alloca(emu, struct.pack("<II", record, context))
    _write_u32(emu, frame.registration + EXCEPTION_POINTERS, pointers)
    level = frame.try_level
    for _ in range(seh.MAX_FRAMES):  # a scope table may be corrupt
        if level == frame.none:
            break
        enclosing, filter_function, handler = frame.scope(level)
        if filter_function:
            verdict = as_long((yield frame.call(filter_function)))
            if verdict < 0:
                return windefs.ExceptionContinueExecution
            if verdict > 0:
                yield from unwind_registrations(emu, frame.registration, record)
                yield from frame.local_unwind(level)
                frame.try_level = enclosing
                ctx = read_context(emu, context)
                ctx.Ebp = frame.ebp
                ctx.Esp = _u32(emu, frame.registration + SAVED_ESP)
                ctx.Eip = handler
                return resume_at(emu, ctx)
        level = enclosing
    return windefs.ExceptionContinueSearch


def except_handler3(emu, record: int, registration: int, context: int, dispatcher: int) -> GeneratorHandler:
    """_except_handler3"""
    scope_table = _u32(emu, registration + SCOPE_TABLE)
    frame = MsvcFrame(emu, registration, scope_table, 0, TRYLEVEL_NONE_SEH3)
    return (yield from msvc_handler(emu, frame, record, context))


def except_handler4_common(
    emu, cookie: int, check_cookie: int, record: int, registration: int, context: int, dispatcher: int
) -> GeneratorHandler:
    """_except_handler4_common: SEH4, whose scope table is encoded with the security cookie. Cookies are not checked."""
    scope_table = _u32(emu, registration + SCOPE_TABLE) ^ _u32(emu, cookie)
    frame = MsvcFrame(emu, registration, scope_table, SEH4_SCOPE_TABLE_HEADER, TRYLEVEL_NONE_SEH4)
    return (yield from msvc_handler(emu, frame, record, context))
