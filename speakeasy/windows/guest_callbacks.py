"""
Guest callbacks: Python code that calls guest functions and uses their results.

A guest callback is a call from the emulator into guest code. An API handler can
give a fixed list of calls (``GuestCallbackFrame.pending``), for example to run a
DllMain. A generator handler selects the next call from the result of the
previous call, as the x64 exception dispatcher does when it runs filters and
handlers. A generator handler runs for an API handler, or for a CPU exception
without an API call.

A generator handler yields a ``GuestCall`` for each guest function that it calls,
and gets the return value of that call. At the end, it returns the return value
of the API that started it, or a ``Resume`` that continues the guest at a
different context:

    def handler(emu, callback):
        result = yield GuestCall(callback, (1, 2))
        return result + 1

Emulation is never nested. Each guest call runs in the normal run loop, on the
stack of the handler frame, and returns to ``GUEST_CALLBACK_RETURN_ADDR``. Then
the handler continues.
"""

from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

import unicorn as uc

from speakeasy.profiler import GuestCallbackFrame
from speakeasy.report import ErrorType
from speakeasy.windows import thread_context
from speakeasy.winenv.arch import CALL_CONV_STDCALL


@dataclass(frozen=True)
class GuestCall:
    function: int
    args: tuple[int, ...] = ()
    # (register, value) pairs to set for the call, such as the frame pointer of x86 SEH filters
    registers: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Resume:
    """Continue the guest at a CONTEXT, and drop the guest callback frames at or below its stack pointer."""

    context: Any


GeneratorHandler = Generator[GuestCall, int, "int | Resume | None"]


class CallbackError(Exception):
    """A generator handler failed. The run ends with an error of type ``kind`` at ``address``."""

    def __init__(
        self, kind: ErrorType, address: int, access_type: str | None = None, pc: int | None = None, **details: Any
    ):
        super().__init__(f"{kind.value} at 0x{address:x}")
        self.kind: ErrorType = kind
        self.address: int = address
        self.access_type: str | None = access_type
        self.pc: int | None = pc  # where the error happened, when that is not the current pc
        self.details: dict[str, Any] = details  # more fields of the run's error, such as interrupt_num


HANDLER_FAULT_ACCESS = {
    uc.UC_ERR_READ_UNMAPPED: "read",
    uc.UC_ERR_READ_PROT: "read",
    uc.UC_ERR_WRITE_UNMAPPED: "write",
    uc.UC_ERR_WRITE_PROT: "write",
}


def get_first_unmapped(emu, address: int, size: int) -> int:
    """Get the first address of a range that no memory region holds, or the start of the range if all are mapped."""
    regions = emu.get_mem_regions()
    current = address
    while current < address + size:
        end = next((last for first, last, _ in regions if first <= current <= last), None)
        if end is None:
            return current
        current = end + 1
    return address


def get_handler_fault(emu, error: Exception, pc: int) -> tuple[ErrorType, int, str | None, str | None]:
    """
    Get the error type, address, access type and message for an exception raised by an API handler.

    If a handler reads or writes an invalid guest pointer, the error address is the first byte
    that the handler cannot access, as for guest code. Unicorn gives the start of the whole access.
    Any other exception is an ``internal_error``, with the exception text as the message.
    """
    access = HANDLER_FAULT_ACCESS.get(error.errno) if isinstance(error, uc.UcError) else None
    if access is None or not error.args:
        return ErrorType.INTERNAL_ERROR, pc, None, str(error) or type(error).__name__
    address = error.args[0]
    if len(error.args) > 1:
        address = get_first_unmapped(emu, address, error.args[1])
    return ErrorType(f"invalid_{access}"), address, access, None


@dataclass
class HandlerState:
    generator: GeneratorHandler
    # Size of the guest stack below the frame that holds data for the guest calls
    scratch: int = 0
    # Address of the CONTEXT of the guest state that the handler interrupted, if the handler has no caller
    context: int = 0


def start(emu, frame: GuestCallbackFrame, generator: GeneratorHandler) -> None:
    """
    Run a generator handler on ``frame`` up to its first guest call.

    Raises:
        CallbackError: if the handler fails before its first guest call.
    """
    frame.handler = HandlerState(generator)
    emu.get_current_run().guest_callbacks.append(frame)
    _step(emu, frame, None)


def start_api_handler(emu, frame: GuestCallbackFrame, generator: GeneratorHandler) -> int | None:
    """Run the generator that an API handler returned. Return the API result if the generator finished."""
    try:
        start(emu, frame, generator)
    except CallbackError as e:
        fail(emu, e)
    return frame.result


def resume(emu, frame: GuestCallbackFrame) -> None:
    """Continue the handler of frame with the return value of its guest call."""
    try:
        _step(emu, frame, emu.get_return_val())
    except CallbackError as e:
        fail(emu, e)


def fail(emu, e: CallbackError) -> None:
    """End the run with the error of ``e``."""
    run = emu.get_current_run()
    if e.pc is not None:
        emu.set_pc(e.pc)
    run.error = emu.get_error_info(e.kind, e.address, access_type=e.access_type, message=e.details.get("message"))
    for name, value in e.details.items():
        setattr(run.error, name, value)
    emu.end_run_on_fault()


def _step(emu, frame: GuestCallbackFrame, value: int | None) -> None:
    run = emu.get_current_run()
    try:
        call = frame.handler.generator.send(value)
        emu.start_guest_callback(frame, call.function, call.args, sp=frame.stack_pointer - frame.handler.scratch)
    except StopIteration as done:
        result = done.value
    except uc.UcError as e:
        kind, address, access_type, message = get_handler_fault(emu, e, emu.get_pc())
        raise CallbackError(kind, address, access_type, message=message) from e
    else:
        for register, contents in call.registers:
            emu.reg_write(register, contents)
        return

    run.guest_callbacks.remove(frame)
    if isinstance(result, Resume):
        transfer(emu, result.context)
        return
    frame.result = result
    if frame.event is not None:
        frame.event.return_value = emu.get_machine_word(result)
    emu.set_stack_ptr(frame.stack_pointer)
    emu.restore_caller_registers(frame)
    emu.do_call_return(frame.argc, frame.return_address, result, conv=frame.convention)


def transfer(emu, context) -> None:
    """Continue the guest at a CONTEXT."""
    drop_abandoned(emu, thread_context.stack_pointer(context))
    emu.load_thread_context(context)


def drop_abandoned(emu, sp: int) -> None:
    """
    Drop the guest callback frames at or below ``sp``, where the guest continues.

    The guest left the guest calls of these frames without a return, for example when a handler continues in an
    ``__except`` block and leaves the dispatch of its exception.
    """
    callbacks = emu.get_current_run().guest_callbacks
    while callbacks and callbacks[-1].stack_pointer <= sp:
        callbacks.pop()


def current(emu) -> HandlerState:
    """Get the state of the running generator handler."""
    state: HandlerState = emu.get_current_run().guest_callbacks[-1].handler
    return state


def alloca(emu, data: bytes) -> int:
    """Copy data to the guest stack below the running handler's frame, 16-byte aligned."""
    frame = emu.get_current_run().guest_callbacks[-1]
    address: int = (frame.stack_pointer - frame.handler.scratch - len(data)) & ~0xF
    frame.handler.scratch = frame.stack_pointer - address
    emu.mem_write(address, data)
    return address


def caller_context(emu):
    """
    Get the context of the caller of the current API call.

    The context is valid in a generator handler before its first guest call, while the registers are still the caller's.
    """
    ctx = emu.get_thread_context()
    frame = emu.active_api_frame
    # A stdcall API on x86 pops its arguments
    args = frame.argc * 4 if emu.get_ptr_size() == 4 and frame and frame.convention == CALL_CONV_STDCALL else 0
    thread_context.set_control(ctx, emu.get_ret_address(), emu.get_stack_ptr() + emu.get_ptr_size() + args)
    return ctx


def unwind_frame(emu, ctx) -> None:
    """Unwind ``ctx`` at ``GUEST_CALLBACK_RETURN_ADDR`` to the guest state that its frame interrupted."""
    frames = [f for f in emu.get_current_run().guest_callbacks if f.stack_pointer >= ctx.Rsp]
    # No frame has this return address, for example a guest copy on a corrupt stack. End the walk.
    if not frames:
        ctx.Rip = 0
        return
    frame = min(frames, key=lambda f: f.stack_pointer)
    if frame.handler is not None and frame.handler.context:
        ctx.cast(emu.mem_read(frame.handler.context, ctx.sizeof()))
    else:
        ctx.Rip, ctx.Rsp = frame.return_address, frame.stack_pointer + emu.get_ptr_size()
