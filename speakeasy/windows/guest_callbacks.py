"""
Guest callbacks: Python code that calls guest functions and acts on their results.

"Guest callback" means the emulator calling back into guest code, as opposed to
the guest calling the emulator through an API. API handlers already do this
with a fixed list of calls decided up front (GuestCallbackFrame.pending), e.g. to
run a DllMain. This module adds code that decides what to call next from what
the previous call returned, like the x64 exception dispatcher, which runs
filters and handlers. That code runs for an API handler or, for a CPU
exception, with no API involved at all; the name says what it does rather than
who starts it.

Such code is a generator handler: it yields a GuestCall for each guest function
it calls, is sent that call's return value, and finally returns either a return
value for the API that started it or a Resume to continue the guest at another
context:

    def handler(emu, callback):
        result = yield GuestCall(callback, (1, 2))
        return result + 1

Emulation is never nested: each guest call runs in the normal run loop on the
stack of the handler's frame and returns to GUEST_CALLBACK_RETURN_ADDR, where the
handler continues. The emulator only calls into this module where an API
handler returns a generator (start_api_handler) or a Resume, such as NtContinue
(transfer), where a guest call returns (resume), and to unwind through handler
frames (unwind_frame).
"""

from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

import speakeasy.windows.thread_context as thread_context
from speakeasy.profiler import GuestCallbackFrame
from speakeasy.winenv.arch import CALL_CONV_STDCALL


@dataclass(frozen=True)
class GuestCall:
    function: int
    args: tuple[int, ...] = ()
    # (register, value) pairs to set for the call, such as the frame pointer of x86 SEH filters
    registers: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Resume:
    """Continue the guest at a CONTEXT, abandoning the stack below it."""

    context: Any


GeneratorHandler = Generator[GuestCall, int, "int | Resume | None"]


class CallbackError(Exception):
    """A generator handler failure that ends the run with an error of type ``kind``."""

    kind = "callback_error"
    access_type: str | None = None
    pc: int | None = None  # where the error happened, when that is not the current pc

    def __init__(self, message: str, address: int):
        super().__init__(message)
        self.address = address


@dataclass
class HandlerState:
    generator: GeneratorHandler
    # Guest stack reserved below the frame for data the guest calls see
    scratch: int = 0
    # CONTEXT64 of the guest state the handler interrupted, if it has no caller to return to
    context: int = 0


def start(emu, frame: GuestCallbackFrame, generator: GeneratorHandler) -> None:
    """Run a generator handler on frame up to its first guest call. A CallbackError of that first step propagates."""
    frame.handler = HandlerState(generator)
    emu.get_current_run().guest_callbacks.append(frame)
    _step(emu, frame, None)


def start_api_handler(emu, frame: GuestCallbackFrame, generator: GeneratorHandler) -> int | None:
    """Run the generator an API handler returned; return the API result if it already finished."""
    try:
        start(emu, frame, generator)
    except CallbackError as e:
        _fail(emu, e)
    return frame.result


def resume(emu, frame: GuestCallbackFrame) -> None:
    """Continue the handler of frame with the return value of its guest call."""
    try:
        _step(emu, frame, emu.get_return_val())
    except CallbackError as e:
        _fail(emu, e)


def _fail(emu, e: CallbackError) -> None:
    run = emu.get_current_run()
    run.guest_callbacks.clear()
    if e.pc is not None:
        emu.set_pc(e.pc)
    run.error = emu.get_error_info(e.kind, e.address, access_type=e.access_type)
    emu.end_run_on_fault()


def _step(emu, frame: GuestCallbackFrame, value: int | None) -> None:
    run = emu.get_current_run()
    try:
        call = frame.handler.generator.send(value)
    except StopIteration as done:
        result = done.value
    else:
        emu.start_guest_callback(frame, call.function, call.args, sp=frame.stack_pointer - frame.handler.scratch)
        for register, value in call.registers:
            emu.reg_write(register, value)
        return

    run.guest_callbacks.remove(frame)
    if isinstance(result, Resume):
        transfer(emu, result.context)
        return
    frame.result = result
    if frame.event is not None:
        frame.event.ret_val = hex(result) if result is not None else None
    emu.set_stack_ptr(frame.stack_pointer)
    emu.do_call_return(frame.argc, frame.return_address, result, conv=frame.convention)


def transfer(emu, context) -> None:
    """Continue the guest at a CONTEXT, abandoning the guest callback frames on the stack below it."""
    callbacks = emu.get_current_run().guest_callbacks
    while callbacks and callbacks[-1].stack_pointer < thread_context.stack_pointer(context):
        callbacks.pop()
    emu.load_thread_context(context)


def current(emu) -> HandlerState:
    """The state of the running generator handler."""
    return emu.get_current_run().guest_callbacks[-1].handler


def alloca(emu, data: bytes) -> int:
    """Copy data to the guest stack below the running handler's frame, 16-byte aligned."""
    frame = emu.get_current_run().guest_callbacks[-1]
    address = (frame.stack_pointer - frame.handler.scratch - len(data)) & ~0xF
    frame.handler.scratch = frame.stack_pointer - address
    emu.mem_write(address, data)
    return address


def caller_context(emu):
    """
    The context of the caller of the API being handled. Valid in a generator
    handler before its first guest call, while the registers are still the caller's.
    """
    ctx = emu.get_thread_context()
    frame = emu._active_api_frame
    # A stdcall API on x86 pops its arguments
    args = frame.argc * 4 if emu.get_ptr_size() == 4 and frame and frame.convention == CALL_CONV_STDCALL else 0
    thread_context.set_control(ctx, emu.get_ret_address(), emu.get_stack_ptr() + emu.get_ptr_size() + args)
    return ctx


def unwind_frame(emu, ctx) -> None:
    """Unwind ctx, returning to GUEST_CALLBACK_RETURN_ADDR, to the guest state its handler frame interrupted."""
    frame = min(
        (f for f in emu.get_current_run().guest_callbacks if f.stack_pointer >= ctx.Rsp),
        key=lambda f: f.stack_pointer,
    )
    if frame.handler is not None and frame.handler.context:
        ctx.cast(emu.mem_read(frame.handler.context, ctx.sizeof()))
    else:
        ctx.Rip, ctx.Rsp = frame.return_address, frame.stack_pointer + emu.get_ptr_size()
