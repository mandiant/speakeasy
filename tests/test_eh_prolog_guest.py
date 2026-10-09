"""The x86 CRT prologue must establish a frame and resume its guest caller."""

import struct

import pytest

from speakeasy.profiler import Run
from speakeasy.winenv import arch


def dword(value):
    return struct.pack("<I", value)


@pytest.mark.parametrize("tracing", [False, True], ids=["normal", "traced"])
@pytest.mark.parametrize("existing_frame", [False, True], ids=["empty_chain", "existing_chain"])
def test_x86_eh_prolog_preserves_frame_arguments_and_resumes_caller(dll_emu, tracing, existing_frame):
    emu = dll_emu.emu
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.set_hooks()
    if tracing:
        emu.add_code_hook(emu._hook_code_tracing)
    target = emu.get_proc("msvcrt", "_EH_prolog")
    code = emu.mem_map(0x1000, tag="eh_prolog.guest")
    data = emu.mem_map(0x1000, tag="eh_prolog.data")
    function, handler = code + 0x100, code + 0x300
    saved_ebp = 0x13572468
    arguments = (0x11223344, 0x10203040)
    previous = data + 0x100 if existing_frame else 0xFFFFFFFF
    if existing_frame:
        emu.mem_write(previous, dword(0xFFFFFFFF) + dword(handler))
    emu.mem_write(handler, b"\x31\xc0\xc3")

    # Caller supplies ordinary arguments and an existing SEH chain. The CRT
    # prologue's handler address is passed in EAX, rather than as a stack arg.
    caller = b"\xbd" + dword(saved_ebp)
    caller += b"\x64\xc7\x05\0\0\0\0" + dword(previous)
    before_arguments = code + len(caller)
    caller += b"\x68" + dword(arguments[1]) + b"\x68" + dword(arguments[0])
    call_site = code + len(caller)
    caller += b"\xe8" + dword((function - call_site - 5) & 0xFFFFFFFF)
    caller_resume = code + len(caller)
    caller += b"\x83\xc4\x08\x40\xa3" + dword(data)  # discard args; INC EAX; store result
    stop_address = code + len(caller)
    emu.mem_write(code, caller + b"\x90")

    callee = b"\xb8" + dword(handler)
    prolog_call = function + len(callee)
    callee += b"\xe8" + dword((target - prolog_call - 5) & 0xFFFFFFFF)
    frame_resume = function + len(callee)
    # Actual guest instructions use the new frame, unlink it, restore EBP/SP,
    # and RET to the caller. Neither continuation is simulated by a Python hook.
    callee += b"\x8b\x45\x08\x03\x45\x0c"  # EAX = arg1 + arg2
    callee += b"\x8b\x4d\xf4\x64\x89\x0d\0\0\0\0"  # FS:[0] = previous
    callee += b"\x89\xec\x5d\xc3"  # MOV ESP,EBP; POP EBP; RET
    emu.mem_write(function, callee)

    observations = {}

    def observe(guest, address, size):
        if address not in (before_arguments, frame_resume, caller_resume, stop_address):
            return
        sp = guest.get_stack_ptr()
        observations[address] = {
            "pc": guest.get_pc(),
            "sp": sp,
            "ebp": guest.reg_read(arch.X86_REG_EBP),
            "eax": guest.get_return_val(),
            "seh": guest.read_ptr(guest.fs_addr),
            "stack": guest.mem_read(sp, 28) if address == frame_resume else None,
        }
        if address == stop_address:
            guest.emu_eng.stop()

    observation_hook = emu.add_code_hook(observe)
    try:
        emu._run_api_engine(code, timeout=3, count=100)
    finally:
        observation_hook.disable()

    assert emu.curr_run.error is None
    assert set(observations) == {before_arguments, frame_resume, caller_resume, stop_address}
    initial_sp = observations[before_arguments]["sp"]
    frame = observations[frame_resume]
    assert frame["pc"] == frame_resume
    assert frame["sp"] == initial_sp - 28
    assert frame["ebp"] == initial_sp - 16
    assert frame["seh"] == frame["sp"] == frame["ebp"] - 12
    assert struct.unpack("<7I", frame["stack"]) == (
        previous,
        handler,
        0xFFFFFFFF,
        saved_ebp,
        caller_resume,
        *arguments,
    )
    resumed = observations[caller_resume]
    assert resumed["pc"] == caller_resume
    assert resumed["sp"] == initial_sp - 8
    assert resumed["ebp"] == saved_ebp
    assert resumed["seh"] == previous
    assert resumed["eax"] == sum(arguments)
    assert emu.get_pc() == stop_address
    assert emu.get_stack_ptr() == initial_sp
    assert emu.reg_read(arch.X86_REG_EBP) == saved_ebp
    assert emu.read_ptr(emu.fs_addr) == previous
    assert emu.read_ptr(data) == sum(arguments) + 1
    assert [event.api_name for event in emu.curr_run.events if event.event == "api"] == ["msvcrt._EH_prolog"]
