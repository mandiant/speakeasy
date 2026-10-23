"""RaiseException on x86 calls the SEH handler with the exception record of the caller."""

import struct

import pytest

from speakeasy import Speakeasy


def dword(value):
    return struct.pack("<I", value)


@pytest.fixture
def session(config):
    with Speakeasy(config=config) as se:
        yield se


def load_guest(se, *, register=True, flags=0):
    """
    Load code that raises 0x0EEDFADE with two parameters under one SEH
    registration. The handler copies the code, flags, parameter count and
    parameters to the returned data address and continues execution.
    """
    code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
    data = se.mem_alloc(0x1000)
    handler = code + 0x100
    registration = data + 0x100
    params = data + 0x200
    se.mem_write(registration, dword(0xFFFFFFFF) + dword(handler))
    se.mem_write(params, dword(0x1111) + dword(0x2222))
    raise_exception = se.emu.get_proc("kernel32", "RaiseException")
    setup = b"\x64\xc7\x05" + dword(0) + dword(registration) if register else b""
    call = b"\x68" + dword(params) + b"\x6a\x02\x6a" + bytes([flags]) + b"\x68" + dword(0x0EEDFADE)
    call += b"\xb8" + dword(raise_exception) + b"\xff\xd0"
    finish = b"\x64\xc7\x05" + dword(0) + dword(0) + b"\xb8" + dword(42) + b"\xc3"
    se.mem_write(code, setup + call + finish)
    handler_code = b"\x8b\x4c\x24\x04"
    for i, offset in enumerate((0x0, 0x4, 0x10, 0x14, 0x18)):
        handler_code += b"\x8b\x41" + bytes([offset]) + b"\xa3" + dword(data + 4 * i)
    handler_code += b"\x31\xc0\xc3"
    se.mem_write(handler, handler_code)
    return code, data


def test_raise_exception_calls_the_seh_handler_and_continues(session):
    code, data = load_guest(session)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is None
    assert run.ret_val == 42
    assert struct.unpack("<5I", session.mem_read(data, 20)) == (0x0EEDFADE, 0, 2, 0x1111, 0x2222)


def test_handler_cannot_continue_a_noncontinuable_exception(session):
    code, data = load_guest(session, flags=1)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert struct.unpack("<2I", session.mem_read(data, 8)) == (0x0EEDFADE, 1)
    assert run.error is not None
    assert run.error.type == "unhandled_exception"
    assert run.ret_val != 42


def test_continuable_exception_without_a_handler_returns(session):
    code, data = load_guest(session, register=False)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is None
    assert run.ret_val == 42
    assert session.mem_read(data, 4) == b"\x00" * 4


def test_noncontinuable_exception_without_a_handler_ends_the_run(session):
    code, data = load_guest(session, register=False, flags=1)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is not None
    assert run.error.type == "unhandled_exception"
    assert run.ret_val != 42


def test_seh_handler_reads_its_arguments_through_the_dispatcher_frame(session):
    code, data = load_guest(session)
    # Borland C++ handlers read the dispatcher arguments through EBP, as the frame of ExecuteHandler2 leaves it.
    handler_code = b"\x8b\x4d\x08\x8b\x01\xa3" + dword(data)
    handler_code += b"\x8b\x45\x0c\xa3" + dword(data + 4)
    handler_code += b"\x31\xc0\xc3"
    session.mem_write(code + 0x100, handler_code)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is None
    assert run.ret_val == 42
    assert struct.unpack("<2I", session.mem_read(data, 8)) == (0x0EEDFADE, data + 0x100)


def test_exceptions_caught_by_unwinding_can_repeat_from_one_call_site(session):
    """
    Raise the same exception from the same call site in a loop. The handler
    counts the exception and resumes at the loop head with the saved stack,
    as a C++ catch block does after it unwinds.
    """
    code = session.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
    data = session.mem_alloc(0x1000)
    handler = code + 0x100
    registration = data + 0x100
    saved_esp = data + 0x300
    session.mem_write(registration, dword(0xFFFFFFFF) + dword(handler))
    raise_exception = session.emu.get_proc("kernel32", "RaiseException")
    register = b"\x64\xc7\x05" + dword(0) + dword(registration)
    setup = register + b"\x89\x25" + dword(saved_esp)
    loop = code + len(setup)
    call = b"\x68" + dword(0) + b"\x6a\x00\x6a\x01\x68" + dword(0xE06D7363)
    call += b"\xb8" + dword(raise_exception) + b"\xff\xd0"
    check = b"\x83\x3d" + dword(data) + b"\x08\x73" + bytes([len(call)])
    finish = b"\x64\xc7\x05" + dword(0) + dword(0) + b"\xb8" + dword(42) + b"\xc3"
    session.mem_write(code, setup + check + call + finish)
    handler_code = b"\xff\x05" + dword(data) + b"\x8b\x25" + dword(saved_esp) + register
    handler_code += b"\xb8" + dword(loop) + b"\xff\xe0"
    session.mem_write(handler, handler_code)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is None
    assert run.ret_val == 42
    assert struct.unpack("<I", session.mem_read(data, 4))[0] == 8


def test_exception_event_records_the_return_address_of_the_call(session):
    code, _ = load_guest(session)
    setup_size, call_size = 11, 21
    return_address = code + setup_size + call_size

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    events = [e for e in run.events or [] if e.event == "exception"]
    assert len(events) == 1
    assert events[0].pos.pc == return_address
    assert events[0].instr.startswith("mov dword ptr fs:[0]")
