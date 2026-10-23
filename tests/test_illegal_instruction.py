"""An invalid opcode on x86 raises STATUS_ILLEGAL_INSTRUCTION to the SEH handler of the guest."""

import struct

import pytest

from speakeasy import Speakeasy

STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
VIRTUAL_PC_PROBE = b"\x0f\x3f\x07\x0b"


def dword(value):
    return struct.pack("<I", value)


@pytest.fixture
def session(config):
    with Speakeasy(config=config) as se:
        yield se


def load_guest(se, *, register=True):
    """
    Load code that runs the Virtual PC probe under one SEH registration.
    The handler copies the exception code to the returned data address and
    continues after the probe.
    """
    code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
    data = se.mem_alloc(0x1000)
    handler = code + 0x100
    registration = data + 0x100
    se.mem_write(registration, dword(0xFFFFFFFF) + dword(handler))
    setup = b"\x64\xc7\x05" + dword(0) + dword(registration) if register else b""
    finish = b"\x64\xc7\x05" + dword(0) + dword(0) + b"\xb8" + dword(42) + b"\xc3"
    se.mem_write(code, setup + VIRTUAL_PC_PROBE + finish)
    handler_code = b"\x8b\x4c\x24\x04\x8b\x01\xa3" + dword(data)
    handler_code += b"\x8b\x4c\x24\x0c\x83\x81\xb8\x00\x00\x00" + bytes([len(VIRTUAL_PC_PROBE)])
    handler_code += b"\x31\xc0\xc3"
    se.mem_write(handler, handler_code)
    return code, data


def test_invalid_opcode_calls_the_seh_handler_and_continues(session):
    code, data = load_guest(session)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is None
    assert run.ret_val == 42
    assert struct.unpack("<I", session.mem_read(data, 4))[0] == STATUS_ILLEGAL_INSTRUCTION


def test_invalid_opcode_without_a_handler_ends_the_run(session):
    code, _ = load_guest(session, register=False)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is not None
    assert run.ret_val != 42
