"""The x86 SEH replay guard stops an unrepaired fault and allows guest progress."""

import struct

import pytest

from speakeasy import Speakeasy

BAD = 0x60000000
CONTEXT_EAX = 0xB0


def dword(value):
    return struct.pack("<I", value)


@pytest.fixture
def session(config):
    with Speakeasy(config=config) as se:
        yield se


def load_guest(se, *, repair=False, change_address=False, iterations=8):
    """
    Load a loop that reads BAD ``iterations`` times under one SEH registration.
    The handler increments a counter at the returned data address. It can repair
    EAX so the read completes, or flip a fault address bit on its first three
    calls without letting the read complete.
    """
    code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
    data = se.mem_alloc(0x1000)
    assert se.get_address_map(BAD) is None
    handler = code + 0x100
    registration = data + 0x100
    se.mem_write(registration, dword(0xFFFFFFFF) + dword(handler))
    setup = b"\x64\xc7\x05" + dword(0) + dword(registration) + b"\xb9" + dword(iterations)
    fault_pc = code + len(setup) + 5
    body = b"\xb8" + dword(BAD) + b"\x8b\x00\xe2\xf7"
    finish = b"\x64\xc7\x05" + dword(0) + dword(0) + b"\xb8" + dword(42) + b"\xc3"
    se.mem_write(code, setup + body + finish)
    handler_code = b"\xff\x05" + dword(data) + b"\x90" * 16
    if repair:
        handler_code += b"\x8b\x4c\x24\x0c\xc7\x81" + dword(CONTEXT_EAX) + dword(data + 4)
    if change_address:
        handler_code += b"\x8b\x4c\x24\x0c\x83\x3d" + dword(data) + b"\x03\x77\x0a"
        handler_code += b"\x81\xb1" + dword(CONTEXT_EAX) + dword(0x1000)
    handler_code += b"\x31\xc0\xc3"
    se.mem_write(handler, handler_code)
    return code, data, fault_pc


def handler_calls(se, data):
    return int.from_bytes(se.mem_read(data, 4), "little")


def test_same_fault_stops_after_three_guest_handlers(session):
    code, data, fault_pc = load_guest(session)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error.type == "invalid_read"
    assert run.error.pc == fault_pc
    assert handler_calls(session, data) == 3


def test_repaired_register_allows_the_same_fault_site_again(session):
    code, data, _ = load_guest(session, repair=True)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error is None
    assert run.ret_val == 42
    assert handler_calls(session, data) == 8


def test_changed_fault_address_resets_guard_without_guest_progress(session):
    code, data, fault_pc = load_guest(session, change_address=True)

    session.run_shellcode(code)

    run = session.get_report().entry_points[0]
    assert run.error.type == "invalid_read"
    assert run.error.pc == fault_pc
    assert handler_calls(session, data) == 6


def test_fresh_public_call_resets_guard(session):
    code, data, fault_pc = load_guest(session)

    session.run_shellcode(code)
    session.call(code)

    runs = session.get_report().entry_points
    assert [(run.error.type, run.error.pc) for run in runs] == [("invalid_read", fault_pc)] * 2
    assert handler_calls(session, data) == 6
