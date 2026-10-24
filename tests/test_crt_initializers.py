import struct

import pytest

from speakeasy import Speakeasy


@pytest.fixture
def x86_session(config):
    config["timeout"] = 2
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch="x86")
        se.run_shellcode(base)
        yield se
    finally:
        se.shutdown()


def write_code(se: Speakeasy, code: bytes) -> int:
    addr = se.mem_alloc(0x1000)
    se.mem_write(addr, code)
    return addr


def call_table(se: Speakeasy, api: str, entries: list[int]) -> int:
    table = se.mem_alloc(0x1000)
    se.mem_write(table, b"".join(struct.pack("<I", e) for e in entries))
    function = se.emu.get_proc("msvcrt", api)
    caller = write_code(
        se,
        b"\x68"
        + struct.pack("<I", table + 4 * len(entries))
        + b"\x68"
        + struct.pack("<I", table)
        + b"\xb8"
        + struct.pack("<I", function)
        + b"\xff\xd0\x83\xc4\x08\xc3",
    )
    se.call(caller)
    assert se.get_report().entry_points[-1].error is None
    return se.reg_read("eax")


def test_initterm_calls_each_initializer_in_order(x86_session):
    se = x86_session
    value = se.mem_alloc(0x1000)
    store_seven = write_code(se, b"\xc7\x05" + struct.pack("<II", value, 7) + b"\xc3")
    double = write_code(se, b"\xd1\x25" + struct.pack("<I", value) + b"\xc3")

    call_table(se, "_initterm", [0, store_seven, 0, double])

    assert struct.unpack("<I", se.mem_read(value, 4))[0] == 14


def test_initterm_e_stops_at_the_first_failing_initializer(x86_session):
    se = x86_session
    value = se.mem_alloc(0x1000)
    succeed = write_code(se, b"\xc7\x05" + struct.pack("<II", value, 7) + b"\x31\xc0\xc3")
    fail = write_code(se, b"\xb8\x05\x00\x00\x00\xc3")
    never = write_code(se, b"\xc7\x05" + struct.pack("<II", value, 1) + b"\x31\xc0\xc3")

    assert call_table(se, "_initterm_e", [succeed, 0, fail, never]) == 5
    assert struct.unpack("<I", se.mem_read(value, 4))[0] == 7


def test_initterm_e_returns_zero_when_all_initializers_succeed(x86_session):
    se = x86_session
    succeed = write_code(se, b"\x31\xc0\xc3")

    assert call_table(se, "_initterm_e", [succeed, succeed]) == 0
