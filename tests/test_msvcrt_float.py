import struct

import pytest

from speakeasy import Speakeasy

CASES = [
    ("pow", (2.0, 10.0), 1024.0),
    ("floor", (-2.5,), -3.0),
    ("sin", (0.0,), 0.0),
]


@pytest.fixture(params=["x86", "amd64"])
def session(request, config):
    config["timeout"] = 2
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch=request.param)
        se.run_shellcode(base)
        yield se
    finally:
        se.shutdown()


def write_code(se: Speakeasy, code: bytes) -> int:
    addr = se.mem_alloc(0x1000)
    se.mem_write(addr, code)
    return addr


def call_x86(se: Speakeasy, function: int, args: tuple[float, ...], out: int) -> bytes:
    pushes = b""
    for value in reversed(args):
        lo, hi = struct.unpack("<II", struct.pack("<d", value))
        pushes += b"\x68" + struct.pack("<I", hi) + b"\x68" + struct.pack("<I", lo)
    return (
        b"\x89\xe6"
        + pushes
        + b"\xb8"
        + struct.pack("<I", function)
        + b"\xff\xd0"
        + b"\x83\xc4"
        + bytes([8 * len(args)])
        + b"\xdd\x1d"
        + struct.pack("<I", out)
        + b"\x29\xe6\x89\x35"
        + struct.pack("<I", out + 8)
        + b"\xc3"
    )


def call_amd64(se: Speakeasy, function: int, args: tuple[float, ...], out: int) -> bytes:
    se.mem_write(out, b"".join(struct.pack("<d", value) for value in args))
    loads = b"\xf2\x0f\x10\x00"
    if len(args) > 1:
        loads += b"\xf2\x0f\x10\x48\x08"
    return (
        b"\x48\xb8"
        + struct.pack("<Q", out)
        + loads
        + b"\x48\x83\xec\x28\x48\xb8"
        + struct.pack("<Q", function)
        + b"\xff\xd0\x48\x83\xc4\x28\x48\xb8"
        + struct.pack("<Q", out)
        + b"\xf2\x0f\x11\x00\x48\xc7\x40\x08\x00\x00\x00\x00\xc3"
    )


@pytest.mark.parametrize(("api", "args", "expected"), CASES)
def test_float_functions_take_and_return_doubles_per_architecture(session, api, args, expected):
    se = session
    out = se.mem_alloc(0x1000)
    function = se.emu.get_proc("msvcrt", api)
    build = call_x86 if se.emu.get_ptr_size() == 4 else call_amd64

    se.call(write_code(se, build(se, function, args, out)))

    assert se.get_report().entry_points[-1].error is None
    result, stack_change = struct.unpack("<dI", se.mem_read(out, 12))
    assert result == expected
    assert stack_change == 0
