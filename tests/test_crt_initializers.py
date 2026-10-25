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


@pytest.mark.parametrize(
    "api, initializer",
    [
        ("_initterm_e", "__initialize_lconv_for_unsigned_char"),
        ("_initterm_e", "__uninitialize_lconv_for_unsigned_char"),
        ("_initterm", "__lconv_init"),
    ],
)
def test_crt_lconv_initializers_succeed(x86_session, api, initializer):
    se = x86_session

    assert call_table(se, api, [se.emu.get_proc("msvcrt", initializer)]) == 0


@pytest.fixture
def x64_session(config):
    config["timeout"] = 2
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch="x64")
        se.run_shellcode(base)
        yield se
    finally:
        se.shutdown()


@pytest.mark.parametrize(
    "ctor, dtor",
    [
        ("??0Init@ios_base@std@@QAE@XZ", "??1Init@ios_base@std@@QAE@XZ"),
        ("??0_Winit@std@@QAE@XZ", "??1_Winit@std@@QAE@XZ"),
        ("??0?$basic_ios@DU?$char_traits@D@std@@@std@@IAE@XZ", "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UAE@XZ"),
        (
            "??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@IAE@XZ",
            "??1?$basic_ios@_WU?$char_traits@_W@std@@@std@@UAE@XZ",
        ),
    ],
)
def test_iostream_static_constructors_are_thiscall_on_x86(x86_session, ctor, dtor):
    se = x86_session
    this = se.mem_alloc(0x1000)
    out = se.mem_alloc(0x1000)
    ctor_addr = se.emu.get_proc("msvcp60", ctor)
    dtor_addr = se.emu.get_proc("msvcp60", dtor)
    caller = write_code(
        se,
        b"\x89\x25"
        + struct.pack("<I", out)
        + b"\xb9"
        + struct.pack("<I", this)
        + b"\xb8"
        + struct.pack("<I", ctor_addr)
        + b"\xff\xd0"
        + b"\xa3"
        + struct.pack("<I", out + 4)
        + b"\xb9"
        + struct.pack("<I", this)
        + b"\xb8"
        + struct.pack("<I", dtor_addr)
        + b"\xff\xd0"
        + b"\x89\x25"
        + struct.pack("<I", out + 8)
        + b"\xc3",
    )
    se.call(caller)

    assert se.get_report().entry_points[-1].error is None
    esp_before, eax, esp_after = struct.unpack("<III", se.mem_read(out, 12))
    assert eax == this
    assert esp_after == esp_before


@pytest.mark.parametrize(
    "ctor, dtor",
    [
        ("??0Init@ios_base@std@@QEAA@XZ", "??1Init@ios_base@std@@QEAA@XZ"),
        ("??0_Winit@std@@QEAA@XZ", "??1_Winit@std@@QEAA@XZ"),
    ],
)
def test_iostream_static_constructors_return_this_on_x64(x64_session, ctor, dtor):
    se = x64_session
    this = se.mem_alloc(0x1000)
    out = se.mem_alloc(0x1000)
    ctor_addr = se.emu.get_proc("msvcp140", ctor)
    dtor_addr = se.emu.get_proc("msvcp140", dtor)
    caller = write_code(
        se,
        b"\x53"
        + b"\x48\x89\xe3"
        + b"\x48\x83\xec\x20"
        + b"\x48\xb9"
        + struct.pack("<Q", this)
        + b"\x48\xb8"
        + struct.pack("<Q", ctor_addr)
        + b"\xff\xd0"
        + b"\x48\xba"
        + struct.pack("<Q", out)
        + b"\x48\x89\x02"
        + b"\x48\xb9"
        + struct.pack("<Q", this)
        + b"\x48\xb8"
        + struct.pack("<Q", dtor_addr)
        + b"\xff\xd0"
        + b"\x48\x83\xc4\x20"
        + b"\x48\xba"
        + struct.pack("<Q", out)
        + b"\x48\x89\x62\x08"
        + b"\x48\x89\x5a\x10"
        + b"\x5b"
        + b"\xc3",
    )
    se.call(caller)

    assert se.get_report().entry_points[-1].error is None
    rax, rsp_after, rsp_before = struct.unpack("<QQQ", se.mem_read(out, 24))
    assert rax == this
    assert rsp_after == rsp_before
