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


@pytest.mark.parametrize("bin_file", ["argv_test_x86.exe.xz", "argv_test_x64.exe.xz"])
def test_initterm_e_runs_the_crt_initializers_in_order(config, load_test_bin, run_test, bin_file):
    report = run_test(config, load_test_bin(bin_file))
    names = [evt.api_name for evt in report.entry_points[0].events or [] if evt.event == "api"]
    initializers = names[names.index("msvcrt._initterm_e") + 1 : names.index("msvcrt._initterm")]
    calls = [
        name
        for name in initializers
        if name in ("msvcrt._configure_narrow_argv", "msvcrt._initialize_narrow_environment")
    ]
    assert calls == ["msvcrt._configure_narrow_argv", "msvcrt._initialize_narrow_environment"]
    assert "msvcrt.__stdio_common_vfprintf" in names


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
