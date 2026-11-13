import struct
from typing import Any

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, start_process
from tests.pe_builder import build_pe

KUSER_SHARED_DATA = 0x7FFE0000
KUSER_TAG_PREFIX = "emu.struct.KUSER_SHARED_DATA"


def read_ksystem_time(se: Speakeasy, base: int, offset: int) -> int:
    low, high1, high2 = struct.unpack("<IiI", se.mem_read(base + offset, 12))
    assert high1 == high2
    return high1 << 32 | low


def read_kuser_times(se: Speakeasy, base: int = KUSER_SHARED_DATA) -> tuple[int, int, int]:
    """Return InterruptTime, SystemTime and the tick count in milliseconds."""
    multiplier = struct.unpack("<I", se.mem_read(base + 0x004, 4))[0]
    tick_quad = struct.unpack("<Q", se.mem_read(base + 0x320, 8))[0]
    return read_ksystem_time(se, base, 0x008), read_ksystem_time(se, base, 0x014), (tick_quad * multiplier) >> 24


def kuser_bases(se: Speakeasy) -> list[int]:
    return [mm.base for mm in se.emu.get_mem_maps() if mm.tag and mm.tag.startswith(KUSER_TAG_PREFIX)]


def test_kuser_shared_data_follows_the_clock_apis(dll_emu: Speakeasy) -> None:
    se = dll_emu
    start_process(se)
    filetime = alloc(se, b"\x00" * 8)

    tick = call(se, "kernel32", "GetTickCount", [])[0]
    interrupt_time, _, kuser_tick = read_kuser_times(se)
    assert kuser_tick == tick
    assert interrupt_time == tick * 10_000

    call(se, "kernel32", "GetSystemTimeAsFileTime", [filetime])
    assert read_kuser_times(se)[1] == struct.unpack("<Q", se.mem_read(filetime, 8))[0]

    pages = {bytes(se.mem_read(base, 0x400)) for base in kuser_bases(se)}
    assert len(pages) == 1


def sleep_until_kuser_time_passes(base: int, iat: dict[tuple[str, str | int], int]) -> bytes:
    """Read SystemTime from KUSER_SHARED_DATA, call Sleep(100) until one second passes, and exit with code 7."""
    sleep = base + iat["kernel32.dll", "Sleep"]
    exit_process = base + iat["kernel32.dll", "ExitProcess"]
    code = b"\x8b\x35\x14\x00\xfe\x7f"  # mov esi, [0x7ffe0014]
    loop = len(code)
    code += b"\x6a\x64"  # push 100
    code += b"\xff\x15" + struct.pack("<I", sleep)  # call [Sleep]
    code += b"\xa1\x14\x00\xfe\x7f"  # mov eax, [0x7ffe0014]
    code += b"\x29\xf0"  # sub eax, esi
    code += b"\x3d" + struct.pack("<I", 10_000_000)  # cmp eax, 10000000
    code += b"\x72" + struct.pack("<b", loop - (len(code) + 2))  # jb loop
    code += b"\x6a\x07"  # push 7
    code += b"\xff\x15" + struct.pack("<I", exit_process)  # call [ExitProcess]
    return code


def test_kuser_shared_data_wait_loop_ends(config: dict[str, Any]) -> None:
    config["limits"]["api_calls"] = 100
    data, _ = build_pe(32, text=sleep_until_kuser_time_passes, imports={"kernel32.dll": ["Sleep", "ExitProcess"]})
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        entry = se.get_report().entry_points[0]
        assert entry.error is None
        exits = [e for e in entry.events if e.event == "api" and e.api_name == "kernel32.ExitProcess"]
        assert len(exits) == 1
        assert exits[0].args[0].value == 7


def test_kuser_shared_data_follows_the_kernel_clock(driver_emu: Speakeasy) -> None:
    current_time = alloc(driver_emu, b"\x00" * 8)
    call(driver_emu, "ntoskrnl", "KeQuerySystemTime", [current_time])
    system_time = struct.unpack("<Q", driver_emu.mem_read(current_time, 8))[0]
    assert read_kuser_times(driver_emu, 0xFFDF0000)[1] == system_time
