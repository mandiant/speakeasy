import struct
from collections.abc import Callable, Iterator
from typing import Any

import pydantic
import pytest

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig
from tests.handler_harness import alloc, call, load_emu

# 2026-10-31T15:15:00Z
START_TIME_UNIX = 1793459700
START_TIME_FILETIME = 116444736000000000 + START_TIME_UNIX * 10000000

KUSER_SYSTEM_TIME = 0x7FFE0014

RANDOM_APIS: list[tuple[str, str, Callable[[int], list[int]]]] = [
    ("advapi32", "SystemFunction036", lambda buf: [buf, 16]),
    ("advapi32", "CryptGenRandom", lambda buf: [0x1234, 16, buf]),
    ("bcrypt", "BCryptGenRandom", lambda buf: [0, buf, 16, 2]),
    ("bcryptprimitives", "ProcessPrng", lambda buf: [buf, 16]),
    ("ole32", "CoCreateGuid", lambda buf: [buf]),
    ("rpcrt4", "UuidCreate", lambda buf: [buf]),
]


@pytest.fixture
def other_dll_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


def get_random_values(se: Speakeasy) -> list[bytes]:
    values = []
    for dll, name, get_argv in RANDOM_APIS:
        buf = alloc(se, b"\x00" * 16)
        call(se, dll, name, get_argv(buf))
        values.append(bytes(se.mem_read(buf, 16)))
    return values


def test_random_apis_repeat_across_emulators(dll_emu: Speakeasy, other_dll_emu: Speakeasy) -> None:
    values = get_random_values(dll_emu)
    assert values == get_random_values(other_dll_emu)
    # One generator serves all the APIs, so no two calls return the same bytes.
    assert len(set(values)) == len(values)


def test_random_seed_changes_the_random_values(
    dll_emu: Speakeasy, config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    config["random_seed"] = 1
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        assert get_random_values(se) != get_random_values(dll_emu)


def get_clock_values(se: Speakeasy) -> list[int]:
    buf = alloc(se, b"\x00" * 260)
    values = []
    for dll, name, argv in [
        ("kernel32", "GetSystemTimeAsFileTime", [buf]),
        ("kernel32", "QueryPerformanceCounter", [buf]),
        ("kernel32", "GetFileTime", [0, buf, 0, 0]),
    ]:
        call(se, dll, name, argv)
        values.append(int.from_bytes(se.mem_read(buf, 8), "little"))
    values.append(call(se, "msvcrt", "time", [0])[0])
    values.append(call(se, "kernel32", "GetTickCount", [])[0])
    values.append(call(se, "winmm", "timeGetTime", [])[0])
    values.append(call(se, "kernel32", "GetTempFileNameA", [alloc(se, b"C:\\tmp\x00"), 0, 0, buf])[0])
    values.append(int.from_bytes(se.mem_read(KUSER_SYSTEM_TIME, 8), "little"))
    return values


def test_clock_apis_repeat_across_emulators(dll_emu: Speakeasy, other_dll_emu: Speakeasy) -> None:
    values = get_clock_values(dll_emu)
    assert values == get_clock_values(other_dll_emu)
    assert values[3] == START_TIME_UNIX
    assert values[-1] == START_TIME_FILETIME


def test_start_time_sets_the_system_time(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> None:
    config["start_time"] = "2000-01-01T00:00:00+02:00"
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        st = alloc(se, b"\x00" * 16)
        call(se, "kernel32", "GetSystemTime", [st])
        year, month, _, day, hour, minute, _, _ = struct.unpack("<8H", se.mem_read(st, 16))
        assert (year, month, day, hour, minute) == (1999, 12, 31, 22, 0)


def test_start_time_needs_a_time_zone(config: dict[str, Any]) -> None:
    config["start_time"] = "2026-10-31T15:15:00"
    with pytest.raises(pydantic.ValidationError, match="no time zone"):
        SpeakeasyConfig.model_validate(config)
