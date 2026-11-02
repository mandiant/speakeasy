import struct
from collections.abc import Callable
from typing import Any

import pytest

from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, get_win32_emu, load_emu, start_process

RTL_OSVERSIONINFOW_SIZE = 276
RTL_OSVERSIONINFOEXW_SIZE = 284


@pytest.fixture
def win10_config(config: dict[str, Any]) -> dict[str, Any]:
    config["os_ver"] = {"major": 10, "minor": 0, "build": 19045}
    return config


@pytest.mark.parametrize("bin_name, dll", [("dll_test_x86.dll.xz", "ntdll"), ("wdm_test_x86.sys.xz", "ntoskrnl")])
@pytest.mark.parametrize("size", [RTL_OSVERSIONINFOW_SIZE, RTL_OSVERSIONINFOEXW_SIZE])
def test_rtl_get_version_reads_the_config(
    win10_config: dict[str, Any], load_test_bin: Callable[[str], bytes], bin_name: str, dll: str, size: int
) -> None:
    for se in load_emu(win10_config, load_test_bin(bin_name)):
        # The bytes after the structure show that the handler writes only the structure of the given size.
        info = alloc(se, struct.pack("<I", size) + b"\xcc" * size)
        assert call(se, dll, "RtlGetVersion", [info])[0] == ddk.STATUS_SUCCESS
        assert struct.unpack("<5I", se.mem_read(info, 20)) == (size, 10, 0, 19045, windefs.VER_PLATFORM_WIN32_NT)
        assert se.mem_read(info + size, 4) == b"\xcc" * 4
        # szCSDVersion is an empty string, not the bytes that were in the buffer.
        assert se.mem_read(info + 20, 256) == b"\x00" * 256
        if size == RTL_OSVERSIONINFOEXW_SIZE:
            # The UCHAR wProductType follows szCSDVersion and three USHORT fields.
            assert se.mem_read(info + 282, 1)[0] == windefs.VER_NT_WORKSTATION


def test_rtl_get_nt_version_numbers_reads_the_config(
    win10_config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    for se in load_emu(win10_config, load_test_bin("dll_test_x86.dll.xz")):
        out = alloc(se, b"\x00" * 12)
        call(se, "ntdll", "RtlGetNtVersionNumbers", [out, out + 4, out + 8])
        assert struct.unpack("<3I", se.mem_read(out, 12)) == (10, 0, 0xF0000000 | 19045)


def test_peb_reads_the_config(win10_config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> None:
    for se in load_emu(win10_config, load_test_bin("dll_test_x86.dll.xz")):
        start_process(se)
        emu = get_win32_emu(se)
        peb = emu.alloc_peb(emu.curr_process)
        # PEB (x86): ULONG OSMajorVersion at 0xA4, ULONG OSMinorVersion at 0xA8, USHORT OSBuildNumber at 0xAC,
        # USHORT OSCSDVersion at 0xAE, ULONG OSPlatformId at 0xB0
        major, minor, build, _, platform = struct.unpack("<IIHHI", se.mem_read(peb.address + 0xA4, 16))
        assert (major, minor, build, platform) == (10, 0, 19045, windefs.VER_PLATFORM_WIN32_NT)
