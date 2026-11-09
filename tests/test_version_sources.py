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


@pytest.mark.parametrize("bin_name, base", [("dll_test_x86.dll.xz", 0x7FFE0000), ("wdm_test_x86.sys.xz", 0xFFDF0000)])
def test_user_shared_data_reads_the_config(
    win10_config: dict[str, Any], load_test_bin: Callable[[str], bytes], bin_name: str, base: int
) -> None:
    for se in load_emu(win10_config, load_test_bin(bin_name)):
        # KUSER_SHARED_DATA: ULONG NtBuildNumber at 0x260, NT_PRODUCT_TYPE NtProductType at 0x264,
        # BOOLEAN ProductTypeIsValid at 0x268, ULONG NtMajorVersion at 0x26C, ULONG NtMinorVersion at 0x270
        build, product_type, is_valid, major, minor = struct.unpack("<IIBxxxII", se.mem_read(base + 0x260, 20))
        assert (build, product_type, is_valid, major, minor) == (19045, 1, 1, 10, 0)


@pytest.mark.parametrize("bin_name, base", [("dll_test_x86.dll.xz", 0x7FFE0000), ("wdm_test_x86.sys.xz", 0xFFDF0000)])
def test_user_shared_data_has_the_system_root(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes], bin_name: str, base: int
) -> None:
    config["env"]["systemroot"] = "D:\\WINNT"
    for se in load_emu(config, load_test_bin(bin_name)):
        # KUSER_SHARED_DATA: WCHAR NtSystemRoot[260] at 0x30
        assert se.mem_read(base + 0x30, 18) == "D:\\WINNT\x00".encode("utf-16le")
