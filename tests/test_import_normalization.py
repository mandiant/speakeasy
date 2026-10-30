"""Test that imports from API sets, aliases and C runtime DLLs reach a handler."""

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.api_resolution import HandlerImplementation
from tests.handler_harness import alloc, call


def has_handler(se: Speakeasy, dll: str, name: str) -> bool:
    emu = se.emu
    assert emu is not None
    entry = emu.api_registry.entries[emu.get_proc(dll, name)]
    return isinstance(emu.resolve_api_implementation(entry.dll, entry.name), HandlerImplementation)


@pytest.mark.parametrize(
    "dll, name",
    [
        ("kernel32", "CreateProcessA"),
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcessW"),
        ("api-ms-win-core-processthreads-l1-1-0", "OpenProcessToken"),
        ("api-ms-win-core-libraryloader-l1-2-0", "LoadLibraryExW"),
        ("api-ms-win-core-libraryloader-l1-2-0", "LoadStringW"),
        ("api-ms-win-core-registry-l1-1-0", "RegQueryValueExW"),
        ("kernel32", "RegOpenKeyExA"),
        ("kernel32", "K32GetModuleBaseNameA"),
        ("api-ms-win-core-com-l1-1-0", "CoInitializeEx"),
        ("api-ms-win-core-crt-l2-1-0", "_initterm_e"),
        ("api-ms-win-crt-heap-l1-1-0", "malloc"),
        ("vcruntime140", "memset"),
        ("ucrtbase", "malloc"),
        ("api-ms-win-security-base-l1-1-0", "GetTokenInformation"),
        ("api-ms-win-core-version-l1-1-0", "VerQueryValueW"),
        ("ext-ms-win-ntuser-message-l1-1-1", "PeekMessageW"),
        ("ext-ms-win-session-wtsapi32-l1-1-0", "WTSFreeMemory"),
        ("sspicli", "GetUserNameExW"),
        ("wsock32", "connect"),
        ("kernelbase", "EncodePointer"),
        ("ntdll", "NtClose"),
        ("ntdll", "ZwClose"),
    ],
)
def test_user_mode_import_has_a_handler(dll_emu: Speakeasy, dll: str, name: str) -> None:
    assert has_handler(dll_emu, dll, name)


@pytest.mark.parametrize("name", ["ZwQueryInformationProcess", "NtClose", "wcsstr", "strnlen"])
def test_ntoskrnl_import_has_a_handler(driver_emu: Speakeasy, name: str) -> None:
    assert has_handler(driver_emu, "ntoskrnl", name)


def test_ntdll_strcpy_copies_the_string(dll_emu: Speakeasy) -> None:
    dst = alloc(dll_emu, b"\xff" * 8)
    assert call(dll_emu, "ntdll", "strcpy", [dst, alloc(dll_emu, b"abc\0")])[0] == dst
    assert dll_emu.mem_read(dst, 4) == b"abc\0"
    assert call(dll_emu, "ntdll", "strlen", [dst])[0] == 3


def test_ntoskrnl_sprintf_s_formats_in_a_driver(driver_emu: Speakeasy) -> None:
    buf = alloc(driver_emu, b"\xee" * 32)
    rv, _ = call(driver_emu, "ntoskrnl", "sprintf_s", [buf, 32, alloc(driver_emu, b"pid=%d\0"), 42])
    assert rv == 6
    assert driver_emu.mem_read(buf, 7) == b"pid=42\0"
