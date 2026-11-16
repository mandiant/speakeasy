"""Test that imports from API sets, aliases and C runtime DLLs reach a handler."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.windows.api_resolution import HandlerImplementation
from tests.handler_harness import alloc, call
from tests.pe_builder import build_pe

APP_MODEL_RUNTIME = "api-ms-win-appmodel-runtime-l1-1-2.dll"
APP_POLICY_PROCESS_TERMINATION_METHOD_EXIT_PROCESS = 0


def has_handler(se: Speakeasy, dll: str, name: str) -> bool:
    emu = se.emu
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
        ("api-ms-win-crt-string-l1-1-0", "wcsnlen"),
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


def app_policy_program(base: int, iat: dict[tuple[str, str | int], int]) -> bytes:
    """Call AppPolicyGetProcessTerminationMethod and save ESP before and after the call, the policy and EAX."""
    data = base + 0x2000
    code = b"\x89\x25" + struct.pack("<I", data)
    code += b"\x68" + struct.pack("<I", data + 8)
    code += b"\x6a\xfa"
    code += b"\xff\x15" + struct.pack("<I", base + iat[APP_MODEL_RUNTIME, "AppPolicyGetProcessTerminationMethod"])
    code += b"\x89\x25" + struct.pack("<I", data + 4)
    code += b"\xa3" + struct.pack("<I", data + 12)
    return code + b"\xc3"


def test_app_policy_from_an_api_set_removes_its_two_arguments() -> None:
    imports = {APP_MODEL_RUNTIME: ["AppPolicyGetProcessTerminationMethod"]}
    data, _ = build_pe(32, text=app_policy_program, data=b"\xcc" * 16, imports=imports)
    with Speakeasy(config=get_default_config_dict()) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        report = se.get_report()
        assert [entry.error for entry in report.runs] == [None]
        [event] = [event for event in report.runs[0].events if event.event == "api"]
        assert event.api_name == "kernel32.AppPolicyGetProcessTerminationMethod"
        assert [arg.name for arg in event.args] == ["processToken", "policy"]
        esp_before, esp_after, policy, rv = struct.unpack("<4I", se.mem_read(module.base + 0x2000, 16))
        assert esp_after == esp_before
        assert (policy, rv) == (APP_POLICY_PROCESS_TERMINATION_METHOD_EXIT_PROCESS, 0)
