"""Each handler that looks up a handle argument fails a bad handle with the result of its API family."""

import struct
from collections.abc import Callable

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import advapi32 as adv32
from speakeasy.winenv.defs.windows import windows as windefs
from speakeasy.winenv.defs.winsock import winsock
from tests.handler_harness import alloc, call, start_process, unicode_string

BAD = 0x9998
UNSET = 0x1234
ERROR_INVALID_HANDLE = windefs.ERROR_INVALID_HANDLE
FAIL_DWORD = 0xFFFFFFFF

Arg = int | Callable[[Speakeasy], int]


def buf(se: Speakeasy) -> int:
    return alloc(se, b"\x00" * 0x400)


def url(se: Speakeasy) -> int:
    return alloc(se, b"http://example.com/\x00")


def unicode_name(se: Speakeasy) -> int:
    return unicode_string(se, "Value")


def bad_handle_array(se: Speakeasy) -> int:
    return alloc(se, struct.pack("<I", BAD))


def bad_root_attributes(se: Speakeasy) -> int:
    return alloc(se, struct.pack("<IIIIII", 24, BAD, unicode_string(se, "Parameters"), 0, 0, 0))


def row(module: str, api: str, args: list[Arg], rv: int, error: int):
    return pytest.param(module, api, args, rv, error, id=f"{module}.{api}")


def kernel_row(module: str, api: str, args: list[Arg]):
    return pytest.param(module, api, args, id=f"{module}.{api}")


USER_ROWS = [
    row("kernel32", "GetProcessTimes", [BAD, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "TerminateProcess", [BAD, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "VirtualAllocEx", [BAD, 0, 0x1000, 0x3000, 4], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "WriteProcessMemory", [BAD, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "ReadProcessMemory", [BAD, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "CreateRemoteThread", [BAD, 0, 0, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetProcessId", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "VirtualQueryEx", [BAD, 0, buf, 0x1C], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "VirtualProtectEx", [BAD, 0, 0x1000, 4, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetModuleFileNameExA", [BAD, 0, buf, 0x100], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "ResumeThread", [BAD], FAIL_DWORD, ERROR_INVALID_HANDLE),
    row("kernel32", "SuspendThread", [BAD], FAIL_DWORD, ERROR_INVALID_HANDLE),
    row("kernel32", "TerminateThread", [BAD, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetThreadId", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetProcessIdOfThread", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetThreadContext", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "SetThreadContext", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Wow64SetThreadContext", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetExitCodeThread", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "SetWaitableTimer", [BAD, buf, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "CancelWaitableTimer", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "SetEvent", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "PulseEvent", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "ResetEvent", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetFinalPathNameByHandleA", [BAD, buf, 0x100, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "CreateFileMappingA", [BAD, 0, 4, 0, 0x1000, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "SetFilePointer", [BAD, 0, 0, 0], windefs.INVALID_SET_FILE_POINTER, ERROR_INVALID_HANDLE),
    row("kernel32", "SetFilePointerEx", [BAD, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetFileSize", [BAD, 0], windefs.INVALID_FILE_SIZE, ERROR_INVALID_HANDLE),
    row("kernel32", "GetFileSizeEx", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetFileInformationByHandle", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "GetFileType", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "_llseek", [BAD, 0, 0], windefs.HFILE_ERROR, ERROR_INVALID_HANDLE),
    row("kernel32", "_lclose", [BAD], windefs.HFILE_ERROR, ERROR_INVALID_HANDLE),
    row("kernel32", "ReadFile", [BAD, buf, 0x10, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "WriteFile", [BAD, buf, 0x10, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "MapViewOfFile", [BAD, 4, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "MapViewOfFileEx", [BAD, 4, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "WaitForSingleObject", [BAD, 0], windefs.WAIT_FAILED, ERROR_INVALID_HANDLE),
    row("kernel32", "WaitForMultipleObjects", [1, bad_handle_array, 0, 0], windefs.WAIT_FAILED, ERROR_INVALID_HANDLE),
    row("kernel32", "PeekNamedPipe", [BAD, 0, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "ConnectNamedPipe", [BAD, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "DisconnectNamedPipe", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "FindNextFileA", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "FindClose", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "FindNextVolumeA", [BAD, buf, 0x100], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "FindVolumeClose", [BAD], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "DeviceIoControl", [BAD, 0, 0, 0, 0, 0, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Process32First", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Process32Next", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Thread32First", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Thread32Next", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Module32First", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("kernel32", "Module32Next", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "RegOpenKeyA", [BAD, 0, buf], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegOpenKeyExA", [BAD, 0, 0, 0, buf], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegQueryValueExA", [BAD, 0, 0, 0, 0, 0], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegSetValueExA", [BAD, 0, 0, 1, 0, 0], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegCloseKey", [BAD], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegEnumKeyA", [BAD, 0, buf, 0x100], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegEnumKeyExA", [BAD, 0, buf, buf, 0, 0, 0, 0], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegCreateKeyA", [BAD, 0, buf], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegCreateKeyExA", [BAD, 0, 0, 0, 0, 0, 0, buf, 0], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegDeleteValueA", [BAD, 0], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegQueryInfoKeyA", [BAD] + [0] * 11, ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "RegGetValueA", [BAD, 0, 0, 0, 0, 0, 0], ERROR_INVALID_HANDLE, UNSET),
    row("advapi32", "OpenProcessToken", [BAD, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "OpenThreadToken", [BAD, 0, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "DuplicateTokenEx", [BAD, 0, 0, 0, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptReleaseContext", [BAD, 0], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptHashData", [BAD, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptGetHashParam", [BAD, 2, 0, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptDeriveKey", [0, 0x6801, BAD, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptImportKey", [BAD, buf, 0x1C, 0, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptGenKey", [BAD, 0x660E, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptSetKeyParam", [BAD, 1, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptExportKey", [BAD, 0, 8, 0, 0, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptEncrypt", [BAD, 0, 1, 0, buf, buf, 0x10], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptDecrypt", [BAD, 0, 1, 0, buf, buf], 0, ERROR_INVALID_HANDLE),
    row("advapi32", "CryptDestroyKey", [BAD], 0, ERROR_INVALID_HANDLE),
    row("ws2_32", "connect", [BAD, buf, 16], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "bind", [BAD, buf, 16], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "accept", [BAD, 0, 0], 0xFFFFFFFF, winsock.WSAENOTSOCK),
    row("ws2_32", "getpeername", [BAD, buf, buf], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "getsockname", [BAD, buf, buf], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "recv", [BAD, buf, 0x10, 0], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "send", [BAD, buf, 0x10, 0], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "closesocket", [BAD], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("ws2_32", "ioctlsocket", [BAD, 0, buf], winsock.SOCKET_ERROR, winsock.WSAENOTSOCK),
    row("bcrypt", "BCryptImportKeyPair", [BAD, 0, buf, buf, buf, 16, 0], ddk.STATUS_INVALID_HANDLE, UNSET),
    row("bcrypt", "BCryptCloseAlgorithmProvider", [BAD, 0], ddk.STATUS_INVALID_HANDLE, UNSET),
    row("bcrypt", "BCryptGetProperty", [BAD, buf, buf, 4, buf, 0], ddk.STATUS_INVALID_HANDLE, UNSET),
    row("bcrypt", "BCryptSetProperty", [BAD, buf, buf, 4, 0], ddk.STATUS_INVALID_HANDLE, UNSET),
    row(
        "bcrypt",
        "BCryptGenerateSymmetricKey",
        [BAD, buf, 0, 0, buf, 16, 0],
        ddk.STATUS_INVALID_HANDLE,
        UNSET,
    ),
    row(
        "bcrypt",
        "BCryptEncrypt",
        [BAD, buf, 16, 0, 0, 0, buf, 16, buf, 0],
        ddk.STATUS_INVALID_HANDLE,
        UNSET,
    ),
    row(
        "bcrypt",
        "BCryptDecrypt",
        [BAD, buf, 16, 0, 0, 0, buf, 16, buf, 0],
        ddk.STATUS_INVALID_HANDLE,
        UNSET,
    ),
    row("bcrypt", "BCryptDestroyKey", [BAD], ddk.STATUS_INVALID_HANDLE, UNSET),
    row("bcrypt", "BCryptGenRandom", [BAD, buf, 16, 0], ddk.STATUS_INVALID_HANDLE, UNSET),
    row("user32", "UpdateWindow", [BAD], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "GetParent", [BAD], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "SetPropA", [BAD, 1, 1], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "GetPropA", [BAD, 1], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "RemovePropA", [BAD, 1], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "GetWindowThreadProcessId", [BAD, buf], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "GetWindowLongA", [BAD, 0], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "GetWindowLongPtrA", [BAD, 0], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "SetWindowLongA", [BAD, 0, 1], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("user32", "SetWindowLongPtrA", [BAD, 0, 1], 0, windefs.ERROR_INVALID_WINDOW_HANDLE),
    row("wininet", "InternetConnectA", [BAD, 0, 80, 0, 0, 3, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("wininet", "HttpOpenRequestA", [BAD, 0, 0, 0, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("wininet", "HttpSendRequestA", [BAD, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("wininet", "InternetReadFile", [BAD, buf, 16, buf], 0, ERROR_INVALID_HANDLE),
    row("wininet", "HttpQueryInfoA", [BAD, 1, buf, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("wininet", "InternetQueryDataAvailable", [BAD, buf, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("wininet", "InternetCloseHandle", [BAD], 0, ERROR_INVALID_HANDLE),
    row("wininet", "InternetOpenUrlA", [BAD, url, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpConnect", [BAD, 0, 80, 0], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpOpenRequest", [BAD, 0, 0, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpSendRequest", [BAD, 0, 0, 0, 0, 0, 0], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpReadData", [BAD, buf, 16, buf], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpQueryDataAvailable", [BAD, buf], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpQueryHeaders", [BAD, 1, 0, buf, buf, 0], 0, ERROR_INVALID_HANDLE),
    row("winhttp", "WinHttpCloseHandle", [BAD], 0, ERROR_INVALID_HANDLE),
    row("ncrypt", "NCryptImportKey", [BAD, 0, buf, 0, buf, buf, 16, 0], adv32.NTE_INVALID_HANDLE, UNSET),
    row("ncrypt", "NCryptDeleteKey", [BAD, 0], adv32.NTE_INVALID_HANDLE, UNSET),
    row("ncrypt", "NCryptFreeObject", [BAD], adv32.NTE_INVALID_HANDLE, UNSET),
    row(
        "ntdll",
        "NtCreateThreadEx",
        [buf, 0, 0, BAD, 0x1000, 0, 0, 0, 0, 0, 0],
        ddk.STATUS_INVALID_HANDLE,
        UNSET,
    ),
    row("ntdll", "NtTerminateProcess", [BAD, 0], ddk.STATUS_INVALID_HANDLE, UNSET),
    row("psapi", "EnumProcessModules", [BAD, buf, 0x100, buf], 0, ERROR_INVALID_HANDLE),
    row("psapi", "GetModuleBaseNameA", [BAD, 0, buf, 0x100], 0, ERROR_INVALID_HANDLE),
    row("psapi", "GetModuleFileNameExW", [BAD, 0, buf, 0x100], 0, ERROR_INVALID_HANDLE),
    row("psapi", "GetModuleInformation", [BAD, 0, buf, 0x100], 0, ERROR_INVALID_HANDLE),
]

KERNEL_ROWS = [
    kernel_row("ntoskrnl", "PsCreateSystemThread", [buf, 0, 0, BAD, 0, 0, 0]),
    kernel_row("ntoskrnl", "ZwWriteVirtualMemory", [BAD, 0, 0, 0, 0]),
    kernel_row("ntoskrnl", "ZwAllocateVirtualMemory", [BAD, buf, 0, buf, 0x3000, 4]),
    kernel_row("ntoskrnl", "ZwDeviceIoControlFile", [BAD] + [0] * 9),
    kernel_row("ntoskrnl", "ObReferenceObjectByHandle", [BAD, 0, 0, 0, buf, 0]),
    kernel_row("ntoskrnl", "ZwQueryInformationProcess", [BAD, 0, buf, 0x18, 0]),
    kernel_row("ntoskrnl", "NtSetInformationThread", [BAD, 0x11, 0, 0]),
    kernel_row("ntoskrnl", "ZwQueryValueKey", [BAD, 0, 2, buf, 0x100, buf]),
    kernel_row("ntoskrnl", "ZwCreateKey", [buf, 0, bad_root_attributes, 0, 0, 0, 0]),
    kernel_row("ntoskrnl", "ZwSetValueKey", [BAD, 0, 0, 4, 0, 0]),
    kernel_row("ntoskrnl", "ZwQueryInformationFile", [BAD, buf, buf, 0x18, 5]),
    kernel_row("ntoskrnl", "ZwWriteFile", [BAD, 0, 0, 0, buf, buf, 0x10, 0, 0]),
    kernel_row("ntoskrnl", "ZwReadFile", [BAD, 0, 0, 0, buf, buf, 0x10, 0, 0]),
    kernel_row("ntoskrnl", "ZwCreateSection", [buf, 0, 0, 0, 4, 0x8000000, BAD]),
    kernel_row("ntoskrnl", "ZwUnmapViewOfSection", [BAD, 0]),
    kernel_row("ntoskrnl", "ZwMapViewOfSection", [BAD, 0xFFFFFFFF, buf] + [0] * 7),
    kernel_row("ntoskrnl", "ZwGetContextThread", [BAD, buf]),
    kernel_row("ntoskrnl", "ZwSetContextThread", [BAD, buf]),
    kernel_row("wdfldr", "WdfRegistryQueryULong", [0, BAD, unicode_name, buf]),
    kernel_row("wdfldr", "WdfUsbTargetDeviceSelectConfig", [0, BAD, 0, buf]),
    kernel_row("wdfldr", "WdfUsbInterfaceSelectSetting", [0, BAD, 0, buf]),
    kernel_row("wdfldr", "WdfUsbTargetDeviceRetrieveInformation", [0, BAD, buf]),
]


def call_with_bad_handle(se: Speakeasy, module: str, api: str, args: list[Arg]) -> tuple[int, int]:
    argv = [a(se) if callable(a) else a for a in args]
    se.emu.set_last_error(UNSET)
    rv, _ = call(se, module, api, argv)
    return rv, se.emu.get_last_error()


@pytest.mark.parametrize(("module", "api", "args", "rv", "error"), USER_ROWS)
def test_a_user_mode_handler_fails_a_bad_handle(
    dll_emu: Speakeasy, module: str, api: str, args: list[Arg], rv: int, error: int
) -> None:
    start_process(dll_emu)
    assert call_with_bad_handle(dll_emu, module, api, args) == (rv, error)


@pytest.mark.parametrize(("module", "api", "args"), KERNEL_ROWS)
def test_a_kernel_mode_handler_fails_a_bad_handle(
    driver_emu: Speakeasy, module: str, api: str, args: list[Arg]
) -> None:
    assert call_with_bad_handle(driver_emu, module, api, args)[0] == ddk.STATUS_INVALID_HANDLE
