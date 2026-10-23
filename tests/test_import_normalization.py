"""Test that DLL-name normalization and A/W (Zw/Nt) folding compose in normalize_import_miss."""

import pytest

from speakeasy.windows.common import normalize_dll_name
from speakeasy.windows.winemu import WindowsEmulator

SENTINEL_HANDLER = ("handler", lambda: None, 4, "stdcall", None)


class HandlerTable:
    """Concrete handler lookup that resolves a fixed set of (dll, func) pairs."""

    def __init__(self, entries):
        self._entries = {(d.lower(), f): SENTINEL_HANDLER for d, f in entries}

    def get_export_func_handler(self, dll, name):
        key = (dll.lower() if dll else dll, name)
        handler = self._entries.get(key)
        return (self, handler) if handler else (None, None)

    def get_data_export_handler(self, dll, name):
        return None, None


class FakeEmulator:
    """Minimal object satisfying normalize_import_miss's self.api contract."""

    def __init__(self, handler_entries):
        self.api = HandlerTable(handler_entries)

    def normalize_import_miss(self, dll, name):
        return WindowsEmulator.normalize_import_miss(self, dll, name)


CANONICAL_HANDLERS = [
    ("kernel32", "CreateProcess"),
    ("kernel32", "LoadLibraryEx"),
    ("kernel32", "GetModuleFileName"),
    ("kernel32", "SetLastError"),
    ("msvcrt", "malloc"),
    ("ws2_32", "connect"),
    ("ntoskrnl", "ZwCreateFile"),
    ("ntoskrnl", "NtQueryInformationProcess"),
]


@pytest.fixture
def emu():
    return FakeEmulator(CANONICAL_HANDLERS)


def test_normalize_dll_name_apiset_core():
    assert normalize_dll_name("api-ms-win-core-processthreads-l1-1-1") == "kernel32"


def test_normalize_dll_name_apiset_winrt_is_combase():
    assert normalize_dll_name("api-ms-win-core-winrt-l1-1-0") == "combase"
    assert normalize_dll_name("api-ms-win-core-winrt-string-l1-1-0") == "combase"
    assert normalize_dll_name("API-MS-WIN-CORE-WINRT-ERROR-L1-1-1") == "combase"


def test_normalize_dll_name_apiset_com_is_ole32():
    assert normalize_dll_name("api-ms-win-core-com-l1-1-0") == "ole32"
    assert normalize_dll_name("api-ms-win-core-com-l2-1-1") == "ole32"


def test_normalize_dll_name_apiset_extensions():
    assert normalize_dll_name("ext-ms-win-rtcore-ntuser-window-ext-l1-1-0") == "user32"
    assert normalize_dll_name("ext-ms-win-ntuser-message-l1-1-1") == "user32"
    assert normalize_dll_name("ext-ms-win-gdi-dc-l1-2-0") == "gdi32"
    assert normalize_dll_name("ext-ms-win-rtcore-gdi-object-l1-1-0") == "gdi32"
    assert normalize_dll_name("api-ms-win-eventing-classicprovider-l1-1-0") == "advapi32"
    assert normalize_dll_name("ext-ms-win-shell-shell32-l1-2-0") == "ext-ms-win-shell-shell32-l1-2-0"
    assert normalize_dll_name("api-ms-win-shell-shellfolders-l1-1-0") == "shell32"
    assert normalize_dll_name("api-ms-win-core-shlwapi-legacy-l1-1-0") == "shlwapi"
    assert normalize_dll_name("api-ms-win-core-shlwapi-obsolete-l1-1-0") == "shlwapi"


def test_normalize_dll_name_crt():
    assert normalize_dll_name("api-ms-win-crt-heap-l1-1-0") == "msvcrt"
    assert normalize_dll_name("vcruntime140") == "msvcrt"
    assert normalize_dll_name("ucrtbase") == "msvcrt"


def test_normalize_dll_name_winsock():
    assert normalize_dll_name("wsock32") == "ws2_32"
    assert normalize_dll_name("winsock") == "ws2_32"


def test_normalize_dll_name_no_change():
    assert normalize_dll_name("kernel32") == "kernel32"
    assert normalize_dll_name("ntdll") == "ntdll"


@pytest.mark.parametrize(
    "dll, func",
    [
        ("kernel32", "CreateProcess"),
        ("kernel32", "CreateProcessA"),
        ("kernel32", "CreateProcessW"),
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcess"),
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcessA"),
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcessW"),
    ],
)
def test_apiset_with_aw_suffix(emu, dll, func):
    _mod, attrs = emu.normalize_import_miss(dll, func)
    assert attrs is not None, f"({dll}, {func}) should resolve"


@pytest.mark.parametrize(
    "dll, func",
    [
        ("api-ms-win-core-libraryloader-l1-2-0", "LoadLibraryEx"),
        ("api-ms-win-core-libraryloader-l1-2-0", "LoadLibraryExA"),
        ("api-ms-win-core-libraryloader-l1-2-0", "LoadLibraryExW"),
    ],
)
def test_apiset_libraryloader(emu, dll, func):
    _mod, attrs = emu.normalize_import_miss(dll, func)
    assert attrs is not None, f"({dll}, {func}) should resolve"


@pytest.mark.parametrize(
    "dll, func",
    [
        ("api-ms-win-crt-heap-l1-1-0", "malloc"),
        ("vcruntime140", "malloc"),
        ("ucrtbase", "malloc"),
    ],
)
def test_crt_normalization(emu, dll, func):
    _mod, attrs = emu.normalize_import_miss(dll, func)
    assert attrs is not None, f"({dll}, {func}) should resolve"


@pytest.mark.parametrize(
    "dll, func",
    [
        ("wsock32", "connect"),
        ("winsock", "connect"),
    ],
)
def test_winsock_normalization(emu, dll, func):
    _mod, attrs = emu.normalize_import_miss(dll, func)
    assert attrs is not None, f"({dll}, {func}) should resolve"


def test_unresolvable_returns_none(emu):
    _mod, attrs = emu.normalize_import_miss("unknown", "NoSuchFunc")
    assert attrs is None


@pytest.mark.parametrize(
    "func, expected_func",
    [
        ("ZwCreateFile", "ZwCreateFile"),
        ("NtCreateFile", "ZwCreateFile"),
    ],
)
def test_ntdll_to_ntoskrnl(emu, func, expected_func):
    _mod, attrs = emu.normalize_import_miss("ntdll", func)
    assert attrs is not None, f"ntdll.{func} should bridge to ntoskrnl.{expected_func}"


def test_ntoskrnl_zw_to_nt(emu):
    _mod, attrs = emu.normalize_import_miss("ntoskrnl", "ZwQueryInformationProcess")
    assert attrs is not None, "ntoskrnl.ZwQueryInformationProcess -> NtQueryInformationProcess"


def test_ntoskrnl_direct(emu):
    _mod, attrs = emu.normalize_import_miss("ntoskrnl", "ZwCreateFile")
    assert attrs is not None


@pytest.mark.parametrize(
    "dll, func",
    [
        ("kernel32", "RegGetValueW"),
        ("KERNEL32", "RegOpenKeyExA"),
        ("api-ms-win-core-registry-l1-1-0", "RegQueryValueExW"),
    ],
)
def test_kernel32_registry_functions_use_advapi32_handlers(dll, func):
    emu = FakeEmulator([("advapi32", "RegGetValue"), ("advapi32", "RegOpenKeyEx"), ("advapi32", "RegQueryValueEx")])
    _mod, attrs = emu.normalize_import_miss(dll, func)
    assert attrs is not None, f"({dll}, {func}) should resolve to advapi32"


def test_kernel32_non_registry_function_does_not_use_advapi32_handlers():
    emu = FakeEmulator([("advapi32", "RegisterEventSource"), ("advapi32", "OpenProcessToken")])
    assert emu.normalize_import_miss("kernel32", "OpenProcessToken")[1] is None


@pytest.mark.parametrize("func", ["K32GetModuleBaseNameA", "K32GetModuleBaseNameW", "K32GetModuleInformation"])
def test_kernel32_k32_aliases_use_psapi(func):
    emu = FakeEmulator([("psapi", "GetModuleBaseName"), ("psapi", "GetModuleInformation")])
    _mod, attrs = emu.normalize_import_miss("kernel32", func)
    assert attrs is not None
