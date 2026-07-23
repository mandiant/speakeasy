"""Test that DLL-name normalization and A/W (Zw/Nt) folding compose in normalize_import_miss."""

import pytest

from speakeasy.windows.common import normalize_dll_name

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
        from speakeasy.windows.winemu import WindowsEmulator

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
