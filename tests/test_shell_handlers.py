"""
Shell, COM, and ntdll handlers return what Windows returns and write what
Windows writes.
"""

import ntpath
import struct
import uuid
import zlib
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import com
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process

UNREAL_LAUNCHER = "0fdd25efd471f2b6c16866c418320102885d179de35da115a8a0a49915e94d38.exe.xz"


def wstr(text: str, width: int) -> bytes:
    return (text + "\x00").encode("utf-16le" if width == 2 else "utf-8")


def read_wstr(se: Speakeasy, addr: int) -> str:
    data = b""
    while not data.endswith(b"\x00\x00") or len(data) % 2:
        data += se.mem_read(addr + len(data), 1)
    return data[:-2].decode("utf-16le")


def test_sys_free_string_accepts_null(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysFreeString", [0])
    assert rv is None


def test_ldr_access_resource_writes_address_and_ulong_size(dll64_emu: Speakeasy) -> None:
    base = 0x180000000
    entry = alloc(dll64_emu, struct.pack("<IIII", 0x1234, 0x56, 0, 0))
    resource = alloc(dll64_emu, b"\xcc" * 8)
    size = alloc(dll64_emu, b"\xcc" * 8)
    rv, _ = call(dll64_emu, "ntdll", "LdrAccessResource", [base, entry, resource, size])
    assert rv == ddk.STATUS_SUCCESS
    assert dll64_emu.mem_read(resource, 8) == struct.pack("<Q", base + 0x1234)
    assert dll64_emu.mem_read(size, 8) == struct.pack("<I", 0x56) + b"\xcc" * 4


@pytest.mark.parametrize("api", ["StrStrA", "StrStrW", "StrStrIA", "StrStrIW"])
def test_str_str_returns_the_match_address(dll_emu: Speakeasy, api: str) -> None:
    width = 2 if api.endswith("W") else 1
    hay = alloc(dll_emu, wstr("abCDef", width))
    needle = alloc(dll_emu, wstr("CD", width))
    rv, _ = call(dll_emu, "shlwapi", api, [hay, needle])
    assert rv == hay + 2 * width


@pytest.mark.parametrize("api", ["StrStrA", "StrStrW", "StrStrIA", "StrStrIW"])
def test_str_str_returns_null_for_null_args(dll_emu: Speakeasy, api: str) -> None:
    s = alloc(dll_emu, b"a\x00\x00\x00")
    assert call(dll_emu, "shlwapi", api, [0, s])[0] == 0
    assert call(dll_emu, "shlwapi", api, [s, 0])[0] == 0


@pytest.mark.parametrize(
    "api, path, index",
    [
        ("PathFindExtension", "C:\\dir\\file.txt", 11),
        ("PathFindExtension", "C:\\dir.d\\file", 13),
        ("PathFindFileName", "C:\\dir\\file.txt", 7),
        ("PathFindFileName", "file.txt", 0),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_find_returns_byte_address(dll_emu: Speakeasy, api: str, path: str, index: int, width: int) -> None:
    p = alloc(dll_emu, wstr(path, width))
    rv, _ = call(dll_emu, "shlwapi", api + ("W" if width == 2 else "A"), [p])
    assert rv == p + index * width


@pytest.mark.parametrize(
    "cmdline, expected",
    [
        ('C:\\dir\\a.exe "x y" a\\\\\\"b', ["C:\\dir\\a.exe", "x y", 'a\\"b']),
        ('"C:\\Program Files\\a.exe" b\\\\"c d" e\\f', ["C:\\Program Files\\a.exe", "b\\c d", "e\\f"]),
        ('C:\\a\\"b c\\\\', ['C:\\a\\"b', "c\\\\"]),
        ('a.exe "" \t x', ["a.exe", "", "x"]),
        ('a.exe "b c', ["a.exe", "b c"]),
        ('a.exe "a""b"', ["a.exe", 'a"b']),
        ('a.exe "a""b" c', ["a.exe", 'a"b c']),
        ("a.exe " + '"' * 3 + "a b" + '"' * 3, ["a.exe", '"a', 'b"']),
        ('a.exe ""a b', ["a.exe", "a", "b"]),
    ],
)
def test_command_line_to_argv_uses_windows_rules(dll_emu: Speakeasy, cmdline: str, expected: list[str]) -> None:
    cl = alloc(dll_emu, wstr(cmdline, 2))
    nargs = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "CommandLineToArgvW", [cl, nargs])
    assert struct.unpack("<I", dll_emu.mem_read(nargs, 4))[0] == len(expected)
    ptrs = struct.unpack(f"<{len(expected)}I", dll_emu.mem_read(rv, 4 * len(expected)))
    assert [read_wstr(dll_emu, p) for p in ptrs] == expected


def test_command_line_to_argv_resolves_through_its_api_set(dll_emu: Speakeasy) -> None:
    cl = alloc(dll_emu, wstr("a.exe b", 2))
    nargs = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "api-ms-win-core-commandlinetoargv-l1-1-0", "CommandLineToArgvW", [cl, nargs])
    assert struct.unpack("<I", dll_emu.mem_read(nargs, 4))[0] == 2
    ptrs = struct.unpack("<2I", dll_emu.mem_read(rv, 8))
    assert [read_wstr(dll_emu, p) for p in ptrs] == ["a.exe", "b"]


@pytest.mark.parametrize("csidl", [0x1A, 0x801A, 0x401A])
def test_sh_get_folder_path_ignores_csidl_flags(dll_emu: Speakeasy, csidl: int) -> None:
    assert dll_emu.emu is not None
    out = alloc(dll_emu, b"\x00" * 520)
    rv, _ = call(dll_emu, "shell32", "SHGetFolderPathW", [0, csidl, 0, 0, out])
    assert rv == 0
    assert read_wstr(dll_emu, out) == f"C:\\Users\\{dll_emu.emu.config.user.name}\\AppData\\Roaming"


@pytest.mark.parametrize(
    ("folder", "expected"),
    [
        ("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97", "C:\\ProgramData"),
        ("3eb685db-65f9-4cf6-a03a-e3ef65729f3d", "C:\\Users\\{user}\\AppData\\Roaming"),
    ],
)
def test_sh_get_known_folder_path_allocates_the_path(dll_emu: Speakeasy, folder: str, expected: str) -> None:
    assert dll_emu.emu is not None
    rfid = alloc(dll_emu, uuid.UUID(folder).bytes_le)
    out = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "api-ms-win-shell-shellfolders-l1-1-0", "SHGetKnownFolderPath", [rfid, 0, 0, out])
    assert rv == 0
    path = struct.unpack("<I", dll_emu.mem_read(out, 4))[0]
    assert read_wstr(dll_emu, path) == expected.format(user=dll_emu.emu.config.user.name)


@pytest.mark.parametrize(
    ("fixture", "csidl", "expected"),
    [
        ("dll_emu", 0x2A, "C:\\Program Files"),
        ("dll_emu", 0x2C, "C:\\Program Files\\Common Files"),
        ("dll64_emu", 0x2A, "C:\\Program Files (x86)"),
        ("dll64_emu", 0x2C, "C:\\Program Files (x86)\\Common Files"),
        ("dll64_emu", 0x26, "C:\\Program Files"),
    ],
)
def test_sh_get_folder_path_gives_the_x86_program_files_of_the_os(
    request: pytest.FixtureRequest, fixture: str, csidl: int, expected: str
) -> None:
    se = request.getfixturevalue(fixture)
    out = alloc(se, b"\x00" * 520)
    rv, _ = call(se, "shell32", "SHGetFolderPathW", [0, csidl, 0, 0, out])
    assert rv == 0
    assert read_wstr(se, out) == expected


def test_x64_environment_names_the_x86_program_files(dll64_emu: Speakeasy) -> None:
    out = alloc(dll64_emu, b"\x00" * 520)
    for name, expected in (
        ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        ("CommonProgramFiles(x86)", "C:\\Program Files (x86)\\Common Files"),
        ("ProgramW6432", "C:\\Program Files"),
    ):
        rv, _ = call(dll64_emu, "kernel32", "GetEnvironmentVariableA", [alloc(dll64_emu, wstr(name, 1)), out, 520])
        assert dll64_emu.mem_read(out, rv) == expected.encode()


def test_sh_get_known_folder_path_fails_for_an_unknown_folder(dll_emu: Speakeasy) -> None:
    rfid = alloc(dll_emu, uuid.UUID("00000000-1111-2222-3333-444444444444").bytes_le)
    out = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "SHGetKnownFolderPath", [rfid, 0, 0, out])
    assert rv == 0x80070002
    assert dll_emu.mem_read(out, 4) == b"\x00" * 4


def read_pidl_path(se: Speakeasy, pidl: int, width: int) -> tuple[int, bytes]:
    buf = alloc(se, b"\xcc" * 520)
    rv, _ = call(se, "shell32", "SHGetPathFromIDList" + ("W" if width == 2 else "A"), [pidl, buf])
    return rv, se.mem_read(buf, 520)


def assert_item_id_list(se: Speakeasy, pidl: int) -> None:
    (cb,) = struct.unpack("<H", se.mem_read(pidl, 2))
    assert cb > 2
    assert se.mem_read(pidl + cb, 2) == b"\x00\x00"


@pytest.mark.parametrize("width", [1, 2])
def test_sh_get_special_folder_location_maps_to_the_folder_path(dll_emu: Speakeasy, width: int) -> None:
    ppidl = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "SHGetSpecialFolderLocation", [0, 0x23, ppidl])
    assert rv == windefs.S_OK
    pidl = read_ptr(dll_emu, ppidl)
    assert pidl != 0
    assert_item_id_list(dll_emu, pidl)

    rv, path = read_pidl_path(dll_emu, pidl, width)
    assert rv == 1
    assert path.startswith(wstr("C:\\ProgramData", width))


def test_psapi_resolves_the_current_process_pseudo_handle(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    proc = dll_emu.emu.get_current_process()
    current = 0xFFFFFFFF

    mods = alloc(dll_emu, b"\x00" * 16)
    needed = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "psapi", "EnumProcessModules", [current, mods, 16, needed])
    assert rv == 1
    assert struct.unpack("<I", dll_emu.mem_read(mods, 4))[0] == proc.base

    buf = alloc(dll_emu, b"\x00" * 520)
    rv, _ = call(dll_emu, "psapi", "GetModuleBaseNameA", [current, 0, buf, 260])
    assert dll_emu.mem_read(buf, rv) == ntpath.basename(proc.path).encode()

    rv, _ = call(dll_emu, "psapi", "GetModuleFileNameExW", [current, 0, buf, 260])
    assert read_wstr(dll_emu, buf) == proc.path
    assert rv == len(proc.path)


def test_psapi_enum_process_modules_ex_lists_the_modules(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    current = 0xFFFFFFFF
    list_modules_all = 3

    expected = alloc(dll_emu, b"\x00" * 64)
    expected_needed = alloc(dll_emu, b"\x00" * 4)
    call(dll_emu, "psapi", "EnumProcessModules", [current, expected, 64, expected_needed])
    mods = alloc(dll_emu, b"\x00" * 64)
    needed = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "psapi", "EnumProcessModulesEx", [current, mods, 64, needed, list_modules_all])

    assert rv == 1
    assert dll_emu.mem_read(needed, 4) == dll_emu.mem_read(expected_needed, 4)
    assert dll_emu.mem_read(mods, 64) == dll_emu.mem_read(expected, 64)
    assert struct.unpack("<I", dll_emu.mem_read(mods, 4))[0] == dll_emu.emu.get_current_process().base


def test_string_from_clsid_writes_the_string(dll_emu: Speakeasy) -> None:
    clsid = alloc(dll_emu, uuid.UUID(com.CLSID_WbemLocator).bytes_le)
    out = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "ole32", "StringFromCLSID", [clsid, out])
    assert rv == com.S_OK
    assert read_wstr(dll_emu, struct.unpack("<I", dll_emu.mem_read(out, 4))[0]) == com.CLSID_WbemLocator


def read_ptr(se: Speakeasy, addr: int) -> int:
    return struct.unpack("<I", se.mem_read(addr, 4))[0]


def guid(se: Speakeasy, text: str) -> int:
    return alloc(se, uuid.UUID(text).bytes_le)


@pytest.mark.parametrize(
    "clsid, iid, expected",
    [
        ("{00000000-0000-0000-0000-000000000001}", com.IID_IWbemLocator, com.REGDB_E_CLASSNOTREG),
        (com.CLSID_WbemLocator, "{00000000-0000-0000-0000-000000000001}", com.E_NOINTERFACE),
    ],
)
def test_co_create_instance_fails_for_unknown_class_or_interface(
    dll_emu: Speakeasy, clsid: str, iid: str, expected: int
) -> None:
    ppv = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "ole32", "CoCreateInstance", [guid(dll_emu, clsid), 0, 1, guid(dll_emu, iid), ppv])
    assert rv == expected
    assert read_ptr(dll_emu, ppv) == 0


def test_co_initialize_ex_counts_calls_and_checks_the_model(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert call(dll_emu, "ole32", "CoInitializeEx", [0, 0])[0] == com.S_OK
    assert call(dll_emu, "ole32", "CoInitializeEx", [0, 0])[0] == com.S_FALSE
    assert call(dll_emu, "ole32", "CoInitializeEx", [0, 2])[0] == com.RPC_E_CHANGED_MODE
    call(dll_emu, "ole32", "CoUninitialize", [])
    call(dll_emu, "ole32", "CoUninitialize", [])
    assert call(dll_emu, "ole32", "CoInitializeEx", [0, 2])[0] == com.S_OK
    assert call(dll_emu, "ole32", "CoInitialize", [0])[0] == com.S_FALSE
    assert call(dll_emu, "ole32", "OleInitialize", [0])[0] == com.S_FALSE


def test_ole_initialize_fails_on_a_multithreaded_apartment(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert call(dll_emu, "ole32", "OleInitialize", [0])[0] == com.S_OK
    call(dll_emu, "ole32", "OleUninitialize", [])
    assert call(dll_emu, "ole32", "CoInitializeEx", [0, 0])[0] == com.S_OK
    assert call(dll_emu, "ole32", "OleInitialize", [0])[0] == com.RPC_E_CHANGED_MODE


def test_co_create_instance_returns_an_object(dll_emu: Speakeasy) -> None:
    ppv = alloc(dll_emu, b"\xcc" * 4)
    clsid, iid = guid(dll_emu, com.CLSID_WbemLocator), guid(dll_emu, com.IID_IWbemLocator)
    rv, _ = call(dll_emu, "ole32", "CoCreateInstance", [clsid, 0, 1, iid, ppv])
    assert rv == com.S_OK
    obj = read_ptr(dll_emu, ppv)
    assert read_ptr(dll_emu, read_ptr(dll_emu, obj)) != 0

    out = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "com_api", "IUnknown.QueryInterface", [obj, guid(dll_emu, com.IID_IUnknown), out])
    assert rv == com.S_OK
    assert read_ptr(dll_emu, out) == obj

    rv, _ = call(dll_emu, "com_api", "IUnknown.QueryInterface", [obj, guid(dll_emu, str(uuid.UUID(int=1))), out])
    assert rv == com.E_NOINTERFACE
    assert read_ptr(dll_emu, out) == 0


def test_sh_get_malloc_returns_an_object_with_a_vtable(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    pp = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "SHGetMalloc", [pp])
    assert rv == com.S_OK
    obj = read_ptr(dll_emu, pp)
    query_interface = read_ptr(dll_emu, read_ptr(dll_emu, obj))
    assert dll_emu.emu.get_symbols()[query_interface] == ("com_api", "IUnknown.QueryInterface")


@pytest.mark.parametrize("emu_fixture", ["dll_emu", "dll64_emu"])
def test_imalloc_alloc_get_size_and_did_alloc(emu_fixture: str, request: pytest.FixtureRequest) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    ptr_size = se.emu.get_ptr_size()  # type: ignore[union-attr]
    pp = alloc(se, b"\xcc" * ptr_size)
    rv, _ = call(se, "shell32", "SHGetMalloc", [pp])
    assert rv == com.S_OK
    obj = int.from_bytes(se.mem_read(pp, ptr_size), "little")
    unknown = alloc(se, b"\x00" * 16)

    block, _ = call(se, "com_api", "IMalloc.Alloc", [obj, 16])
    assert block
    assert call(se, "com_api", "IMalloc.GetSize", [obj, block])[0] == 16
    assert call(se, "com_api", "IMalloc.DidAlloc", [obj, block])[0] == 1
    assert call(se, "com_api", "IMalloc.DidAlloc", [obj, unknown])[0] == 0
    assert call(se, "com_api", "IMalloc.DidAlloc", [obj, 0])[0] == 0xFFFFFFFF
    assert call(se, "com_api", "IMalloc.GetSize", [obj, unknown])[0] == (1 << (8 * ptr_size)) - 1

    se.mem_write(block, b"0123456789abcdef")
    bigger, _ = call(se, "com_api", "IMalloc.Realloc", [obj, block, 32])
    assert call(se, "com_api", "IMalloc.GetSize", [obj, bigger])[0] == 32
    assert se.mem_read(bigger, 16) == b"0123456789abcdef"

    assert call(se, "com_api", "IMalloc.Free", [obj, bigger])[0] is None
    assert call(se, "com_api", "IMalloc.DidAlloc", [obj, bigger])[0] == 0
    assert call(se, "com_api", "IMalloc.HeapMinimize", [obj])[0] is None


def test_com_method_without_a_handler_is_an_unsupported_api(config: dict, load_test_bin, run_test) -> None:
    """wmi_cases.c connects to WMI and calls IWbemServices::PutInstance, which has no handler."""
    run = run_test(config, load_test_bin("wmi_cases_x86.exe.xz")).entry_points[0]
    assert run.error is not None
    assert (run.error.type, run.error.api_name) == ("unsupported_api", "com_api.IWbemServices.PutInstance")


def test_rtl_compute_crc32_continues_from_the_initial_value(dll_emu: Speakeasy) -> None:
    hello, world = alloc(dll_emu, b"hello"), alloc(dll_emu, b" world")
    first, _ = call(dll_emu, "ntdll", "RtlComputeCrc32", [0, hello, 5])
    rv, _ = call(dll_emu, "ntdll", "RtlComputeCrc32", [first, world, 6])
    assert rv == zlib.crc32(b"hello world")


def call_with_seed(se: Speakeasy, api: str, seed: int) -> tuple[int, int]:
    pointer = alloc(se, struct.pack("<I", seed))
    rv, _ = call(se, "ntdll", api, [pointer])
    return rv, struct.unpack("<I", se.mem_read(pointer, 4))[0]


@pytest.mark.parametrize("seed, value", [(0, 0x7FFFFFC3), (1, 0x7FFFFFB1), (0x12345678, 0x3851EB51)])
def test_rtl_uniform_returns_the_next_seed(dll_emu: Speakeasy, seed: int, value: int) -> None:
    assert call_with_seed(dll_emu, "RtlUniform", seed) == (value, value)


@pytest.mark.parametrize("path", ["C:\\dir", "C:\\dir\\"])
@pytest.mark.parametrize("width", [1, 2])
def test_path_add_backslash_returns_the_terminator(dll_emu: Speakeasy, path: str, width: int) -> None:
    p = alloc(dll_emu, wstr(path, width) + b"\xcc" * 8)
    rv, _ = call(dll_emu, "shlwapi", "PathAddBackslash" + ("W" if width == 2 else "A"), [p])
    assert rv == p + 7 * width
    assert dll_emu.mem_read(p, 8 * width) == wstr("C:\\dir\\", width)


@pytest.mark.parametrize("more", ["file.exe", "\\file.exe"])
@pytest.mark.parametrize("width", [1, 2])
def test_path_append_keeps_the_path_for_a_leading_backslash(dll_emu: Speakeasy, more: str, width: int) -> None:
    p = alloc(dll_emu, wstr("C:\\dir", width) + b"\x00" * 40)
    rv, _ = call(
        dll_emu, "shlwapi", "PathAppend" + ("W" if width == 2 else "A"), [p, alloc(dll_emu, wstr(more, width))]
    )
    assert rv == 1
    assert dll_emu.mem_read(p, 16 * width) == wstr("C:\\dir\\file.exe", width)


@pytest.mark.parametrize(
    "directory, file, expected",
    [
        ("C:\\a\\b", "c.dll", "C:\\a\\b\\c.dll"),
        ("C:\\a\\b\\", "c.dll", "C:\\a\\b\\c.dll"),
        ("C:\\a\\b", "..\\c", "C:\\a\\c"),
        ("C:\\a", ".\\b\\.\\c", "C:\\a\\b\\c"),
        ("C:\\a", "D:\\x", "D:\\x"),
        ("C:\\a\\b", "\\x", "C:\\x"),
        ("C:\\a", "\\\\srv\\share", "\\\\srv\\share"),
        ("C:\\a", "", "C:\\a"),
        (None, "x\\y", "x\\y"),
        ("", "x", "x"),
        ("C:\\", "..\\x", "C:\\x"),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_combine_joins_and_canonicalizes(
    dll_emu: Speakeasy, directory: str | None, file: str, expected: str, width: int
) -> None:
    dest = alloc(dll_emu, b"\xcc" * 64 * width)
    d = alloc(dll_emu, wstr(directory, width)) if directory is not None else 0
    rv, _ = call(
        dll_emu, "shlwapi", "PathCombine" + ("W" if width == 2 else "A"), [dest, d, alloc(dll_emu, wstr(file, width))]
    )
    assert rv == dest
    assert dll_emu.mem_read(dest, (len(expected) + 1) * width) == wstr(expected, width)


@pytest.mark.parametrize(
    "path, relative",
    [("file.txt", True), ("..\\file.txt", True), ("", True), ("C:\\file.txt", False), ("\\\\srv\\share", False)],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_is_relative(dll_emu: Speakeasy, path: str, relative: bool, width: int) -> None:
    p = alloc(dll_emu, wstr(path, width))
    rv, _ = call(dll_emu, "shlwapi", "PathIsRelative" + ("W" if width == 2 else "A"), [p])
    assert bool(rv) == relative


def test_path_is_relative_null(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "shlwapi", "PathIsRelativeA", [0])
    assert rv


def read_bstr(se: Speakeasy, bstr: int) -> bytes:
    (size,) = struct.unpack("<I", se.mem_read(bstr - 4, 4))
    assert se.mem_read(bstr + size, 2) == b"\x00\x00"
    return se.mem_read(bstr, size)


@pytest.mark.parametrize("text", ["", "abc"])
def test_sys_alloc_string_copies_the_string(dll_emu: Speakeasy, text: str) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysAllocString", [alloc(dll_emu, wstr(text, 2))])
    assert rv != 0
    assert read_bstr(dll_emu, rv) == text.encode("utf-16le")


def test_sys_alloc_string_returns_null_for_null(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysAllocString", [0])
    assert rv == 0


@pytest.mark.parametrize("text, length", [("", 0), ("abc", 2), ("a\x00b", 3)])
def test_sys_alloc_string_len_copies_length_characters(dll_emu: Speakeasy, text: str, length: int) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysAllocStringLen", [alloc(dll_emu, wstr(text, 2)), length])
    assert rv != 0
    assert read_bstr(dll_emu, rv) == text[:length].encode("utf-16le")


@pytest.mark.parametrize("data, length", [(b"", 0), (b"abcd", 3), (b"a\x00bc", 4), (b"xyz", 0)])
def test_sys_alloc_string_byte_len_copies_length_bytes(dll_emu: Speakeasy, data: bytes, length: int) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysAllocStringByteLen", [alloc(dll_emu, data + b"\xcc" * 4), length])
    assert rv != 0
    assert read_bstr(dll_emu, rv) == data[:length]
    assert call(dll_emu, "oleaut32", "SysStringByteLen", [rv])[0] == length


@pytest.mark.parametrize("width", [1, 2])
def test_path_canonicalize_uses_the_char_width(dll_emu: Speakeasy, width: int) -> None:
    src = alloc(dll_emu, wstr("C:\\abc", width) + b"\x41" * 8)
    out = alloc(dll_emu, b"\xcc" * 32)
    rv, _ = call(dll_emu, "shlwapi", "PathCanonicalize" + ("W" if width == 2 else "A"), [out, src])
    assert rv == 1
    assert dll_emu.mem_read(out, 8 * width) == wstr("C:\\abc", width) + b"\xcc" * width


@pytest.mark.parametrize(
    "path, ext, expected",
    [
        ("C:\\dir.v1\\file", ".exe", "C:\\dir.v1\\file.exe"),
        ("C:\\dir.v1\\file.txt", ".exe", "C:\\dir.v1\\file.exe"),
        ("file", ".exe", "file.exe"),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_rename_extension_changes_the_file_name_only(
    dll_emu: Speakeasy, path: str, ext: str, expected: str, width: int
) -> None:
    p = alloc(dll_emu, wstr(path, width) + b"\x00" * 16)
    rv, _ = call(
        dll_emu, "shlwapi", "PathRenameExtension" + ("W" if width == 2 else "A"), [p, alloc(dll_emu, wstr(ext, width))]
    )
    assert rv == 1
    assert dll_emu.mem_read(p, (len(expected) + 1) * width) == wstr(expected, width)


@pytest.mark.parametrize(
    "path, expected, rv",
    [
        ("C:\\dir\\file.txt", "C:\\dir", 1),
        ("C:\\file.txt", "C:\\", 1),
        ("file.txt", "", 1),
        ("\\file.txt", "\\", 1),
        ("C:\\dir\\", "C:\\dir", 1),
        ("C:\\", "C:\\", 0),
        ("\\\\srv\\share", "\\\\srv", 1),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_remove_file_spec(dll_emu: Speakeasy, path: str, expected: str, rv: int, width: int) -> None:
    p = alloc(dll_emu, wstr(path, width))
    result, _ = call(dll_emu, "shlwapi", "PathRemoveFileSpec" + ("W" if width == 2 else "A"), [p])
    assert result == rv
    assert dll_emu.mem_read(p, (len(expected) + 1) * width) == wstr(expected, width)


@pytest.fixture
def strict_fs_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    files = config["filesystem"]["files"]
    config["filesystem"]["files"] = [f for f in files if f["mode"] == "full_path"]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        start_process(se)
        yield se


@pytest.mark.parametrize(
    "path, exists",
    [("c:\\nofile\\x.bin", 0), ("c:\\windows\\system32\\cmd.exe", 1), ("c:\\windows", 1)],
)
@pytest.mark.parametrize("width", [1, 2])
def test_path_file_exists(strict_fs_emu: Speakeasy, path: str, exists: int, width: int) -> None:
    assert strict_fs_emu.emu is not None
    strict_fs_emu.emu.set_last_error(0)
    p = alloc(strict_fs_emu, wstr(path, width))
    rv, _ = call(strict_fs_emu, "shlwapi", "PathFileExists" + ("W" if width == 2 else "A"), [p])
    assert rv == exists
    assert strict_fs_emu.emu.get_last_error() == (0 if exists else windefs.ERROR_FILE_NOT_FOUND)


def test_ldr_get_procedure_address_without_name_or_ordinal(dll_emu: Speakeasy) -> None:
    out = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "ntdll", "LdrGetProcedureAddress", [0x10000000, 0, 0, out])
    assert rv == ddk.STATUS_INVALID_PARAMETER


@pytest.mark.parametrize("a, b, sign", [("abc", "ABD", -1), ("ABC", "abc", 0), ("abd", "ABC", 1)])
@pytest.mark.parametrize("width", [1, 2])
def test_str_cmp_i_orders_strings(dll_emu: Speakeasy, a: str, b: str, sign: int, width: int) -> None:
    pa, pb = alloc(dll_emu, wstr(a, width)), alloc(dll_emu, wstr(b, width))
    rv, _ = call(dll_emu, "shlwapi", "StrCmpI" + ("W" if width == 2 else "A"), [pa, pb])
    rv = rv - (1 << 32) if rv >= 1 << 31 else rv
    assert (rv > 0) - (rv < 0) == sign


def test_co_set_proxy_blanket_returns_s_ok(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "ole32", "CoSetProxyBlanket", [0x1000, 10, 0, 0, 3, 3, 0, 0])
    assert rv == com.S_OK


def test_wnsprintfw_reads_s_as_wide_and_S_as_ansi(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 40)
    fmt = alloc(dll_emu, wstr("%s|%S|%%s", 2))
    args = [alloc(dll_emu, wstr("ab", 2)), alloc(dll_emu, wstr("cd", 1))]
    assert call(dll_emu, "shlwapi", "wnsprintfW", [buf, 20, fmt, *args])[0] == 8
    assert read_wstr(dll_emu, buf) == "ab|cd|%s"


@pytest.mark.parametrize("api, width", [("wnsprintfA", 1), ("wnsprintfW", 2)])
def test_wnsprintf_writes_one_percent_for_escape_without_arguments(dll_emu: Speakeasy, api: str, width: int) -> None:
    buf = alloc(dll_emu, b"\xcc" * 32)
    fmt = alloc(dll_emu, wstr("100%%", width))
    assert call(dll_emu, "shlwapi", api, [buf, 16, fmt])[0] == 4
    assert dll_emu.mem_read(buf, 5 * width) == wstr("100%", width)


def test_enum_processes_reports_bytes_written(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert len(dll_emu.emu.get_processes()) > 1
    pids = alloc(dll_emu, b"\xcc" * 8)
    needed = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "psapi", "EnumProcesses", [pids, 4, needed])[0] == 1
    assert int.from_bytes(dll_emu.mem_read(needed, 4), "little") == 4
    assert dll_emu.mem_read(pids + 4, 4) == b"\xcc" * 4


@pytest.mark.parametrize(
    ("dll", "api", "module"),
    [("kernel32", "K32GetModuleInformation", None), ("psapi", "GetModuleInformation", "kernel32")],
)
def test_get_module_information_describes_the_module(
    dll_emu: Speakeasy, dll: str, api: str, module: str | None
) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    mod = (
        dll_emu.emu.get_mod_by_name(module)
        if module
        else dll_emu.emu.get_mod_from_addr(dll_emu.emu.get_current_process().base)
    )
    info = alloc(dll_emu, b"\xcc" * 12)
    rv, _ = call(dll_emu, dll, api, [0xFFFFFFFF, mod.base if module else 0, info, 12])
    assert rv == 1
    assert struct.unpack("<III", dll_emu.mem_read(info, 12)) == (mod.base, mod.image_size, mod.get_ep())


def test_get_module_information_needs_room_for_the_structure(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    info = alloc(dll_emu, b"\xcc" * 12)
    rv, _ = call(dll_emu, "kernel32", "K32GetModuleInformation", [0xFFFFFFFF, 0, info, 8])
    assert rv == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INSUFFICIENT_BUFFER


@pytest.mark.parametrize("name, argv", [("SetupDiEnumDeviceInfo", [0]), ("SetupDiEnumDeviceInterfaces", [0, 0, 0])])
def test_setupapi_device_enumeration_is_empty(dll_emu: Speakeasy, name: str, argv: list[int]) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    hdevinfo = 0x238
    data = alloc(dll_emu, struct.pack("<I", 0x20) + b"\x00" * 0x1C)

    rv, _ = call(dll_emu, "setupapi", name, [hdevinfo, *argv, data])

    assert rv == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_NO_MORE_ITEMS


@pytest.mark.parametrize("api, enc", [("UrlCombineA", "utf-8"), ("UrlCombineW", "utf-16le")])
@pytest.mark.parametrize(
    "base, relative, combined",
    [
        ("http://example.com/a/b.php", "c.php?id=1", "http://example.com/a/c.php?id=1"),
        ("http://example.com/a/b.php", "/gate.php", "http://example.com/gate.php"),
        ("http://example.com/a/", "https://other.org/x", "https://other.org/x"),
    ],
)
def test_url_combine_joins_a_relative_url(
    dll_emu: Speakeasy, api: str, enc: str, base: str, relative: str, combined: str
) -> None:
    width = len("\0".encode(enc))
    size = alloc(dll_emu, struct.pack("<I", 0x100))
    out = alloc(dll_emu, b"\xcc" * 0x200)
    args = [alloc(dll_emu, (base + "\0").encode(enc)), alloc(dll_emu, (relative + "\0").encode(enc)), out, size, 0]
    assert call(dll_emu, "shlwapi", api, args)[0] == 0
    assert struct.unpack("<I", dll_emu.mem_read(size, 4))[0] == len(combined)
    assert dll_emu.mem_read(out, (len(combined) + 1) * width) == (combined + "\0").encode(enc)

    dll_emu.mem_write(size, struct.pack("<I", len(combined)))
    assert call(dll_emu, "shlwapi", api, args)[0] == 0x80004003
    assert struct.unpack("<I", dll_emu.mem_read(size, 4))[0] == len(combined) + 1


def is_freed(se: Speakeasy, addr: int) -> bool:
    assert se.emu is not None
    mm = se.emu.get_address_map(addr)
    return mm is None or mm.free or mm.base != addr


def test_co_task_mem_alloc_realloc_and_free(dll_emu: Speakeasy) -> None:
    block, _ = call(dll_emu, "ole32", "CoTaskMemAlloc", [8])
    assert block
    dll_emu.mem_write(block, b"abcdefgh")

    bigger, _ = call(dll_emu, "ole32", "CoTaskMemRealloc", [block, 0x100])
    assert bigger
    assert dll_emu.mem_read(bigger, 8) == b"abcdefgh"
    assert is_freed(dll_emu, block)

    assert call(dll_emu, "ole32", "CoTaskMemRealloc", [bigger, 0])[0] == 0
    assert is_freed(dll_emu, bigger)
    assert call(dll_emu, "ole32", "CoTaskMemRealloc", [0, 4])[0]
    empty, _ = call(dll_emu, "ole32", "CoTaskMemAlloc", [0])
    assert empty
    call(dll_emu, "ole32", "CoTaskMemFree", [empty])
    assert is_freed(dll_emu, empty)
    call(dll_emu, "ole32", "CoTaskMemFree", [0])


@pytest.mark.parametrize("name", ["", " ", "\u00a0"])
def test_shell_execute_fails_for_an_empty_program_name(dll_emu: Speakeasy, name: str) -> None:
    start_process(dll_emu)
    fn = alloc(dll_emu, wstr(name, 2))
    rv, _ = call(dll_emu, "shell32", "ShellExecuteW", [0, 0, fn, 0, 0, 1])
    assert rv == 2
    assert dll_emu.emu.get_last_error() == windefs.ERROR_FILE_NOT_FOUND


def test_shell_execute_ex_writes_h_inst_app_without_a_process_handle(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    fn = alloc(dll_emu, wstr("C:\\x.exe", 2))
    sei = alloc(dll_emu, struct.pack("<IIIIIIIiI", 60, 0, 0, 0, fn, 0, 0, 1, 0) + b"\x00" * 24)
    rv, _ = call(dll_emu, "shell32", "ShellExecuteExW", [sei])
    assert rv == 1
    assert struct.unpack("<I", dll_emu.mem_read(sei + 32, 4))[0] > 32
    assert struct.unpack("<I", dll_emu.mem_read(sei + 56, 4))[0] == 0


def test_shell_execute_ex_writes_h_inst_app_and_h_process(config: dict, load_test_bin) -> None:
    """
    0fdd25ef is an Unreal Engine game launcher (x64). When the VC++ runtime is missing, it
    runs UEPrereqSetup_x64.exe with ShellExecuteExW and SEE_MASK_NOCLOSEPROCESS, from a
    SHELLEXECUTEINFOW at rsp+0x40. It then waits on the hProcess member and reads the exit
    code of the setup program.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(UNREAL_LAUNCHER))
        sei = []
        wait_result = []

        def after_shell_execute_ex(emu: Any, address: int, size: int) -> None:
            sei.append(se.mem_read(se.get_stack_ptr() + 0x40, 0x70))

        def after_wait(emu: Any, address: int, size: int) -> None:
            wait_result.append(se.reg_read("eax"))
            se.stop()

        se.add_code_hook(after_shell_execute_ex, begin=0x14000136E, end=0x14000136E)
        se.add_code_hook(after_wait, begin=0x14000138D, end=0x14000138D)
        se.run_module(module)
        events = [e for ep in se.get_report().entry_points for e in ep.events or [] if e.event == "api"]

    cb_size, mask = struct.unpack_from("<II", sei[0])
    h_inst_app, h_process = struct.unpack_from("<Q", sei[0], 0x38)[0], struct.unpack_from("<Q", sei[0], 0x68)[0]
    assert (cb_size, mask) == (0x70, 0x40)  # SEE_MASK_NOCLOSEPROCESS
    assert h_inst_app > 32
    assert h_process != 0
    wait = next(e for e in events if e.api_name == "kernel32.WaitForSingleObject")
    assert wait.args[0].value == h_process
    assert wait_result == [0]  # WAIT_OBJECT_0


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_nt_create_thread_ex_queues_a_thread(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    assert se.emu is not None
    ptr = se.emu.get_ptr_size()
    current_process = (1 << (8 * ptr)) - 1
    out = alloc(se, b"\x00" * ptr)
    rv, _ = call(se, "ntdll", "NtCreateThreadEx", [out, 0x1FFFFF, 0, current_process, 0x401000, 0x55, 0, 0, 0, 0, 0])
    assert rv == ddk.STATUS_SUCCESS
    hnd = int.from_bytes(se.mem_read(out, ptr), "little")
    run = se.emu.run_queue[-1]
    assert (run.type, run.start_addr, run.args) == ("thread", 0x401000, (0x55,))
    assert call(se, "kernel32", "GetThreadId", [hnd])[0] == run.thread.tid


def test_nt_create_thread_ex_creates_a_suspended_thread(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    runs = len(dll_emu.emu.run_queue)
    out = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "ntdll", "NtCreateThreadEx", [out, 0x1FFFFF, 0, 0xFFFFFFFF, 0x401000, 0, 1, 0, 0, 0, 0])
    assert rv == ddk.STATUS_SUCCESS
    assert len(dll_emu.emu.run_queue) == runs
    hnd = struct.unpack("<I", dll_emu.mem_read(out, 4))[0]
    assert call(dll_emu, "kernel32", "ResumeThread", [hnd])[0] == 1
    assert len(dll_emu.emu.run_queue) == runs + 1


def test_nt_terminate_process_ends_the_current_process(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    rv, _ = call(dll_emu, "ntdll", "NtTerminateProcess", [0, 0])
    assert rv == ddk.STATUS_SUCCESS
    assert not dll_emu.emu.run_complete

    rv, _ = call(dll_emu, "ntdll", "NtTerminateProcess", [0xFFFFFFFF, 0])
    assert rv == ddk.STATUS_SUCCESS
    assert dll_emu.emu.run_complete


def test_nt_terminate_process_leaves_the_caller_running_for_another_process(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    app = alloc(dll_emu, b"c:\\Windows\\system32\\cmd.exe\x00")
    si = alloc(dll_emu, b"\x00" * 0x44)
    pi = alloc(dll_emu, b"\x00" * 0x10)
    assert call(dll_emu, "kernel32", "CreateProcessA", [app, 0, 0, 0, 0, 0, 0, 0, si, pi])[0]
    hproc = struct.unpack("<I", dll_emu.mem_read(pi, 4))[0]

    rv, _ = call(dll_emu, "ntdll", "NtTerminateProcess", [hproc, 0])
    assert rv == ddk.STATUS_SUCCESS
    assert not dll_emu.emu.run_complete

    rv, _ = call(dll_emu, "ntdll", "NtTerminateProcess", [0x1234, 0])
    assert rv == ddk.STATUS_INVALID_HANDLE


@pytest.mark.parametrize("dll, major, minor", [("shlwapi", 10, 0), ("comctl32", 6, 10)])
def test_dll_get_version_uses_the_emulated_os_build(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes], dll: str, major: int, minor: int
) -> None:
    config["os_ver"].update(major=10, minor=0, build=19045)
    for se in load_emu(config, load_test_bin("dll_test_x64.dll.xz")):
        info = alloc(se, struct.pack("<I", 20) + b"\x00" * 16)
        assert call(se, dll, "DllGetVersion", [info])[0] == windefs.S_OK
        assert se.mem_read(info, 20) == struct.pack("<IIIII", 20, major, minor, 19045, 2)
