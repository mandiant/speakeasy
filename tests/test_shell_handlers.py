"""
Shell, COM, and ntdll handlers return what Windows returns and write what
Windows writes.
"""

import ntpath
import struct
import uuid
import zlib

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import com
from tests.handler_harness import alloc, call, start_process


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


@pytest.mark.parametrize("csidl", [0x1A, 0x801A, 0x401A])
def test_sh_get_folder_path_ignores_csidl_flags(dll_emu: Speakeasy, csidl: int) -> None:
    assert dll_emu.emu is not None
    out = alloc(dll_emu, b"\x00" * 520)
    rv, _ = call(dll_emu, "shell32", "SHGetFolderPathW", [0, csidl, 0, 0, out])
    assert rv == 0
    assert read_wstr(dll_emu, out) == f"C:\\Users\\{dll_emu.emu.config.user.name}\\AppData\\Roaming"


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
    assert (query_interface, "com_api", "IUnknown.QueryInterface") in dll_emu.emu.callbacks


def test_rtl_compute_crc32_continues_from_the_initial_value(dll_emu: Speakeasy) -> None:
    hello, world = alloc(dll_emu, b"hello"), alloc(dll_emu, b" world")
    first, _ = call(dll_emu, "ntdll", "RtlComputeCrc32", [0, hello, 5])
    rv, _ = call(dll_emu, "ntdll", "RtlComputeCrc32", [first, world, 6])
    assert rv == zlib.crc32(b"hello world")


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


def test_ldr_get_procedure_address_without_name_or_ordinal(dll_emu: Speakeasy) -> None:
    out = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "ntdll", "LdrGetProcedureAddress", [0x10000000, 0, 0, out])
    assert rv == ddk.STATUS_PROCEDURE_NOT_FOUND


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


def test_enum_processes_reports_bytes_written(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert len(dll_emu.emu.get_processes()) > 1
    pids = alloc(dll_emu, b"\xcc" * 8)
    needed = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "psapi", "EnumProcesses", [pids, 4, needed])[0] == 1
    assert int.from_bytes(dll_emu.mem_read(needed, 4), "little") == 4
    assert dll_emu.mem_read(pids + 4, 4) == b"\xcc" * 4
