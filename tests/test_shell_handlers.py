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
from speakeasy.config import DEFAULT_CONFIG_DATA
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import com
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process


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
    "api, text, match, index",
    [
        ("StrChr", "a\\b\\c", "\\", 1),
        ("StrChr", "Hello", "L", None),
        ("StrChrI", "Hello", "L", 2),
        ("StrChr", "abc", "\0", None),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_str_chr_returns_the_first_match(
    dll_emu: Speakeasy, api: str, text: str, match: str, index: int | None, width: int
) -> None:
    p = alloc(dll_emu, wstr(text, width))
    rv, _ = call(dll_emu, "shlwapi", api + ("W" if width == 2 else "A"), [p, ord(match)])
    assert rv == (0 if index is None else p + index * width)


@pytest.mark.parametrize(
    "api, text, end, match, index",
    [
        ("StrRChrI", "a\\b\\c", None, "\\", 3),
        ("StrRChr", "a\\b\\c", 3, "\\", 1),
        ("StrRChr", "HelLo", None, "l", 2),
        ("StrRChrI", "HelLo", None, "l", 3),
        ("StrRChr", "abc", None, "x", None),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_str_r_chr_returns_the_last_match_before_the_end(
    dll_emu: Speakeasy, api: str, text: str, end: int | None, match: str, index: int | None, width: int
) -> None:
    p = alloc(dll_emu, wstr(text, width))
    end_ptr = 0 if end is None else p + end * width
    rv, _ = call(dll_emu, "shlwapi", api + ("W" if width == 2 else "A"), [p, end_ptr, ord(match)])
    assert rv == (0 if index is None else p + index * width)


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


@pytest.mark.parametrize("width", [1, 2])
@pytest.mark.parametrize(
    ("csidl", "expected"),
    [
        (0x24, "C:\\Windows"),
        (0x25, "C:\\Windows\\System32"),
        (0x1A, "C:\\Users\\{user}\\AppData\\Roaming"),
    ],
)
def test_sh_get_special_folder_path_writes_the_path(dll_emu: Speakeasy, width: int, csidl: int, expected: str) -> None:
    assert dll_emu.emu is not None
    api = "SHGetSpecialFolderPathW" if width == 2 else "SHGetSpecialFolderPathA"
    out = alloc(dll_emu, b"\xcc" * 520)
    rv, _ = call(dll_emu, "shell32", api, [0, out, csidl, 1])
    assert rv == 1
    path = expected.format(user=dll_emu.emu.config.user.name)
    assert dll_emu.mem_read(out, (len(path) + 1) * width) == wstr(path, width)


@pytest.mark.parametrize("api", ["SHGetSpecialFolderPathA", "SHGetSpecialFolderPathW"])
def test_sh_get_special_folder_path_fails_for_an_unknown_csidl(dll_emu: Speakeasy, api: str) -> None:
    out = alloc(dll_emu, b"\xcc" * 8)
    rv, _ = call(dll_emu, "shell32", api, [0, out, 0x7F, 0])
    assert rv == 0
    assert dll_emu.mem_read(out, 8) == b"\xcc" * 8


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


@pytest.mark.parametrize(
    ("fixture", "folder", "expected"),
    [
        ("dll_emu", "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e", "C:\\Program Files"),
        ("dll_emu", "de974d24-d9c6-4d3e-bf91-f4455120b917", "C:\\Program Files\\Common Files"),
        ("dll64_emu", "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e", "C:\\Program Files (x86)"),
        ("dll64_emu", "de974d24-d9c6-4d3e-bf91-f4455120b917", "C:\\Program Files (x86)\\Common Files"),
    ],
)
def test_sh_get_known_folder_path_gives_the_x86_program_files_of_the_os(
    request: pytest.FixtureRequest, fixture: str, folder: str, expected: str
) -> None:
    se = request.getfixturevalue(fixture)
    assert se.emu is not None
    ptr_size = se.emu.get_ptr_size()
    rfid = alloc(se, uuid.UUID(folder).bytes_le)
    out = alloc(se, b"\xcc" * ptr_size)
    rv, _ = call(se, "shell32", "SHGetKnownFolderPath", [rfid, 0, 0, out])
    assert rv == 0
    assert read_wstr(se, int.from_bytes(se.mem_read(out, ptr_size), "little")) == expected


def test_x64_environment_names_the_x86_program_files(dll64_emu: Speakeasy) -> None:
    out = alloc(dll64_emu, b"\x00" * 520)
    for name, expected in (
        ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        ("CommonProgramFiles(x86)", "C:\\Program Files (x86)\\Common Files"),
        ("ProgramW6432", "C:\\Program Files"),
    ):
        rv, _ = call(dll64_emu, "kernel32", "GetEnvironmentVariableA", [alloc(dll64_emu, wstr(name, 1)), out, 520])
        assert dll64_emu.mem_read(out, rv) == expected.encode()


def test_x86_environment_has_no_x86_program_files(dll_emu: Speakeasy) -> None:
    out = alloc(dll_emu, b"\x00" * 520)
    rv, _ = call(dll_emu, "kernel32", "GetEnvironmentVariableA", [alloc(dll_emu, b"ProgramFiles(x86)\x00"), out, 520])
    assert rv == 0


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


def test_sh_get_folder_location_maps_to_the_folder_path(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    ppidl = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "SHGetFolderLocation", [0, 0x801A, 0, 0, ppidl])
    assert rv == windefs.S_OK
    pidl = read_ptr(dll_emu, ppidl)
    assert_item_id_list(dll_emu, pidl)

    rv, path = read_pidl_path(dll_emu, pidl, 2)
    assert rv == 1
    assert path.startswith(wstr(f"C:\\Users\\{dll_emu.emu.config.user.name}\\AppData\\Roaming", 2))


@pytest.mark.parametrize(
    "api, argv", [("SHGetSpecialFolderLocation", [0, 0x7F]), ("SHGetFolderLocation", [0, 0x7F, 0, 0])]
)
def test_sh_get_folder_location_fails_for_an_unknown_folder(dll_emu: Speakeasy, api: str, argv: list[int]) -> None:
    ppidl = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", api, [*argv, ppidl])
    assert rv == windefs.E_INVALIDARG
    assert read_ptr(dll_emu, ppidl) == 0


def test_sh_get_known_folder_id_list_maps_to_the_folder_path(dll_emu: Speakeasy) -> None:
    rfid = alloc(dll_emu, uuid.UUID("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97").bytes_le)
    ppidl = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "shell32", "SHGetKnownFolderIDList", [rfid, 0, 0, ppidl])
    assert rv == windefs.S_OK
    pidl = read_ptr(dll_emu, ppidl)
    assert_item_id_list(dll_emu, pidl)

    rv, path = read_pidl_path(dll_emu, pidl, 1)
    assert rv == 1
    assert path.startswith(wstr("C:\\ProgramData", 1))


@pytest.mark.parametrize("pidl", [0, -1])
def test_sh_get_path_from_id_list_fails_for_an_unknown_pidl(dll_emu: Speakeasy, pidl: int) -> None:
    if pidl == -1:
        pidl = alloc(dll_emu, struct.pack("<H4sH", 6, b"abcd", 0))
    rv, path = read_pidl_path(dll_emu, pidl, 1)
    assert rv == 0
    assert path[:1] == b"\x00"


@pytest.mark.parametrize("width", [1, 2])
def test_sh_get_folder_path_and_sub_dir_appends_the_sub_dir(dll_emu: Speakeasy, width: int) -> None:
    out = alloc(dll_emu, b"\xcc" * 520)
    sub = alloc(dll_emu, wstr("Synaptics", width))
    api = "SHGetFolderPathAndSubDir" + ("W" if width == 2 else "A")
    rv, _ = call(dll_emu, "shell32", api, [0, 0x23, 0, 0, sub, out])
    assert rv == windefs.S_OK
    assert dll_emu.mem_read(out, 25 * width) == wstr("C:\\ProgramData\\Synaptics", width)


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


@pytest.mark.parametrize(
    "api, progid, clsid",
    [
        ("CLSIDFromProgID", "WbemScripting.SWbemLocator", "{76A64158-CB41-11D1-8B02-00600806D9B6}"),
        ("CLSIDFromProgID", "MSXML2.XMLHTTP", "{F6D90F16-9C73-11D3-B32E-00C04F990BB4}"),
        ("CLSIDFromProgIDEx", "wscript.shell", "{72C24DD5-D70A-438B-8A42-98424B88AFB8}"),
    ],
)
def test_clsid_from_progid_writes_the_class_id(dll_emu: Speakeasy, api: str, progid: str, clsid: str) -> None:
    out = alloc(dll_emu, b"\xcc" * 16)
    rv, _ = call(dll_emu, "ole32", api, [alloc(dll_emu, wstr(progid, 2)), out])
    assert rv == com.S_OK
    assert dll_emu.mem_read(out, 16) == uuid.UUID(clsid).bytes_le


def test_clsid_from_progid_fails_for_an_unknown_progid(dll_emu: Speakeasy) -> None:
    out = alloc(dll_emu, b"\xcc" * 16)
    rv, _ = call(dll_emu, "ole32", "CLSIDFromProgID", [alloc(dll_emu, wstr("No.Such.Class", 2)), out])
    assert rv == 0x800401F3
    assert dll_emu.mem_read(out, 16) == b"\x00" * 16


def test_co_create_guid_returns_a_new_version_4_guid_each_call(dll_emu: Speakeasy) -> None:
    guids = []
    for _ in range(2):
        out = alloc(dll_emu, b"\xcc" * 16)
        rv, _ = call(dll_emu, "ole32", "CoCreateGuid", [out])
        assert rv == com.S_OK
        guids.append(uuid.UUID(bytes_le=bytes(dll_emu.mem_read(out, 16))))
    assert guids[0] != guids[1]
    assert all(g.version == 4 and g.variant == uuid.RFC_4122 for g in guids)


@pytest.mark.parametrize("cch, rv", [(39, 39), (38, 0)])
def test_string_from_guid2_writes_the_braced_string(dll_emu: Speakeasy, cch: int, rv: int) -> None:
    text = "{4590F811-1D3A-11D0-891F-00AA004B2E24}"
    out = alloc(dll_emu, b"\xcc" * 80)
    result, _ = call(dll_emu, "ole32", "StringFromGUID2", [alloc(dll_emu, uuid.UUID(text).bytes_le), out, cch])
    assert result == rv
    expected = (text + "\x00").encode("utf-16le") if rv else b"\xcc" * 78
    assert dll_emu.mem_read(out, 80) == expected + b"\xcc" * (80 - len(expected))


def test_rtl_format_current_user_key_path_allocates_the_user_key(dll64_emu: Speakeasy) -> None:
    us = alloc(dll64_emu, b"\x00" * 16)
    rv, _ = call(dll64_emu, "ntdll", "RtlFormatCurrentUserKeyPath", [us])
    assert rv == ddk.STATUS_SUCCESS
    length, maximum, _, buf = struct.unpack("<HHIQ", dll64_emu.mem_read(us, 16))
    expected = "\\REGISTRY\\USER\\" + DEFAULT_CONFIG_DATA["user"]["sid"]
    assert (length, maximum) == (2 * len(expected), 2 * len(expected) + 2)
    assert dll64_emu.mem_read(buf, maximum) == (expected + "\x00").encode("utf-16le")


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


@pytest.mark.parametrize("emu_fixture", ["dll_emu", "dll64_emu"])
def test_co_get_object_fails_for_names_it_does_not_model(emu_fixture: str, request: pytest.FixtureRequest) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    ptr_size = se.emu.get_ptr_size()  # type: ignore[union-attr]
    ppv = alloc(se, (0x41414141).to_bytes(ptr_size, "little"))
    iid = guid(se, "{00020400-0000-0000-C000-000000000046}")
    rv, _ = call(se, "ole32", "CoGetObject", [alloc(se, wstr("winmgmts:", 2)), 0, iid, ppv])
    assert rv == com.MK_E_SYNTAX
    assert se.mem_read(ppv, ptr_size) == b"\x00" * ptr_size


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


def _call_wbem_services_slot(se: Speakeasy, slot: int) -> int:
    """Call IWbemServices method ``slot`` with a pointer for ``ppObject`` and return that pointer."""
    code = se.load_shellcode(data=b"\xcc" * 0x100, arch="x86")
    assert se.emu is not None
    vtable = se.emu.com.get_interface(se.emu, 4, "IWbemServices").address
    obj = se.mem_alloc(0x100)
    se.mem_write(obj, struct.pack("<II", vtable, 0xCCCCCCCC))
    pushes = b"\x6a\x00" + b"\x68" + struct.pack("<I", obj + 4) + b"\x6a\x00" * 3 + b"\x68" + struct.pack("<I", obj)
    se.mem_write(code, pushes + b"\xb8" + struct.pack("<I", vtable + slot * 4) + b"\xff\x10\xc3")
    se.run_shellcode(code)
    return obj + 4


def test_wbem_services_get_object_is_not_found(config: dict) -> None:
    with Speakeasy(config=config) as se:
        pp_object = _call_wbem_services_slot(se, 6)
        run = se.get_report().entry_points[0]
        assert (run.error, run.ret_val) == (None, com.WBEM_E_NOT_FOUND)
        assert read_ptr(se, pp_object) == 0


def test_com_method_without_a_handler_is_an_unsupported_api(config: dict) -> None:
    with Speakeasy(config=config) as se:
        _call_wbem_services_slot(se, 14)
        run = se.get_report().entry_points[0]
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


@pytest.mark.parametrize("api", ["RtlRandom", "RtlRandomEx"])
def test_rtl_random_shuffles_through_the_saved_values(dll_emu: Speakeasy, api: str) -> None:
    pointer = alloc(dll_emu, struct.pack("<I", 0x12345678))
    values, seeds = [], []
    for _ in range(3):
        values.append(call(dll_emu, "ntdll", api, [pointer])[0])
        seeds.append(struct.unpack("<I", dll_emu.mem_read(pointer, 4))[0])
    assert values == [0x2232827A, 0x5974B425, 0x25920C78]
    assert seeds == [0x2BCDF382, 0x456C669C, 0x65DCB646]

    assert call_with_seed(dll_emu, api, 5)[0] == 0x23E444B6
    assert call_with_seed(dll_emu, api, 5)[0] == 0x7FFFFF65


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
    "directory, file", [(None, None), ("C:\\" + "a" * 200, "b" * 60)], ids=["both null", "too long"]
)
def test_path_combine_fails_with_an_empty_result(dll_emu: Speakeasy, directory: str | None, file: str | None) -> None:
    dest = alloc(dll_emu, b"\xcc" * 8)
    d = alloc(dll_emu, wstr(directory, 2)) if directory is not None else 0
    f = alloc(dll_emu, wstr(file, 2)) if file is not None else 0
    rv, _ = call(dll_emu, "shlwapi", "PathCombineW", [dest, d, f])
    assert rv == 0
    assert dll_emu.mem_read(dest, 2) == b"\x00\x00"


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


def test_sys_alloc_string_byte_len_without_a_source_allocates_zeros(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysAllocStringByteLen", [0, 5])
    assert rv != 0
    assert read_bstr(dll_emu, rv) == b"\x00" * 5


@pytest.mark.parametrize("text", ["", "abc", "a\x00b"])
def test_sys_string_len_reads_the_length_prefix(dll_emu: Speakeasy, text: str) -> None:
    bstr, _ = call(dll_emu, "oleaut32", "SysAllocStringLen", [alloc(dll_emu, wstr(text, 2)), len(text)])
    assert call(dll_emu, "oleaut32", "SysStringLen", [bstr])[0] == len(text)
    assert call(dll_emu, "oleaut32", "SysStringByteLen", [bstr])[0] == len(text) * 2


@pytest.mark.parametrize("name", ["SysStringLen", "SysStringByteLen"])
def test_sys_string_len_of_null_is_zero(dll_emu: Speakeasy, name: str) -> None:
    assert call(dll_emu, "oleaut32", name, [0])[0] == 0


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


@pytest.mark.parametrize(
    "api, a, b, sign",
    [
        ("StrCmpIC", "ABC", "abd", -1),
        ("StrCmpIC", "ABC", "abc", 0),
        ("StrCmpIC", "myarg1", "specialize", -1),
        ("StrCmpIC", "abd", "ABC", 1),
        ("StrCmpC", "ABC", "abc", -1),
        ("StrCmpC", "abc", "abc", 0),
        ("StrCmpC", "abd", "abc", 1),
    ],
)
@pytest.mark.parametrize("width", [1, 2])
def test_str_cmp_c_orders_strings(dll_emu: Speakeasy, api: str, a: str, b: str, sign: int, width: int) -> None:
    pa, pb = alloc(dll_emu, wstr(a, width)), alloc(dll_emu, wstr(b, width))
    rv, _ = call(dll_emu, "shlwapi", api + ("W" if width == 2 else "A"), [pa, pb])
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


def test_shell_execute_ex_writes_the_error_to_h_inst_app(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    fn = alloc(dll_emu, wstr("", 2))
    sei = alloc(dll_emu, struct.pack("<IIIIIIIiI", 60, 0, 0, 0, fn, 0, 0, 1, 0xCCCCCCCC) + b"\x00" * 24)
    rv, _ = call(dll_emu, "shell32", "ShellExecuteExW", [sei])
    assert rv == 0
    assert struct.unpack("<I", dll_emu.mem_read(sei + 32, 4))[0] == 2
    assert dll_emu.emu.get_last_error() == windefs.ERROR_FILE_NOT_FOUND


@pytest.mark.parametrize("mask", [0, 0x40], ids=["no process handle", "SEE_MASK_NOCLOSEPROCESS"])
def test_shell_execute_ex_writes_h_inst_app_and_h_process(dll_emu: Speakeasy, mask: int) -> None:
    start_process(dll_emu)
    fn = alloc(dll_emu, wstr("C:\\x.exe", 2))
    sei = alloc(dll_emu, struct.pack("<IIIIIIIiI", 60, mask, 0, 0, fn, 0, 0, 1, 0) + b"\x00" * 24)
    rv, _ = call(dll_emu, "shell32", "ShellExecuteExW", [sei])
    assert rv == 1
    assert struct.unpack("<I", dll_emu.mem_read(sei + 32, 4))[0] > 32
    h_process = struct.unpack("<I", dll_emu.mem_read(sei + 56, 4))[0]
    if mask:
        assert h_process != 0
        assert call(dll_emu, "kernel32", "WaitForSingleObject", [h_process, 0])[0] != 0xFFFFFFFF
    else:
        assert h_process == 0


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_microsoft_telemetry_assert_triggered_um_returns(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    record = alloc(se, b"\x00" * 0x24)
    rv, _ = call(se, "ntdll", "MicrosoftTelemetryAssertTriggeredUM", [record])
    assert rv is None


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_rtl_get_persisted_state_location_copies_the_default_path(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    source = alloc(se, wstr("SharedAccessEpoch2", 2))
    default = alloc(se, wstr("SYSTEM\\Foo", 2))
    target = alloc(se, b"\xcc" * 0x208)
    length = alloc(se, b"\xcc" * 4)

    rv, _ = call(se, "ntdll", "RtlGetPersistedStateLocation", [source, 0, default, 1, target, 0x208, length])
    assert rv == ddk.STATUS_SUCCESS
    assert read_wstr(se, target) == "SYSTEM\\Foo"
    assert struct.unpack("<I", se.mem_read(length, 4))[0] == 22

    small = alloc(se, b"\xcc" * 4)
    rv, _ = call(se, "ntdll", "RtlGetPersistedStateLocation", [source, 0, default, 1, small, 4, length])
    assert rv == ddk.STATUS_BUFFER_TOO_SMALL
    assert se.mem_read(small, 4) == b"\xcc" * 4
    assert struct.unpack("<I", se.mem_read(length, 4))[0] == 22


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_rtl_disown_module_heap_allocation_succeeds(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    heap, _ = call(se, "kernel32", "GetProcessHeap", [])
    block, _ = call(se, "kernel32", "HeapAlloc", [heap, 0, 0x10])
    rv, _ = call(se, "ntdll", "RtlDisownModuleHeapAllocation", [heap, block])
    assert rv == ddk.STATUS_SUCCESS


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_rtl_dll_shutdown_in_progress_is_false_while_the_process_runs(
    request: pytest.FixtureRequest, fixture: str
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    rv, _ = call(se, "ntdll", "RtlDllShutdownInProgress", [])
    assert rv == 0


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_log_staged_feature_usage_returns(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    rv, _ = call(se, "kernelbase", "LogStagedFeatureUsage", [0x1234, 1, 1])
    assert rv is None


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


def test_nt_create_thread_ex_fails_for_an_unknown_process(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    out = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "ntdll", "NtCreateThreadEx", [out, 0x1FFFFF, 0, 0x1234, 0x401000, 0, 0, 0, 0, 0, 0])
    assert rv == ddk.STATUS_INVALID_HANDLE
    assert dll_emu.mem_read(out, 4) == b"\xcc" * 4


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


@pytest.mark.parametrize("dll, major, minor", [("shell32", 6, 1), ("shlwapi", 6, 1), ("comctl32", 6, 10)])
def test_dll_get_version_fills_dllversioninfo(dll_emu: Speakeasy, dll: str, major: int, minor: int) -> None:
    info = alloc(dll_emu, struct.pack("<I", 20) + b"\xcc" * 20)
    assert call(dll_emu, dll, "DllGetVersion", [info])[0] == windefs.S_OK
    assert dll_emu.mem_read(info, 24) == struct.pack("<IIIII", 20, major, minor, 7601, 2) + b"\xcc" * 4


@pytest.mark.parametrize("dll, major, minor", [("shell32", 6, 1), ("comctl32", 6, 10)])
def test_dll_get_version_fills_dllversioninfo2(dll_emu: Speakeasy, dll: str, major: int, minor: int) -> None:
    info = alloc(dll_emu, struct.pack("<I", 32) + b"\xcc" * 32)
    assert call(dll_emu, dll, "DllGetVersion", [info])[0] == windefs.S_OK
    version = major << 48 | minor << 32 | 7601 << 16
    assert dll_emu.mem_read(info, 36) == struct.pack("<IIIIIIQ", 32, major, minor, 7601, 2, 0, version) + b"\xcc" * 4


@pytest.mark.parametrize("size", [0, 4, 24])
def test_dll_get_version_rejects_an_unknown_size(dll_emu: Speakeasy, size: int) -> None:
    info = alloc(dll_emu, struct.pack("<I", size) + b"\xcc" * 28)
    assert call(dll_emu, "shell32", "DllGetVersion", [info])[0] == windefs.E_INVALIDARG
    assert dll_emu.mem_read(info, 32) == struct.pack("<I", size) + b"\xcc" * 28


@pytest.mark.parametrize("dll, major, minor", [("shlwapi", 10, 0), ("comctl32", 6, 10)])
def test_dll_get_version_uses_the_emulated_os_build(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes], dll: str, major: int, minor: int
) -> None:
    config["os_ver"].update(major=10, minor=0, build=19045)
    for se in load_emu(config, load_test_bin("dll_test_x64.dll.xz")):
        info = alloc(se, struct.pack("<I", 20) + b"\x00" * 16)
        assert call(se, dll, "DllGetVersion", [info])[0] == windefs.S_OK
        assert se.mem_read(info, 20) == struct.pack("<IIIII", 20, major, minor, 19045, 2)
