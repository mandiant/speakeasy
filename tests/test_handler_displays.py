"""
Handlers put each decoded value on the parameter it came from.
"""

import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.api import sigdb
from speakeasy.winenv.api.api import ApiContext, HandlerArgs
from speakeasy.winenv.defs.nt import ddk


def _load(config: dict[str, Any], data: bytes) -> Iterator[Speakeasy]:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        se.load_module(data=data)
        assert se.emu is not None
        se.emu.curr_run = Run()
        yield se
    finally:
        se.shutdown()


@pytest.fixture
def dll_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from _load(config, load_test_bin("dll_test_x86.dll.xz"))


@pytest.fixture
def dll64_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from _load(config, load_test_bin("dll_test_x64.dll.xz"))


@pytest.fixture
def driver_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from _load(config, load_test_bin("wdm_test_x86.sys.xz"))


def _alloc(se: Speakeasy, data: bytes) -> int:
    addr = se.mem_alloc(len(data), base=0x20000000)
    se.mem_write(addr, data)
    return addr


def _unicode_string(se: Speakeasy, text: str) -> int:
    """Build an x86 UNICODE_STRING for ``text`` and return its address."""
    buf = text.encode("utf-16le")
    buf_addr = _alloc(se, buf + b"\x00\x00")
    return _alloc(se, struct.pack("<HHI", len(buf), len(buf) + 2, buf_addr))


def _object_attributes(se: Speakeasy, name: str) -> int:
    """Build an x86 OBJECT_ATTRIBUTES for ``name`` and return its address."""
    return _alloc(se, struct.pack("<IIIIII", 24, 0, _unicode_string(se, name), 0, 0, 0))


def _call(se: Speakeasy, dll: str, name: str, argv: list[int]) -> tuple[int, dict[str | int, str]]:
    """
    Call a handler with the context dispatch builds. A variadic handler reads
    ``argv`` from the stack. Return the handler result and the displays, by
    parameter name, or by slot index for a call without a signature.
    """
    emu = se.emu
    assert emu is not None and emu.api is not None
    mod, func_attrs = emu.api.get_export_func_handler(dll, name)
    if not func_attrs:
        mod, func_attrs = emu.normalize_import_miss(dll, name)
    _, func, argc, conv, _ = func_attrs
    if argc == e_arch.VAR_ARGS:
        emu.set_func_args(emu.stack_base, 0, *argv, conv=conv)
        argv = []
    assert argc in (e_arch.VAR_ARGS, len(argv))
    sig = emu.get_handler_signature(dll, name, argc)
    if sig is None:
        args = HandlerArgs.from_slots(argv)
    else:
        args = HandlerArgs.from_signature(sig, emu.get_ptr_size(), emu._render_signature_args(sig, argv), argv)
    ctx = ApiContext(func_name=f"{dll}.{name}", args=args)
    rv = func(mod, emu, list(argv), ctx)
    return rv, {i if a.name is None else a.name: a.display for i, a in enumerate(args.get_report_args())}


def test_find_resource_ex_names_match_params(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    hmod = dll_emu.emu.modules[0].base
    lp_type = _alloc(dll_emu, b"MYTYPE\x00")
    lp_name = _alloc(dll_emu, b"MYNAME\x00")
    _, displays = _call(dll_emu, "kernel32", "FindResourceExA", [hmod, lp_type, lp_name, 0])
    assert displays["lpType"] == "MYTYPE"
    assert displays["lpName"] == "MYNAME"


def test_resource_name_above_16mb_is_a_string(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    assert emu is not None
    k32, _ = emu.normalize_import_miss("kernel32", "FindResourceA")
    addr = _alloc(dll_emu, b"MYNAME\x00")
    assert addr >> 24
    assert k32.normalize_res_identifier(emu, 1, addr) == "MYNAME"
    assert k32.normalize_res_identifier(emu, 1, 0x65) == 0x65


def test_get_temp_file_name_shows_the_output_path(dll_emu: Speakeasy) -> None:
    path = _alloc(dll_emu, b"C:\\tmp\x00")
    prefix = _alloc(dll_emu, b"abcd\x00")
    out = _alloc(dll_emu, b"\x00" * 260)
    rv, displays = _call(dll_emu, "kernel32", "GetTempFileNameA", [path, prefix, 0x1A2B, out])
    assert rv == 0x1A2B
    assert displays["lpPrefixString"] == "abcd"
    assert displays["lpTempFileName"] == "C:\\tmp\\abc1A2B.TMP"
    assert dll_emu.mem_read(out, 19) == b"C:\\tmp\\abc1A2B.TMP\x00"
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_file_manager().get_file_from_path("C:\\tmp\\abc1A2B.TMP") is None


def test_get_temp_file_name_creates_a_unique_file(dll_emu: Speakeasy) -> None:
    path = _alloc(dll_emu, b"C:\\tmp\\\x00")
    prefix = _alloc(dll_emu, b"\x00")
    out = _alloc(dll_emu, b"\x00" * 260)
    rv, displays = _call(dll_emu, "kernel32", "GetTempFileNameA", [path, prefix, 0, out])
    assert 0 < rv <= 0xFFFF
    assert displays["lpTempFileName"] == f"C:\\tmp\\{rv:X}.TMP"
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_file_manager().get_file_from_path(f"C:\\tmp\\{rv:X}.TMP") is not None


@pytest.mark.parametrize(
    "api, argv",
    [
        ("ZwCreateFile", [0, 0x80000000, 0, 0, 0, 0, 1, 3, 0, 0, 0]),
        ("ZwOpenFile", [0, 0x80000000, 0, 0, 1, 0]),
    ],
)
def test_zw_file_path_is_on_object_attributes(driver_emu: Speakeasy, api: str, argv: list[int]) -> None:
    path = "\\??\\C:\\test.txt"
    argv = list(argv)
    argv[0] = _alloc(driver_emu, b"\x00" * 4)
    argv[2] = _object_attributes(driver_emu, path)
    argv[3] = _alloc(driver_emu, b"\x00" * 8)
    _, displays = _call(driver_emu, "ntoskrnl", api, argv)
    assert displays["ObjectAttributes"] == path
    assert displays["IoStatusBlock"] == hex(argv[3])


def _format_args(se: Speakeasy) -> tuple[int, int, int]:
    """Return (output buffer, format string, va_list) for "n=%d" with 7."""
    return _alloc(se, b"\x00" * 64), _alloc(se, b"n=%d\x00"), _alloc(se, struct.pack("<I", 7))


def test_vsnprintf_format_is_on_the_format_slot(dll_emu: Speakeasy) -> None:
    buf, fmt, va = _format_args(dll_emu)
    _, displays = _call(dll_emu, "msvcrt", "_vsnprintf", [buf, 64, fmt, va])
    assert displays == {0: "n=7", 1: "0x40", 2: "n=%d", 3: hex(va)}


def test_kernel_vsnprintf_format_is_on_the_format_slot(driver_emu: Speakeasy) -> None:
    buf, fmt, va = _format_args(driver_emu)
    _, displays = _call(driver_emu, "ntoskrnl", "_vsnprintf", [buf, 64, fmt, va])
    assert displays == {0: "n=7", 1: "0x40", 2: "n=%d", 3: hex(va)}


def test_stdio_common_vsprintf_output_and_format_are_on_their_slots(dll_emu: Speakeasy) -> None:
    buf, fmt, va = _format_args(dll_emu)
    _, displays = _call(dll_emu, "msvcrt", "__stdio_common_vsprintf", [0, 0, buf, 64, fmt, 0, va])
    assert displays == {0: "0x0", 1: "0x0", 2: "n=7", 3: "0x40", 4: "n=%d", 5: "0x0", 6: hex(va)}


def test_stdio_common_vsprintf_x64_options_use_one_slot(dll64_emu: Speakeasy) -> None:
    buf = _alloc(dll64_emu, b"\x00" * 64)
    fmt = _alloc(dll64_emu, b"n=%d\x00")
    va = _alloc(dll64_emu, struct.pack("<Q", 7))
    _, displays = _call(dll64_emu, "msvcrt", "__stdio_common_vsprintf", [0, buf, 64, fmt, 0, va, 0])
    assert dll64_emu.mem_read(buf, 4) == b"n=7\x00"
    assert displays[1] == "n=7"
    assert displays[3] == "n=%d"


def test_wvnsprintf_format_is_on_psz_fmt(dll_emu: Speakeasy) -> None:
    buf, fmt, va = _format_args(dll_emu)
    _, displays = _call(dll_emu, "shlwapi", "wvnsprintfA", [buf, 64, fmt, va])
    assert displays["pszDest"] == "n=7"
    assert displays["cchDest"] == "0x40"
    assert displays["pszFmt"] == "n=%d"


def test_zw_query_value_key_accepts_a_null_value_name(driver_emu: Speakeasy) -> None:
    info = _alloc(driver_emu, b"\x00" * 64)
    ret_len = _alloc(driver_emu, b"\x00" * 4)
    rv, displays = _call(driver_emu, "ntoskrnl", "ZwQueryValueKey", [0, 0, 2, info, 64, ret_len])
    assert rv == ddk.STATUS_INVALID_HANDLE
    assert displays["ValueName"] == "0x0"


def test_crypt_create_hash_rejects_an_unknown_algid(dll_emu: Speakeasy) -> None:
    ph_hash = _alloc(dll_emu, b"\x00" * 4)
    rv, displays = _call(dll_emu, "advapi32", "CryptCreateHash", [1, 0x1234, 0, 0, ph_hash])
    assert rv == 0
    assert displays["Algid"] == "0x1234"


def test_crypt_create_hash_shows_a_known_algid(dll_emu: Speakeasy) -> None:
    ph_hash = _alloc(dll_emu, b"\x00" * 4)
    rv, displays = _call(dll_emu, "advapi32", "CryptCreateHash", [1, 0x8003, 0, 0, ph_hash])
    assert rv == 1
    assert displays["Algid"] == "CALG_MD5"


def test_win_http_query_headers_shows_the_info_level(dll_emu: Speakeasy) -> None:
    buf = _alloc(dll_emu, b"\x00" * 64)
    buf_len = _alloc(dll_emu, struct.pack("<I", 64))
    index = _alloc(dll_emu, b"\x00" * 4)
    _, displays = _call(dll_emu, "winhttp", "WinHttpQueryHeaders", [1, 22, 0, buf, buf_len, index])
    assert displays["dwInfoLevel"] == "WINHTTP_QUERY_RAW_HEADERS_CRLF"
    assert displays["pwszName"] == "0x0"
    assert displays["lpdwIndex"] == hex(index)


def _query_status_code(se: Speakeasy, level: int, size: int) -> tuple[int, bytes, int]:
    buf = _alloc(se, b"\xcc" * 16)
    buf_len = _alloc(se, struct.pack("<I", size))
    rv, _ = _call(se, "winhttp", "WinHttpQueryHeaders", [1, level, 0, buf, buf_len, 0])
    return rv, se.mem_read(buf, 16), int.from_bytes(se.mem_read(buf_len, 4), "little")


def test_win_http_query_status_code_as_text(dll_emu: Speakeasy) -> None:
    rv, buf, length = _query_status_code(dll_emu, 19, 16)
    assert rv == 1
    assert buf[:8] == "200\x00".encode("utf-16le")
    assert length == 6


def test_win_http_query_status_code_as_number(dll_emu: Speakeasy) -> None:
    rv, buf, length = _query_status_code(dll_emu, 19 | 0x20000000, 16)
    assert rv == 1
    assert buf[:4] == struct.pack("<I", 200)
    assert length == 4


def test_win_http_query_status_code_small_buffer(dll_emu: Speakeasy) -> None:
    rv, buf, length = _query_status_code(dll_emu, 19, 4)
    assert rv == 0
    assert buf == b"\xcc" * 16
    assert length == 8


def test_url_download_to_cache_file_names_its_params(dll_emu: Speakeasy) -> None:
    url = _alloc(dll_emu, b"http://example.com/a.bin\x00")
    out = _alloc(dll_emu, b"\x00" * 260)
    _, displays = _call(dll_emu, "urlmon", "URLDownloadToCacheFileA", [0, url, out, 260, 0, 0])
    assert list(displays) == ["lpUnkcaller", "szURL", "szFileName", "cchFileName", "dwReserved", "pBSC"]
    assert displays["szURL"] == "http://example.com/a.bin"
    assert displays["szFileName"] == "C:\\Windows\\Temp\\a.bin"


def _open_usbsamp(se: Speakeasy) -> int:
    subkey = _alloc(se, b"System\\CurrentControlSet\\Services\\usbsamp\x00")
    phk = _alloc(se, b"\x00" * 4)
    rv, _ = _call(se, "advapi32", "RegOpenKeyExA", [0x80000002, subkey, 0, 0xF003F, phk])
    assert rv == 0
    return int.from_bytes(se.mem_read(phk, 4), "little")


def test_reg_query_value_ex_writes_the_value_type(dll_emu: Speakeasy) -> None:
    hkey = _open_usbsamp(dll_emu)
    name = _alloc(dll_emu, b"Start\x00")
    lp_type = _alloc(dll_emu, struct.pack("<I", 1))
    rv, displays = _call(dll_emu, "advapi32", "RegQueryValueExA", [hkey, name, 0, lp_type, 0, 0])
    assert rv == 0
    assert dll_emu.mem_read(lp_type, 4) == struct.pack("<I", 4)
    assert displays["lpType"] == "REG_DWORD"


def test_reg_get_value_writes_the_value_type(dll_emu: Speakeasy) -> None:
    hkey = _open_usbsamp(dll_emu)
    name = _alloc(dll_emu, b"DisplayName\x00")
    pdw_type = _alloc(dll_emu, struct.pack("<I", 4))
    data = _alloc(dll_emu, b"\x00" * 64)
    cb = _alloc(dll_emu, struct.pack("<I", 64))
    rv, displays = _call(dll_emu, "advapi32", "RegGetValueA", [hkey, 0, name, 0xFFFF, pdw_type, data, cb])
    assert rv == 0
    assert dll_emu.mem_read(pdw_type, 4) == struct.pack("<I", 1)
    assert displays["pdwType"] == "REG_SZ"


@pytest.mark.parametrize(
    "api, argv",
    [
        ("RegEnumKeyExA", [0x1234, 0, 0, 0, 0, 0, 0, 0]),
        ("RegCreateKeyA", [0x1234, 0, 0]),
    ],
)
def test_reg_unknown_handle_is_invalid(dll_emu: Speakeasy, api: str, argv: list[int]) -> None:
    rv, displays = _call(dll_emu, "advapi32", api, argv)
    assert rv == 6
    assert displays["hKey"] == "0x1234"


def test_reg_enum_key_ex_shows_the_key_path(dll_emu: Speakeasy) -> None:
    hkey = _open_usbsamp(dll_emu)
    rv, displays = _call(dll_emu, "advapi32", "RegEnumKeyExA", [hkey, 99, 0, 0, 0, 0, 0, 0])
    assert rv == 259
    assert displays["hKey"].endswith("\\usbsamp")


@pytest.mark.parametrize("dll", ["netapi32", "wkscli"])
def test_net_get_join_information_shows_the_join_status(dll_emu: Speakeasy, dll: str) -> None:
    name_buf = _alloc(dll_emu, b"\x00" * 4)
    status = _alloc(dll_emu, b"\x00" * 4)
    rv, displays = _call(dll_emu, dll, "NetGetJoinInformation", [0, name_buf, status])
    assert rv == 0
    assert dll_emu.mem_read(status, 4) == struct.pack("<I", 3)
    assert displays["BufferType"] == "NetSetupDomainName"


@pytest.mark.parametrize(
    "api, width, encoding",
    [("GetConsoleTitleA", 1, "utf-8"), ("GetConsoleTitleW", 2, "utf-16le")],
)
def test_get_console_title_shows_the_title(dll_emu: Speakeasy, api: str, width: int, encoding: str) -> None:
    buf = _alloc(dll_emu, b"\xcc" * 64)
    rv, displays = _call(dll_emu, "kernel32", api, [buf, 32])
    assert rv == len("explorer.exe")
    assert dll_emu.mem_read(buf, 13 * width) == "explorer.exe\x00".encode(encoding)
    assert displays["lpConsoleTitle"] == "explorer.exe"
    assert displays["nSize"] == "0x20"


def test_get_console_title_truncates_to_the_buffer(dll_emu: Speakeasy) -> None:
    buf = _alloc(dll_emu, b"\xcc" * 16)
    rv, displays = _call(dll_emu, "kernel32", "GetConsoleTitleA", [buf, 4])
    assert rv == len("explorer.exe")
    assert dll_emu.mem_read(buf, 5) == b"exp\x00\xcc"
    assert displays["lpConsoleTitle"] == "exp"


@pytest.mark.parametrize(
    "dll, api, width, encoding",
    [
        ("shlwapi", "wnsprintfA", 1, "utf-8"),
        ("shlwapi", "wnsprintfW", 2, "utf-16le"),
        ("msvcrt", "_snwprintf", 2, "utf-16le"),
    ],
)
def test_variadic_sprintf_shows_the_output(dll_emu: Speakeasy, dll: str, api: str, width: int, encoding: str) -> None:
    buf = _alloc(dll_emu, b"\x00" * 64)
    fmt = _alloc(dll_emu, "n=%d\x00".encode(encoding))
    rv, displays = _call(dll_emu, dll, api, [buf, 32, fmt, 7])
    assert rv == 3
    assert dll_emu.mem_read(buf, 4 * width) == "n=7\x00".encode(encoding)
    assert displays == {0: "n=7"}


def _bounded_format(se: Speakeasy, dll: str, api: str, count: int) -> tuple[int, bytes]:
    buf = _alloc(se, b"\xcc" * 8)
    fmt = _alloc(se, b"n=%d\x00")
    va = _alloc(se, struct.pack("<I", 7))
    rv, _ = _call(se, dll, api, [buf, count, fmt, va])
    return rv, se.mem_read(buf, 5)


@pytest.mark.parametrize(
    "fixture, dll",
    [("dll_emu", "msvcrt"), ("driver_emu", "ntoskrnl")],
)
@pytest.mark.parametrize(
    "count, rv, out",
    [
        (8, 3, b"n=7\x00\xcc"),
        (3, 3, b"n=7\xcc\xcc"),
        (2, -1, b"n=\xcc\xcc\xcc"),
    ],
)
def test_vsnprintf_truncation(
    request: pytest.FixtureRequest, fixture: str, dll: str, count: int, rv: int, out: bytes
) -> None:
    assert _bounded_format(request.getfixturevalue(fixture), dll, "_vsnprintf", count) == (rv, out)


@pytest.mark.parametrize(
    "count, rv, out",
    [
        (8, 3, b"n=7\x00\xcc"),
        (3, -1, b"n=\x00\xcc\xcc"),
    ],
)
def test_wvnsprintf_truncation(dll_emu: Speakeasy, count: int, rv: int, out: bytes) -> None:
    assert _bounded_format(dll_emu, "shlwapi", "wvnsprintfA", count) == (rv, out)


@pytest.mark.parametrize(
    "options, count, rv, out",
    [
        (0, 8, 3, b"n=7\x00\xcc"),
        (0, 3, -1, b"n=\x00\xcc\xcc"),
        (1, 3, 3, b"n=7\xcc\xcc"),
        (1, 2, -1, b"n=\xcc\xcc\xcc"),
        (2, 3, 3, b"n=\x00\xcc\xcc"),
        (2, 8, 3, b"n=7\x00\xcc"),
    ],
)
def test_stdio_common_vsprintf_truncation(dll_emu: Speakeasy, options: int, count: int, rv: int, out: bytes) -> None:
    buf = _alloc(dll_emu, b"\xcc" * 8)
    fmt = _alloc(dll_emu, b"n=%d\x00")
    va = _alloc(dll_emu, struct.pack("<I", 7))
    result, _ = _call(dll_emu, "msvcrt", "__stdio_common_vsprintf", [options, 0, buf, count, fmt, 0, va])
    assert (result, dll_emu.mem_read(buf, 5)) == (rv, out)


def test_stdio_common_vsprintf_measures_without_a_buffer(dll_emu: Speakeasy) -> None:
    fmt = _alloc(dll_emu, b"n=%d\x00")
    va = _alloc(dll_emu, struct.pack("<I", 7))
    rv, _ = _call(dll_emu, "msvcrt", "__stdio_common_vsprintf", [2, 0, 0, 0, fmt, 0, va])
    assert rv == 3


def _query_value(se: Speakeasy, api: str, hkey: int, name: bytes, size: int | None) -> tuple[int, int, bytes]:
    name_addr = _alloc(se, name)
    data = _alloc(se, b"\xcc" * 64) if size is not None else 0
    cb = _alloc(se, struct.pack("<I", size or 0))
    rv, _ = _call(se, "advapi32", api, [hkey, name_addr, 0, 0, data, cb])
    length = int.from_bytes(se.mem_read(cb, 4), "little")
    return rv, length, se.mem_read(data, length) if data else b""


@pytest.mark.parametrize(
    "api, name, expected",
    [
        ("RegQueryValueExA", b"DisplayName\x00", b"An example service\x00"),
        ("RegQueryValueExW", "DisplayName\x00".encode("utf-16le"), "An example service\x00".encode("utf-16le")),
        ("RegQueryValueExA", b"Start\x00", struct.pack("<I", 3)),
    ],
)
def test_reg_query_value_ex_returns_the_data(dll_emu: Speakeasy, api: str, name: bytes, expected: bytes) -> None:
    hkey = _open_usbsamp(dll_emu)
    assert _query_value(dll_emu, api, hkey, name, 64) == (0, len(expected), expected)


def test_reg_query_value_ex_returns_the_size(dll_emu: Speakeasy) -> None:
    hkey = _open_usbsamp(dll_emu)
    assert _query_value(dll_emu, "RegQueryValueExA", hkey, b"DisplayName\x00", None) == (0, 19, b"")


def test_reg_query_value_ex_small_buffer(dll_emu: Speakeasy) -> None:
    hkey = _open_usbsamp(dll_emu)
    rv, length, _ = _query_value(dll_emu, "RegQueryValueExA", hkey, b"DisplayName\x00", 4)
    assert (rv, length) == (234, 19)


def test_reg_query_value_ex_returns_a_value_it_set(dll_emu: Speakeasy) -> None:
    hkey = _open_usbsamp(dll_emu)
    name = _alloc(dll_emu, b"Extra\x00")
    value = _alloc(dll_emu, b"abc\x00")
    rv, _ = _call(dll_emu, "advapi32", "RegSetValueExA", [hkey, name, 0, 1, value, 4])
    assert rv == 0
    assert _query_value(dll_emu, "RegQueryValueExA", hkey, b"Extra\x00", 64) == (0, 4, b"abc\x00")


def _get_value(se: Speakeasy, api: str, name: bytes, size: int | None) -> tuple[int, int, bytes]:
    hkey = _open_usbsamp(se)
    name_addr = _alloc(se, name)
    data = _alloc(se, b"\xcc" * 64) if size is not None else 0
    cb = _alloc(se, struct.pack("<I", size or 0))
    rv, _ = _call(se, "advapi32", api, [hkey, 0, name_addr, 0xFFFF, 0, data, cb])
    length = int.from_bytes(se.mem_read(cb, 4), "little")
    return rv, length, se.mem_read(data, length) if data else b""


@pytest.mark.parametrize(
    "api, name, expected",
    [
        ("RegGetValueA", b"DisplayName\x00", b"An example service\x00"),
        ("RegGetValueW", "DisplayName\x00".encode("utf-16le"), "An example service\x00".encode("utf-16le")),
        ("RegGetValueA", b"Start\x00", struct.pack("<I", 3)),
    ],
)
def test_reg_get_value_returns_the_data(dll_emu: Speakeasy, api: str, name: bytes, expected: bytes) -> None:
    assert _get_value(dll_emu, api, name, 64) == (0, len(expected), expected)


def test_reg_get_value_returns_the_size(dll_emu: Speakeasy) -> None:
    assert _get_value(dll_emu, "RegGetValueA", b"DisplayName\x00", None) == (0, 19, b"")


def test_reg_get_value_small_buffer(dll_emu: Speakeasy) -> None:
    rv, length, _ = _get_value(dll_emu, "RegGetValueA", b"DisplayName\x00", 4)
    assert (rv, length) == (234, 19)


@pytest.mark.parametrize(
    "name, val_type, data",
    [
        ("DisplayName", 1, "An example service\x00".encode("utf-16le")),
        ("Start", 4, struct.pack("<I", 3)),
    ],
)
def test_zw_query_value_key_returns_the_data(driver_emu: Speakeasy, name: str, val_type: int, data: bytes) -> None:
    phnd = _alloc(driver_emu, b"\x00" * 4)
    oa = _object_attributes(driver_emu, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\usbsamp")
    rv, _ = _call(driver_emu, "ntoskrnl", "ZwOpenKey", [phnd, 0xF003F, oa])
    assert rv == 0
    hnd = int.from_bytes(driver_emu.mem_read(phnd, 4), "little")
    info = _alloc(driver_emu, b"\xcc" * 128)
    ret_len = _alloc(driver_emu, b"\x00" * 4)
    value_name = _unicode_string(driver_emu, name)
    rv, _ = _call(driver_emu, "ntoskrnl", "ZwQueryValueKey", [hnd, value_name, 2, info, 128, ret_len])
    assert rv == 0
    assert int.from_bytes(driver_emu.mem_read(ret_len, 4), "little") == 12 + len(data)
    assert driver_emu.mem_read(info, 12 + len(data)) == struct.pack("<III", 0, val_type, len(data)) + data


@pytest.mark.parametrize(
    "info_class, name, val_type, data, data_offset",
    [
        (1, "Start", 4, struct.pack("<I", 3), 32),
        (1, "DisplayName", 1, "An example service\x00".encode("utf-16le"), 44),
        (3, "DisplayName", 1, "An example service\x00".encode("utf-16le"), 48),
    ],
)
def test_zw_query_value_key_returns_the_full_information(
    driver_emu: Speakeasy, info_class: int, name: str, val_type: int, data: bytes, data_offset: int
) -> None:
    phnd = _alloc(driver_emu, b"\x00" * 4)
    oa = _object_attributes(driver_emu, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\usbsamp")
    rv, _ = _call(driver_emu, "ntoskrnl", "ZwOpenKey", [phnd, 0xF003F, oa])
    assert rv == 0
    hnd = int.from_bytes(driver_emu.mem_read(phnd, 4), "little")
    info = _alloc(driver_emu, b"\xcc" * 128)
    ret_len = _alloc(driver_emu, b"\x00" * 4)
    value_name = _unicode_string(driver_emu, name)
    rv, _ = _call(driver_emu, "ntoskrnl", "ZwQueryValueKey", [hnd, value_name, info_class, info, 128, ret_len])
    assert rv == 0
    encoded_name = name.encode("utf-16le")
    header = struct.pack("<IIIII", 0, val_type, data_offset, len(data), len(encoded_name))
    assert int.from_bytes(driver_emu.mem_read(ret_len, 4), "little") == data_offset + len(data)
    assert driver_emu.mem_read(info, 20 + len(encoded_name)) == header + encoded_name
    assert driver_emu.mem_read(info + data_offset, len(data)) == data


def test_zw_query_value_key_full_information_without_data(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    config["registry"]["keys"][0]["values"].append({"name": "Empty", "type": "REG_BINARY", "data": ""})
    for se in _load(config, load_test_bin("wdm_test_x86.sys.xz")):
        phnd = _alloc(se, b"\x00" * 4)
        oa = _object_attributes(se, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\usbsamp")
        rv, _ = _call(se, "ntoskrnl", "ZwOpenKey", [phnd, 0xF003F, oa])
        assert rv == 0
        hnd = int.from_bytes(se.mem_read(phnd, 4), "little")
        info = _alloc(se, b"\xcc" * 128)
        ret_len = _alloc(se, b"\x00" * 4)
        rv, _ = _call(se, "ntoskrnl", "ZwQueryValueKey", [hnd, _unicode_string(se, "Empty"), 1, info, 128, ret_len])
        assert rv == 0
        assert int.from_bytes(se.mem_read(ret_len, 4), "little") == 30
        assert se.mem_read(info, 30) == struct.pack("<IIIII", 0, 3, 0xFFFFFFFF, 0, 10) + "Empty".encode("utf-16le")


@pytest.mark.parametrize("dll", ["netapi32", "wkscli"])
def test_net_get_join_information_fits_a_long_domain(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes], dll: str
) -> None:
    domain = "d" * 3000
    config["domain"] = domain
    for se in _load(config, load_test_bin("dll_test_x86.dll.xz")):
        name_buf = _alloc(se, b"\x00" * 4)
        status = _alloc(se, b"\x00" * 4)
        rv, _ = _call(se, dll, "NetGetJoinInformation", [0, name_buf, status])
        assert rv == 0
        name = int.from_bytes(se.mem_read(name_buf, 4), "little")
        assert se.mem_read(name, 2 * len(domain) + 2) == (domain + "\x00").encode("utf-16le")


def test_reg_get_value_opens_the_subkey(dll_emu: Speakeasy) -> None:
    subkey = _alloc(dll_emu, b"System\\CurrentControlSet\\Services\\usbsamp\x00")
    name = _alloc(dll_emu, b"Start\x00")
    data = _alloc(dll_emu, b"\xcc" * 8)
    cb = _alloc(dll_emu, struct.pack("<I", 8))
    rv, displays = _call(dll_emu, "advapi32", "RegGetValueA", [0x80000002, subkey, name, 0xFFFF, 0, data, cb])
    assert rv == 0
    assert dll_emu.mem_read(data, 4) == struct.pack("<I", 3)
    assert displays["lpSubKey"] == "System\\CurrentControlSet\\Services\\usbsamp"


def test_reg_get_value_missing_subkey(dll_emu: Speakeasy) -> None:
    subkey = _alloc(dll_emu, b"Software\\NoSuchKey\x00")
    name = _alloc(dll_emu, b"Start\x00")
    rv, _ = _call(dll_emu, "advapi32", "RegGetValueA", [0x80000002, subkey, name, 0xFFFF, 0, 0, 0])
    assert rv == 2


@pytest.mark.parametrize(
    "api, argv",
    [
        ("GetComputerNameA", []),
        ("GetComputerNameExA", [1]),
    ],
)
def test_get_computer_name_copies_the_host(dll_emu: Speakeasy, api: str, argv: list[int]) -> None:
    assert dll_emu.emu is not None
    host = dll_emu.emu.config.hostname
    buf = _alloc(dll_emu, b"\xcc" * 64)
    size = _alloc(dll_emu, (64).to_bytes(4, "little"))
    rv, displays = _call(dll_emu, "kernel32", api, [*argv, buf, size])
    assert rv
    assert dll_emu.mem_read(buf, len(host) + 1) == host.encode() + b"\x00"
    assert dll_emu.mem_read(size, 4) == len(host).to_bytes(4, "little")
    assert displays["lpBuffer"] == host
    assert displays["nSize"] == hex(size)


@pytest.mark.parametrize(
    "api, argv",
    [
        ("GetComputerNameA", []),
        ("GetComputerNameExA", [1]),
    ],
)
def test_get_computer_name_small_buffer(dll_emu: Speakeasy, api: str, argv: list[int]) -> None:
    assert dll_emu.emu is not None
    host = dll_emu.emu.config.hostname
    buf = _alloc(dll_emu, b"\xcc" * 4)
    size = _alloc(dll_emu, len(host).to_bytes(4, "little"))
    rv, displays = _call(dll_emu, "kernel32", api, [*argv, buf, size])
    assert not rv
    assert dll_emu.mem_read(buf, 4) == b"\xcc" * 4
    assert dll_emu.mem_read(size, 4) == (len(host) + 1).to_bytes(4, "little")
    assert displays["lpBuffer"] == hex(buf)


def test_get_volume_path_names_shows_the_names(dll_emu: Speakeasy) -> None:
    volume = _alloc(dll_emu, b"\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000001}\\\x00")
    names = _alloc(dll_emu, b"\xcc" * 16)
    length = _alloc(dll_emu, b"\x00" * 4)
    rv, displays = _call(dll_emu, "kernel32", "GetVolumePathNamesForVolumeNameA", [volume, names, 16, length])
    assert rv == 1
    assert dll_emu.mem_read(names, 6) == b"C:\\\x00\x00\xcc"
    assert dll_emu.mem_read(length, 4) == (5).to_bytes(4, "little")
    assert displays["lpszVolumePathNames"] == "C:\\"
    assert displays["lpcchReturnLength"] == hex(length)


def test_find_volume_shows_the_volume_names(dll_emu: Speakeasy) -> None:
    buf = _alloc(dll_emu, b"\x00" * 64)
    hnd, displays = _call(dll_emu, "kernel32", "FindFirstVolumeA", [buf, 64])
    assert displays["lpszVolumeName"] == "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000001}\\"
    rv, displays = _call(dll_emu, "kernel32", "FindNextVolumeA", [hnd, buf, 64])
    assert rv == 1
    assert displays["lpszVolumeName"] == "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000002}\\"
