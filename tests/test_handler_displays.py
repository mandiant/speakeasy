"""
Handlers put each decoded value on the parameter it came from.
"""

import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler import Run
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


def _object_attributes(se: Speakeasy, name: str) -> int:
    """Build an x86 OBJECT_ATTRIBUTES for ``name`` and return its address."""
    buf = name.encode("utf-16le")
    buf_addr = _alloc(se, buf + b"\x00\x00")
    us_addr = _alloc(se, struct.pack("<HHI", len(buf), len(buf) + 2, buf_addr))
    return _alloc(se, struct.pack("<IIIIII", 24, 0, us_addr, 0, 0, 0))


def _call(se: Speakeasy, dll: str, name: str, argv: list[int]) -> tuple[int, dict[str | int, str]]:
    """
    Call a handler with the context dispatch builds. Return the handler result
    and the displays, by parameter name, or by slot index for a call without a
    signature.
    """
    emu = se.emu
    assert emu is not None and emu.api is not None
    mod, func_attrs = emu.api.get_export_func_handler(dll, name)
    if not func_attrs:
        mod, func_attrs = emu.normalize_import_miss(dll, name)
    _, func, argc, _, _ = func_attrs
    assert argc == len(argv)
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
