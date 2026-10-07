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


@pytest.fixture
def dll_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        assert se.emu is not None
        se.emu.curr_run = Run()
        yield se
    finally:
        se.shutdown()


@pytest.fixture
def driver_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("wdm_test_x86.sys.xz"))
        assert se.emu is not None
        se.emu.curr_run = Run()
        yield se
    finally:
        se.shutdown()


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
    prefix = _alloc(dll_emu, b"abc\x00")
    out = _alloc(dll_emu, b"\x00" * 260)
    _, displays = _call(dll_emu, "kernel32", "GetTempFileNameA", [path, prefix, 0, out])
    assert displays["lpPrefixString"] == "abc"
    assert displays["lpTempFileName"].startswith("C:\\tmp\\abc_")


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
