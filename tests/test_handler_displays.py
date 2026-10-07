"""
Handlers put each decoded value on the parameter it came from.
"""

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api import sigdb
from speakeasy.winenv.api.api import ApiContext, HandlerArgs


@pytest.fixture
def dll_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        yield se
    finally:
        se.shutdown()


def _alloc(se: Speakeasy, data: bytes) -> int:
    addr = se.mem_alloc(len(data), base=0x20000000)
    se.mem_write(addr, data)
    return addr


def _call(se: Speakeasy, dll: str, name: str, argv: list[int]) -> tuple[int, dict[str, str]]:
    """Call a handler with the context dispatch builds, and return (rv, {param name: display})."""
    emu = se.emu
    assert emu is not None and emu.api is not None
    mod, func_attrs = emu.api.get_export_func_handler(dll, name)
    if not func_attrs:
        mod, func_attrs = emu.normalize_import_miss(dll, name)
    _, func, argc, _, _ = func_attrs
    assert argc == len(argv)
    sig = emu.get_handler_signature(dll, name, argc)
    assert sig is not None
    args = HandlerArgs.from_signature(sig, emu.get_ptr_size(), emu._render_signature_args(sig, argv), argv)
    ctx = ApiContext(func_name=f"{dll}.{name}", args=args)
    rv = func(mod, emu, list(argv), ctx)
    return rv, {a.name: a.display for a in args.get_report_args() if a.name is not None}


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
