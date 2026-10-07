"""
advapi32, secur32, crypt32, bcrypt and ncrypt handlers give callers the
results and out-params that Windows gives.
"""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call

HKEY_CURRENT_USER = 0x80000001


def _dword(se: Speakeasy, addr: int) -> int:
    return int.from_bytes(se.mem_read(addr, 4), "little")


def _create_key(se: Speakeasy, hkey: int, subkey: bytes) -> int:
    phk = alloc(se, b"\x00" * 4)
    rv, _ = call(se, "advapi32", "RegCreateKeyExA", [hkey, alloc(se, subkey + b"\x00"), 0, 0, 0, 0xF003F, 0, phk, 0])
    assert rv == windefs.ERROR_SUCCESS
    return _dword(se, phk)


@pytest.mark.parametrize("api, encoding", [("RegEnumKeyExA", "utf-8"), ("RegEnumKeyExW", "utf-16le")])
def test_reg_enum_key_ex_returns_the_subkey_name(dll_emu: Speakeasy, api: str, encoding: str) -> None:
    _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo\\Bar")
    hfoo = _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo")
    buf = alloc(dll_emu, b"\xcc" * 64)
    cch = alloc(dll_emu, struct.pack("<I", 32))
    rv, _ = call(dll_emu, "advapi32", api, [hfoo, 0, buf, cch, 0, 0, 0, 0])
    expected = "Bar\x00".encode(encoding)
    assert (rv, _dword(dll_emu, cch)) == (windefs.ERROR_SUCCESS, 3)
    assert dll_emu.mem_read(buf, len(expected)) == expected
    rv, _ = call(dll_emu, "advapi32", api, [hfoo, 1, buf, cch, 0, 0, 0, 0])
    assert rv == windefs.ERROR_NO_MORE_ITEMS


def test_reg_enum_key_ex_small_buffer(dll_emu: Speakeasy) -> None:
    _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo\\Bar")
    hfoo = _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo")
    buf = alloc(dll_emu, b"\xcc" * 8)
    cch = alloc(dll_emu, struct.pack("<I", 3))
    rv, _ = call(dll_emu, "advapi32", "RegEnumKeyExA", [hfoo, 0, buf, cch, 0, 0, 0, 0])
    assert rv == windefs.ERROR_MORE_DATA
    assert dll_emu.mem_read(buf, 8) == b"\xcc" * 8


def test_reg_enum_key_uses_the_buffer_size(dll_emu: Speakeasy) -> None:
    _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo\\Bar")
    hfoo = _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo")
    buf = alloc(dll_emu, b"\xcc" * 8)
    rv, _ = call(dll_emu, "advapi32", "RegEnumKeyA", [hfoo, 0, buf, 8])
    assert (rv, dll_emu.mem_read(buf, 4)) == (windefs.ERROR_SUCCESS, b"Bar\x00")
    rv, _ = call(dll_emu, "advapi32", "RegEnumKeyA", [hfoo, 0, buf, 3])
    assert rv == windefs.ERROR_MORE_DATA


def test_get_subkeys_lists_each_child_once() -> None:
    regman = RegistryManager(HandleAllocator())
    for path in ("HKEY_LOCAL_MACHINE\\T\\A\\x", "HKEY_LOCAL_MACHINE\\T\\A\\y", "HKEY_LOCAL_MACHINE\\TT"):
        regman.create_key(path)
    parent = regman.create_key("HKEY_LOCAL_MACHINE\\T")
    assert regman.get_subkeys(parent) == ["A"]
