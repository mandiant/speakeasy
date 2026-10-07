"""
advapi32, secur32, crypt32, bcrypt and ncrypt handlers give callers the
results and out-params that Windows gives.
"""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import advapi32 as adv32defs
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, start_process

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


def test_reg_create_key_returns_a_handle_to_the_subkey(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    phk = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "advapi32", "RegCreateKeyA", [HKEY_CURRENT_USER, alloc(dll_emu, b"Software\\Evil\x00"), phk])
    assert rv == windefs.ERROR_SUCCESS
    key = dll_emu.emu.regman.get_key_from_handle(_dword(dll_emu, phk))
    assert key is not None and key.get_path() == "HKEY_CURRENT_USER\\Software\\Evil"


def test_reg_create_key_without_a_subkey_returns_the_key(dll_emu: Speakeasy) -> None:
    phk = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "advapi32", "RegCreateKeyA", [HKEY_CURRENT_USER, 0, phk])
    assert (rv, _dword(dll_emu, phk)) == (windefs.ERROR_SUCCESS, HKEY_CURRENT_USER)


def _open_key(se: Speakeasy, api: str, hkey: int, subkey: int) -> tuple[int, str | None]:
    """Open ``subkey`` below ``hkey`` and return the status and the path of the new handle."""
    assert se.emu is not None
    phk = alloc(se, b"\x00" * 4)
    argv = [hkey, subkey, phk] if api == "RegOpenKeyA" else [hkey, subkey, 0, 0xF003F, phk]
    rv, _ = call(se, "advapi32", api, argv)
    key = se.emu.regman.get_key_from_handle(_dword(se, phk))
    return rv, key.get_path() if key else None


@pytest.mark.parametrize("api", ["RegOpenKeyA", "RegOpenKeyExA"])
def test_reg_open_key_below_an_open_key(dll_emu: Speakeasy, api: str) -> None:
    _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo\\Bar")
    hfoo = _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo")
    rv, path = _open_key(dll_emu, api, hfoo, alloc(dll_emu, b"Bar\x00"))
    assert (rv, path) == (windefs.ERROR_SUCCESS, "HKEY_CURRENT_USER\\Software\\Foo\\Bar")


@pytest.mark.parametrize("api", ["RegOpenKeyA", "RegOpenKeyExA"])
def test_reg_open_missing_key_is_file_not_found(dll_emu: Speakeasy, api: str) -> None:
    rv, path = _open_key(dll_emu, api, HKEY_CURRENT_USER, alloc(dll_emu, b"Software\\NoSuchKey\x00"))
    assert (rv, path) == (windefs.ERROR_FILE_NOT_FOUND, None)


@pytest.mark.parametrize("api", ["RegOpenKeyA", "RegOpenKeyExA"])
def test_reg_open_unknown_handle_is_invalid(dll_emu: Speakeasy, api: str) -> None:
    rv, _ = _open_key(dll_emu, api, 0x1234, alloc(dll_emu, b"Bar\x00"))
    assert rv == windefs.ERROR_INVALID_HANDLE


@pytest.mark.parametrize("api", ["RegOpenKeyA", "RegOpenKeyExA"])
@pytest.mark.parametrize("subkey", [None, b"\x00"])
def test_reg_open_key_without_a_subkey_opens_the_key(dll_emu: Speakeasy, api: str, subkey: bytes | None) -> None:
    hfoo = _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo")
    rv, path = _open_key(dll_emu, api, hfoo, alloc(dll_emu, subkey) if subkey else 0)
    assert (rv, path) == (windefs.ERROR_SUCCESS, "HKEY_CURRENT_USER\\Software\\Foo")


def test_reg_query_info_key_counts_subkeys_and_values(dll_emu: Speakeasy) -> None:
    _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo\\Bar")
    _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo\\Bazzz")
    hfoo = _create_key(dll_emu, HKEY_CURRENT_USER, b"Software\\Foo")
    value = alloc(dll_emu, b"abc\x00")
    rv, _ = call(dll_emu, "advapi32", "RegSetValueExA", [hfoo, alloc(dll_emu, b"Name\x00"), 0, 1, value, 4])
    assert rv == windefs.ERROR_SUCCESS
    outs = [alloc(dll_emu, b"\xcc" * 4) for _ in range(8)]
    ft = alloc(dll_emu, b"\xcc" * 8)
    rv, _ = call(dll_emu, "advapi32", "RegQueryInfoKeyA", [hfoo, 0, outs[0], 0, *outs[1:], ft])
    assert rv == windefs.ERROR_SUCCESS
    cch_class, subkeys, max_subkey, max_class, values, max_name, max_value, sec = (_dword(dll_emu, a) for a in outs)
    assert (subkeys, max_subkey, values, max_name, max_value) == (2, 5, 1, 4, 4)
    assert (cch_class, max_class, sec) == (0, 0, 0)
    assert dll_emu.mem_read(ft, 8) == b"\x00" * 8


def test_rtl_gen_random_fills_a_large_buffer(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 0x401)
    rv, _ = call(dll_emu, "advapi32", "SystemFunction036", [buf, 0x400])
    assert rv
    assert dll_emu.mem_read(buf + 0x3FF, 2) == b"\xff\xcc"


def _last_error(se: Speakeasy) -> int:
    assert se.emu is not None
    return se.emu.get_last_error()


def test_lookup_account_sid_reports_the_sizes(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    sid = alloc(dll_emu, bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<I", 18))
    cch_name = alloc(dll_emu, struct.pack("<I", 0))
    cch_dom = alloc(dll_emu, struct.pack("<I", 0))
    use = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "advapi32", "LookupAccountSidA", [0, sid, 0, cch_name, 0, cch_dom, use])
    assert not rv
    assert _last_error(dll_emu) == windefs.ERROR_INSUFFICIENT_BUFFER
    name_size, dom_size = _dword(dll_emu, cch_name), _dword(dll_emu, cch_dom)

    name = alloc(dll_emu, b"\xcc" * name_size)
    dom = alloc(dll_emu, b"\xcc" * dom_size)
    rv, _ = call(dll_emu, "advapi32", "LookupAccountSidA", [0, sid, name, cch_name, dom, cch_dom, use])
    assert rv
    assert dll_emu.mem_read(name, name_size)[-1:] == b"\x00"
    assert dll_emu.mem_read(dom, dom_size)[-1:] == b"\x00"
    assert (_dword(dll_emu, cch_name), _dword(dll_emu, cch_dom)) == (name_size - 1, dom_size - 1)
    assert _dword(dll_emu, use) == 1


def test_get_user_name_ex_reports_the_size(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    user = dll_emu.emu.config.user.name
    size = alloc(dll_emu, struct.pack("<I", 0))
    rv, _ = call(dll_emu, "secur32", "GetUserNameExA", [2, 0, size])
    assert (rv, _last_error(dll_emu), _dword(dll_emu, size)) == (0, windefs.ERROR_MORE_DATA, len(user) + 1)

    buf = alloc(dll_emu, b"\xcc" * (len(user) + 1))
    rv, _ = call(dll_emu, "secur32", "GetUserNameExA", [2, buf, size])
    assert (rv, _dword(dll_emu, size)) == (1, len(user))
    assert dll_emu.mem_read(buf, len(user) + 1) == user.encode() + b"\x00"


@pytest.mark.parametrize("api, encoding", [("GetUserNameA", "utf-8"), ("GetUserNameW", "utf-16le")])
def test_get_user_name_reports_the_size(dll_emu: Speakeasy, api: str, encoding: str) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    expected = (dll_emu.emu.config.user.name + "\x00").encode(encoding)
    need = len(dll_emu.emu.config.user.name) + 1
    size = alloc(dll_emu, struct.pack("<I", 0))
    rv, _ = call(dll_emu, "advapi32", api, [0, size])
    assert (rv, _last_error(dll_emu), _dword(dll_emu, size)) == (0, windefs.ERROR_INSUFFICIENT_BUFFER, need)

    buf = alloc(dll_emu, b"\xcc" * 64)
    rv, _ = call(dll_emu, "advapi32", api, [buf, size])
    assert (rv, _dword(dll_emu, size)) == (1, need)
    assert dll_emu.mem_read(buf, len(expected)) == expected


def test_crypt_release_context_rejects_an_unknown_handle(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    phprov = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "advapi32", "CryptAcquireContextA", [phprov, 0, 0, 1, 0xF0000000])
    assert rv
    hprov = _dword(dll_emu, phprov)
    assert call(dll_emu, "advapi32", "CryptReleaseContext", [hprov, 0])[0]
    rv, _ = call(dll_emu, "advapi32", "CryptReleaseContext", [hprov, 0])
    assert (rv, _last_error(dll_emu)) == (0, windefs.ERROR_INVALID_HANDLE)
    rv, _ = call(dll_emu, "advapi32", "CryptReleaseContext", [0, 0])
    assert not rv


def test_bcrypt_close_algorithm_provider_twice(dll_emu: Speakeasy) -> None:
    ph = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(
        dll_emu, "bcrypt", "BCryptOpenAlgorithmProvider", [ph, alloc(dll_emu, "RSA\x00".encode("utf-16le")), 0, 0]
    )
    assert rv == 0
    halg = _dword(dll_emu, ph)
    assert call(dll_emu, "bcrypt", "BCryptCloseAlgorithmProvider", [halg, 0])[0] == 0
    assert call(dll_emu, "bcrypt", "BCryptCloseAlgorithmProvider", [halg, 0])[0] == ddk.STATUS_INVALID_HANDLE


def _open_storage_provider(se: Speakeasy, name: str | None) -> int:
    assert se.emu is not None
    ph = alloc(se, b"\xcc" * 8)
    pname = alloc(se, (name + "\x00").encode("utf-16le")) if name is not None else 0
    rv, _ = call(se, "ncrypt", "NCryptOpenStorageProvider", [ph, pname, 0])
    assert rv == 0
    return int.from_bytes(se.mem_read(ph, se.emu.get_ptr_size()), "little")


@pytest.mark.parametrize("name", [None, "Microsoft Software Key Storage Provider"])
def test_ncrypt_open_storage_provider_returns_a_handle(dll_emu: Speakeasy, name: str | None) -> None:
    assert dll_emu.emu is not None
    hprov = _open_storage_provider(dll_emu, name)
    assert dll_emu.emu.get_crypt_manager().crypt_get(hprov) is not None


def test_ncrypt_import_key_ignores_the_high_bits_of_the_size(dll64_emu: Speakeasy) -> None:
    hprov = _open_storage_provider(dll64_emu, None)
    phkey = alloc(dll64_emu, b"\x00" * 8)
    blob_type = alloc(dll64_emu, "RSAPUBLICBLOB\x00".encode("utf-16le"))
    data = alloc(dll64_emu, b"\x01" * 16)
    argv = [hprov, 0, blob_type, 0, phkey, data, 0xDEADBEEF00000010, 0]
    rv, _ = call(dll64_emu, "ncrypt", "NCryptImportKey", argv)
    assert rv == 0
    assert int.from_bytes(dll64_emu.mem_read(phkey, 8), "little") != 0


def test_import_key_rejects_an_unknown_provider(dll_emu: Speakeasy) -> None:
    blob_type = alloc(dll_emu, "RSAPUBLICBLOB\x00".encode("utf-16le"))
    data = alloc(dll_emu, b"\x01" * 16)
    phkey = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "ncrypt", "NCryptImportKey", [0x1234, 0, blob_type, 0, phkey, data, 16, 0])
    assert rv == adv32defs.NTE_INVALID_HANDLE
    rv, _ = call(dll_emu, "bcrypt", "BCryptImportKeyPair", [0x1234, 0, blob_type, phkey, data, 16, 0])
    assert rv == ddk.STATUS_INVALID_HANDLE
