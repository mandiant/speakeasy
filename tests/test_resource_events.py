"""Handlers that change or read files, registry keys or DNS names record report events."""

import struct

from speakeasy import Speakeasy
from speakeasy.winenv.defs.enums import FILE_CREATION_DISPOSITION, REG_VALUE_TYPE
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, start_process
from tests.test_ntoskrnl_driver_apis import SOFTWARE_KEY, _create_key, _object_attributes, _query_value, _unicode_string

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
HKEY_CURRENT_USER = 0x80000001
KEY_ALL_ACCESS = 0xF003F


def get_events(se: Speakeasy) -> list[tuple[str, str]]:
    run = se.emu.get_current_run()
    return [(e.event.value, getattr(e, "path", None) or e.query) for e in run.events]


def test_kernel32_file_handlers_record_events(dll_emu: Speakeasy) -> None:
    se = dll_emu
    start_process(se)
    path = "c:\\users\\public\\dropped.txt"
    name = alloc(se, path.encode() + b"\x00")
    hnd, _ = call(
        se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, FILE_CREATION_DISPOSITION.CREATE_ALWAYS, 0, 0]
    )
    call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"abc"), 3, 0, 0])
    hnd, _ = call(
        se, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, FILE_CREATION_DISPOSITION.OPEN_EXISTING, 0, 0]
    )
    call(se, "kernel32", "ReadFile", [hnd, alloc(se, b"\x00" * 8), 8, alloc(se, b"\x00" * 4), 0])
    assert call(se, "kernel32", "DeleteFileA", [name])[0] == 1
    assert get_events(se) == [
        ("file_create", path),
        ("file_write", path),
        ("file_open", path),
        ("file_read", path),
        ("file_delete", path),
    ]


def test_kernel32_directory_handlers_record_events(dll_emu: Speakeasy) -> None:
    se = dll_emu
    start_process(se)
    path = "c:\\programdata\\stage"
    name = alloc(se, path.encode() + b"\x00")
    call(se, "kernel32", "CreateDirectoryA", [name, 0])
    call(se, "kernel32", "RemoveDirectoryA", [name])
    assert get_events(se) == [("directory_create", path), ("directory_delete", path)]


def test_crt_file_handlers_record_events(dll_emu: Speakeasy) -> None:
    se = dll_emu
    path = "c:\\users\\public\\out.bin"
    stream, _ = call(se, "msvcrt", "fopen", [alloc(se, path.encode() + b"\x00"), alloc(se, b"wb\x00")])
    call(se, "msvcrt", "fwrite", [alloc(se, b"abc"), 1, 3, stream])
    wide_path = alloc(se, path.encode("utf-16le") + b"\x00\x00")
    stream, _ = call(se, "msvcrt", "_wfopen", [wide_path, alloc(se, "rb\x00".encode("utf-16le"))])
    call(se, "msvcrt", "fread", [alloc(se, b"\x00" * 8), 1, 8, stream])
    assert call(se, "msvcrt", "_open", [alloc(se, path.encode() + b"\x00"), 0, 0])[0] != 0xFFFFFFFF
    assert get_events(se) == [
        ("file_create", path),
        ("file_write", path),
        ("file_open", path),
        ("file_read", path),
        ("file_open", path),
    ]


def test_advapi32_registry_handlers_record_events(dll_emu: Speakeasy) -> None:
    se = dll_emu
    phk = alloc(se, b"\x00" * 4)
    subkey = alloc(se, b"Software\\Evil\x00")
    call(se, "advapi32", "RegCreateKeyExA", [HKEY_CURRENT_USER, subkey, 0, 0, 0, KEY_ALL_ACCESS, 0, phk, 0])
    hkey = struct.unpack("<I", se.mem_read(phk, 4))[0]
    value = alloc(se, b"Run\x00")
    data = b"evil.exe\x00"
    call(se, "advapi32", "RegSetValueExA", [hkey, value, 0, REG_VALUE_TYPE.REG_SZ, alloc(se, data), len(data)])
    size = alloc(se, struct.pack("<I", 0x40))
    call(se, "advapi32", "RegQueryValueExA", [hkey, value, 0, 0, alloc(se, b"\x00" * 0x40), size])
    assert call(se, "advapi32", "RegDeleteValueA", [hkey, value])[0] == windefs.ERROR_SUCCESS
    path = "HKEY_CURRENT_USER\\Software\\Evil"
    assert get_events(se) == [
        ("reg_create_key", path),
        ("reg_write_value", path),
        ("reg_read_value", path),
        ("reg_delete_value", path),
    ]


def test_ntoskrnl_registry_handlers_record_events(driver_emu: Speakeasy) -> None:
    se = driver_emu
    _, hnd, _ = _create_key(se, SOFTWARE_KEY)
    data = struct.pack("<I", 3)
    call(
        se,
        "ntoskrnl",
        "ZwSetValueKey",
        [hnd, _unicode_string(se, "Start"), 0, REG_VALUE_TYPE.REG_DWORD, alloc(se, data), 4],
    )
    phnd = alloc(se, b"\x00" * 4)
    call(se, "ntoskrnl", "ZwOpenKey", [phnd, KEY_ALL_ACCESS, _object_attributes(se, SOFTWARE_KEY)])
    _query_value(se, hnd, "Start")
    call(se, "ntoskrnl", "ZwDeleteKey", [hnd])
    path = "HKEY_LOCAL_MACHINE\\Software\\Contoso"
    assert get_events(se) == [
        ("reg_create_key", path),
        ("reg_write_value", path),
        ("reg_open_key", path),
        ("reg_read_value", path),
        ("reg_delete_key", path),
    ]


def test_ws2_32_name_lookups_record_dns_events(dll_emu: Speakeasy) -> None:
    se = dll_emu
    call(se, "ws2_32", "gethostbyname", [alloc(se, b"one.example.com\x00")])
    call(se, "ws2_32", "getaddrinfo", [alloc(se, b"two.example.com\x00"), 0, 0, alloc(se, b"\x00" * 8)])
    assert get_events(se) == [("net_dns", "one.example.com"), ("net_dns", "two.example.com")]
