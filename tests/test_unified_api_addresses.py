"""Import slots, export tables and procedure resolvers agree on mapped API entries."""

import struct

import pefile
import pytest
import unicorn as uc

from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from tests.handler_harness import alloc, call, load_emu

TEST_BINS = {4: "dll_test_x86.dll.xz", 8: "dll_test_x64.dll.xz"}


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


@pytest.fixture
def placeholder_emu(config, load_test_bin):
    config["modules"]["modules_always_exist"] = True
    yield from load_emu(config, load_test_bin(TEST_BINS[4]))


def module_handle(se, name):
    handle, _ = call(se, "kernel32", "GetModuleHandleA", [alloc(se, name.encode() + b"\0")])
    assert handle
    return handle


def get_proc_address(se, handle, name):
    result, _ = call(se, "kernel32", "GetProcAddress", [handle, alloc(se, name.encode() + b"\0")])
    return result


def mapped_pe(se, base):
    size = pefile.PE(data=se.mem_read(base, 0x1000), fast_load=True).OPTIONAL_HEADER.SizeOfImage
    return pefile.PE(data=se.mem_read(base, size))


def permissions_at(se, address):
    return next(perms for start, end, perms in se.emu.get_mem_regions() if start <= address <= end)


def test_iat_slots_match_get_proc_address(api_emu, load_test_bin):
    ptr = api_emu.get_ptr_size()
    pe = pefile.PE(data=load_test_bin(TEST_BINS[ptr]))
    base = api_emu.emu.modules[0].base
    checked = 0
    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        handle = module_handle(api_emu, descriptor.dll.decode())
        for imp in descriptor.imports:
            slot = base + imp.address - pe.OPTIONAL_HEADER.ImageBase
            address = int.from_bytes(api_emu.mem_read(slot, ptr), "little")
            assert address == get_proc_address(api_emu, handle, imp.name.decode())
            assert api_emu.mem_read(address, 1)
            checked += 1
    assert checked >= 26


def test_eat_and_resolvers_share_one_entry(api_emu):
    ptr = api_emu.get_ptr_size()
    kernel32 = module_handle(api_emu, "kernel32.dll")
    export = next(e for e in mapped_pe(api_emu, kernel32).DIRECTORY_ENTRY_EXPORT.symbols if e.name == b"MoveFileExW")
    address = kernel32 + export.address
    assert get_proc_address(api_emu, kernel32, "MoveFileExW") == address
    by_ordinal, _ = call(api_emu, "kernel32", "GetProcAddress", [kernel32, export.ordinal])
    assert by_ordinal == address
    name = alloc(api_emu, b"MoveFileExW\0")
    padding = b"\0" * 4 if ptr == 8 else b""
    ansi = alloc(api_emu, struct.pack("<HH", 11, 12) + padding + name.to_bytes(ptr, "little"))
    output = alloc(api_emu, b"\0" * ptr)
    status, _ = call(api_emu, "ntdll", "LdrGetProcedureAddress", [kernel32, ansi, 0, output])
    assert status == 0
    assert int.from_bytes(api_emu.mem_read(output, ptr), "little") == address
    assert api_emu.mem_read(address, 2) == (b"\x8b\xff" if ptr == 4 else b"\x66\x90")
    assert permissions_at(api_emu, address) & uc.UC_PROT_EXEC
    assert api_emu.get_symbol_from_address(address + 2).endswith("MoveFileExW+0x2")


def test_missing_known_export_fails_both_resolvers(dll_emu):
    kernel32 = module_handle(dll_emu, "kernel32.dll")
    assert get_proc_address(dll_emu, kernel32, "NotARealKernel32Export") == 0
    output = alloc(dll_emu, b"\0" * 4)
    status, _ = call(dll_emu, "ntdll", "LdrGetProcedureAddress", [kernel32, 0, 65535, output])
    assert status != 0
    assert dll_emu.mem_read(output, 4) == b"\0" * 4


def test_unknown_module_entries_are_stable_and_leave_pe_unchanged(placeholder_emu):
    se = placeholder_emu
    handle, _ = call(se, "kernel32", "LoadLibraryA", [alloc(se, b"unknown_vendor.dll\0")])
    assert handle
    before = mapped_pe(se, handle)
    headers = before.OPTIONAL_HEADER.SizeOfHeaders
    address = get_proc_address(se, handle, "UnknownFunction")
    assert address
    assert get_proc_address(se, handle, "UnknownFunction") == address
    assert get_proc_address(se, handle, "AnotherFunction") not in (0, address)
    assert se.mem_read(handle, headers) == before.__data__[:headers]
    assert handle <= address < handle + before.OPTIONAL_HEADER.SizeOfImage
    perms = permissions_at(se, address)
    assert perms & uc.UC_PROT_EXEC
    assert not perms & uc.UC_PROT_WRITE


def test_forwarders_resolve_to_destination_and_keep_eat_strings(dll_emu):
    emu = dll_emu.emu
    base, _ = emu.get_valid_ranges(0x20000, addr=0x63000000)
    module = dll_emu.load_image(
        build_api_image(
            name="forwarding_test",
            arch=emu.arch,
            base=base,
            emu_path="forwarding_test.dll",
            exports=[
                ApiExportSpec("Tick", forwarder="kernel32.GetTickCount"),
                ApiExportSpec("Variable", forwarder="msvcrt._acmdln"),
                ApiExportSpec("Cycle", forwarder="forwarding_test.Cycle"),
                ApiExportSpec("Missing", forwarder="kernel32.NotARealExport"),
            ],
        )
    )
    before = dll_emu.mem_read(module.base, module.image_size)
    kernel32 = module_handle(dll_emu, "kernel32.dll")
    msvcrt = module_handle(dll_emu, "msvcrt.dll")
    assert get_proc_address(dll_emu, module.base, "Tick") == get_proc_address(dll_emu, kernel32, "GetTickCount")
    assert get_proc_address(dll_emu, module.base, "Variable") == get_proc_address(dll_emu, msvcrt, "_acmdln")
    assert get_proc_address(dll_emu, module.base, "Cycle") == 0
    assert get_proc_address(dll_emu, module.base, "Missing") == 0
    assert dll_emu.mem_read(module.base, module.image_size) == before


def test_dynamic_arena_holds_2048_entries_then_refuses_without_moving_them(dll_emu):
    emu = dll_emu.emu
    emu.load_module_by_name("capacity_vendor")
    addresses = [emu.get_proc("capacity_vendor", f"Dynamic{index}") for index in range(2048)]
    assert len(set(addresses)) == 2048
    assert all(addresses)
    first_bytes = emu.mem_read(addresses[0], 16)
    last_bytes = emu.mem_read(addresses[-1], 16)

    assert emu.get_proc("capacity_vendor", "Overflow") == 0
    assert emu.get_proc("capacity_vendor", 7) == 0

    assert emu.get_proc("capacity_vendor", "Dynamic0") == addresses[0]
    assert emu.get_proc("capacity_vendor", "Dynamic2047") == addresses[-1]
    assert emu.mem_read(addresses[0], 16) == first_bytes
    assert emu.mem_read(addresses[-1], 16) == last_bytes
