"""Public symbol snapshots and kernel auxiliary symbols."""

import unicorn as uc

from speakeasy import Speakeasy


def test_legacy_tuple_snapshot_tracks_mapped_dynamic_and_data_symbols(dll_emu):
    se = dll_emu
    emu = se.emu
    address = emu.get_proc("kernel32", "GetTickCount")
    data = emu.get_proc("msvcrt", "_acmdln")
    before = se.get_symbols()
    dynamic = emu.get_proc("unknown_symbol_vendor", "NewFunction")
    symbols = se.get_symbols()
    assert symbols[address] == ("kernel32", "GetTickCount")
    assert symbols[data] == ("msvcrt", "_acmdln")
    assert symbols[dynamic] == ("unknown_symbol_vendor", "NewFunction")
    assert dynamic not in before
    assert se.get_api_symbols() == {a: "{}.{}".format(*v) for a, v in symbols.items()}
    assert se.get_symbol_from_address(address + 2) == "kernel32.GetTickCount+0x2"
    assert se.mem_read(address, 6) == b"\x8b\xff\x0f\x1f\x00\xe9"
    trap = address + 10 + int.from_bytes(se.mem_read(address + 6, 4), "little", signed=True)
    assert trap not in symbols
    assert se.get_symbol_from_address(trap) is None
    symbols.clear()
    assert se.get_symbols()[address] == ("kernel32", "GetTickCount")


def test_native_guest_exports_remain_public_symbols(dll_emu):
    se = dll_emu
    module = se.emu.modules[0]
    exports = [export for export in module.get_exports() if export.address and not export.forwarder]
    assert exports
    for export in exports:
        symbol = f"{module.name}.{export.name}"
        assert se.get_symbols()[export.address] == (module.name, export.name)
        assert se.get_api_symbols()[export.address] == symbol
        assert se.get_symbol_from_address(export.address) == symbol


def test_kernel_auxiliary_symbols_and_syscall_stub_outside_image(config, load_test_bin):
    with Speakeasy(config=config) as se:
        se.load_module(data=load_test_bin("wdm_test_x64.sys.xz"))
        emu = se.emu
        module = emu.get_kernel_mod()
        assert se.mem_read(module.base, 2) == b"MZ"
        symbols = se.get_symbols()
        sdt = emu.get_proc("ntoskrnl", "KeServiceDescriptorTable")
        stub = next(address for address, value in symbols.items() if value[1] == "KiSystemCall64")
        kernel = symbols[stub][0]
        assert symbols[sdt] == ("ntoskrnl", "KeServiceDescriptorTable")
        assert symbols[sdt + 1] == (kernel, "KeServiceDescriptorTable")
        assert symbols[sdt + 0x10] == (kernel, "KeServiceDescriptorTable.NumberOfServices")
        assert se.get_symbol_from_address(stub) == f"{kernel}.KiSystemCall64"
        assert se.get_api_symbols()[sdt + 0x10] == f"{kernel}.KeServiceDescriptorTable.NumberOfServices"
        assert not module.base <= stub < module.base + module.image_size
        perms = next(p for start, end, p in emu.get_mem_regions() if start <= stub <= end)
        assert perms == uc.UC_PROT_READ | uc.UC_PROT_EXEC
        for offset in (0, 7):
            displacement = int.from_bytes(se.mem_read(stub + offset + 3, 4), "little", signed=True)
            assert stub + offset + 7 + displacement == sdt
