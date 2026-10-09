"""Public symbol snapshots and legacy kernel auxiliary lookup compatibility."""

import pytest
import unicorn as uc

from speakeasy import Speakeasy, WinKernelEmulator
from speakeasy.windows.api_image import ApiExportSpec, build_api_image


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def symbol_emu(request):
    return request.getfixturevalue(request.param)


def test_legacy_tuple_snapshot_tracks_mapped_dynamic_and_data_symbols(symbol_emu):
    se = symbol_emu
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
    assert symbols == emu.get_symbols()
    assert all(isinstance(value, tuple) and len(value) == 2 for value in symbols.values())
    assert se.get_api_symbols() == {a: "{}.{}".format(*v) for a, v in symbols.items()}
    assert set(emu.api_registry.traps).isdisjoint(symbols)
    assert se.get_symbol_from_address(address + 2) == "kernel32.GetTickCount+0x2"
    symbols.clear()
    assert se.get_symbols()[address] == ("kernel32", "GetTickCount")


def test_registry_precedence_auxiliary_fallback_and_private_trap_exclusion(symbol_emu):
    se = symbol_emu
    emu = se.emu
    address = emu.get_proc("kernel32", "GetTickCount")
    trap = emu.api_registry.entries[address].trap
    auxiliary = emu.mem_map(0x1000, tag="test.symbol.auxiliary")
    emu.symbols.update({address: ("stale", "Wrong"), auxiliary: ("legacy", "Auxiliary")})
    emu.symbols[trap] = ("private", "Trap")
    emu.symbols[trap + 1] = ("private", "TrapInterior")
    assert se.get_symbols()[address] == ("kernel32", "GetTickCount")
    assert se.get_symbol_from_address(address) == "kernel32.GetTickCount"
    assert se.get_symbols()[auxiliary] == ("legacy", "Auxiliary")
    assert se.get_api_symbols()[auxiliary] == "legacy.Auxiliary"
    assert se.get_symbol_from_address(auxiliary) == "legacy.Auxiliary"
    assert se.get_symbol_from_address(auxiliary + 1) is None
    for private in (trap, trap + 1):
        assert private not in se.get_symbols()
        assert private not in se.get_api_symbols()
        assert se.get_symbol_from_address(private) is None


def test_native_guest_exports_remain_public_symbols(symbol_emu):
    se = symbol_emu
    emu = se.emu
    module = emu.modules[0]
    exports = [entry for entry in module.get_exports() if entry.address and not entry.forwarder]
    assert exports
    for export in exports:
        entry = emu.api_registry.entries[export.address]
        assert entry.trap is None
        assert se.get_symbols()[export.address] == (entry.dll, entry.name)
        assert se.get_api_symbols()[export.address] == entry.symbol
        assert se.get_symbol_from_address(export.address) == entry.symbol


def test_forwarder_strings_are_excluded_from_snapshots(symbol_emu):
    se = symbol_emu
    emu = se.emu
    base, _ = emu.get_valid_ranges(0x20000, addr=0x63000000)
    module = emu.load_image(
        build_api_image(
            name="symbol_forwarder",
            arch=emu.arch,
            base=base,
            emu_path="symbol_forwarder.dll",
            exports=[ApiExportSpec("Tick", forwarder="kernel32.GetTickCount")],
        )
    )
    forwarder = module.get_export_by_name("Tick").address
    emu.symbols[forwarder] = ("stale", "Forwarder")
    target = emu.resolve_export(module, "Tick")
    assert forwarder not in se.get_symbols()
    assert forwarder not in se.get_api_symbols()
    assert se.get_symbols()[target] == ("kernel32", "GetTickCount")


def test_kernel_auxiliary_symbols_and_stub_preserve_headers(config, load_test_bin, monkeypatch):
    original = WinKernelEmulator.setup_msrs
    headers = []

    def capture_headers(emu):
        module = emu.get_kernel_mod()
        headers.append(bytes(emu.mem_read(module.base, emu.page_size)))
        original(emu)

    monkeypatch.setattr(WinKernelEmulator, "setup_msrs", capture_headers)
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("wdm_test_x64.sys.xz"))
        emu = se.emu
        module = emu.get_kernel_mod()
        assert bytes(emu.mem_read(module.base, emu.page_size)) == headers[0]
        sdt = emu.get_proc("ntoskrnl", "KeServiceDescriptorTable")
        stub = next(a for a, value in emu.symbols.items() if value[1] == "KiSystemCall64")
        assert se.get_symbols()[sdt] == ("ntoskrnl", "KeServiceDescriptorTable")
        for address in (sdt + 1, sdt + 0x10, stub):
            expected = emu.symbols[address]
            assert se.get_symbols()[address] == expected
            assert se.get_symbol_from_address(address) == "{}.{}".format(*expected)
            assert se.get_api_symbols()[address] == "{}.{}".format(*expected)
        assert not module.base <= stub < module.base + module.image_size
        assert emu.get_address_map(stub).tag.startswith("emu.KiSystemCall64.")
        perms = next(p for start, end, p in emu.get_mem_regions() if start <= stub <= end)
        assert perms == uc.UC_PROT_READ | uc.UC_PROT_EXEC
        assert emu.mem_read(stub, 3) == b"\x90\x90\xc3"
        for offset in (0, 7):
            displacement = int.from_bytes(emu.mem_read(stub + offset + 3, 4), "little", signed=True)
            assert stub + offset + 7 + displacement == sdt
    finally:
        se.shutdown()
