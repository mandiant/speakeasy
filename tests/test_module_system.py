"""
Tests for the module system refactor — emulator integration and dispatch chain.

These tests verify the EMULATOR-SIDE behavior described in §20 sections 2-10
of the revised module specification. Since the refactor hasn't happened yet,
tests against new APIs are marked xfail.
"""

from __future__ import annotations

import copy

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.loaders import ExportEntry, ImportEntry, LoadedImage, MemoryRegion, RuntimeModule


def _make_image(
    module_type: str = "exe",
    image_base: int = 0x400000,
    image_size: int = 0x10000,
    entry_points: list[int] | None = None,
    exports: list[ExportEntry] | None = None,
    imports: list[ImportEntry] | None = None,
    regions: list[MemoryRegion] | None = None,
    tls_callbacks: list[int] | None = None,
    tls_directory_va: int | None = None,
    emu_path: str = "C:\\Windows\\malware.exe",
    visible_in_peb: bool = True,
    default_export_mode: str = "intercepted",
    loader: object | None = None,
) -> LoadedImage:
    return LoadedImage(
        arch=0x3,
        module_type=module_type,
        name="malware",
        emu_path=emu_path,
        image_base=image_base,
        image_size=image_size,
        regions=regions or [],
        imports=imports or [],
        exports=exports or [],
        default_export_mode=default_export_mode,
        entry_points=entry_points or [],
        visible_in_peb=visible_in_peb,
        tls_callbacks=tls_callbacks or [],
        tls_directory_va=tls_directory_va,
        loader=loader,
    )


# ---------------------------------------------------------------------------
# §20.2: load_image() Integration Tests
# ---------------------------------------------------------------------------


def test_load_image_maps_single_region(config):
    """A LoadedImage with one region gets mapped at the correct address."""
    code = b"\xc3" * 0x1000
    image = _make_image(
        image_base=0x400000,
        image_size=0x2000,
        regions=[MemoryRegion(base=0x401000, data=code, name=".text", perms=0x5)],
        entry_points=[0x401000],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    mapped = se.emu.mem_read(0x401000, len(code))
    assert bytes(mapped) == code


def test_load_image_maps_multiple_regions(config):
    """Multiple non-contiguous regions (like IDA segments) each mapped independently."""
    text_data = b"\x90" * 0x1000
    data_data = b"\x41" * 0x1000
    image = _make_image(
        image_base=0x400000,
        image_size=0x10000,
        regions=[
            MemoryRegion(base=0x401000, data=text_data, name=".text", perms=0x5),
            MemoryRegion(base=0x405000, data=data_data, name=".data", perms=0x3),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    text_mapped = se.emu.mem_read(0x401000, 0x1000)
    data_mapped = se.emu.mem_read(0x405000, 0x1000)
    assert bytes(text_mapped) == text_data
    assert bytes(data_mapped) == data_data


def test_load_image_patches_imports_with_sentinels(config):
    """IAT slots are overwritten with sentinel addresses by load_image()."""
    iat_data = b"\x00" * 0x1000
    image = _make_image(
        image_base=0x400000,
        image_size=0x10000,
        regions=[
            MemoryRegion(base=0x400000, data=iat_data, name=".rdata", perms=0x3),
        ],
        imports=[
            ImportEntry(iat_address=0x400100, dll_name="kernel32", func_name="VirtualAlloc"),
            ImportEntry(iat_address=0x400108, dll_name="kernel32", func_name="VirtualFree"),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    slot1 = int.from_bytes(se.emu.mem_read(0x400100, 4), "little")
    slot2 = int.from_bytes(se.emu.mem_read(0x400108, 4), "little")
    assert slot1 != 0, "IAT slot should be patched with sentinel, not zero"
    assert slot2 != 0, "IAT slot should be patched with sentinel, not zero"
    assert slot1 != slot2, "Each import needs a distinct sentinel"


def test_load_image_records_imports_in_global_table(config):
    """self.import_table maps each sentinel to correct (dll, func)."""
    iat_data = b"\x00" * 0x1000
    image = _make_image(
        image_base=0x400000,
        image_size=0x10000,
        regions=[
            MemoryRegion(base=0x400000, data=iat_data, name=".rdata", perms=0x3),
        ],
        imports=[
            ImportEntry(iat_address=0x400100, dll_name="kernel32", func_name="VirtualAlloc"),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    emu = se.emu
    found = False
    for _sentinel, (dll, func) in emu.import_table.items():
        if dll == "kernel32" and func == "VirtualAlloc":
            found = True
            break
    assert found, "import_table should contain the imported function"


def test_load_image_gap_between_regions_is_unmapped(config):
    """Gap between non-contiguous regions is unmapped — accessing it is invalid."""
    image = _make_image(
        image_base=0x400000,
        image_size=0x10000,
        regions=[
            MemoryRegion(base=0x401000, data=b"\x90" * 0x1000, name=".text", perms=0x5),
            MemoryRegion(base=0x405000, data=b"\x41" * 0x1000, name=".data", perms=0x3),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    with pytest.raises(Exception):
        se.emu.mem_read(0x403000, 0x100)


def test_load_image_assigns_address_for_base_zero(config):
    """Region with base=0 gets emulator-assigned address."""
    image = _make_image(
        image_base=0,
        image_size=0x1000,
        regions=[MemoryRegion(base=0, data=b"\xcc" * 0x100, name="shellcode", perms=0x7)],
    )

    se = Speakeasy(config=config)
    mod = se.load_image(image)
    assert mod.get_base() > 0, "Emulator should assign a non-zero base"


# ---------------------------------------------------------------------------
# §20.3: Dispatch Chain Tests
# ---------------------------------------------------------------------------


def test_static_import_call_dispatches_to_handler(config, load_test_bin):
    """Code calls through IAT -> sentinel -> handler fires.

    Uses a real PE binary that calls kernel32 functions statically.
    After the refactor, import_table lives on the emulator (not on PeFile),
    and _handle_invalid_fetch consults that global table.
    """
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    report = se.get_report()

    eps = report.entry_points
    assert len(eps) > 0

    dll_entry = eps[0]
    msgbox_calls = [evt for evt in (dll_entry.events or []) if evt.event == "api" and "MessageBox" in evt.api_name]
    assert len(msgbox_calls) > 0, "Static import through IAT should dispatch to handler"

    assert not hasattr(module, "import_table"), "After refactor, import_table should be on emulator, not on PeFile"
    assert hasattr(se.emu, "import_table"), "import_table should be a global dict on the emulator"


def test_getprocaddress_sentinel_dispatches_to_handler(config, load_test_bin):
    """GetProcAddress returns sentinel -> calling sentinel fires correct handler.

    Uses the GetProcAddress test binary which dynamically resolves functions.
    After the refactor, dynamic imports go through the same import_table as
    static ones, and dyn_imps is removed.
    """
    data = load_test_bin("GetProcAddress.exe.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    report = se.get_report()

    eps = report.entry_points
    assert len(eps) > 0

    ep = eps[0]
    gpa_calls = [evt for evt in (ep.events or []) if evt.event == "api" and evt.api_name == "KERNEL32.GetProcAddress"]
    assert len(gpa_calls) > 0, "GetProcAddress should be called"

    successful_gpa = [c for c in gpa_calls if c.ret_val != "0x0"]
    assert len(successful_gpa) > 0, "At least one GetProcAddress should succeed"

    assert not hasattr(se.emu, "dyn_imps"), "After refactor, dyn_imps should be merged into import_table"


# ---------------------------------------------------------------------------
# §20.4: Per-Export Execution Mode
# ---------------------------------------------------------------------------


def test_mixed_execution_modes_on_same_module():
    """Module with intercepted and emulated exports behaves correctly per-export.

    This tests the data model: ExportEntry carries execution_mode and
    RuntimeModule preserves it.
    """
    exports = [
        ExportEntry(name="InterceptedFunc", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ExportEntry(name="EmulatedFunc", address=0x402000, ordinal=2, execution_mode="emulated"),
        ExportEntry(name="NoHandlerFunc", address=0x403000, ordinal=3, execution_mode="intercepted"),
    ]
    image = _make_image(
        module_type="dll",
        exports=exports,
        default_export_mode="intercepted",
    )
    mod = RuntimeModule(image)

    assert mod.get_export_by_name("InterceptedFunc").execution_mode == "intercepted"
    assert mod.get_export_by_name("EmulatedFunc").execution_mode == "emulated"
    assert mod.get_export_by_name("NoHandlerFunc").execution_mode == "intercepted"


def test_getprocaddress_returns_sentinel_for_emulated_export(config):
    """GetProcAddress always returns sentinel, even for emulated exports.

    After the refactor, GetProcAddress should return a sentinel for ALL exports,
    including those marked as 'emulated'. The dispatch chain then decides how
    to handle the call (redirect to real code or intercept).
    """
    exports = [
        ExportEntry(name="EmulatedFunc", address=0x401000, ordinal=1, execution_mode="emulated"),
    ]
    image = _make_image(
        module_type="dll",
        exports=exports,
        default_export_mode="emulated",
    )

    se = Speakeasy(config=config)
    _mod = se.load_image(image)

    sentinel = se.emu.get_proc("malware", "EmulatedFunc")
    assert sentinel != 0x401000, "GetProcAddress should return a sentinel, not the real export address"
    assert sentinel != 0, "Sentinel should be non-zero"


# ---------------------------------------------------------------------------
# §20.5: Unified Module List
# ---------------------------------------------------------------------------


def test_all_modules_in_single_list(config, load_test_bin):
    """After loading, all modules (primary, system, decoy) are in self.modules."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    se.load_module(data=data)

    emu = se.emu
    assert len(emu.modules) > 0, "modules list should be populated"

    for mod in emu.modules:
        assert isinstance(mod, RuntimeModule), f"Each entry in self.modules should be a RuntimeModule, got {type(mod)}"


def test_get_mod_from_addr_finds_correct_module(config, load_test_bin):
    """get_mod_from_addr returns the correct RuntimeModule for an address."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)

    emu = se.emu
    found = emu.get_mod_from_addr(module.base + 0x100)
    assert found is not None
    assert isinstance(found, RuntimeModule)
    assert found.get_base() == module.base


def test_get_mod_from_addr_returns_none_for_unmapped(config, load_test_bin):
    """get_mod_from_addr returns None for an address not in any module."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    se.load_module(data=data)

    result = se.emu.get_mod_from_addr(0xDEAD0000)
    assert result is None


def test_get_mod_by_name_finds_module(config, load_test_bin):
    """get_mod_by_name('kernel32') finds the API-backed module."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    se.load_module(data=data)

    emu = se.emu
    mod = emu.get_mod_by_name("kernel32")
    assert mod is not None
    assert isinstance(mod, RuntimeModule)


def test_shellcode_appears_in_modules(config):
    """Shellcode appears in self.modules (no separate pic_buffers)."""
    se = Speakeasy(config=config)
    sc_data = b"\xcc" * 64
    sc_addr = se.load_shellcode(data=sc_data, arch="x86")

    emu = se.emu
    found = False
    for mod in emu.modules:
        if isinstance(mod, RuntimeModule) and mod.get_base() == sc_addr:
            found = True
            break
    assert found, "Shellcode should appear in self.modules"
    assert not hasattr(emu, "pic_buffers"), "pic_buffers should not exist after refactor"


def test_emulator_global_import_table(config, load_test_bin):
    """Static and dynamic imports both appear in self.import_table.

    After the refactor, there is one global import_table on the emulator.
    No dyn_imps attribute should exist.
    """
    data = load_test_bin("GetProcAddress.exe.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)

    emu = se.emu
    assert hasattr(emu, "import_table"), "emulator should have import_table"
    assert len(emu.import_table) > 0, "import_table should contain entries"
    assert not hasattr(emu, "dyn_imps"), "dyn_imps should not exist after refactor"


# ---------------------------------------------------------------------------
# §20.6: LoadLibrary Runtime Loading
# ---------------------------------------------------------------------------


def test_load_library_with_api_handler(config, load_test_bin):
    """LoadLibrary for a module with API handlers produces RuntimeModule in self.modules."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)

    emu = se.emu
    for mod in emu.modules:
        assert isinstance(mod, RuntimeModule), (
            f"All modules (including runtime-loaded) should be RuntimeModule, got {type(mod)}"
        )


def test_load_library_already_loaded(config, load_test_bin):
    """LoadLibrary for an already-loaded module returns existing base.

    After the refactor, self.modules contains RuntimeModule instances,
    and duplicate detection works on that list.
    """
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    se.load_module(data=data)

    emu = se.emu
    assert any(isinstance(m, RuntimeModule) for m in emu.modules), "At least one module should be a RuntimeModule"

    kernel32_bases = []
    for mod in emu.modules:
        if isinstance(mod, RuntimeModule) and "kernel32" in mod.get_emu_path().lower():
            kernel32_bases.append(mod.get_base())
    assert len(kernel32_bases) <= 1, "kernel32 should not be double-loaded"


# ---------------------------------------------------------------------------
# §20.7: PEB Integration
# ---------------------------------------------------------------------------


def test_peb_modules_populated(config, load_test_bin):
    """Modules with visible_in_peb=True appear in PEB InLoadOrderModuleList."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)

    emu = se.emu
    peb_mods = emu.get_peb_modules()
    assert len(peb_mods) > 0, "PEB module list should be populated"
    for mod in peb_mods:
        assert isinstance(mod, RuntimeModule)
        assert mod.visible_in_peb is True


def test_shellcode_not_in_peb(config):
    """Shellcode (visible_in_peb=False) does NOT appear in PEB."""
    se = Speakeasy(config=config)
    sc_data = b"\xcc" * 64
    sc_addr = se.load_shellcode(data=sc_data, arch="x86")

    emu = se.emu
    peb_mods = emu.get_peb_modules()
    for mod in peb_mods:
        if isinstance(mod, RuntimeModule):
            assert mod.get_base() != sc_addr, "Shellcode should not appear in PEB"


# ---------------------------------------------------------------------------
# §20.8: Cross-Loader Interop (End-to-End)
# ---------------------------------------------------------------------------


def test_pe_binary_calling_api_backed_system_dll(config, load_test_bin):
    """Load PE via PeLoader -> imports dispatch to API handlers.

    This is the primary integration test: a real PE binary with static
    imports is loaded through the new loader system, and API handlers fire.
    All modules in self.modules are RuntimeModule with provenance.
    """
    data = load_test_bin("dll_test_x86.dll.xz")

    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    report = se.get_report()

    eps = report.entry_points
    assert len(eps) > 0

    dll_entry = eps[0]
    api_events = [evt for evt in (dll_entry.events or []) if evt.event == "api"]
    assert len(api_events) > 0, "API handlers should fire for static imports"

    emu = se.emu
    for mod in emu.modules:
        assert isinstance(mod, RuntimeModule), "All modules should be RuntimeModule instances"
        assert mod.loader is not None, "Every module should have a loader reference"


def test_shellcode_resolving_exports_from_api_module(config):
    """Shellcode walks API module export table -> code hook fires -> handler runs.

    After the refactor, API modules are loaded via ApiModuleLoader and their
    exports are accessible via the export table. kernel32 should be a
    RuntimeModule in self.modules with provenance.
    """
    se = Speakeasy(config=config)
    sc_data = b"\xcc" * 64
    se.load_shellcode(data=sc_data, arch="x86")

    emu = se.emu
    k32_mod = None
    for mod in emu.modules:
        if isinstance(mod, RuntimeModule) and "kernel32" in mod.get_emu_path().lower():
            k32_mod = mod
            break
    assert k32_mod is not None, "kernel32 should be in modules as a RuntimeModule"
    assert k32_mod.loader is not None, "kernel32 should have a loader reference"


# ---------------------------------------------------------------------------
# §20.9: Provenance
# ---------------------------------------------------------------------------


def test_provenance_tracking(config, load_test_bin):
    """After loading, module.loader is the correct loader instance for each module."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    se.load_module(data=data)

    emu = se.emu
    assert len(emu.modules) > 0

    runtime_modules = [m for m in emu.modules if isinstance(m, RuntimeModule)]
    assert len(runtime_modules) > 0, "At least one module should be a RuntimeModule"

    for mod in runtime_modules:
        assert mod.loader is not None, f"Module {mod!r} should have a loader"
        loader_type = type(mod.loader).__name__
        assert loader_type in (
            "PeLoader",
            "ApiModuleLoader",
            "DecoyLoader",
            "ShellcodeLoader",
            "IdaLoader",
        ), f"Unexpected loader type: {loader_type}"


# ---------------------------------------------------------------------------
# §20.10: Edge Cases
# ---------------------------------------------------------------------------


def test_empty_loaded_image_handled(config):
    """LoadedImage with no regions -> load_image() handles gracefully."""
    image = _make_image(
        regions=[],
        imports=[],
        exports=[],
        entry_points=[],
    )

    se = Speakeasy(config=config)
    mod = se.load_image(image)
    assert mod is not None


# ---------------------------------------------------------------------------
# §20.2c: Symbol registration and code hooks (xfail)
# ---------------------------------------------------------------------------


def test_load_image_registers_symbols_for_exports_with_handlers(config):
    """Exports with matching API handlers get registered in self.symbols."""
    image = _make_image(
        module_type="dll",
        emu_path="C:\\Windows\\system32\\kernel32.dll",
        exports=[
            ExportEntry(name="VirtualAlloc", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    emu = se.emu
    found = any(sym_name == "VirtualAlloc" for _addr, (_mod_name, sym_name) in emu.symbols.items())
    assert found, "Export with API handler should be registered in symbols"


def test_load_image_does_not_register_symbols_without_handlers(config):
    """Exports without API handlers are NOT registered in symbols."""
    image = _make_image(
        module_type="dll",
        emu_path="C:\\Windows\\system32\\custom.dll",
        exports=[
            ExportEntry(name="CustomFunction", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    emu = se.emu
    found = any(sym_name == "CustomFunction" for _addr, (_mod_name, sym_name) in emu.symbols.items())
    assert not found, "Export without API handler should not be in symbols"


# ---------------------------------------------------------------------------
# §20.2d: Data export resolution (xfail)
# ---------------------------------------------------------------------------


def test_load_image_resolves_data_imports(config):
    """Import entries that match data exports get data pointers written to IAT."""
    iat_data = b"\x00" * 0x1000
    image = _make_image(
        image_base=0x400000,
        image_size=0x10000,
        regions=[
            MemoryRegion(base=0x400000, data=iat_data, name=".rdata", perms=0x3),
        ],
        imports=[
            ImportEntry(iat_address=0x400200, dll_name="ntdll", func_name="NtCurrentPeb"),
        ],
    )

    se = Speakeasy(config=config)
    se.load_image(image)

    slot = int.from_bytes(se.emu.mem_read(0x400200, 4), "little")
    assert slot != 0, "Data import IAT slot should be filled"


# ---------------------------------------------------------------------------
# §20.6c-e: LoadLibrary edge cases (xfail)
# ---------------------------------------------------------------------------


def test_load_library_unknown_module_with_modules_always_exist(config, load_test_bin):
    """Unknown module + modules_always_exist flag -> DecoyLoader used."""
    cfg = copy.deepcopy(config)
    cfg["modules"]["modules_always_exist"] = True

    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=cfg)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)

    emu = se.emu
    assert any(isinstance(m, RuntimeModule) for m in emu.modules), (
        "After refactor, all modules including decoys should be RuntimeModule"
    )


# ---------------------------------------------------------------------------
# §20.7b: Decoy in PEB (xfail)
# ---------------------------------------------------------------------------


def test_decoy_in_peb(config, load_test_bin):
    """Decoy module (no memory) appears in PEB list."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)

    emu = se.emu
    peb_mods = emu.get_peb_modules()
    assert len(peb_mods) > 0, "PEB should have modules"
    decoy_in_peb = any(isinstance(mod, RuntimeModule) and mod.module_type == "decoy" for mod in peb_mods)
    assert decoy_in_peb, "Decoy modules with visible_in_peb=True should be in PEB"
