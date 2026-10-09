"""Warm loader transactions must restore ownership without disturbing survivors."""

from types import SimpleNamespace

import pytest

from speakeasy import Speakeasy
from speakeasy.errors import WindowsEmuError
from speakeasy.windows.loaders import ApiModuleLoader, ExportEntry, ImportEntry, LoadedImage, MemoryRegion
from tests.test_peb_module_links import assert_process_rings


@pytest.fixture(params=["x86", "amd64"])
def warm_emu(request, config):
    config["max_instructions"] = 1
    se = Speakeasy(config=config)
    try:
        address = se.load_shellcode(data=b"\x90\x90", arch=request.param)
        se.run_shellcode(address)
        yield se.emu
    finally:
        se.shutdown()


def guest_image(emu, name, base):
    return LoadedImage(
        arch=emu.get_arch(),
        module_type="dll",
        name=name,
        emu_path=rf"C:\test\{name}.dll",
        image_base=base,
        image_size=0x5000,
        regions=[
            MemoryRegion(base, b"MZ" + b"\0" * 0xFE, ".headers", 3),
            MemoryRegion(base + 0x1000, b"\xc3", ".text", 5),
        ],
        imports=[],
        exports=[ExportEntry("GuestStep", base + 0x1000, 1, "guest")],
        default_export_mode="guest",
        entry_points=[],
    )


def snapshot(emu):
    proc = emu.get_current_process()
    registry = emu.api_registry
    return {
        "modules": list(emu.modules),
        "entries": list(proc.ldr_entries),
        "peb_modules": dict(proc._peb_modules),
        "entry_bytes": {entry.address: emu.mem_read(entry.address, entry.sizeof()) for entry in proc.ldr_entries},
        "ldr": emu.mem_read(proc.peb_ldr_data.address, proc.peb_ldr_data.sizeof()),
        "registry": dict(registry.entries),
        "traps": dict(registry.traps),
        "names": {key: dict(value) for key, value in registry.names.items()},
        "ordinals": {key: dict(value) for key, value in registry.ordinals.items()},
        "dynamic": dict(registry.dynamic_offsets),
        "addresses": list(registry._addresses),
        "bindings": dict(emu._import_bindings),
        "module_maps": [
            (id(mapping), mapping.base, mapping.size)
            for mapping in emu.maps
            if (mapping.tag or "").startswith("emu.module.")
        ],
        "shared": set(emu._shared_peb_modules),
        "dependencies": list(emu._guest_dependencies),
        "public_bytes": {
            entry.address: emu.mem_read(entry.address, 2)
            for entry in registry.entries.values()
            if entry.trap is not None
        },
    }


def assert_image_unmapped(emu, base, size):
    for offset in (0, 0x1000, size - 1):
        assert emu.get_address_map(base + offset) is None
    # Verify the native engine as well as the memory manager's ownership table.
    assert not any(start < base + size and end >= base for start, end, _ in emu.get_mem_regions())


def assert_restored(emu, before, removed=()):
    assert snapshot(emu) == before
    registry = emu.api_registry
    assert getattr(emu, "_load_depth", 0) == 0
    assert_process_rings(emu.get_current_process())
    for module in removed:
        assert module not in emu.modules
        assert module.base not in emu.get_current_process()._peb_modules
        assert id(module) not in registry.names
        assert id(module) not in registry.ordinals
        assert id(module) not in registry.dynamic_offsets
        assert all(entry.module is not module for entry in registry.entries.values())
        assert all(entry.module is not module for entry in registry.traps.values())
        assert_image_unmapped(emu, module.base, module.image_size)
        assert not any(module.base <= slot < module.base + module.image_size for slot in emu._import_bindings)


def install_dependency_graph(emu, monkeypatch):
    dep_base, _ = emu.get_valid_ranges(0x20000, addr=0x65000000)
    api = SimpleNamespace(funcs={"SyntheticStep": ("SyntheticStep", None, 0, "stdcall", None)}, data={})
    synthetic = ApiModuleLoader(
        name="rollback_synthetic",
        api=api,
        arch=emu.get_arch(),
        base=dep_base,
        emu_path=r"C:\test\rollback_synthetic.dll",
    ).make_image()
    guest_base, _ = emu.get_valid_ranges(0x5000, addr=0x66000000)
    dependency = guest_image(emu, "rollback_guest", guest_base)
    dependency.imports = [ImportEntry(guest_base + 0x2000, synthetic.name, "SyntheticStep")]
    root_base, _ = emu.get_valid_ranges(0x5000, addr=0x67000000)
    root = guest_image(emu, "rollback_importer", root_base)
    root.imports = [ImportEntry(root_base + 0x2000, dependency.name, "GuestStep")]
    images = {image.name: image for image in (synthetic, dependency)}
    loaded = []
    original = emu.load_module_by_name

    def load(name, *args, **kwargs):
        if name not in images:
            return original(name, *args, **kwargs)
        existing = emu.get_mod_by_name(name)
        if existing is not None:
            return existing
        module = emu.load_image(images[name])
        loaded.append(module)
        return module

    monkeypatch.setattr(emu, "load_module_by_name", load)
    return root, loaded


def test_warm_malformed_image_preserves_existing_ownership(warm_emu):
    emu = warm_emu
    before = snapshot(emu)
    base, _ = emu.get_valid_ranges(0x5000, addr=0x67000000)
    image = guest_image(emu, "rollback_malformed", base)
    image.regions.append(MemoryRegion(base + image.image_size - 1, b"xx", ".bad", 3))
    with pytest.raises(WindowsEmuError, match="outside its image span"):
        emu.load_image(image)
    assert_restored(emu, before)
    assert_image_unmapped(emu, base, image.image_size)


def test_warm_missing_guest_import_rolls_back_loaded_dependency_graph(warm_emu, monkeypatch):
    emu = warm_emu
    emu.config = emu.config.model_copy(
        update={"modules": emu.config.modules.model_copy(update={"strict_pe_parsing": True})}
    )
    root, loaded = install_dependency_graph(emu, monkeypatch)
    root.imports.append(ImportEntry(root.image_base + 0x2000 + emu.get_ptr_size(), "rollback_guest", "StrictMissing"))
    before = snapshot(emu)
    observed_traps = []
    publications = []
    original = emu.resolve_export

    def resolve(module, reference, **kwargs):
        if module.name == "rollback_guest" and reference == "StrictMissing":
            assert len(loaded) == 2
            for dependency in loaded:
                assert dependency.base in emu.get_current_process()._peb_modules
            assert len(emu._import_bindings) >= len(before["bindings"]) + 2
            observed_traps.extend(set(emu.api_registry.traps) - set(before["traps"]))
            assert observed_traps
        return original(module, reference, **kwargs)

    monkeypatch.setattr(emu, "resolve_export", resolve)
    emu.module_change_listeners.append(lambda: publications.append(list(emu.modules)))
    with pytest.raises(WindowsEmuError, match="unresolved import rollback_guest!StrictMissing"):
        emu.load_image(root)
    assert publications == []
    assert_restored(emu, before, loaded)
    assert_image_unmapped(emu, root.image_base, root.image_size)
    assert all(trap not in emu.api_registry.traps for trap in observed_traps)
    # Failed graph trap tokens remain retired; a subsequent successful load gets fresh ones.
    replacement = emu.load_module_by_name("rollback_synthetic")
    traps = [entry.trap for entry in emu.api_registry.entries.values() if entry.module is replacement]
    assert traps and all(trap not in observed_traps for trap in traps)


def test_warm_initializer_exception_rolls_back_after_dependencies_attach(warm_emu, monkeypatch):
    emu = warm_emu
    root, loaded = install_dependency_graph(emu, monkeypatch)
    before = snapshot(emu)
    original = emu._initialize_api_data
    raised = []

    def initialize(entry):
        if len(loaded) == 2:
            assert all(module.base in emu.get_current_process()._peb_modules for module in loaded)
            raised.append(entry)
            raise RuntimeError("injected data initializer failure")
        return original(entry)

    monkeypatch.setattr(emu, "_initialize_api_data", initialize)
    with pytest.raises(RuntimeError, match="injected data initializer failure"):
        emu.load_image(root)
    assert raised
    assert_restored(emu, before, loaded)
    assert_image_unmapped(emu, root.image_base, root.image_size)


def test_warm_discard_cleans_module_owned_span_and_bindings(warm_emu):
    emu = warm_emu
    before = snapshot(emu)
    base, _ = emu.get_valid_ranges(0x20000, addr=0x68000000)
    api = SimpleNamespace(funcs={"DiscardStep": ("DiscardStep", None, 0, "stdcall", None)}, data={})
    image = ApiModuleLoader(
        name="rollback_discard", api=api, arch=emu.get_arch(), base=base, emu_path=r"C:\test\rollback_discard.dll"
    ).make_image()
    image.imports = [ImportEntry(base + image.image_size - emu.get_ptr_size(), "kernel32", "GetTickCount")]
    module = emu.load_image(image)
    owned_maps = [
        mapping for mapping in emu.maps if mapping.base < base + image.image_size and mapping.base + mapping.size > base
    ]
    assert len(owned_maps) == 1
    assert owned_maps[0].base == base
    assert owned_maps[0].size >= image.image_size
    entry = emu.api_registry.lookup(module, "DiscardStep")
    trap = entry.trap
    assert trap is not None
    assert module.base in emu.get_current_process()._peb_modules
    assert image.imports[0].iat_address in emu._import_bindings
    for offset in (0, image.image_size // 2, image.image_size - 1):
        assert emu.get_address_map(base + offset) is not None
    emu._discard_loaded_module(module)
    assert_restored(emu, before, [module])
    assert trap not in emu.api_registry.traps


def test_failed_graph_restores_new_attachment_of_cached_dependency(warm_emu):
    from speakeasy.windows.objman import Process

    emu = warm_emu
    emu.config = emu.config.model_copy(
        update={"modules": emu.config.modules.model_copy(update={"strict_pe_parsing": True})}
    )
    first = emu.get_current_process()
    base, _ = emu.get_valid_ranges(0x5000, addr=0x69000000)
    dependency = emu.load_image(guest_image(emu, "cached_guest_dependency", base))
    first_entries = list(first.ldr_entries)
    second = Process(emu, name="second")
    emu.processes.append(second)
    emu.alloc_peb(second)
    emu.set_current_process(second)
    before = snapshot(emu)
    base, _ = emu.get_valid_ranges(0x5000, addr=0x6A000000)
    root = guest_image(emu, "cached_dependency_importer", base)
    root.imports = [
        ImportEntry(base + 0x2000, dependency.name, "GuestStep"),
        ImportEntry(base + 0x2000 + emu.get_ptr_size(), dependency.name, "StrictMissing"),
    ]
    with pytest.raises(WindowsEmuError, match="unresolved import cached_guest_dependency!StrictMissing"):
        emu.load_image(root)
    assert_restored(emu, before)
    assert_image_unmapped(emu, root.image_base, root.image_size)
    assert dependency.base not in second._peb_modules
    assert first.ldr_entries == first_entries
    assert emu.get_mod_by_name(dependency.name) is dependency
    assert_process_rings(first)
