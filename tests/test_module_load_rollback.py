"""Failed module loads leave existing modules, addresses and process loader lists unchanged."""

import pytest

from speakeasy import Speakeasy
from speakeasy.errors import WindowsEmuError
from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from speakeasy.windows.loaders import ExportEntry, ImportEntry, LoadedImage, MemoryRegion
from tests.test_peb_module_links import assert_process_rings


@pytest.fixture
def warm_emu(config):
    config["max_instructions"] = 1
    se = Speakeasy(config=config)
    try:
        address = se.load_shellcode(data=b"\x90\x90", arch="x86")
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


def assert_image_unmapped(emu, base, size):
    for offset in (0, 0x1000, size - 1):
        assert emu.get_address_map(base + offset) is None
    assert not any(start < base + size and end >= base for start, end, _ in emu.get_mem_regions())


def loader_bases(process):
    return [entry.object.DllBase for entry in process.ldr_entries]


def write_guest_dll(emu, path, base):
    image = build_api_image(
        name=path.stem, arch=emu.arch, base=base, emu_path=path.name, exports=[ApiExportSpec("GuestStep")]
    )
    data = bytearray(image.image_size)
    for region in image.regions:
        data[region.base - base : region.base - base + len(region.data)] = region.data
    path.write_bytes(bytes(data))
    return image


def test_image_region_outside_span_is_rejected_without_mapping(warm_emu):
    emu = warm_emu
    survivor = emu.get_proc("kernel32", "GetTickCount")
    modules = list(emu.modules)
    base, _ = emu.get_valid_ranges(0x5000, addr=0x67000000)
    image = guest_image(emu, "rollback_malformed", base)
    image.regions.append(MemoryRegion(base + image.image_size - 1, b"xx", ".bad", 3))

    with pytest.raises(WindowsEmuError, match="outside its image span"):
        emu.load_image(image)

    assert emu.modules == modules
    assert_image_unmapped(emu, base, image.image_size)
    assert emu.get_proc("kernel32", "GetTickCount") == survivor


def test_strict_import_failure_rolls_back_whole_load_graph(warm_emu, tmp_path):
    emu = warm_emu
    emu.config = emu.config.model_copy(
        update={
            "modules": emu.config.modules.model_copy(
                update={"strict_pe_parsing": True, "module_directory_x86": str(tmp_path)}
            )
        }
    )
    process = emu.get_current_process()
    base, _ = emu.get_valid_ranges(0x5000, addr=0x69000000)
    cached = emu.load_image(guest_image(emu, "cached_guest_dependency", base))
    cached_step = emu.get_proc(cached.name, "GuestStep")
    survivor = emu.get_proc("kernel32", "GetTickCount")
    new_base, _ = emu.get_valid_ranges(0x20000, addr=0x6C000000)
    new_image = write_guest_dll(emu, tmp_path / "new_guest_dependency.dll", new_base)
    bases = loader_bases(process)
    modules = list(emu.modules)
    published = []
    emu.module_change_listeners.append(lambda: published.append(list(emu.modules)))

    root_base, _ = emu.get_valid_ranges(0x5000, addr=0x6A000000)
    root = guest_image(emu, "dependency_importer", root_base)
    ptr = emu.get_ptr_size()
    root.imports = [
        ImportEntry(root_base + 0x2000, cached.name, "GuestStep"),
        ImportEntry(root_base + 0x2000 + ptr, "new_guest_dependency", "GuestStep"),
        ImportEntry(root_base + 0x2000 + 2 * ptr, cached.name, "StrictMissing"),
    ]
    with pytest.raises(WindowsEmuError, match="unresolved import cached_guest_dependency!StrictMissing"):
        emu.load_image(root)

    assert published == []
    assert emu.modules == modules
    assert emu.get_mod_by_name("new_guest_dependency") is None
    assert_image_unmapped(emu, root_base, root.image_size)
    assert_image_unmapped(emu, new_base, new_image.image_size)
    assert loader_bases(process) == bases
    assert emu.get_mod_by_name(cached.name) is cached
    assert emu.get_proc(cached.name, "GuestStep") == cached_step
    assert emu.get_proc("kernel32", "GetTickCount") == survivor
    assert_process_rings(process)


def test_listener_failure_does_not_interrupt_load_or_other_listeners(warm_emu):
    emu = warm_emu
    base, _ = emu.get_valid_ranges(0x5000, addr=0x6B000000)
    observed = []

    def broken():
        observed.append("broken")
        raise RuntimeError("observer failure")

    def healthy():
        observed.append(emu.get_mod_by_name("listener_guest"))

    emu.module_change_listeners.extend([broken, healthy])
    module = emu.load_image(guest_image(emu, "listener_guest", base))

    assert observed == ["broken", module]
    assert emu.get_proc("listener_guest", "GuestStep") == base + 0x1000
    assert base in [entry.object.DllBase for entry in emu.get_current_process().ldr_entries]
