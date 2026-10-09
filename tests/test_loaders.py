import pefile
import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.windows.loaders import ApiModuleLoader, ExportEntry, LoadedImage, PeLoader, RuntimeModule


def _make_image(
    module_type: str = "dll",
    image_base: int = 0x400000,
    exports: list[ExportEntry] | None = None,
    emu_path: str = "C:\\Windows\\System32\\kernel32.dll",
) -> LoadedImage:
    return LoadedImage(
        arch=_arch.ARCH_X86,
        module_type=module_type,
        name="kernel32",
        emu_path=emu_path,
        image_base=image_base,
        image_size=0x10000,
        regions=[],
        imports=[],
        exports=exports or [],
        default_export_mode="intercepted",
        entry_points=[],
        visible_in_peb=True,
        tls_callbacks=[],
        sections=[],
    )


def test_runtime_module_export_lookup_and_base_name():
    exports = [
        ExportEntry(name="DllMain", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ExportEntry(name="Init", address=0x402000, ordinal=2, execution_mode="intercepted"),
    ]
    mod = RuntimeModule(_make_image(exports=exports))

    assert mod.get_base_name() == "kernel32.dll"
    found = mod.get_export_by_name("Init")
    assert found is not None
    assert found.address == 0x402000


def test_pe_loader_make_image_from_data(load_test_bin):
    loader = PeLoader(data=load_test_bin("dll_test_x86.dll.xz"))
    image = loader.make_image()

    assert image.arch == _arch.ARCH_X86
    assert image.module_type == "dll"
    assert image.image_size > 0
    assert len(image.imports) > 0
    assert len(image.exports) > 0
    assert len(image.sections) > 0


def test_api_module_loader_make_image():
    class FakeApiHandler:
        def __init__(self):
            self.funcs = {
                "CreateFileW": ("CreateFileW", None, 7, "stdcall", None),
                "CloseHandle": ("CloseHandle", None, 1, "stdcall", None),
            }
            self.data = {"GlobalCounter": 0x1234}

    loader = ApiModuleLoader(
        name="kernel32",
        api=FakeApiHandler(),
        arch=_arch.ARCH_X86,
        base=0x76000000,
        emu_path="C:\\Windows\\System32\\kernel32.dll",
    )
    image = loader.make_image()
    export_names = {exp.name for exp in image.exports if exp.name}

    assert image.module_type == "dll"
    assert image.name == "kernel32"
    assert image.image_base == 0x76000000
    assert len(image.exports) > 0
    assert "CreateFileW" in export_names or "CreateFileWA" in export_names
    assert "GlobalCounter" in export_names


def test_api_module_loader_sections_within_image():
    class FakeApiHandler:
        def __init__(self, count):
            self.funcs = {f"Func{i}": (f"Func{i}", None, 1, "stdcall", i) for i in range(count)}
            self.data = {}

    loader = ApiModuleLoader(
        name="kernel32",
        api=FakeApiHandler(200),
        arch=_arch.ARCH_X86,
        base=0x76000000,
        emu_path="C:\\Windows\\System32\\kernel32.dll",
    )
    image = loader.make_image()

    for section in image.sections:
        end = section.virtual_address + section.virtual_size
        assert end <= image.image_size


@pytest.mark.parametrize("filename", ["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"])
def test_native_rebase_header_imports_and_exports_are_consistent(filename, load_test_bin):
    raw = load_test_bin(filename)
    original = pefile.PE(data=raw)
    base = 0x60000000
    image = PeLoader(data=raw, base_override=base).make_image()
    assert image.image_base == base
    expected = pefile.PE(data=raw)
    expected.relocate_image(base)
    assert image.regions[0].data == expected.get_memory_mapped_image()
    assert [e.iat_address for e in image.imports] == [
        base + d.struct.FirstThunk + i * (image.arch // 8)
        for d in original.DIRECTORY_ENTRY_IMPORT
        for i, _ in enumerate(d.imports)
    ]
    assert [(e.address - base, e.ordinal) for e in image.exports] == [
        (e.address, e.ordinal) for e in original.DIRECTORY_ENTRY_EXPORT.symbols if e.address
    ]


def test_pma_0501_padded_sections_map_with_section_permissions(base_config):
    from pathlib import Path

    import unicorn as uc

    from speakeasy import Speakeasy

    path = Path(__file__).parent / "capa-testfiles" / "Practical Malware Analysis Lab 05-01.dll_"
    if not path.exists():
        pytest.skip("PMA malware fixture is unavailable")
    se = Speakeasy(config=base_config)
    try:
        module = se.load_module(str(path))

        def permissions(address):
            return next(p for start, end, p in se.emu.get_mem_regions() if start <= address <= end)

        for rva in (0x1656, 0x7025):
            assert permissions(module.base + rva) & uc.UC_PROT_EXEC
        data = next(s for s in module.sections if s.name == ".data")
        assert permissions(module.base + data.virtual_address) & uc.UC_PROT_WRITE
        assert not permissions(module.base + data.virtual_address) & uc.UC_PROT_EXEC
    finally:
        se.shutdown()
