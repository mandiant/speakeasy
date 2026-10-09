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
    assert "CreateFileW" in export_names
    assert "CreateFileWA" not in export_names
    assert "CreateFileWW" not in export_names
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


class StrictCatalog:
    def __init__(self, names=()):
        self.names = names
        self.calls = []

    def iter_functions(self, dll, arch):
        from types import SimpleNamespace

        self.calls.append((dll, arch))
        return iter(SimpleNamespace(name=name) for name in self.names)

    def lookup(self, *args):
        raise AssertionError("Surface enumeration must not use permissive lookup")


def test_metadata_only_module():
    db = StrictCatalog(["Unsupported", "NoHandler"])
    image = ApiModuleLoader(
        name="metadata", arch=_arch.ARCH_AMD64, base=0x180000000, emu_path="metadata.dll", signature_db=db
    ).make_image()
    assert db.calls == [("metadata", "x64")]
    assert {e.name for e in image.exports} == {"Unsupported", "NoHandler"}
    assert all(e.kind == "function" and e.visibility == "static" for e in image.exports)
    assert image.source == "synthetic"


def test_handler_metadata_union_no_indiscriminate_aliases():
    from types import SimpleNamespace

    api = SimpleNamespace(
        funcs={
            "CreateFile": ("CreateFile", None, 7, "stdcall", 30),
            "CreateFileW": ("CreateFileW", None, 7, "stdcall", None),
            "CloseHandle": ("CloseHandle", None, 1, "stdcall", 90),
        },
        data={"Counter": None},
    )
    db = StrictCatalog(["CreateFileA", "CreateFileW", "Unsupported"])
    image = ApiModuleLoader(
        name="fixture", api=api, arch=_arch.ARCH_X86, base=0x76000000, emu_path="fixture.dll", signature_db=db
    ).make_image()
    exports = {e.name: e for e in image.exports}
    assert set(exports) == {"CreateFile", "CreateFileA", "CreateFileW", "CloseHandle", "Counter", "Unsupported"}
    assert exports["CreateFile"].ordinal == 30
    assert exports["CloseHandle"].ordinal == 90
    assert exports["Counter"].kind == "data"
    assert db.calls == [("fixture", "x86")]


def test_decoy_is_valid_mapped_empty_pe():
    import pefile

    from speakeasy.windows.loaders import DecoyLoader
    from tests.test_api_image import image_bytes

    for arch in (_arch.ARCH_X86, _arch.ARCH_AMD64):
        loader = DecoyLoader(name="empty", base=0x60000000, emu_path="empty.dll", image_size=0x20000, arch=arch)
        image = loader.make_image()
        pe = pefile.PE(data=image_bytes(image))
        assert image.image_size >= 0x20000
        assert pe.OPTIONAL_HEADER.SizeOfImage == image.image_size
        assert image.arch == arch
        assert image.module_type == "decoy"
        assert image.source == "synthetic"
        assert image.exports == []
        assert image.loader is loader
    assert (
        DecoyLoader(name="x86", base=0x60000000, emu_path="x86.dll", image_size=0).make_image().arch == _arch.ARCH_X86
    )


def test_real_pe_guest_exports_preserve_forwarders_data_and_holes():
    from speakeasy.windows.api_image import ApiExportSpec, build_api_image
    from tests.test_api_image import image_bytes

    synthetic = build_api_image(
        name="guest",
        arch=_arch.ARCH_X86,
        base=0x60000000,
        emu_path="guest.dll",
        exports=[
            ApiExportSpec("Code", 10),
            ApiExportSpec("Data", 20, "data"),
            ApiExportSpec("Forward", 30, forwarder="other.#10"),
        ],
    )
    image = PeLoader(data=image_bytes(synthetic)).make_image()
    exports = {e.name: e for e in image.exports}
    assert set(exports) == {"Code", "Data", "Forward"}
    assert image.source == "guest_pe"
    assert image.default_export_mode == "guest"
    assert all(e.execution_mode == "guest" for e in image.exports)
    assert exports["Data"].kind == "data"
    assert exports["Code"].kind == "function"
    assert exports["Forward"].forwarder == "other.#10"


def test_shellcode_guest_source():
    from speakeasy.windows.loaders import ShellcodeLoader

    image = ShellcodeLoader(data=b"\xc3", arch=_arch.ARCH_X86).make_image()
    assert image.source == "guest_shellcode"


def test_api_loader_defaults_to_global_database(monkeypatch):
    from speakeasy.winenv.api import sigdb

    database = StrictCatalog(["GlobalCatalogEntry"])
    monkeypatch.setattr(sigdb, "get_default_database", lambda: database)
    image = ApiModuleLoader(name="fixture", arch=_arch.ARCH_X86, base=0x60000000, emu_path="fixture.dll").make_image()
    assert [entry.name for entry in image.exports] == ["GlobalCatalogEntry"]
    assert database.calls == [("fixture", "x86")]


def test_explicit_native_and_ordinal_only_handler_exports():
    from types import SimpleNamespace

    nested = SimpleNamespace(funcs={"NtExample": ("NtExample", None, 0, "stdcall", 9)}, data={})
    api = SimpleNamespace(funcs={40: (None, None, 0, "stdcall", 40)}, data={}, _nt_handler=nested)
    image = ApiModuleLoader(
        name="ntdll", api=api, arch=_arch.ARCH_X86, base=0x60000000, emu_path="ntdll.dll", signature_db=StrictCatalog()
    ).make_image()
    assert {(entry.name, entry.ordinal) for entry in image.exports} == {("NtExample", 9), (None, 40)}


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("strict", [False, True])
def test_native_aliases_and_forwarders_preserve_pe_surface(architecture, strict):
    import pefile

    from speakeasy.windows.api_image import ApiExportSpec
    from tests.test_api_image import build, image_bytes

    raw = image_bytes(
        build(
            [
                ApiExportSpec("Alias", 10),
                ApiExportSpec("Original", 10),
                ApiExportSpec(None, 11),
                ApiExportSpec("Forward", 20, forwarder="target.dll.#12"),
            ],
            architecture,
        )
    )
    native = PeLoader(data=raw, strict=strict).make_image()
    independent = pefile.PE(data=raw)
    assert {(e.name, e.ordinal, e.address - native.image_base, e.forwarder) for e in native.exports} == {
        (s.name.decode() if s.name else None, s.ordinal, s.address, s.forwarder.decode() if s.forwarder else None)
        for s in independent.DIRECTORY_ENTRY_EXPORT.symbols
    }
    assert native.regions[0].data == independent.get_memory_mapped_image()
    assert all(e.execution_mode == "guest" for e in native.exports)


@pytest.mark.parametrize("size", [0, 1])
def test_native_section_metadata_covers_raw_bytes(size):
    import pefile

    from speakeasy.windows.api_image import ApiExportSpec
    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([ApiExportSpec("RawText")])))
    pe.sections[0].Misc_VirtualSize = size
    image = PeLoader(data=pe.write()).make_image()
    section = RuntimeModule(image).get_section_for_addr(image.exports[0].address)
    assert section.name == ".text"
    assert section.virtual_size == pe.sections[0].SizeOfRawData
    assert image.exports[0].kind == "function"


@pytest.mark.parametrize("forwarder", ["", "invalid", "target.#no", "target.#65536"])
def test_native_malformed_forwarder_rejected(forwarder):
    from speakeasy.windows.api_image import ApiExportSpec
    from tests.test_api_image import build, image_bytes

    image = build([ApiExportSpec("Forward", forwarder="target.Function")])
    raw = bytearray(image_bytes(image))
    rva = image.exports[0].address - image.image_base
    replacement = forwarder.encode() + b"\0"
    raw[rva : rva + len(replacement)] = replacement
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


def test_native_forwarder_terminator_must_be_inside_directory():
    import pefile

    from speakeasy.windows.api_image import ApiExportSpec
    from tests.test_api_image import build, image_bytes

    image = build([ApiExportSpec("Forward", forwarder="target.Function")])
    pe = pefile.PE(data=image_bytes(image))
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    directory.Size -= 1  # Its forwarder terminator remains readable, but outside the directory.
    with pytest.raises(ValueError, match="Unterminated forwarder"):
        PeLoader(data=pe.write(), strict=True).make_image()


@pytest.mark.parametrize("mutate", ["export", "directory", "machine"])
def test_native_malformed_export_bounds_and_machine_rejected(mutate):
    import struct

    import pefile

    from speakeasy.windows.api_image import ApiExportSpec
    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([ApiExportSpec("Code")])))
    if mutate == "directory":
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size = pe.OPTIONAL_HEADER.SizeOfImage
    elif mutate == "machine":
        pe.FILE_HEADER.Machine = 0x8664
    raw = bytearray(pe.write())
    if mutate == "export":
        eat = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions
        struct.pack_into("<I", raw, eat, pe.OPTIONAL_HEADER.SizeOfImage)
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


@pytest.mark.parametrize("strict", [False, True])
def test_native_no_relocation_rebase_rejected(strict):
    from tests.test_api_image import build, image_bytes

    with pytest.raises(ValueError, match="without valid relocation data"):
        PeLoader(data=image_bytes(build([])), strict=strict, base_override=0x60000000).make_image()


@pytest.mark.parametrize("filename", ["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"])
def test_native_rebase_header_imports_and_exports_are_consistent(filename, load_test_bin):
    import pefile

    raw = load_test_bin(filename)
    original = pefile.PE(data=raw)
    base = 0x60000000
    loader = PeLoader(data=raw, base_override=base)
    image = loader.make_image()
    assert image.image_base == base
    assert loader._pe_obj.OPTIONAL_HEADER.ImageBase == base
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


def test_explicit_handler_alias_keys_keep_names_and_ordinal_identity():
    from types import SimpleNamespace

    function = ("Original", None, 0, "stdcall", 20)
    api = SimpleNamespace(funcs={"Original": function, "Alias": function, 20: function}, data={})
    image = ApiModuleLoader(
        name="fixture",
        arch=_arch.ARCH_X86,
        base=0x60000000,
        emu_path="fixture.dll",
        api=api,
        signature_db=StrictCatalog(),
    ).make_image()
    assert {e.name for e in image.exports} == {"Original", "Alias"}
    assert {e.ordinal for e in image.exports} == {20}
    assert len({e.address for e in image.exports}) == 1


@pytest.mark.parametrize("strict", [False, True])
def test_native_section_cannot_extend_beyond_declared_image(strict):
    import pefile

    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([])))
    pe.sections[-1].Misc_VirtualSize = pe.OPTIONAL_HEADER.SizeOfImage
    with pytest.raises(ValueError, match="section extends beyond"):
        PeLoader(data=pe.write(), strict=strict).make_image()


def _make_delay_import_pe(architecture, *, attrs=1, with_relocations=False):
    import struct

    import pefile

    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([], architecture)))
    data = next(s.VirtualAddress for s in pe.sections if s.Name.startswith(b".data"))
    base = pe.OPTIONAL_HEADER.ImageBase
    width = architecture // 8
    raw = bytearray(pe.write())

    def pointer(rva):
        return base + rva if attrs == 0 and architecture == _arch.ARCH_X86 else rva

    def thunks(rva, values):
        for i, value in enumerate(values):
            struct.pack_into("<I" if width == 4 else "<Q", raw, rva + i * width, value)

    raw[data + 0x100 : data + 0x111] = b"DelayTarget.dll\0\0"
    raw[data + 0x120 : data + 0x132] = b"NormalTarget.dll\0\0"
    raw[data + 0x140 : data + 0x149] = b"\0\0ByName\0"
    raw[data + 0x160 : data + 0x169] = b"\0\0Normal\0"
    thunks(data + 0x200, [pointer(data + 0x140), (1 << (architecture - 1)) | 17, 0])
    thunks(data + 0x240, [0x12345678, 0x76543210, 0])
    thunks(data + 0x300, [data + 0x160, 0])
    thunks(data + 0x340, [0x23456789, 0])
    struct.pack_into(
        "<8I",
        raw,
        data,
        attrs,
        pointer(data + 0x100),
        pointer(data + 0x180),
        pointer(data + 0x240),
        pointer(data + 0x200),
        0,
        0,
        0x12345678,
    )
    struct.pack_into("<5I", raw, data + 0x40, data + 0x300, 0, 0, data + 0x120, data + 0x340)
    pe = pefile.PE(data=bytes(raw))
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = data
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = 64
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = data + 0x40
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = 40
    if with_relocations:
        # An ABSOLUTE relocation block allows a base change without changing
        # this RVA-only fixture's thunks or intentionally bound IAT values.
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = data + 0x380
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = 12
        raw = bytearray(pe.write())
        struct.pack_into("<IIHH", raw, data + 0x380, data, 12, 0, 0)
        return bytes(raw), data
    return pe.write(), data


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("strict", [False, True])
def test_eager_delay_imports_join_static_inventory_without_mutating_iat(architecture, strict):
    import struct

    raw, data = _make_delay_import_pe(architecture)
    image = PeLoader(data=raw, strict=strict).make_image()
    assert [(e.dll_name, e.func_name, e.source) for e in image.imports] == [
        ("NormalTarget", "Normal", "static"),
        ("DelayTarget", "ByName", "delay"),
        ("DelayTarget", "ordinal_17", "delay"),
    ]
    width = architecture // 8
    assert [e.iat_address - image.image_base for e in image.imports] == [
        data + 0x340,
        data + 0x240,
        data + 0x240 + width,
    ]
    mapped = image.regions[0].data
    for rva in (data + 0x240, data + 0x340):
        assert mapped[rva : rva + width * 2] == raw[rva : rva + width * 2]
    assert struct.unpack_from("<I" if width == 4 else "<Q", mapped, data + 0x240)[0] == 0x12345678


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("strict", [False, True])
def test_delay_import_rvas_rebase_without_using_stale_pefile_symbol_addresses(architecture, strict):
    raw, data = _make_delay_import_pe(architecture, with_relocations=True)
    image = PeLoader(data=raw, strict=strict, base_override=0x60000000).make_image()
    delayed = [e for e in image.imports if e.source == "delay"]
    assert [e.iat_address for e in delayed] == [
        0x60000000 + data + 0x240,
        0x60000000 + data + 0x240 + architecture // 8,
    ]


def test_legacy_x86_va_delay_imports_keep_native_descriptor_bytes():
    raw, data = _make_delay_import_pe(_arch.ARCH_X86, attrs=0)
    image = PeLoader(data=raw).make_image()
    assert [(e.func_name, e.iat_address - image.image_base) for e in image.imports if e.source == "delay"] == [
        ("ByName", data + 0x240),
        ("ordinal_17", data + 0x244),
    ]
    assert image.regions[0].data == raw


@pytest.mark.parametrize("mutate", ["iat", "iat_tail", "name", "int", "attrs", "directory", "dll"])
def test_malformed_delay_imports_rejected(mutate):
    import struct

    import pefile

    raw, data = _make_delay_import_pe(_arch.ARCH_X86)
    pe = pefile.PE(data=raw)
    if mutate == "directory":
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = pe.OPTIONAL_HEADER.SizeOfImage
        raw = pe.write()
    raw = bytearray(raw)
    if mutate in ("iat", "name", "int"):
        offset = {"iat": 12, "name": 4, "int": 16}[mutate]
        struct.pack_into("<I", raw, data + offset, pe.OPTIONAL_HEADER.SizeOfImage)
    elif mutate == "iat_tail":
        struct.pack_into("<I", raw, data + 12, pe.OPTIONAL_HEADER.SizeOfImage - 4)
    elif mutate == "attrs":
        struct.pack_into("<I", raw, data, 3)
    elif mutate == "dll":
        raw[data + 0x100] = ord("*")
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


def test_x64_delay_descriptor_requires_rva_attributes():
    raw, _ = _make_delay_import_pe(_arch.ARCH_AMD64, attrs=0)
    with pytest.raises(ValueError, match="architecture"):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("virtual_size", [0, 0x800])
def test_native_raw_padding_outside_image_is_clipped(virtual_size):
    import pefile

    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([])))
    last = pe.sections[-1]
    last.Misc_VirtualSize = virtual_size
    pe.OPTIONAL_HEADER.SizeOfImage = last.VirtualAddress + 0x800
    raw = pe.write()
    assert len(pefile.PE(data=raw).get_memory_mapped_image()) > pe.OPTIONAL_HEADER.SizeOfImage
    image = PeLoader(data=raw).make_image()
    assert image.sections[-1].virtual_size == 0x800
    assert len(image.regions[0].data) <= image.image_size
    assert all(s.virtual_address + s.virtual_size <= image.image_size for s in image.sections)
    assert image.regions[0].data == pefile.PE(data=raw).get_memory_mapped_image()[: image.image_size]


def test_native_zero_virtual_section_entirely_outside_image_is_not_mapped():
    import pefile

    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([])))
    last = pe.sections[-1]
    last.Misc_VirtualSize = 0
    pe.OPTIONAL_HEADER.SizeOfImage = last.VirtualAddress
    image = PeLoader(data=pe.write()).make_image()
    assert all(s.name != ".dyn" for s in image.sections)
    assert len(image.regions[0].data) <= image.image_size


def test_pma_0501_section_padding_does_not_prevent_loading():
    from pathlib import Path

    import pefile

    path = Path(__file__).parent / "capa-testfiles" / "Practical Malware Analysis Lab 05-01.dll_"
    if not path.exists():
        pytest.skip("PMA malware fixture is unavailable")
    pe = pefile.PE(data=path.read_bytes())
    assert any(s.VirtualAddress + s.SizeOfRawData > pe.OPTIONAL_HEADER.SizeOfImage for s in pe.sections)
    image = PeLoader(path=str(path)).make_image()
    assert image.image_size == pe.OPTIONAL_HEADER.SizeOfImage
    assert image.imports
    assert image.exports
    assert all(s.virtual_address + s.virtual_size <= image.image_size for s in image.sections)
    assert len(image.regions[0].data) <= image.image_size
    reloc = next(s for s in image.sections if s.name == ".reloc")
    assert reloc.virtual_address + reloc.virtual_size == image.image_size


@pytest.mark.parametrize("architecture,eligible", [(_arch.ARCH_X86, "Only32"), (_arch.ARCH_AMD64, "Only64")])
def test_api_loader_consumes_strict_architecture_catalog_without_lookup_reuse(tmp_path, architecture, eligible):
    from speakeasy.winenv.api.sigdb import SignatureDatabase
    from tests.test_export_catalog import _source

    source = _source(
        tmp_path,
        {
            "Only32": [{"dll": "kernel32", "arch": ["x86"]}],
            "Only64": [{"dll": "kernel32", "arch": ["x64"]}],
            "Unsupported": [{"dll": "kernel32", "skip": "unsupported ABI"}],
            "Foreign": [{"dll": "user32"}],
            "K32Example": [{"dll": "kernel32"}],
        },
    )
    database = SignatureDatabase([source])
    image = ApiModuleLoader(
        name="kernel32", arch=architecture, base=0x60000000, emu_path="kernel32.dll", signature_db=database
    ).make_image()
    assert {e.name for e in image.exports} == {eligible, "Unsupported", "K32Example"}
    # Neither an advisory DLL alias nor permissive ABI reuse adds physical exports.
    foreign = ApiModuleLoader(
        name="psapi", arch=architecture, base=0x60000000, emu_path="psapi.dll", signature_db=database
    ).make_image()
    assert foreign.exports == []


def test_guest_physical_exports_never_expand_from_catalog(monkeypatch):
    from speakeasy.windows.api_image import ApiExportSpec
    from speakeasy.winenv.api import sigdb
    from tests.test_api_image import build, image_bytes

    def unexpected_catalog_access():
        raise AssertionError("Guest physical exports must not access the synthetic catalog")

    monkeypatch.setattr(sigdb, "get_default_database", unexpected_catalog_access)
    raw = image_bytes(build([ApiExportSpec("OnlyGuest", 100), ApiExportSpec("Forward", 104, forwarder="target.#12")]))
    image = PeLoader(data=raw, emu_path="C:\\Windows\\System32\\kernel32.dll").make_image()
    assert {(e.name, e.ordinal) for e in image.exports} == {("OnlyGuest", 100), ("Forward", 104)}
    assert image.source == "guest_pe"
    assert all(e.execution_mode == "guest" for e in image.exports)


def test_rebased_legacy_delay_import_descriptors_keep_relocated_virtual_addresses():
    import struct

    import pefile

    raw, data = _make_delay_import_pe(_arch.ARCH_X86, attrs=0)
    pe = pefile.PE(data=raw)
    directory_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].get_file_offset()
    raw = bytearray(raw)
    struct.pack_into("<II", raw, directory_offset, data + 0x380, 20)
    struct.pack_into("<II6H", raw, data + 0x380, data, 20, 0x3004, 0x3008, 0x300C, 0x3010, 0x3200, 0)
    image = PeLoader(data=bytes(raw), base_override=0x60000000).make_image()
    assert [(e.func_name, e.iat_address) for e in image.imports if e.source == "delay"] == [
        ("ByName", 0x60000000 + data + 0x240),
        ("ordinal_17", 0x60000000 + data + 0x244),
    ]
    fields = struct.unpack_from("<8I", image.regions[0].data, data)
    assert fields[1] == 0x60000000 + data + 0x100
    assert fields[3] == 0x60000000 + data + 0x240
    assert fields[4] == 0x60000000 + data + 0x200
    assert struct.unpack_from("<I", image.regions[0].data, data + 0x200)[0] == 0x60000000 + data + 0x140


def test_pma_0501_text_pages_remain_executable_after_contiguous_mapping(base_config):
    from pathlib import Path

    import unicorn as uc

    import speakeasy.common as common
    from speakeasy import Speakeasy

    path = Path(__file__).parent / "capa-testfiles" / "Practical Malware Analysis Lab 05-01.dll_"
    if not path.exists():
        pytest.skip("PMA malware fixture is unavailable")
    se = Speakeasy(config=base_config)
    try:
        module = se.load_module(str(path))
        emu = se.emu
        for rva, instruction_size in ((0x1656, 6), (0x7025, 10)):
            address = module.base + rva
            section = module.get_section_for_addr(address)
            assert section.name == ".text"
            assert section.perms & common.PERM_MEM_EXEC
            permissions = next(p for start, end, p in emu.get_mem_regions() if start <= address <= end)
            assert permissions & uc.UC_PROT_EXEC
            # Execute the reported faulting instruction directly. Both are
            # ordinary guest instructions; neither calls a synthetic API.
            emu.emu_eng.start(address, count=1)
            assert emu.get_pc() == address + instruction_size
        data = next(s for s in module.sections if s.name == ".data")
        permissions = next(
            p for start, end, p in emu.get_mem_regions() if start <= module.base + data.virtual_address <= end
        )
        assert permissions & uc.UC_PROT_WRITE
        assert not permissions & uc.UC_PROT_EXEC
    finally:
        se.shutdown()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("mutate", ["outside_image", "junk_attributes"])
def test_lenient_bad_delay_directory_preserves_static_imports(architecture, mutate, caplog):
    import struct

    import pefile

    raw, data = _make_delay_import_pe(architecture)
    pe = pefile.PE(data=raw)
    if mutate == "outside_image":
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = pe.OPTIONAL_HEADER.SizeOfImage
        raw = pe.write()
    else:
        raw = bytearray(raw)
        struct.pack_into("<I", raw, data, 3)
        raw = bytes(raw)
    image = PeLoader(data=raw).make_image()
    assert [(e.dll_name, e.func_name, e.source) for e in image.imports] == [("NormalTarget", "Normal", "static")]
    assert image.imports[0].iat_address == image.image_base + data + 0x340
    assert image.regions[0].data == pefile.PE(data=raw).get_memory_mapped_image()[: image.image_size]
    assert "Skipping malformed PE delay import directory" in caplog.text
    with pytest.raises(ValueError):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
def test_lenient_export_directory_outside_image_preserves_imports(architecture, caplog):
    import pefile

    raw, data = _make_delay_import_pe(architecture)
    pe = pefile.PE(data=raw)
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress = pe.OPTIONAL_HEADER.SizeOfImage
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size = 40
    raw = pe.write()
    image = PeLoader(data=raw).make_image()
    assert image.exports == []
    assert [(e.dll_name, e.func_name, e.source) for e in image.imports] == [
        ("NormalTarget", "Normal", "static"),
        ("DelayTarget", "ByName", "delay"),
        ("DelayTarget", "ordinal_17", "delay"),
    ]
    assert "Skipping malformed PE export directory" in caplog.text
    with pytest.raises(ValueError, match="Export directory"):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("source", ["static", "delay"])
def test_lenient_non_ascii_dll_name_is_lossless(architecture, source, caplog):
    raw, data = _make_delay_import_pe(architecture)
    raw = bytearray(raw)
    offset = data + (0x120 if source == "static" else 0x100)
    raw[offset] = 0xE9  # Not valid UTF-8; preserve this byte with Latin-1.
    image = PeLoader(data=bytes(raw)).make_image()
    expected_dll = "éormalTarget" if source == "static" else "éelayTarget"
    selected = [e for e in image.imports if e.source == source]
    assert selected
    assert all(e.dll_name == expected_dll for e in selected)
    assert (selected[0].dll_name + ".dll").encode("latin-1") == bytes(raw[offset : raw.index(0, offset)])
    assert len(image.imports) == 3
    assert "Non-ASCII imported DLL name decoded as Latin-1" in caplog.text
    with pytest.raises(UnicodeDecodeError):
        PeLoader(data=bytes(raw), strict=True).make_image()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("mutate", ["target", "forwarder", "terminator", "directory"])
def test_lenient_malformed_exports_preserve_valid_entries(architecture, mutate, caplog):
    import struct

    import pefile

    from speakeasy.windows.api_image import ApiExportSpec
    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(
        data=image_bytes(
            build(
                [
                    ApiExportSpec("Valid", 10),
                    ApiExportSpec("Bad", 11, forwarder="target.Function"),
                ],
                architecture,
            )
        )
    )
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    if mutate == "directory":
        directory.Size = pe.OPTIONAL_HEADER.SizeOfImage
    elif mutate == "terminator":
        directory.Size -= 1
    raw = bytearray(pe.write())
    bad = next(e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name == b"Bad")
    if mutate == "target":
        eat = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions
        struct.pack_into("<I", raw, eat + 4, pe.OPTIONAL_HEADER.SizeOfImage)
    elif mutate == "forwarder":
        raw[bad.address : bad.address + 8] = b"invalid\0"
    image = PeLoader(data=bytes(raw)).make_image()
    assert [e.name for e in image.exports] == ([] if mutate == "directory" else ["Valid"])
    assert "Skipping malformed PE export" in caplog.text
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("mutate", ["iat", "dll", "non_ascii_invalid_dll"])
def test_lenient_bad_static_import_preserves_delay_inventory(architecture, mutate, caplog):
    import struct

    import pefile

    raw, data = _make_delay_import_pe(architecture)
    raw = bytearray(raw)
    pe = pefile.PE(data=bytes(raw))
    if mutate == "iat":
        struct.pack_into("<I", raw, data + 0x50, pe.OPTIONAL_HEADER.SizeOfImage)
    else:
        raw[data + 0x120] = ord("*")
        if mutate == "non_ascii_invalid_dll":
            raw[data + 0x121] = 0xE9
    image = PeLoader(data=bytes(raw)).make_image()
    assert [(e.dll_name, e.func_name, e.source) for e in image.imports] == [
        ("DelayTarget", "ByName", "delay"),
        ("DelayTarget", "ordinal_17", "delay"),
    ]
    assert "Skipping malformed PE static import" in caplog.text
    assert all(image.image_base <= e.iat_address < image.image_base + image.image_size for e in image.imports)
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("mutate", ["machine", "address_space", "headers", "base", "rebased_address_space"])
def test_loader_safety_checks_are_mandatory(strict, mutate):
    import pefile

    from tests.test_api_image import build, image_bytes

    pe = pefile.PE(data=image_bytes(build([])))
    base_override = None
    if mutate == "machine":
        pe.FILE_HEADER.Machine = 0x8664
    elif mutate == "address_space":
        pe.OPTIONAL_HEADER.ImageBase = 0xFFFFF000
    elif mutate == "headers":
        pe.OPTIONAL_HEADER.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfImage + 1
    elif mutate == "base":
        base_override = -1
    else:
        base_override = 0xFFFFF000
    with pytest.raises(ValueError):
        PeLoader(data=pe.write(), base_override=base_override, strict=strict).make_image()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("directory_index", [0, 13])
def test_lenient_unreadable_optional_directory_preserves_static_imports(architecture, directory_index, caplog):
    import pefile

    raw, _ = _make_delay_import_pe(architecture)
    pe = pefile.PE(data=raw)
    # A virtual gap is in the image's address space but has no file backing.
    pe.OPTIONAL_HEADER.SizeOfImage += 0x2000
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    directory.VirtualAddress = pe.OPTIONAL_HEADER.SizeOfImage - 0x1000
    directory.Size = 64
    image = PeLoader(data=pe.write()).make_image()
    assert any(e.dll_name == "NormalTarget" and e.source == "static" for e in image.imports)
    if directory_index == 13:
        assert all(e.source == "static" for e in image.imports)
        assert "Skipping malformed PE delay import directory" in caplog.text
    else:
        assert image.exports == []
        assert "Skipping malformed PE export directory" in caplog.text
    with pytest.raises((ValueError, pefile.PEFormatError)):
        PeLoader(data=pe.write(), strict=True).make_image()


@pytest.mark.parametrize("architecture", [_arch.ARCH_X86, _arch.ARCH_AMD64])
@pytest.mark.parametrize("mode", ["user", "kernel", "dependency"])
@pytest.mark.parametrize("strict", [None, False, True], ids=["default", "lenient", "strict"])
def test_guest_loader_config_controls_optional_parsing(architecture, mode, strict, config, tmp_path):
    import pefile

    from speakeasy import Speakeasy
    from tests.test_api_image import build, image_bytes

    if strict is not None:
        config.setdefault("modules", {})["strict_pe_parsing"] = strict
    pe = pefile.PE(data=image_bytes(build([], architecture)))
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = pe.OPTIONAL_HEADER.SizeOfImage
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = 64
    if mode == "kernel":
        pe.OPTIONAL_HEADER.Subsystem = 1  # IMAGE_SUBSYSTEM_NATIVE
    malformed = pe.write()
    se = Speakeasy(config=config)
    try:
        if mode == "dependency":
            se.load_module(data=image_bytes(build([], architecture, base=0x400000)))
            path = tmp_path / "malformed_dependency.dll"
            path.write_bytes(malformed)

            def load():
                return se.emu.load_module_by_name(
                    "malformed_dependency", native_path=str(path), base=pe.OPTIONAL_HEADER.ImageBase
                )
        else:

            def load():
                return se.load_module(data=malformed)

        if strict:
            with pytest.raises(ValueError, match="Delay import directory"):
                load()
        else:
            module = load()
            assert module._image.source == "guest_pe"
            assert module._image.imports == []
            assert module.loader._strict is False
        assert se.emu.config.modules.strict_pe_parsing is (strict is True)
        if mode == "kernel":
            assert se.emu.kernel_mode
    finally:
        se.shutdown()
