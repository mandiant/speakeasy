import logging
import struct
from types import SimpleNamespace

import pefile
import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.windows.api_image import ApiExportSpec
from speakeasy.windows.loaders import ApiModuleLoader, ExportEntry, LoadedImage, PeLoader, RuntimeModule
from tests.test_api_image import build, image_bytes


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


def _warned(caplog):
    return any(record.levelno == logging.WARNING for record in caplog.records)


@pytest.mark.parametrize("architecture,eligible", [(_arch.ARCH_X86, "Only32"), (_arch.ARCH_AMD64, "Only64")])
def test_api_loader_combines_catalog_and_handler_surfaces(tmp_path, architecture, eligible):
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
    api = SimpleNamespace(funcs={"HandlerOnly": ("HandlerOnly", None, 0, "stdcall", 30)}, data={"Counter": None})
    image = ApiModuleLoader(
        name="kernel32", api=api, arch=architecture, base=0x60000000, emu_path="kernel32.dll", signature_db=database
    ).make_image()
    exports = {e.name: e for e in image.exports}
    assert set(exports) == {eligible, "Unsupported", "K32Example", "HandlerOnly", "Counter"}
    assert exports["HandlerOnly"].ordinal == 30
    assert exports["Counter"].kind == "data"
    # Neither an advisory DLL alias nor permissive ABI reuse adds physical exports.
    foreign = ApiModuleLoader(
        name="psapi", arch=architecture, base=0x60000000, emu_path="psapi.dll", signature_db=database
    ).make_image()
    assert foreign.exports == []


def test_native_exports_preserve_pe_surface():
    raw = image_bytes(
        build(
            [
                ApiExportSpec("Alias", 10),
                ApiExportSpec("Original", 10),
                ApiExportSpec(None, 11),
                ApiExportSpec("Data", 20, "data"),
                ApiExportSpec("Forward", 30, forwarder="target.dll.#12"),
            ],
            _arch.ARCH_AMD64,
        )
    )
    image = PeLoader(data=raw, emu_path="C:\\Windows\\System32\\kernel32.dll").make_image()
    independent = pefile.PE(data=raw)
    assert {(e.name, e.ordinal, e.address - image.image_base, e.forwarder) for e in image.exports} == {
        (s.name.decode() if s.name else None, s.ordinal, s.address, s.forwarder.decode() if s.forwarder else None)
        for s in independent.DIRECTORY_ENTRY_EXPORT.symbols
    }
    assert image.regions[0].data == independent.get_memory_mapped_image()
    assert all(e.execution_mode == "guest" for e in image.exports)
    kinds = {e.name: e.kind for e in image.exports}
    assert kinds["Data"] == "data"
    assert kinds["Original"] == "function"


@pytest.mark.parametrize("mutate", ["machine", "section_extent", "rebase_without_relocations"])
def test_loader_safety_checks_apply_in_lenient_mode(mutate):
    pe = pefile.PE(data=image_bytes(build([])))
    base_override = None
    if mutate == "machine":
        pe.FILE_HEADER.Machine = 0x8664
    elif mutate == "section_extent":
        pe.sections[-1].Misc_VirtualSize = pe.OPTIONAL_HEADER.SizeOfImage
    else:
        base_override = 0x60000000
    with pytest.raises(ValueError):
        PeLoader(data=pe.write(), base_override=base_override).make_image()


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


def test_native_raw_padding_outside_image_is_clipped():
    pe = pefile.PE(data=image_bytes(build([])))
    last = pe.sections[-1]
    last.Misc_VirtualSize = 0
    pe.OPTIONAL_HEADER.SizeOfImage = last.VirtualAddress + 0x800
    raw = pe.write()
    assert len(pefile.PE(data=raw).get_memory_mapped_image()) > pe.OPTIONAL_HEADER.SizeOfImage
    image = PeLoader(data=raw).make_image()
    assert image.sections[-1].virtual_size == 0x800
    assert all(s.virtual_address + s.virtual_size <= image.image_size for s in image.sections)
    assert image.regions[0].data == pefile.PE(data=raw).get_memory_mapped_image()[: image.image_size]


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


def _make_delay_import_pe(architecture, *, attrs=1, with_relocations=False):
    import struct

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
def test_eager_delay_imports_join_static_inventory_without_mutating_iat(architecture):
    import struct

    raw, data = _make_delay_import_pe(architecture)
    image = PeLoader(data=raw).make_image()
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


def test_delay_import_rvas_rebase_without_using_stale_pefile_symbol_addresses():
    raw, data = _make_delay_import_pe(_arch.ARCH_AMD64, with_relocations=True)
    image = PeLoader(data=raw, base_override=0x60000000).make_image()
    delayed = [e for e in image.imports if e.source == "delay"]
    assert [e.iat_address for e in delayed] == [0x60000000 + data + 0x240, 0x60000000 + data + 0x248]


def test_rebased_legacy_delay_import_descriptors_keep_relocated_virtual_addresses():
    import struct

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


def test_lenient_malformed_forwarder_preserves_valid_exports(caplog):
    pe = pefile.PE(
        data=image_bytes(build([ApiExportSpec("Valid", 10), ApiExportSpec("Bad", 11, forwarder="target.Function")]))
    )
    raw = bytearray(pe.write())
    bad = next(e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name == b"Bad")
    raw[bad.address : bad.address + 8] = b"invalid\0"
    image = PeLoader(data=bytes(raw)).make_image()
    assert [e.name for e in image.exports] == ["Valid"]
    assert _warned(caplog)
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


def test_lenient_non_ascii_dll_name_is_lossless(caplog):
    raw, data = _make_delay_import_pe(_arch.ARCH_X86)
    raw = bytearray(raw)
    raw[data + 0x120] = 0xE9  # Not valid UTF-8; preserve this byte with Latin-1.
    image = PeLoader(data=bytes(raw)).make_image()
    static = [e for e in image.imports if e.source == "static"]
    assert [e.dll_name for e in static] == ["éormalTarget"]
    assert len(image.imports) == 3
    assert _warned(caplog)
    with pytest.raises(UnicodeDecodeError):
        PeLoader(data=bytes(raw), strict=True).make_image()


@pytest.mark.parametrize("mode", ["user", "kernel", "dependency"])
@pytest.mark.parametrize("strict", [None, True], ids=["default", "strict"])
def test_guest_loader_config_controls_optional_parsing(mode, strict, config, tmp_path):
    from speakeasy import Speakeasy

    if strict is not None:
        config.setdefault("modules", {})["strict_pe_parsing"] = strict
    pe = pefile.PE(data=image_bytes(build([])))
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = pe.OPTIONAL_HEADER.SizeOfImage
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = 64
    if mode == "kernel":
        pe.OPTIONAL_HEADER.Subsystem = 1  # IMAGE_SUBSYSTEM_NATIVE
    malformed = pe.write()
    se = Speakeasy(config=config)
    try:
        if mode == "dependency":
            se.load_module(data=image_bytes(build([], base=0x400000)))
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
            assert load().base == pe.OPTIONAL_HEADER.ImageBase
        if mode == "kernel":
            assert se.emu.kernel_mode
    finally:
        se.shutdown()


def two_static_names(architecture, *, first=b"Normal", oft_zero=False):
    raw, data = _make_delay_import_pe(architecture, with_relocations=True)
    raw = bytearray(raw)
    width = architecture // 8
    table = data + (0x340 if oft_zero else 0x300)
    first_record = b"\0\0" + first + b"\0"
    second_record = b"\0\0Survivor\0"
    raw[data + 0x160 : data + 0x160 + len(first_record)] = first_record
    raw[data + 0x1A0 : data + 0x1A0 + len(second_record)] = second_record
    for index, value in enumerate((data + 0x160, data + 0x1A0, 0)):
        struct.pack_into("<I" if width == 4 else "<Q", raw, table + index * width, value)
    if oft_zero:
        struct.pack_into("<I", raw, data + 0x40, 0)
    return bytes(raw), data


def static_imports(image):
    return [(e.func_name, e.iat_address - image.image_base) for e in image.imports if e.source == "static"]


def test_reserved_ordinal_bits_are_not_masked_to_valid_ordinal(caplog):
    architecture = _arch.ARCH_X86
    raw, data = two_static_names(architecture)
    raw = bytearray(raw)
    struct.pack_into("<I", raw, data + 0x300, (1 << 31) | (1 << 16) | 17)
    raw = bytes(raw)
    assert not getattr(pefile.PE(data=raw), "DIRECTORY_ENTRY_IMPORT", ())  # pefile rejects 0x80010011.

    image = PeLoader(data=raw).make_image()
    assert static_imports(image) == [("Survivor", data + 0x344)]
    assert any(record.levelno == logging.WARNING for record in caplog.records)
    with pytest.raises(ValueError):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("strict", [False, True])
def test_unreadable_lookup_table_falls_back_to_iat_after_rebase(strict):
    architecture = _arch.ARCH_X86
    raw, data = two_static_names(architecture, oft_zero=True)
    raw = bytearray(raw)
    image_size = pefile.PE(data=bytes(raw)).OPTIONAL_HEADER.SizeOfImage
    struct.pack_into("<I", raw, data + 0x40, image_size + 0x1000)
    raw = bytes(raw)
    expected = pefile.PE(data=raw)
    expected.relocate_image(0x60000000)

    image = PeLoader(data=raw, base_override=0x60000000, strict=strict).make_image()
    assert static_imports(image) == [("Normal", data + 0x340), ("Survivor", data + 0x344)]
    assert image.regions[0].data == expected.get_memory_mapped_image()[: image.image_size]
