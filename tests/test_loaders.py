import logging
import struct
from pathlib import Path
from types import SimpleNamespace

import pefile
import pytest
import unicorn as uc

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from speakeasy.errors import NotSupportedError
from speakeasy.windows.api_image import ApiExportSpec, ApiModuleLoader
from speakeasy.windows.common import _PeParser
from speakeasy.windows.loaders import ExportEntry, LoadedImage, PeLoader, RuntimeModule, relocate_image
from speakeasy.winenv.api.sigdb import SignatureDatabase
from tests.pe_builder import build_pe
from tests.test_api_image import build, image_bytes
from tests.test_export_catalog import _source

SECTION_PAST_EOF_EXE = "04ca62db586d451d22f2477cf90b94db3f012281666248c15aca18661d7fe3b4.exe.xz"


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
        entry_points=[],
        visible_in_peb=True,
        tls_callbacks=[],
        sections=[],
    )


def test_runtime_module_export_lookup_and_base_name():
    exports = [
        ExportEntry(name="DllMain", address=0x401000, ordinal=1),
        ExportEntry(name="Init", address=0x402000, ordinal=2),
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
        signature_db=SignatureDatabase([]),
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
        signature_db=SignatureDatabase([]),
    )
    image = loader.make_image()

    for section in image.sections:
        end = section.virtual_address + section.virtual_size
        assert end <= image.image_size


def _warned(caplog):
    return any(record.levelno == logging.WARNING for record in caplog.records)


@pytest.mark.parametrize("architecture,eligible", [(_arch.ARCH_X86, "Only32"), (_arch.ARCH_AMD64, "Only64")])
def test_api_loader_combines_catalog_and_handler_surfaces(tmp_path, architecture, eligible):
    source = _source(
        tmp_path,
        {
            "Only32": [{"dll": "examplelib", "arch": ["x86"]}],
            "Only64": [{"dll": "examplelib", "arch": ["x64"]}],
            "Unsupported": [{"dll": "examplelib", "skip": "unsupported ABI"}],
            "Foreign": [{"dll": "otherlib"}],
            "ExpExample": [{"dll": "examplelib"}],
        },
        dll_aliases={"aliaslib": "examplelib"},
        name_prefixes={"examplelib": ["Exp"]},
    )
    database = SignatureDatabase([source])
    api = SimpleNamespace(funcs={"HandlerOnly": ("HandlerOnly", None, 0, "stdcall", 30)}, data={"Counter": None})
    image = ApiModuleLoader(
        name="examplelib", api=api, arch=architecture, base=0x60000000, emu_path="examplelib.dll", signature_db=database
    ).make_image()
    exports = {e.name: e for e in image.exports}
    assert set(exports) == {eligible, "Unsupported", "ExpExample", "HandlerOnly", "Counter"}
    assert exports["HandlerOnly"].ordinal == 30
    assert exports["Counter"].kind == "data"
    # Neither an advisory DLL alias nor permissive ABI reuse adds physical exports.
    foreign = ApiModuleLoader(
        name="aliaslib", arch=architecture, base=0x60000000, emu_path="aliaslib.dll", signature_db=database
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
    assert {(e.name, e.ordinal, e.address, e.forwarder) for e in image.exports} == {
        (s.name.decode() if s.name else None, s.ordinal, s.address, s.forwarder.decode() if s.forwarder else None)
        for s in independent.DIRECTORY_ENTRY_EXPORT.symbols
    }
    assert image.regions[0].data == independent.get_memory_mapped_image()
    kinds = {e.name: e.kind for e in image.exports}
    assert kinds["Data"] == "data"
    assert kinds["Original"] == "function"


@pytest.mark.parametrize("mutate", ["machine", "section_extent", "rebase_without_relocations"])
def test_loader_safety_checks_apply_in_lenient_mode(mutate):
    pe = pefile.PE(data=image_bytes(build([])))
    base = pe.OPTIONAL_HEADER.ImageBase
    if mutate == "machine":
        pe.FILE_HEADER.Machine = 0x8664
    elif mutate == "section_extent":
        pe.sections[-1].Misc_VirtualSize = pe.OPTIONAL_HEADER.SizeOfImage
    else:
        base = 0x60000000
    with pytest.raises(ValueError):
        relocate_image(PeLoader(data=pe.write()).make_image(), base)


@pytest.mark.parametrize("filename", ["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"])
def test_native_rebase_moves_imports_and_exports(filename, load_test_bin):
    raw = load_test_bin(filename)
    original = pefile.PE(data=raw)
    base = 0x60000000
    image = relocate_image(PeLoader(data=raw).make_image(), base)
    assert image.image_base == base
    assert image.regions[0].base == base
    assert [e.iat_address for e in image.imports] == [
        base + d.struct.FirstThunk + i * (image.arch // 8)
        for d in original.DIRECTORY_ENTRY_IMPORT
        for i, _ in enumerate(d.imports)
    ]
    assert [(e.address - base, e.ordinal) for e in image.exports] == [
        (e.address, e.ordinal) for e in original.DIRECTORY_ENTRY_EXPORT.symbols if e.address
    ]


@pytest.mark.parametrize(
    "filename",
    [
        "dll_test_x86.dll.xz",
        "dll_test_x64.dll.xz",
        "argv_test_x86.exe.xz",
        "argv_test_x64.exe.xz",
        "wdm_test_x86.sys.xz",
        "wdm_test_x64.sys.xz",
    ],
)
def test_relocated_image_matches_pefile_rebase(filename, load_test_bin):
    raw = load_test_bin(filename)
    base = 0x60000000
    data = relocate_image(PeLoader(data=raw).make_image(), base).regions[0].data
    expected = _PeParser(data=raw)
    expected.rebase(base)
    mapped = expected.get_mapped_image()[: len(data)]
    # pefile does not write the new ImageBase into its mapped image.
    field = expected.OPTIONAL_HEADER.get_file_offset() + (24 if expected.arch == 64 else 28)
    end = field + expected.arch // 8
    assert int.from_bytes(data[field:end], "little") == base
    assert data[:field] + data[end:] == mapped[:field] + mapped[end:]


def test_image_without_relocations_loads_only_at_its_preferred_base(load_test_bin):
    image = PeLoader(data=load_test_bin("child_x86.exe.xz")).make_image()
    assert image.relocations is None
    assert relocate_image(image, image.image_base).entry_points == [image.image_base + image.entry_points[0]]
    with pytest.raises(ValueError, match="Cannot rebase a guest PE without valid relocation data"):
        relocate_image(image, 0x60000000)


def test_image_whose_preferred_base_is_in_use_loads_at_the_next_free_range(config, load_test_bin):
    image = PeLoader(data=load_test_bin("dll_test_x86.dll.xz")).make_image()
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch="x86")
        se.emu.mem_map(0x1000, base=image.image_base, tag="test.block")
        module = se.emu.load_image(image)
        expected = relocate_image(image, module.base)
        assert module.base > image.image_base
        text = next(s for s in image.sections if s.name == ".text")
        start, end = text.virtual_address, text.virtual_address + text.virtual_size
        assert se.mem_read(module.base + start, end - start) == expected.regions[0].data[start:end]
        assert se.mem_read(module.base + start, end - start) != image.regions[0].data[start:end]
        assert module.get_export_by_name("emu_test_one").address == expected.exports[0].address
    finally:
        se.shutdown()


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
    raw, data = _make_delay_import_pe(architecture)
    image = PeLoader(data=raw).make_image()
    assert [(e.dll_name, e.func_name, e.source) for e in image.imports] == [
        ("NormalTarget", "Normal", "static"),
        ("DelayTarget", "ByName", "delay"),
        ("DelayTarget", "ordinal_17", "delay"),
    ]
    width = architecture // 8
    assert [e.iat_address for e in image.imports] == [
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
    image = relocate_image(PeLoader(data=raw).make_image(), 0x60000000)
    delayed = [e for e in image.imports if e.source == "delay"]
    assert [e.iat_address for e in delayed] == [0x60000000 + data + 0x240, 0x60000000 + data + 0x248]


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


@pytest.mark.parametrize("mode", ["user", "kernel", "dependency"])
def test_guest_loaders_accept_malformed_optional_inventory(mode, config, tmp_path):
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

            module = se.emu.load_module_by_name(
                "malformed_dependency", native_path=str(path), base=pe.OPTIONAL_HEADER.ImageBase
            )
        else:
            module = se.load_module(data=malformed)
        assert module.base == pe.OPTIONAL_HEADER.ImageBase
        if mode == "kernel":
            assert se.emu.is_kernel_mode
    finally:
        se.shutdown()


def test_load_module_rejects_a_dotnet_image_without_an_mscoree_import(config) -> None:
    image, _ = build_pe(data=b"\0" * 0x48, extra_dirs={14: (0x2000, 0x48)})
    se = Speakeasy(config=config)
    with pytest.raises(NotSupportedError):
        se.load_module(data=image)


def test_section_raw_data_past_end_of_file_keeps_file_bytes(load_test_bin):
    """
    04ca62db gives .text (RVA 0x1000, raw offset 0x1000, virtual size 0x2a5c4) a SizeOfRawData
    of 0xc3b000, far past the end of the 479917-byte file. Windows maps the bytes that the file
    has, so the entry point code at RVA 0x13d4 is there.
    """
    raw = load_test_bin(SECTION_PAST_EOF_EXE)

    image = PeLoader(data=raw).make_image().regions[0].data

    assert image[0x1000:0x2B5C4] == raw[0x1000:0x2B5C4]
    assert image[0x2C000:0x2CA20] == raw[0x2C000:0x2CA20]


def test_last_section_raw_data_past_end_of_file_stays_inside_the_image(load_test_bin):
    raw = bytearray(load_test_bin("child_x86.exe.xz")) + b"y" * 0x8000
    pe = pefile.PE(data=bytes(raw))
    last = pe.sections[-1]
    struct.pack_into("<I", raw, last.get_file_offset() + 16, 0x00C3B000)

    parser = _PeParser(data=bytes(raw))

    assert len(parser.mapped_image) <= pe.OPTIONAL_HEADER.SizeOfImage
    start = last.PointerToRawData
    assert (
        parser.mapped_image[last.VirtualAddress : last.VirtualAddress + last.Misc_VirtualSize]
        == raw[start : start + last.Misc_VirtualSize]
    )
