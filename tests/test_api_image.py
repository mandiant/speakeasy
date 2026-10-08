import struct

import pefile
import pytest

import speakeasy.common as common
import speakeasy.winenv.arch as arch
from speakeasy.windows.api_image import (
    API_DATA_SIZE,
    API_DYNAMIC_SIZE,
    API_ENTRY_OFFSET,
    API_SLOT_SIZE,
    ApiExportSpec,
    build_api_image,
    encode_api_stub,
)


def image_bytes(image):
    data = bytearray(image.image_size)
    for region in image.regions:
        offset = region.base - image.image_base
        data[offset : offset + len(region.data)] = region.data
    return bytes(data)


def build(exports, architecture=arch.ARCH_X86, base=None):
    return build_api_image(
        name="fixture",
        arch=architecture,
        base=base if base is not None else (0x180000000 if architecture == arch.ARCH_AMD64 else 0x76000000),
        emu_path="fixture.dll",
        exports=exports,
    )


@pytest.mark.parametrize(
    "architecture,machine,magic", [(arch.ARCH_X86, 0x14C, 0x10B), (arch.ARCH_AMD64, 0x8664, 0x20B)]
)
def test_independent_parse_and_mapping(architecture, machine, magic):
    image = build([ApiExportSpec("Function"), ApiExportSpec("Variable", kind="data")], architecture)
    raw = image_bytes(image)
    pe = pefile.PE(data=raw)
    assert pe.FILE_HEADER.Machine == machine
    assert pe.OPTIONAL_HEADER.Magic == magic
    assert pe.OPTIONAL_HEADER.ImageBase == image.image_base
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0
    assert pe.OPTIONAL_HEADER.SizeOfImage == image.image_size
    assert pe.get_memory_mapped_image() == raw
    assert image.source == "synthetic"
    assert image.entry_points == []
    exports = {e.name: e for e in image.exports}
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        entry = exports[symbol.name.decode()]
        assert (symbol.address + image.image_base, symbol.ordinal) == (entry.address, entry.ordinal)
    expected = {
        ".text": common.PERM_MEM_READ | common.PERM_MEM_EXEC,
        ".edata": common.PERM_MEM_READ,
        ".data": common.PERM_MEM_READ | common.PERM_MEM_WRITE,
        ".dyn": common.PERM_MEM_READ | common.PERM_MEM_EXEC,
    }
    for section, declared, region in zip(pe.sections, image.sections, image.regions[1:]):
        assert section.Name.rstrip(b"\0").decode() == declared.name == region.name
        assert section.VirtualAddress == declared.virtual_address == region.base - image.image_base
        assert section.Misc_VirtualSize == declared.virtual_size == len(region.data)
        assert region.perms == declared.perms == expected[declared.name]
        assert section.PointerToRawData == section.VirtualAddress
    assert image.regions[0].perms == common.PERM_MEM_READ
    text = image.sections[0]
    assert exports["Function"].address == image.image_base + text.virtual_address + API_ENTRY_OFFSET
    text_region = next(r for r in image.regions if r.name == ".text")
    assert text_region.data[:API_ENTRY_OFFSET] == b"\x90" * API_ENTRY_OFFSET
    assert text_region.data[API_ENTRY_OFFSET:API_SLOT_SIZE] == b"\xcc" * 16
    assert exports["Variable"].kind == "data"
    data = next(r for r in image.regions if r.name == ".data")
    assert exports["Variable"].address == data.base
    assert data.data[:API_DATA_SIZE] == b"\0" * API_DATA_SIZE
    dynamic = next(r for r in image.regions if r.name == ".dyn")
    assert len(dynamic.data) == API_DYNAMIC_SIZE
    assert dynamic.data == b"\xcc" * API_DYNAMIC_SIZE


def test_sparse_ordinals_and_sorted_names():
    specs = [ApiExportSpec("Zulu", 100), ApiExportSpec("Alpha", 10), ApiExportSpec(None, 12), ApiExportSpec("Middle")]
    image = build(specs)
    pe = pefile.PE(data=image_bytes(image))
    directory = pe.DIRECTORY_ENTRY_EXPORT.struct
    assert directory.Base == 1
    assert directory.NumberOfFunctions == 100
    assert directory.NumberOfNames == 3
    # Read the independent arrays, rather than relying on pefile's symbol ordering.
    name_rvas = struct.unpack("<3I", pe.get_data(directory.AddressOfNames, 12))
    assert [pe.get_string_at_rva(rva) for rva in name_rvas] == [b"Alpha", b"Middle", b"Zulu"]
    assert struct.unpack("<3H", pe.get_data(directory.AddressOfNameOrdinals, 6)) == (9, 0, 99)
    eat = struct.unpack("<100I", pe.get_data(directory.AddressOfFunctions, 400))
    assert {i + 1 for i, rva in enumerate(eat) if rva} == {1, 10, 12, 100}
    assert {e.ordinal for e in image.exports} == {1, 10, 12, 100}
    assert not any(e.name and e.name.startswith("ordinal_") for e in image.exports)
    assert image_bytes(build(list(reversed(specs)))) == image_bytes(image)


def test_non_one_base_aliases_data_storage_and_forwarders():
    image = build(
        [
            ApiExportSpec("Alias", 40),
            ApiExportSpec("Target", 40),
            ApiExportSpec(None, 43),
            ApiExportSpec("FirstData", 45, "data"),
            ApiExportSpec("SecondData", 46, "data"),
            ApiExportSpec("Forward", 48, forwarder="other.Target"),
        ]
    )
    pe = pefile.PE(data=image_bytes(image))
    entries = {e.name: e for e in image.exports}
    assert pe.DIRECTORY_ENTRY_EXPORT.struct.Base == 40
    assert entries["Alias"].address == entries["Target"].address
    assert entries[None].address - entries["Target"].address == API_SLOT_SIZE
    assert entries["SecondData"].address - entries["FirstData"].address == API_DATA_SIZE
    forward = next(e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name == b"Forward")
    assert forward.forwarder == b"other.Target"
    assert entries["Forward"].forwarder == "other.Target"
    assert all(e.forwarder is None for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name != b"Forward")


@pytest.mark.parametrize("architecture", [arch.ARCH_X86, arch.ARCH_AMD64])
def test_empty_image(architecture):
    image = build([], architecture)
    pe = pefile.PE(data=image_bytes(image))
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress == 0
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size == 0
    assert not hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
    assert len(pe.sections) == 4
    assert image.exports == []
    assert image.image_size == len(image_bytes(image))


def test_x86_stub_wraps_modulo32():
    entry = 0xFFFFFFFC
    trap = 0x12345678
    stub = encode_api_stub(arch.ARCH_X86, entry, trap)
    assert stub[:3] == b"\x8b\xff\xe9"
    assert len(stub) == 7
    displacement = struct.unpack("<I", stub[3:])[0]
    assert (entry + len(stub) + displacement) & 0xFFFFFFFF == trap


def test_x64_stub_preserves_full_token():
    trap = 0xFFFF800012345678
    stub = encode_api_stub(arch.ARCH_AMD64, 0x180001010, trap)
    assert stub[:8] == b"\x66\x90\xff\x25\0\0\0\0"
    assert len(stub) == 16
    assert struct.unpack("<Q", stub[8:])[0] == trap


@pytest.mark.parametrize(
    "exports",
    [
        [ApiExportSpec("Repeated"), ApiExportSpec("Repeated")],
        [ApiExportSpec(None)],
        [ApiExportSpec("Bad", -1)],
        [ApiExportSpec("First", 1), ApiExportSpec("Last", 0x10001)],
        [ApiExportSpec("Func", 1), ApiExportSpec("Data", 1, "data")],
        [ApiExportSpec("Unknown", kind="unknown")],
    ],
)
def test_invalid_export_tables_rejected(exports):
    with pytest.raises(ValueError):
        build(exports)


def test_invalid_architecture_rejected():
    with pytest.raises(ValueError):
        encode_api_stub(0, 0, 0)
    with pytest.raises(ValueError):
        build([], 0)


def test_explicit_zero_ordinal_and_only_ordinal_exports():
    image = build([ApiExportSpec(None, 0), ApiExportSpec(None, 10)])
    pe = pefile.PE(data=image_bytes(image))
    directory = pe.DIRECTORY_ENTRY_EXPORT.struct
    assert directory.Base == 0
    assert directory.NumberOfNames == 0
    assert directory.NumberOfFunctions == 11
    assert {(s.name, s.ordinal) for s in pe.DIRECTORY_ENTRY_EXPORT.symbols} == {(None, 0), (None, 10)}


@pytest.mark.parametrize("architecture", [arch.ARCH_X86, arch.ARCH_AMD64])
def test_synthetic_forwarders_share_eat_target_without_allocating_storage(architecture):
    specs = [
        ApiExportSpec("Code", 10),
        ApiExportSpec("FuncForward", 20, forwarder="target.dll.Function"),
        ApiExportSpec("FuncAlias", 20, forwarder="target.dll.Function"),
        ApiExportSpec("DataForward", 30, kind="data", forwarder="target.#12"),
        ApiExportSpec("Data", 40, kind="data"),
        ApiExportSpec("OtherCode", 50),
    ]
    image = build(specs, architecture)
    pe = pefile.PE(data=image_bytes(image))
    entries = {e.name: e for e in image.exports}
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    for name in ("FuncForward", "FuncAlias", "DataForward"):
        entry = entries[name]
        rva = entry.address - image.image_base
        assert directory.VirtualAddress <= rva < directory.VirtualAddress + directory.Size
        assert pe.get_string_at_rva(rva).decode() == entry.forwarder
    assert entries["FuncForward"].address == entries["FuncAlias"].address
    assert entries["DataForward"].kind == "data"
    assert entries["Data"].address == next(r.base for r in image.regions if r.name == ".data")
    assert entries["OtherCode"].address - entries["Code"].address == API_SLOT_SIZE
    assert image_bytes(build(list(reversed(specs)), architecture)) == image_bytes(image)


@pytest.mark.parametrize(
    "forwarder",
    [
        "",
        "missing_separator",
        ".Name",
        "dll.",
        "dll.#",
        "dll.#0",
        "dll.#65536",
        "dll.#-1",
        "dll.#1x",
        "dll.Name\0suffix",
        "dll.Na mé",
        "dll. Name",
        "path/dll.Name",
        "dll..Name",
        12,
    ],
)
def test_malformed_synthetic_forwarders_rejected(forwarder):
    with pytest.raises(ValueError):
        build([ApiExportSpec("Forward", forwarder=forwarder)])


@pytest.mark.parametrize(
    "spec",
    [
        ApiExportSpec(12),
        ApiExportSpec(""),
        ApiExportSpec("Null\0Name"),
        ApiExportSpec("NonAsciié"),
        ApiExportSpec("Bad", True),
        ApiExportSpec("Bad", "12"),
        ApiExportSpec("Bad", 1.5),
        object(),
        ApiExportSpec("Alias", 1, forwarder="other.Name"),
    ],
)
def test_malformed_specs_and_conflicting_aliases_rejected(spec):
    with pytest.raises(ValueError):
        build([ApiExportSpec("Original", 1), spec])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": ""},
        {"name": "bad\0module"},
        {"name": "é"},
        {"base": -1},
        {"base": True},
        {"base": 0xFFFFFFFF},
        {"minimum_size": -1},
        {"minimum_size": 1.5},
        {"minimum_size": 0x100000000},
        {"dynamic_size": 0x4000000},
        {"dynamic_size": True},
        {"dynamic_size": 0x100000000},
    ],
)
def test_malformed_image_inputs_rejected_before_allocation(kwargs):
    values = dict(name="fixture", arch=arch.ARCH_X86, base=0x76000000, emu_path="fixture.dll", exports=[])
    values.update(kwargs)
    with pytest.raises(ValueError):
        build_api_image(**values)


@pytest.mark.parametrize("architecture", [arch.ARCH_X86, arch.ARCH_AMD64])
def test_many_mapped_entries_are_disjoint_patchable_and_aligned(architecture):
    image = build([ApiExportSpec(f"Name{i:03}") for i in range(260)], architecture)
    text = next(r for r in image.regions if r.name == ".text")
    patched = bytearray(text.data)
    for index, entry in enumerate(sorted(image.exports, key=lambda e: e.ordinal)):
        offset = entry.address - text.base
        assert offset == index * API_SLOT_SIZE + API_ENTRY_OFFSET
        assert entry.address % 16 == 0
        assert patched[offset - 5 : offset] == b"\x90" * 5
        assert patched[offset : offset + 16] == b"\xcc" * 16
        trap = 0xFFFF800012345678 + index * 16 if architecture == arch.ARCH_AMD64 else 0xF0000000 + index * 16
        stub = encode_api_stub(architecture, entry.address, trap)
        patched[offset : offset + len(stub)] = stub
        assert len(stub) <= 16
    assert len(patched) == len(text.data)
    assert patched[-1] == 0xCC  # Unused page padding remains faulting.


@pytest.mark.parametrize(
    "architecture,entry,trap",
    [
        (arch.ARCH_X86, -1, 0),
        (arch.ARCH_X86, 0, 0x100000000),
        (arch.ARCH_AMD64, 0x10000000000000000, 0),
        (arch.ARCH_AMD64, 0, -1),
        (arch.ARCH_AMD64, 0, True),
        (arch.ARCH_X86, "12", 0),
    ],
)
def test_stub_malformed_addresses_rejected(architecture, entry, trap):
    with pytest.raises(ValueError):
        encode_api_stub(architecture, entry, trap)
