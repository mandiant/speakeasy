"""Synthetic API module images are valid mapped PE files with a documented export layout."""

import struct

import pefile
import pytest

import speakeasy.common as common
import speakeasy.winenv.arch as arch
from speakeasy.windows.api_image import ApiExportSpec, build_api_image


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
def test_image_is_a_mapped_pe_with_documented_section_permissions(architecture, machine, magic):
    image = build([ApiExportSpec("Function"), ApiExportSpec("Variable", kind="data")], architecture)
    raw = image_bytes(image)
    pe = pefile.PE(data=raw)
    assert pe.FILE_HEADER.Machine == machine
    assert pe.OPTIONAL_HEADER.Magic == magic
    assert pe.OPTIONAL_HEADER.ImageBase == image.image_base
    assert pe.OPTIONAL_HEADER.SizeOfImage == image.image_size
    assert pe.get_memory_mapped_image() == raw
    exports = {e.name: e for e in image.exports}
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        entry = exports[symbol.name.decode()]
        assert (symbol.address + image.image_base, symbol.ordinal) == (entry.address, entry.ordinal)
    regions = {region.name: region for region in image.regions[1:]}
    assert image.regions[0].perms == common.PERM_MEM_READ
    assert {name: region.perms for name, region in regions.items()} == {
        ".text": common.PERM_MEM_READ | common.PERM_MEM_EXEC,
        ".edata": common.PERM_MEM_READ,
        ".data": common.PERM_MEM_READ | common.PERM_MEM_WRITE,
        ".dyn": common.PERM_MEM_READ | common.PERM_MEM_EXEC,
    }
    assert [s.Name.rstrip(b"\0").decode() for s in pe.sections] == list(regions)

    def owner(address):
        return next(name for name, region in regions.items() if region.base <= address < region.base + len(region.data))

    assert exports["Function"].kind == "function" and owner(exports["Function"].address) == ".text"
    assert exports["Variable"].kind == "data" and owner(exports["Variable"].address) == ".data"


def test_export_directory_sorts_names_and_keeps_sparse_ordinals():
    specs = [ApiExportSpec("Zulu", 100), ApiExportSpec("Alpha", 10), ApiExportSpec(None, 12), ApiExportSpec("Middle")]
    image = build(specs)
    pe = pefile.PE(data=image_bytes(image))
    directory = pe.DIRECTORY_ENTRY_EXPORT.struct
    assert directory.Base == 1
    assert directory.NumberOfFunctions == 100
    assert directory.NumberOfNames == 3
    name_rvas = struct.unpack("<3I", pe.get_data(directory.AddressOfNames, 12))
    assert [pe.get_string_at_rva(rva) for rva in name_rvas] == [b"Alpha", b"Middle", b"Zulu"]
    assert struct.unpack("<3H", pe.get_data(directory.AddressOfNameOrdinals, 6)) == (9, 0, 99)
    eat = struct.unpack("<100I", pe.get_data(directory.AddressOfFunctions, 400))
    assert {i + 1 for i, rva in enumerate(eat) if rva} == {1, 10, 12, 100}
    assert {e.ordinal for e in image.exports} == {1, 10, 12, 100}
    assert image_bytes(build(list(reversed(specs)))) == image_bytes(image)


def test_ordinal_aliases_share_an_entry_and_forwarders_keep_eat_strings():
    image = build(
        [
            ApiExportSpec("Alias", 40),
            ApiExportSpec("Target", 40),
            ApiExportSpec("Data", 45, "data"),
            ApiExportSpec("Forward", 48, forwarder="other.Target"),
            ApiExportSpec("DataForward", 49, kind="data", forwarder="other.#12"),
        ]
    )
    pe = pefile.PE(data=image_bytes(image))
    entries = {e.name: e for e in image.exports}
    assert pe.DIRECTORY_ENTRY_EXPORT.struct.Base == 40
    assert entries["Alias"].address == entries["Target"].address
    forwarders = {s.name: s.forwarder for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}
    assert forwarders == {
        b"Alias": None,
        b"Target": None,
        b"Data": None,
        b"Forward": b"other.Target",
        b"DataForward": b"other.#12",
    }
    assert entries["Forward"].forwarder == "other.Target"
    assert entries["DataForward"].kind == "data"


def test_empty_image_is_a_valid_pe_with_a_dynamic_arena():
    image = build([])
    pe = pefile.PE(data=image_bytes(image))
    assert not hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
    assert image.exports == []
    assert ".dyn" in [s.Name.rstrip(b"\0").decode() for s in pe.sections]
    assert pe.OPTIONAL_HEADER.SizeOfImage == image.image_size == len(image_bytes(image))


def test_conflicting_ordinals_are_rejected():
    with pytest.raises(ValueError):
        build([ApiExportSpec("Func", 1), ApiExportSpec("Data", 1, "data")])
