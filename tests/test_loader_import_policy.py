"""Parser-only malformed-import policy and original IAT-slot regressions."""

import struct

import pefile
import pytest

from speakeasy.windows.common import _PeParser
from speakeasy.windows.loaders import PeLoader
from tests.test_api_image import build, image_bytes
from tests.test_loaders import _make_delay_import_pe


def two_static_names(architecture, *, first=b"Normal", oft_zero=False, survivor_ordinal=False):
    raw, data = _make_delay_import_pe(architecture, with_relocations=True)
    raw = bytearray(raw)
    width = architecture // 8
    table = data + (0x340 if oft_zero else 0x300)
    first_record = b"\0\0" + first + b"\0"
    second_record = b"\0\0Survivor\0"
    raw[data + 0x160 : data + 0x160 + len(first_record)] = first_record
    raw[data + 0x1A0 : data + 0x1A0 + len(second_record)] = second_record
    second = (1 << (architecture - 1)) | 17 if survivor_ordinal else data + 0x1A0
    for index, value in enumerate((data + 0x160, second, 0)):
        struct.pack_into("<I" if width == 4 else "<Q", raw, table + index * width, value)
    if oft_zero:
        struct.pack_into("<I", raw, data + 0x40, 0)
    return bytes(raw), data


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("oft_zero", [False, True])
@pytest.mark.parametrize("rebased", [False, True])
@pytest.mark.parametrize("first", [b"", b"\xe9Bad"])
@pytest.mark.parametrize("survivor_ordinal", [False, True])
def test_raw_filtered_static_import_keeps_original_iat_slot(
    architecture, oft_zero, rebased, first, survivor_ordinal, caplog
):
    raw, data = two_static_names(architecture, first=first, oft_zero=oft_zero, survivor_ordinal=survivor_ordinal)
    expected = pefile.PE(data=raw)
    width = architecture // 8
    parsed = expected.DIRECTORY_ENTRY_IMPORT[0].imports
    assert len(parsed) == 1  # pefile filters the first raw import.
    assert parsed[0].thunk_rva == data + (0x340 if oft_zero else 0x300) + width
    assert parsed[0].address == expected.OPTIONAL_HEADER.ImageBase + data + 0x340 + width
    base_override = 0x60000000 if rebased else None
    if rebased:
        expected.relocate_image(base_override)

    image = PeLoader(data=raw, base_override=base_override).make_image()
    static = [entry for entry in image.imports if entry.source == "static"]
    assert [(entry.func_name, entry.iat_address) for entry in static] == [
        ("ordinal_17" if survivor_ordinal else "Survivor", image.image_base + data + 0x340 + width)
    ]
    assert len([entry for entry in image.imports if entry.source == "delay"]) == 2
    assert image.regions[0].data == expected.get_memory_mapped_image()[: image.image_size]
    assert "Skipping malformed PE static import entry" in caplog.text
    error = UnicodeDecodeError if first else ValueError
    with pytest.raises(error):
        PeLoader(data=raw, base_override=base_override, strict=True).make_image()


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("first", [b"", b"\xe9Bad"])
def test_entirely_filtered_static_descriptor_is_not_silently_accepted(architecture, first, caplog):
    raw, data = two_static_names(architecture, first=first)
    raw = bytearray(raw)
    struct.pack_into("<I" if architecture == 32 else "<Q", raw, data + 0x300 + architecture // 8, 0)
    raw = bytes(raw)
    assert not getattr(pefile.PE(data=raw), "DIRECTORY_ENTRY_IMPORT", ())
    image = PeLoader(data=raw).make_image()
    assert all(entry.source == "delay" for entry in image.imports)
    assert "Skipping malformed PE static import entry" in caplog.text
    with pytest.raises(ValueError):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("source", ["static", "delay"])
@pytest.mark.parametrize("name", [None, b"", b"\xffFunction"])
def test_direct_import_name_guards_preserve_valid_siblings(architecture, source, name, monkeypatch, caplog):
    raw, data = two_static_names(architecture)
    original = _PeParser.__init__

    def modify_names(pe, *args, **kwargs):
        original(pe, *args, **kwargs)
        entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT" if source == "static" else "DIRECTORY_ENTRY_DELAY_IMPORT")
        assert not entries[0].imports[0].import_by_ordinal
        # ImportData.name's setter edits the guest; inject metadata only.
        object.__setattr__(entries[0].imports[0], "name", name)

    monkeypatch.setattr(_PeParser, "__init__", modify_names)
    image = PeLoader(data=raw).make_image()
    selected = [entry for entry in image.imports if entry.source == source]
    expected_name = "Survivor" if source == "static" else "ordinal_17"
    expected_rva = data + (0x340 if source == "static" else 0x240) + architecture // 8
    assert [(entry.func_name, entry.iat_address - image.image_base) for entry in selected] == [
        (expected_name, expected_rva)
    ]
    assert "Skipping malformed PE " + source + " import entry" in caplog.text
    with pytest.raises(UnicodeDecodeError if name else ValueError):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("kind", ["raw_filtered", "parsed_incomplete"])
def test_incomplete_delay_inventory_preserves_static_imports(architecture, kind, monkeypatch, caplog):
    raw, data = two_static_names(architecture)
    if kind == "raw_filtered":
        raw = bytearray(raw)
        raw[data + 0x142] = 0xFF
        raw = bytes(raw)
    else:
        original = _PeParser.__init__

        def remove_import(pe, *args, **kwargs):
            original(pe, *args, **kwargs)
            pe.DIRECTORY_ENTRY_DELAY_IMPORT[0].imports.pop(0)

        monkeypatch.setattr(_PeParser, "__init__", remove_import)
    image = PeLoader(data=raw).make_image()
    assert [(entry.func_name, entry.source) for entry in image.imports] == [
        ("Normal", "static"),
        ("Survivor", "static"),
    ]
    assert "Delay import descriptors could not be parsed completely" in caplog.text
    with pytest.raises(ValueError, match="parsed completely"):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("source", ["static", "delay"])
@pytest.mark.parametrize("boundary", ["zero", "outside", "tail"])
def test_lenient_iat_boundaries_preserve_other_inventory(architecture, source, boundary, caplog):
    raw, data = two_static_names(architecture)
    raw = bytearray(raw)
    pe = pefile.PE(data=bytes(raw))
    width = architecture // 8
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    iat = {"zero": 0, "outside": image_size, "tail": image_size - width}[boundary]
    struct.pack_into("<I", raw, data + (0x50 if source == "static" else 12), iat)
    raw = bytes(raw)
    image = PeLoader(data=raw).make_image()
    selected = [entry for entry in image.imports if entry.source == source]
    if source == "static" and boundary == "tail":
        assert [(entry.func_name, entry.iat_address - image.image_base) for entry in selected] == [("Normal", iat)]
    else:
        assert selected == []
    other = [entry for entry in image.imports if entry.source != source]
    assert len(other) == 2
    assert all(
        image.image_base <= entry.iat_address <= image.image_base + image.image_size - width for entry in image.imports
    )
    assert "Skipping malformed PE" in caplog.text
    assert image.regions[0].data == pefile.PE(data=raw).get_memory_mapped_image()[: image.image_size]
    with pytest.raises(ValueError):
        PeLoader(data=raw, strict=True).make_image()


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("forwarder", [b"", b"invalid", b"target.#no", b"target.#65536", b"target.\xff"])
def test_lenient_forwarder_variants_preserve_valid_export(architecture, forwarder, caplog):
    from speakeasy.windows.api_image import ApiExportSpec

    raw = image_bytes(
        build([ApiExportSpec("Valid", 10), ApiExportSpec("Bad", 11, forwarder="target.Function")], architecture)
    )
    pe = pefile.PE(data=raw)
    bad = next(entry for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols if entry.name == b"Bad")
    raw = bytearray(raw)
    replacement = forwarder + b"\0"
    raw[bad.address : bad.address + len(replacement)] = replacement
    image = PeLoader(data=bytes(raw)).make_image()
    assert [entry.name for entry in image.exports] == ["Valid"]
    assert "Skipping malformed PE export entry" in caplog.text
    with pytest.raises(ValueError):
        PeLoader(data=bytes(raw), strict=True).make_image()


@pytest.mark.parametrize("strict", [False, True])
def test_static_raw_table_walk_is_globally_bounded(strict, monkeypatch, caplog):
    from types import SimpleNamespace

    # A huge image and a table that never terminates must not cause a huge walk.
    monkeypatch.setattr(pefile, "MAX_IMPORT_SYMBOLS", 3)
    reads = []

    def read(rva, size):
        reads.append((rva, size))
        return ((1 << 31) | len(reads)).to_bytes(size, "little")

    pe = SimpleNamespace(arch=32, image_size=1 << 32, get_data=read)
    entry = SimpleNamespace(struct=SimpleNamespace(OriginalFirstThunk=0x1000, FirstThunk=0x2000))
    budget = [pefile.MAX_IMPORT_SYMBOLS + 1]
    loader = PeLoader(strict=strict)
    slots = loader._static_import_slots(pe, entry, (), budget)
    assert [next(slots)[0] for _ in range(4)] == [0x2000, 0x2004, 0x2008, 0x200C]
    if strict:
        with pytest.raises(ValueError, match="symbol limit"):
            next(slots)
    else:
        assert list(slots) == []
        assert "Import symbol limit exceeded" in caplog.text
    assert reads == [(0x1000 + index * 4, 4) for index in range(5)]
    assert budget == [0]
    # A later descriptor gets only one lookahead, not a fresh slot budget.
    if strict:
        with pytest.raises(ValueError, match="symbol limit"):
            list(loader._static_import_slots(pe, entry, (), budget))
    else:
        assert list(loader._static_import_slots(pe, entry, (), budget)) == []
    assert len(reads) == 6


@pytest.mark.parametrize("result", ["none", "error"])
@pytest.mark.parametrize("strict", [False, True])
def test_names_only_parse_none_or_error_preserves_delay_inventory(result, strict, monkeypatch, caplog):
    raw, _ = _make_delay_import_pe(32)
    original = pefile.PE.parse_import_directory

    def parse(pe, rva, size, dllnames_only=False):
        if not dllnames_only:
            return original(pe, rva, size, dllnames_only=dllnames_only)
        if result == "none":
            return None
        raise pefile.PEFormatError("names-only failure")

    monkeypatch.setattr(pefile.PE, "parse_import_directory", parse)
    if strict and result == "error":
        with pytest.raises(pefile.PEFormatError, match="names-only failure"):
            PeLoader(data=raw, strict=True).make_image()
    else:
        image = PeLoader(data=raw, strict=strict).make_image()
        assert [(entry.func_name, entry.source) for entry in image.imports] == [
            ("ByName", "delay"),
            ("ordinal_17", "delay"),
        ]
        if result == "error":
            assert "Skipping malformed PE static import directory" in caplog.text


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("extra", [0, 1], ids=["MAX", "MAX-plus-one"])
@pytest.mark.parametrize("kind", ["named", "ordinal"])
def test_raw_slot_limit_equality_accepts_terminator(architecture, strict, extra, kind, caplog):
    from types import SimpleNamespace

    count = pefile.MAX_IMPORT_SYMBOLS + extra
    width = architecture // 8
    reads = []
    symbols = []

    def read(rva, size):
        reads.append((rva, size))
        index = (rva - 0x1000) // width
        value = ((1 << (architecture - 1)) | (index + 1)) if kind == "ordinal" else 0x50000
        return (value if index < count else 0).to_bytes(size, "little")

    for index in range(count):
        symbols.append(
            SimpleNamespace(
                thunk_rva=0x1000 + index * width,
                import_by_ordinal=kind == "ordinal",
                ordinal=index + 1 if kind == "ordinal" else None,
                name=b"Function" if kind == "named" else None,
            )
        )
    pe = SimpleNamespace(arch=architecture, image_size=1 << 32, get_data=read)
    entry = SimpleNamespace(struct=SimpleNamespace(OriginalFirstThunk=0x1000, FirstThunk=0x40000))
    budget = [pefile.MAX_IMPORT_SYMBOLS + 1]
    slots = list(PeLoader(strict=strict)._static_import_slots(pe, entry, symbols, budget))
    assert len(slots) == count
    assert slots[0] == (0x40000, symbols[0])
    assert slots[-1] == (0x40000 + (count - 1) * width, symbols[-1])
    assert len(reads) == count + 1
    assert reads[-1] == (0x1000 + count * width, width)
    assert budget == [1 - extra]
    assert "Import symbol limit exceeded" not in caplog.text


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("following", ["terminator", "nonzero"])
def test_shared_budget_and_one_lookahead_per_descriptor(strict, following, caplog):
    from types import SimpleNamespace

    values = {
        0x1000: (1 << 31) | 1,
        0x1004: 0,
        0x2000: (1 << 31) | 2,
        0x2004: 0,
        0x3000: 0 if following == "terminator" else (1 << 31) | 3,
        0x4000: 0,
    }
    reads = []

    def read(rva, size):
        reads.append(rva)
        return values[rva].to_bytes(size, "little")

    pe = SimpleNamespace(arch=32, image_size=0x10000, get_data=read)
    loader = PeLoader(strict=strict)
    budget = [2]

    def slots(table):
        entry = SimpleNamespace(struct=SimpleNamespace(OriginalFirstThunk=table, FirstThunk=table + 0x100))
        return loader._static_import_slots(pe, entry, (), budget)

    assert len(list(slots(0x1000))) == 1
    assert budget == [1]  # The first descriptor's NUL did not consume a slot.
    assert len(list(slots(0x2000))) == 1
    assert budget == [0]
    if strict and following == "nonzero":
        with pytest.raises(ValueError, match="symbol limit"):
            list(slots(0x3000))
    else:
        assert list(slots(0x3000)) == []
        assert ("Import symbol limit exceeded" in caplog.text) is (following == "nonzero")
    assert list(slots(0x4000)) == []
    assert reads == [0x1000, 0x1004, 0x2000, 0x2004, 0x3000, 0x4000]


@pytest.mark.parametrize("strict", [False, True])
def test_malformed_nonzero_slot_consumes_shared_budget(strict, caplog):
    from types import SimpleNamespace

    values = {0x1000: 0xFFFF, 0x1004: (1 << 31) | 17, 0x1008: (1 << 31) | 18}
    reads = []

    def read(rva, size):
        reads.append(rva)
        return values[rva].to_bytes(size, "little")

    pe = SimpleNamespace(arch=32, image_size=0x4000, get_data=read)
    entry = SimpleNamespace(struct=SimpleNamespace(OriginalFirstThunk=0x1000, FirstThunk=0x2000))
    budget = [2]
    slots = PeLoader(strict=strict)._static_import_slots(pe, entry, (), budget)
    if strict:
        with pytest.raises(ValueError, match="function name lies outside"):
            next(slots)
        assert budget == [1]
        assert reads == [0x1000]
    else:
        accepted = list(slots)
        assert [(slot, symbol.ordinal) for slot, symbol in accepted] == [(0x2004, 17)]
        assert budget == [0]
        assert reads == [0x1000, 0x1004, 0x1008]
        assert "Import function name lies outside the image" in caplog.text
        assert "Import symbol limit exceeded" in caplog.text


@pytest.mark.parametrize("strict", [False, True])
def test_loader_initializes_MAX_plus_one_slot_budget(strict, monkeypatch, caplog):
    raw, data = _make_delay_import_pe(32)
    raw = bytearray(raw)
    directory_offset = pefile.PE(data=bytes(raw)).OPTIONAL_HEADER.DATA_DIRECTORY[13].get_file_offset()
    struct.pack_into("<II", raw, directory_offset, 0, 0)
    for index, value in enumerate(((1 << 31) | 1, (1 << 31) | 2, (1 << 31) | 3, 0)):
        struct.pack_into("<I", raw, data + 0x300 + index * 4, value)
    monkeypatch.setattr(pefile, "MAX_IMPORT_SYMBOLS", 2)
    image = PeLoader(data=bytes(raw), strict=strict).make_image()
    assert [(entry.func_name, entry.iat_address - image.image_base) for entry in image.imports] == [
        ("ordinal_1", data + 0x340),
        ("ordinal_2", data + 0x344),
        ("ordinal_3", data + 0x348),
    ]
    assert "Import symbol limit exceeded" not in caplog.text


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("rebased", [False, True])
@pytest.mark.parametrize("oft_zero", [False, True])
@pytest.mark.parametrize("reserved", ["low", "high"])
def test_raw_ordinal_reserved_bits_are_not_masked_to_valid_ordinal(architecture, rebased, oft_zero, reserved, caplog):
    raw, data = two_static_names(architecture, oft_zero=oft_zero)
    raw = bytearray(raw)
    width = architecture // 8
    table = data + (0x340 if oft_zero else 0x300)
    reserved_bit = 16 if reserved == "low" else architecture - 2
    invalid = (1 << (architecture - 1)) | (1 << reserved_bit) | 17
    struct.pack_into("<I" if architecture == 32 else "<Q", raw, table, invalid)
    raw = bytes(raw)
    expected = pefile.PE(data=raw)
    if reserved == "low":
        assert not getattr(expected, "DIRECTORY_ENTRY_IMPORT", ())  # pefile rejects 0x80010011.
    base_override = 0x60000000 if rebased else None
    if rebased:
        expected.relocate_image(base_override)
    image = PeLoader(data=raw, base_override=base_override).make_image()
    static = [entry for entry in image.imports if entry.source == "static"]
    assert [(entry.func_name, entry.iat_address - image.image_base) for entry in static] == [
        ("Survivor", data + 0x340 + width)
    ]
    assert "Invalid ordinal import reserved bits" in caplog.text
    assert image.regions[0].data == expected.get_memory_mapped_image()[: image.image_size]
    with pytest.raises(ValueError, match="ordinal import reserved bits"):
        PeLoader(data=raw, base_override=base_override, strict=True).make_image()


def fallback_iat_pe(architecture, kind, *, first=b"Normal", survivor_ordinal=False):
    raw, data = two_static_names(architecture, first=first, oft_zero=True, survivor_ordinal=survivor_ordinal)
    raw = bytearray(raw)
    image_size = pefile.PE(data=bytes(raw)).OPTIONAL_HEADER.SizeOfImage
    preferred = data + 0x300 if kind == "empty" else image_size + 0x1000
    struct.pack_into("<I", raw, data + 0x40, preferred)
    # The former lookup table is empty; all symbols are now in the valid IAT.
    struct.pack_into("<I" if architecture == 32 else "<Q", raw, data + 0x300, 0)
    return bytes(raw), data


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("rebased", [False, True])
@pytest.mark.parametrize("kind", ["empty", "outside"])
@pytest.mark.parametrize("survivor_ordinal", [False, True])
@pytest.mark.parametrize("strict", [False, True])
def test_nonzero_oft_honors_pefile_iat_fallback(architecture, rebased, kind, survivor_ordinal, strict, caplog):
    raw, data = fallback_iat_pe(architecture, kind, survivor_ordinal=survivor_ordinal)
    pe = pefile.PE(data=raw)
    width = architecture // 8
    parsed = pe.DIRECTORY_ENTRY_IMPORT[0].imports
    assert [entry.thunk_rva for entry in parsed] == [data + 0x340, data + 0x340 + width]
    base_override = 0x60000000 if rebased else None
    if rebased:
        pe.relocate_image(base_override)
    assert [entry.address for entry in parsed] == [
        pe.OPTIONAL_HEADER.ImageBase + data + 0x340,
        pe.OPTIONAL_HEADER.ImageBase + data + 0x340 + width,
    ]
    image = PeLoader(data=raw, base_override=base_override, strict=strict).make_image()
    assert [
        (entry.func_name, entry.iat_address - image.image_base) for entry in image.imports if entry.source == "static"
    ] == [
        ("Normal", data + 0x340),
        ("ordinal_17" if survivor_ordinal else "Survivor", data + 0x340 + width),
    ]
    assert image.regions[0].data == pe.get_memory_mapped_image()[: image.image_size]
    assert "Skipping malformed PE static import" not in caplog.text


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("rebased", [False, True])
@pytest.mark.parametrize("kind", ["empty", "outside"])
def test_fallback_iat_filtered_name_keeps_original_slot(architecture, rebased, kind, caplog):
    raw, data = fallback_iat_pe(architecture, kind, first=b"\xe9Bad")
    pe = pefile.PE(data=raw)
    width = architecture // 8
    parsed = pe.DIRECTORY_ENTRY_IMPORT[0].imports
    assert len(parsed) == 1
    assert parsed[0].thunk_rva == data + 0x340 + width
    base_override = 0x60000000 if rebased else None
    image = PeLoader(data=raw, base_override=base_override).make_image()
    assert [
        (entry.func_name, entry.iat_address - image.image_base) for entry in image.imports if entry.source == "static"
    ] == [("Survivor", data + 0x340 + width)]
    assert "Skipping malformed PE static import entry" in caplog.text
    with pytest.raises(UnicodeDecodeError):
        PeLoader(data=raw, base_override=base_override, strict=True).make_image()


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("rebased", [False, True])
@pytest.mark.parametrize("all_filtered", [False, True])
def test_populated_malformed_name_oft_is_not_redirected_to_valid_iat(architecture, rebased, all_filtered, caplog):
    raw, data = two_static_names(architecture, first=b"\xe9Bad")
    raw = bytearray(raw)
    width = architecture // 8
    fmt = "<I" if architecture == 32 else "<Q"
    normal_iat_name = b"\0\0GoodIat\0"
    raw[data + 0x1C0 : data + 0x1C0 + len(normal_iat_name)] = normal_iat_name
    for index, value in enumerate((data + 0x1C0, (1 << (architecture - 1)) | 18, 0)):
        struct.pack_into(fmt, raw, data + 0x340 + index * width, value)
    if all_filtered:
        raw[data + 0x1A2] = 0xFF
    raw = bytes(raw)
    pe = pefile.PE(data=raw)
    parsed = getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
    if all_filtered:
        assert not parsed
    else:
        assert parsed[0].imports[0].thunk_rva == data + 0x300 + width
    base_override = 0x60000000 if rebased else None
    image = PeLoader(data=raw, base_override=base_override).make_image()
    assert [
        (entry.func_name, entry.iat_address - image.image_base) for entry in image.imports if entry.source == "static"
    ] == ([] if all_filtered else [("Survivor", data + 0x340 + width)])
    assert "Skipping malformed PE static import entry" in caplog.text
    with pytest.raises(UnicodeDecodeError):
        PeLoader(data=raw, base_override=base_override, strict=True).make_image()
