import struct

from speakeasy import Speakeasy
from tests.pe_builder import build_pe


def test_strings_in_a_large_zero_filled_heap_block_keep_their_offsets(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    base = emu.mem_map(0x4000000, tag="api.heap.test")
    emu.mem_write(base + 0x2000001, b"needle-ansi\x00")
    emu.mem_write(base + 0x3000000, "wide-needle".encode("utf-16le"))
    ansi, unicode = emu.get_mem_strings()
    assert (0x2000001, "needle-ansi") in ansi
    assert (0x3000000, "wide-needle") in unicode


def test_a_string_that_repeats_part_of_an_earlier_string_gets_its_own_offset(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    assert emu.get_ansi_strings(b"ABCDABCD\x00ABCD") == [(0, "ABCDABCD"), (9, "ABCD")]
    wide = "ABCDABCD\x00ABCD".encode("utf-16le")
    assert emu.get_unicode_strings(wide) == [(0, "ABCDABCD"), (18, "ABCD")]


def test_strings_that_the_guest_decodes_in_its_own_image_are_in_memory_strings(config) -> None:
    config["memory"]["strings"] = True
    marker = b"IMAGE_DECODED_MARKER"
    literal = b"IMAGE_STATIC_LITERAL"
    key = 0x55
    data_va = 0x400000 + 0x2000
    # mov esi, data_va; mov ecx, len; xor byte [esi], key; inc esi; loop; ret
    code = b"\xbe" + struct.pack("<I", data_va) + b"\xb9" + struct.pack("<I", len(marker))
    code += b"\x80\x36" + bytes([key]) + b"\x46\xe2\xfa\xc3"
    data = bytes(b ^ key for b in marker) + b"\0" + literal + b"\0"
    image, _ = build_pe(32, text=code, data=data)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=image)
        se.run_module(module)

        report = se.get_report()
        assert [entry.error for entry in report.runs] == [None]
        assert report.strings is not None
        assert literal.decode() in report.strings.static.ansi
        assert marker.decode() in report.strings.in_memory.ansi
        assert literal.decode() not in report.strings.in_memory.ansi
        assert ".text" not in report.strings.in_memory.ansi
