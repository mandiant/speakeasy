from speakeasy import Speakeasy


def test_strings_in_a_large_zero_filled_heap_block_keep_their_offsets(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    base = emu.mem_map(0x4000000, tag="api.heap.test")
    emu.mem_write(base + 0x2000001, b"needle-ansi\x00")
    emu.mem_write(base + 0x3000000, "wide-needle".encode("utf-16le"))
    ansi, unicode = emu.get_mem_strings()
    assert (0x2000001, "needle-ansi") in ansi
    assert (0x3000000, "wide-needle") in unicode
