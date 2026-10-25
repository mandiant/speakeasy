"""imagehlp handlers return what Windows returns and write what Windows writes."""

import struct

import pefile
import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call
from tests.pe_builder import build_pe


@pytest.mark.parametrize("stored", [0, 0x12345678, 0xFFFFFFFF])
def test_check_sum_mapped_file_computes_the_pe_checksum(dll_emu: Speakeasy, stored: int) -> None:
    image = bytearray(build_pe(32, text=b"\x90" * 0x123 + b"\xc3", data=b"\x5a" * 0x77)[0])
    struct.pack_into("<I", image, 0x80 + 24 + 64, stored)
    base = alloc(dll_emu, bytes(image))
    sums = alloc(dll_emu, b"\xcc" * 8)

    rv, _ = call(dll_emu, "imagehlp", "CheckSumMappedFile", [base, len(image), sums, sums + 4])

    assert rv == base + 0x80
    assert struct.unpack("<II", dll_emu.mem_read(sums, 8)) == (
        stored,
        pefile.PE(data=bytes(image)).generate_checksum(),
    )


def test_check_sum_mapped_file_returns_null_for_data_that_is_not_a_pe(dll_emu: Speakeasy) -> None:
    data = alloc(dll_emu, b"\x00" * 0x200)
    sums = alloc(dll_emu, b"\xcc" * 8)

    rv, _ = call(dll_emu, "imagehlp", "CheckSumMappedFile", [data, 0x200, sums, sums + 4])

    assert rv == 0
    assert dll_emu.mem_read(sums, 8) == b"\xcc" * 8
