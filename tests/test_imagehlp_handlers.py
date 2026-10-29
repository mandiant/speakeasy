"""imagehlp handlers return what Windows returns and write what Windows writes."""

import struct
from collections.abc import Callable

import pefile
import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call
from tests.pma_harness import PMA_DIR


@pytest.mark.parametrize(
    "name",
    [
        "dll_test_x86.dll.xz",
        "Practical Malware Analysis Lab 18-03.exe_",
        "Practical Malware Analysis Lab 10-03.sys_",
        "Practical Malware Analysis Lab 21-01.exe_",
    ],
)
def test_check_sum_mapped_file_computes_the_pe_checksum(
    dll_emu: Speakeasy, load_test_bin: Callable[[str], bytes], name: str
) -> None:
    if name.endswith(".xz"):
        image = load_test_bin(name)
    elif (PMA_DIR / name).is_file():
        image = (PMA_DIR / name).read_bytes()
    else:
        pytest.skip("capa-testfiles is not checked out")
    pe = pefile.PE(data=image)
    base = alloc(dll_emu, image)
    sums = alloc(dll_emu, b"\xcc" * 8)

    rv, _ = call(dll_emu, "imagehlp", "CheckSumMappedFile", [base, len(image), sums, sums + 4])

    assert rv == base + pe.DOS_HEADER.e_lfanew
    assert struct.unpack("<II", dll_emu.mem_read(sums, 8)) == (pe.OPTIONAL_HEADER.CheckSum, pe.generate_checksum())
