import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.common import EMU_RESERVED, EMU_RESERVED_END


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_no_memory_is_mapped_in_the_first_64_kb(config, arch):
    config["timeout"] = 2
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch=arch)
        se.run_shellcode(base)
        for _ in range(32):
            se.mem_alloc(0x100)
            se.mem_alloc(0x1000)
        assert min(start for start, _, _ in se.emu.get_mem_regions()) >= 0x10000
    finally:
        se.shutdown()


@pytest.mark.parametrize("arch, code", [("x86", "31c0c3"), ("amd64", "4831c0c3")])
def test_allocations_do_not_cover_the_return_hook(config, arch, code):
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=bytes.fromhex(code), arch=arch)
        block = se.mem_alloc(0x200000, base=0xFEE00000)
        assert not block <= EMU_RESERVED < block + 0x200000
        assert not se.emu.is_address_valid(EMU_RESERVED)
        se.run_shellcode(base)
        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 0
    finally:
        se.shutdown()


@pytest.mark.parametrize("access, insn", [("read", b"\x8b\x07"), ("write", b"\x89\x07")])
def test_access_across_the_end_of_the_reserved_range_faults_past_its_end(config, access, insn):
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x100, arch="x86")
        # mov edi, EMU_RESERVED_END - 3; mov eax, [edi] or mov [edi], eax
        se.mem_write(base, b"\xbf" + struct.pack("<I", EMU_RESERVED_END - 3) + insn + b"\xc3")

        se.run_shellcode(base)

        error = se.get_report().entry_points[0].error
        assert (error.type, error.address) == (f"invalid_{access}", EMU_RESERVED_END)
