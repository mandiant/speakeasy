import pytest

from speakeasy import Speakeasy
from speakeasy.windows.common import EMU_RESERVED


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
