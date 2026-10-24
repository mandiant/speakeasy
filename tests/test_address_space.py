import pytest

from speakeasy import Speakeasy


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
