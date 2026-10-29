"""Temporary pages mapped to recover from a fault leave no memory map behind."""

import copy

from speakeasy import Speakeasy

# fault: xor eax, eax; mov eax, [eax]; ret
# ok: nop; ret
_SC_FAULT_THEN_OK = b"\x31\xc0\x8b\x00\xc3" + b"\x90" * 3 + b"\x90\xc3"


def test_fault_page_is_released_with_its_map(base_config) -> None:
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        addr = se.load_shellcode(data=_SC_FAULT_THEN_OK, arch="x86")
        se.run_shellcode(addr)
        se.call(addr + 8)
        assert se.get_address_map(0) is None
        assert not se.is_address_valid(0)
        se.mem_free(0)
    finally:
        se.shutdown()
