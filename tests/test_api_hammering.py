"""The API hammering mitigation patches x86 call sites so that they return 0 without the API call."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe

ABS = {"msvcrt.dll": ["abs"]}
LOOPS = 5
THRESHOLD = 2


def hammer_loop(indirect: bool):
    """
    Call msvcrt.abs(42) LOOPS times from one call site, then return the stack drift in eax.

    edi gets the sum of the return values.
    """

    def text(base, iat):
        target = base + iat["msvcrt.dll", "abs"]
        code = b"\xbb" + struct.pack("<I", LOOPS)  # mov ebx, LOOPS
        code += b"\x8b\x35" + struct.pack("<I", target)  # mov esi, [abs]
        code += b"\x31\xff"  # xor edi, edi
        code += b"\x89\xe5"  # mov ebp, esp
        loop = len(code)
        code += b"\x6a\x2a"  # push 42
        code += b"\xff\xd6" if indirect else b"\xff\x15" + struct.pack("<I", target)  # call esi / call [abs]
        code += b"\x83\xc4\x04"  # add esp, 4
        code += b"\x01\xc7"  # add edi, eax
        code += b"\x4b"  # dec ebx
        code += b"\x75" + struct.pack("<b", loop - (len(code) + 2))  # jnz loop
        code += b"\x89\xe8"  # mov eax, ebp
        code += b"\x29\xe0"  # sub eax, esp
        return code + b"\xc3"

    return text


@pytest.mark.parametrize("indirect", [False], ids=["call_mem"])
def test_a_patched_cdecl_call_site_keeps_the_caller_code(indirect: bool) -> None:
    config = get_default_config_dict()
    config["api_hammering"] = {"enabled": True, "threshold": THRESHOLD}
    data, _ = build_pe(32, text=hammer_loop(indirect), imports=ABS)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None
        # The loop ran to the end, only the calls before the patch called abs, and the stack is balanced.
        assert se.reg_read("ebx") == 0
        assert se.reg_read("edi") == 42 * THRESHOLD
        assert se.reg_read("eax") == 0
