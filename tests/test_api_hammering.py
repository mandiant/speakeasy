"""The API hammering mitigation patches x86 call sites so that they return 0 without the API call."""

import logging
import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe

ABS = {"msvcrt.dll": ["abs"]}
METRICS = {"user32.dll": ["GetSystemMetrics"]}
LOOPS = 5
THRESHOLD = 2


def hammer_loop(form: str, dll: str, name: str, cdecl: bool, arg: int = 42):
    """
    Call the API with ``arg`` LOOPS times from one call site, then return the stack drift in eax.

    edi gets the sum of the return values. ``form`` selects the call instruction: ``call_mem`` is ``call [iat]``,
    ``call_reg`` is ``call esi``, ``call_rel32`` is a direct call to a ``jmp [iat]`` thunk, and ``call_esi_mem``
    is ``call [esi]``.
    """

    def text(base, iat):
        target = base + iat[dll, name]
        code = bytearray(b"\xbb" + struct.pack("<I", LOOPS))  # mov ebx, LOOPS
        code += b"\x8b\x35" + struct.pack("<I", target)  # mov esi, [iat]
        if form == "call_esi_mem":
            code += b"\xbe" + struct.pack("<I", target)  # mov esi, iat
        code += b"\x31\xff"  # xor edi, edi
        code += b"\x89\xe5"  # mov ebp, esp
        loop = len(code)
        code += b"\x6a" + struct.pack("<b", arg)  # push arg
        call_rel32 = len(code)
        code += {
            "call_mem": b"\xff\x15" + struct.pack("<I", target),
            "call_reg": b"\xff\xd6",
            "call_rel32": b"\xe8" + struct.pack("<i", 0),
            "call_esi_mem": b"\xff\x16",
        }[form]
        if cdecl:
            code += b"\x83\xc4\x04"  # add esp, 4
        code += b"\x01\xc7"  # add edi, eax
        code += b"\x4b"  # dec ebx
        code += b"\x75" + struct.pack("<b", loop - (len(code) + 2))  # jnz loop
        code += b"\x89\xe8"  # mov eax, ebp
        code += b"\x29\xe0"  # sub eax, esp
        code += b"\xc3"  # ret
        thunk = len(code)
        code += b"\xff\x25" + struct.pack("<I", target)  # jmp [iat]
        if form == "call_rel32":
            struct.pack_into("<i", code, call_rel32 + 1, thunk - (call_rel32 + 5))
        return bytes(code)

    return text


@pytest.mark.parametrize("form", ["call_mem", "call_reg", "call_rel32"])
def test_a_patched_cdecl_call_site_keeps_the_caller_code(form: str) -> None:
    config = get_default_config_dict()
    config["api_hammering"] = {"enabled": True, "threshold": THRESHOLD}
    data, _ = build_pe(32, text=hammer_loop(form, "msvcrt.dll", "abs", cdecl=True), imports=ABS)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None
        # The loop ran to the end, only the calls before the patch called abs, and the stack is balanced.
        assert se.reg_read("ebx") == 0
        assert se.reg_read("edi") == 42 * THRESHOLD
        assert se.reg_read("eax") == 0


def test_a_patched_stdcall_call_to_a_thunk_removes_the_arguments() -> None:
    config = get_default_config_dict()
    config["api_hammering"] = {"enabled": True, "threshold": THRESHOLD}
    # GetSystemMetrics(SM_CXVSCROLL) returns 17.
    text = hammer_loop("call_rel32", "user32.dll", "GetSystemMetrics", cdecl=False, arg=2)
    data, _ = build_pe(32, text=text, imports=METRICS)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        assert se.get_report().entry_points[0].error is None
        assert se.reg_read("ebx") == 0
        assert se.reg_read("edi") == 17 * THRESHOLD
        assert se.reg_read("eax") == 0


def test_an_unpatchable_call_site_is_logged_once(caplog: pytest.LogCaptureFixture) -> None:
    config = get_default_config_dict()
    config["api_hammering"] = {"enabled": True, "threshold": THRESHOLD}
    data, _ = build_pe(32, text=hammer_loop("call_esi_mem", "msvcrt.dll", "abs", cdecl=True), imports=ABS)
    with Speakeasy(config=config) as se, caplog.at_level(logging.INFO, logger="speakeasy.windows.hammer"):
        module = se.load_module(data=data)
        se.run_module(module)
        assert se.get_report().entry_points[0].error is None
        # Each call went to abs.
        assert se.reg_read("ebx") == 0
        assert se.reg_read("edi") == 42 * LOOPS
        assert se.reg_read("eax") == 0
    assert len([r for r in caplog.records if r.name == "speakeasy.windows.hammer"]) == 1
