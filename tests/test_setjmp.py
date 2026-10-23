"""setjmp and longjmp of the C runtime transfer control the way the guest expects."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe

BUF_RVA = 0x2000
RESULT_RVA = 0x2100


def build_x86(setjmp):
    def text(base, iat):
        code = bytearray()
        code += b"\xbe" + struct.pack("<I", 0x1111)
        code += b"\x68" + struct.pack("<I", base + BUF_RVA)
        code += b"\xff\x15" + struct.pack("<I", base + iat["msvcrt.dll", setjmp])
        code += b"\x83\xc4\x04\x85\xc0\x75\x00"
        jnz = len(code)
        code += b"\xbe" + struct.pack("<I", 0x2222)
        code += b"\x6a\x07\x68" + struct.pack("<I", base + BUF_RVA)
        code += b"\xff\x15" + struct.pack("<I", base + iat["msvcrt.dll", "longjmp"])
        code += b"\xcc"
        code[jnz - 1] = len(code) - jnz
        code += b"\xa3" + struct.pack("<I", base + RESULT_RVA)
        code += b"\x89\x35" + struct.pack("<I", base + RESULT_RVA + 8)
        return bytes(code + b"\xc3")

    return text


def build_x64(setjmp):
    def text(base, iat):
        code = bytearray()

        def rip(target, length):
            return struct.pack("<i", target - (0x1000 + len(code) + length))

        code += b"\x48\x83\xec\x28\xbe" + struct.pack("<I", 0x1111)
        code += b"\x48\x8d\x0d" + rip(BUF_RVA, 7)
        code += b"\x31\xd2"
        code += b"\xff\x15" + rip(iat["msvcrt.dll", setjmp], 6)
        code += b"\x85\xc0\x75\x00"
        jnz = len(code)
        code += b"\xbe" + struct.pack("<I", 0x2222)
        code += b"\x48\x8d\x0d" + rip(BUF_RVA, 7)
        code += b"\xba\x07\x00\x00\x00"
        code += b"\xff\x15" + rip(iat["msvcrt.dll", "longjmp"], 6)
        code += b"\xcc"
        code[jnz - 1] = len(code) - jnz
        code += b"\x89\x05" + rip(RESULT_RVA, 6)
        code += b"\x48\x89\x35" + rip(RESULT_RVA + 8, 7)
        return bytes(code + b"\x48\x83\xc4\x28\xc3")

    return text


@pytest.mark.parametrize(
    "arch, setjmp",
    [(32, "_setjmp"), (32, "_setjmp3"), (64, "_setjmp"), (64, "__intrinsic_setjmp"), (64, "_setjmpex")],
)
def test_longjmp_returns_from_setjmp_with_the_saved_registers(arch, setjmp):
    build = build_x86 if arch == 32 else build_x64
    image, _ = build_pe(arch, text=build(setjmp), data=b"\0" * 0x200, imports={"msvcrt.dll": [setjmp, "longjmp"]})
    with Speakeasy(config=get_default_config_dict()) as se:
        module = se.load_module(data=image)
        se.run_module(module)

        entry = se.get_report().entry_points[0]
        assert entry.error is None
        assert struct.unpack(
            "<II", se.mem_read(module.base + RESULT_RVA, 4) + se.mem_read(module.base + RESULT_RVA + 8, 4)
        ) == (
            7,
            0x1111,
        )
