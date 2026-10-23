"""Static TLS data of the main module."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe

TEMPLATE = bytes(range(0x11, 0x19))
ZERO_FILL = 8


def build_tls_pe(arch):
    is64 = arch == 64
    width = arch // 8
    base = 0x140000000 if is64 else 0x400000
    template_rva, index_rva, block_rva, callbacks_rva, tls_rva = 0x1800, 0x2000, 0x2010, 0x2020, 0x2100

    def text(base, iat):
        if is64:
            code = b"\x65\x48\x8b\x04\x25\x58\x00\x00\x00"
            code += b"\x48\x8b\x00"
            code += b"\xc7\x40\x0c" + struct.pack("<I", 0x12345678)
            code += b"\xc7\x00" + struct.pack("<I", 0xDDCCBBAA)
            code += b"\x48\x89\x05" + struct.pack("<i", block_rva - (0x1000 + len(code) + 7))
        else:
            code = b"\x64\xa1\x2c\x00\x00\x00"
            code += b"\x8b\x00"
            code += b"\xc7\x40\x0c" + struct.pack("<I", 0x12345678)
            code += b"\xc7\x00" + struct.pack("<I", 0xDDCCBBAA)
            code += b"\xa3" + struct.pack("<I", base + block_rva)
        code += b"\xc3"
        offset = template_rva - 0x1000
        return code.ljust(offset, b"\xcc") + TEMPLATE

    tls = struct.pack(
        "<4QII" if is64 else "<6I",
        base + template_rva,
        base + template_rva + len(TEMPLATE),
        base + index_rva,
        base + callbacks_rva,
        ZERO_FILL,
        0,
    )
    data = bytearray(0x200)
    struct.pack_into("<I", data, index_rva - 0x2000, 0x7F)
    data[tls_rva - 0x2000 : tls_rva - 0x2000 + len(tls)] = tls
    image, _ = build_pe(arch, text=text, data=bytes(data), extra_dirs={9: (tls_rva, len(tls))})
    return image, width, block_rva, index_rva, template_rva


@pytest.mark.parametrize("arch", [32, 64])
def test_main_module_tls_slot_is_a_writable_copy_of_the_template(arch):
    image, width, block_rva, index_rva, template_rva = build_tls_pe(arch)
    with Speakeasy(config=get_default_config_dict()) as se:
        module = se.load_module(data=image)
        se.run_module(module)

        assert [entry.error for entry in se.get_report().entry_points] == [None]
        block = int.from_bytes(se.mem_read(module.base + block_rva, width), "little")
        assert block not in (0, module.base + template_rva)
        assert se.mem_read(block, len(TEMPLATE) + ZERO_FILL) == (
            struct.pack("<I", 0xDDCCBBAA) + TEMPLATE[4:] + b"\0" * 4 + struct.pack("<I", 0x12345678)
        )
        assert se.mem_read(module.base + template_rva, len(TEMPLATE)) == TEMPLATE
        assert se.mem_read(module.base + index_rva, 4) == b"\0\0\0\0"
