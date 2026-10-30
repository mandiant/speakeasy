"""Static TLS data of the main module."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.windows.loaders import PeLoader
from tests.pe_builder import build_pe

TEMPLATE = bytes(range(0x11, 0x19))
ZERO_FILL = 8

DUMPED_DLL = "028d0275c553456244ff1de023beb83e245ca208304eeaad9ba476d7c896b2c8.dll.xz"
UPX_EXE = "03018edf97807729c7e94c782f14546fe6b64cc01a6890ae6347329681dd83e4.exe.xz"


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


def test_unreadable_tls_callback_array_does_not_stop_the_load(load_test_bin):
    """
    028d0275 is a 64-bit DLL dumped from memory. Its TLS directory holds runtime pointers, so
    AddressOfCallBacks is 0x25a9af75daa, far outside the image at 0x180000000.
    """
    image = PeLoader(data=load_test_bin(DUMPED_DLL)).make_image()

    assert image.tls_callbacks == []
    assert image.entry_points == [0x85618]


def test_tls_directory_past_the_raw_end_of_its_section_is_read_from_the_mapped_image(load_test_bin):
    """
    03018edf is packed with UPX. Its 24-byte TLS directory starts at RVA 0x1dff4, 12 bytes before
    the raw end of UPX1 at 0x1e000, so the rest of it is in the zero-filled tail of the section.
    """
    image = PeLoader(data=load_test_bin(UPX_EXE)).make_image()

    assert image.tls_directory == 0x1DFF4
    assert image.tls_callbacks == []
