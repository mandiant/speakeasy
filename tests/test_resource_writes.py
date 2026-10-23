"""Writes to the read-only resource data of an image."""

import struct

import pefile

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe

RESOURCE_RVA = 0x3000


def build_writer_pe(target_rva):
    base = 0x400000
    code = b"\xc7\x05" + struct.pack("<II", base + target_rva, 0x11223344) + b"\xc3"
    image, _ = build_pe(32, text=code, extra_dirs={2: (RESOURCE_RVA, 0x10)})
    pe = pefile.PE(data=image)
    pe.sections[2].Characteristics = 0x40000040
    return pe.write()


def test_write_to_resource_data_makes_the_resource_pages_writable():
    with Speakeasy(config=get_default_config_dict()) as se:
        module = se.load_module(data=build_writer_pe(RESOURCE_RVA + 8))
        se.run_module(module)

        assert [entry.error for entry in se.get_report().entry_points] == [None]
        assert se.mem_read(module.base + RESOURCE_RVA + 8, 4) == struct.pack("<I", 0x11223344)


def test_write_to_other_read_only_data_still_faults():
    with Speakeasy(config=get_default_config_dict()) as se:
        module = se.load_module(data=build_writer_pe(0x1F00))
        se.run_module(module)

        [entry] = se.get_report().entry_points
        assert entry.error is not None and entry.error.type == "invalid_protect_write"
