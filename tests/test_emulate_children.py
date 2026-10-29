"""Child processes run after the parent when emulate_children is set."""

import hashlib
import logging
import struct

import pefile

from speakeasy import Speakeasy
from tests.pe_builder import build_pe

CHILD_PATH = "c:\\child.exe"
CHILD_RESULT = 7


def build_parent(path: str = CHILD_PATH) -> bytes:
    def text(base, iat):
        app_name, startup_info, process_info = base + 0x2000, base + 0x2100, base + 0x2200
        code = b"\x68" + struct.pack("<I", process_info)
        code += b"\x68" + struct.pack("<I", startup_info)
        code += b"\x6a\x00" * 7
        code += b"\x68" + struct.pack("<I", app_name)
        code += b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "CreateProcessA"])
        return code + b"\xc3"

    data = bytearray(0x300)
    data[: len(path) + 1] = path.encode() + b"\0"
    struct.pack_into("<I", data, 0x100, 68)
    return build_pe(32, text=text, data=bytes(data), imports={"kernel32.dll": ["CreateProcessA"]})[0]


def build_child(base: int | None = None) -> bytes:
    data = build_pe(32, text=b"\xb8" + struct.pack("<I", CHILD_RESULT) + b"\xc3")[0]
    if base is None:
        return data
    pe = pefile.PE(data=data)
    pe.OPTIONAL_HEADER.ImageBase = base
    return bytes(pe.write())


def test_child_exe_runs_at_the_base_of_the_parent_exe(config):
    parent = build_parent()
    with Speakeasy(config=config) as se:
        module = se.load_module(data=parent)
        assert se.emu is not None
        se.emu.fileman.add_existing_file(CHILD_PATH, build_child())
        se.run_module(module, emulate_children=True)
        child = se.emu.get_mod_from_addr(module.base)
        report = se.get_report()
        entries = report.entry_points

    assert (child.name, child.emu_path) == ("child", CHILD_PATH)
    assert report.sha256 == hashlib.sha256(parent).hexdigest()

    assert [(ep.ep_type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[0].ret_val == 1
    assert entries[1].ret_val == CHILD_RESULT
    assert entries[0].pid != entries[1].pid


def test_child_without_an_image_is_skipped(config):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_parent("c:\\missing\\program.dat"))
        se.run_module(module, emulate_children=True)
        report = se.get_report()

    assert [(ep.ep_type, ep.error) for ep in report.entry_points] == [("module_entry", None)]
    assert report.entry_points[0].start_addr == module.base + module.ep
    assert report.entry_points[0].ret_val == 1


def test_child_whose_base_is_in_use_is_skipped(config, caplog):
    base = 0x10000000
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_parent())
        assert se.emu is not None
        se.emu.fileman.add_existing_file(CHILD_PATH, build_child(base))
        se.emu.mem_map(0x1000, base=base, tag="test.block")
        with caplog.at_level(logging.WARNING):
            se.run_module(module, emulate_children=True)
        report = se.get_report()

    assert [(ep.ep_type, ep.error) for ep in report.entry_points] == [("module_entry", None)]
    assert f"skipping child process {CHILD_PATH}" in caplog.text
    assert "address range is in use" in caplog.text
