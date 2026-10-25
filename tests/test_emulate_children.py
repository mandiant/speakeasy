"""Child processes run after the parent when emulate_children is set."""

import struct

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


def build_child() -> bytes:
    return build_pe(32, text=b"\xb8" + struct.pack("<I", CHILD_RESULT) + b"\xc3")[0]


def test_child_exe_runs_at_the_base_of_the_parent_exe(config):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_parent())
        assert se.emu is not None
        se.emu.fileman.add_existing_file(CHILD_PATH, build_child())
        se.run_module(module, emulate_children=True)
        entries = se.get_report().entry_points

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
