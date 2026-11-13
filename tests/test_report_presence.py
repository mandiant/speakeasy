"""Which report keys are absent, empty or zero."""

import json
import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe


def get_heap_test_pe() -> bytes:
    """Get a PE that allocates two heap blocks of one page and frees the first."""

    def text(base, iat):
        def call(name):
            return b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", name])

        code = call("GetProcessHeap") + b"\x89\xc3"  # mov ebx, eax
        code += b"\x6a\x10\x6a\x00\x53" + call("HeapAlloc") + b"\x89\xc6"  # HeapAlloc(ebx, 0, 16); mov esi, eax
        code += b"\x6a\x10\x6a\x00\x53" + call("HeapAlloc")  # HeapAlloc(ebx, 0, 16)
        code += b"\x56\x6a\x00\x53" + call("HeapFree")  # HeapFree(ebx, 0, esi)
        return code + b"\xc3"

    data, _ = build_pe(32, text=text, imports={"kernel32.dll": ["GetProcessHeap", "HeapAlloc", "HeapFree"]})
    return data


def test_counters_are_present_when_zero():
    with Speakeasy(config=get_default_config_dict()) as se:
        se.run_shellcode(se.load_shellcode(None, "x86", data=b"\xc3"))
        se.call(0x13370000)
        runs = json.loads(se.get_json_report())["runs"]

    assert runs[-1]["error"]["type"] == "invalid_fetch"
    assert runs[-1]["instruction_count"] == 0
    assert runs[-1]["api_call_count"] == 0


def test_freed_marks_each_region_with_freed_regions_on():
    config = get_default_config_dict()
    config["memory"]["freed_regions"] = True
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=get_heap_test_pe()))
        layout = json.loads(se.get_json_report())["runs"][0]["memory"]["layout"]

    assert all("freed" in region for region in layout)
    blocks = [region for region in layout if region.get("tag") == "api.heap.HeapAlloc"]
    assert [region["freed"] for region in blocks] == [True, False]


def test_layout_leaves_out_freed_allocations_with_freed_regions_off():
    config = get_default_config_dict()
    config["memory"]["freed_regions"] = False
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=get_heap_test_pe()))
        freed = [m for m in se.emu.get_mem_maps() if m.free and (m.tag or "").startswith("api.heap.HeapAlloc")]
        layout = json.loads(se.get_json_report())["runs"][0]["memory"]["layout"]

    assert len(freed) == 1, "the freed block stays mapped because the other block of its page is live"
    assert not [region for region in layout if "freed" in region]
    assert any(region.get("tag") == "api.heap.HeapAlloc" for region in layout)
    assert hex(freed[0].base) not in [region["base"] for region in layout]


@pytest.mark.parametrize(("sample", "present"), [("dll_test_x86.dll.xz", True), ("wdm_test_x86.sys.xz", False)])
def test_dropped_files_absent_in_kernel_mode(config, load_test_bin, sample, present):
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=load_test_bin(sample)))
        runs = json.loads(se.get_json_report())["runs"]

    assert runs
    assert all(("dropped_files" in run) == present for run in runs)
