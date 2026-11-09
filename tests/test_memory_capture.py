import base64
import copy
import struct
import zlib

import pytest

from speakeasy import Speakeasy
from tests.pe_builder import build_pe


@pytest.fixture(scope="module")
def report_with_dumps(base_config, load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")

    cfg = copy.deepcopy(base_config)
    cfg["snapshot_memory_regions"] = True
    cfg["analysis"] = dict(cfg.get("analysis", {}))
    cfg["analysis"]["memory_tracing"] = True

    se = Speakeasy(config=cfg)
    try:
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        return se.get_report()
    finally:
        se.shutdown()


def test_captured_data_refs_resolve(report_with_dumps):
    assert report_with_dumps.data

    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.data_ref is not None:
                    assert region.data_ref in report_with_dumps.data
                    assert report_with_dumps.data[region.data_ref].size == region.size


def test_stack_regions_excluded(report_with_dumps):
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.tag.startswith("emu.stack"):
                    assert region.data_ref is None


def test_heap_block_captured(config):
    payload = b"MZ\x90\x00" + b"unpacked stage" * 4

    def text(base, iat):
        code = b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "GetProcessHeap"])  # call [GetProcessHeap]
        code += b"\x68" + struct.pack("<I", len(payload))  # push len(payload)
        code += b"\x6a\x00"  # push 0
        code += b"\x50"  # push eax
        code += b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "HeapAlloc"])  # call [HeapAlloc]
        code += b"\x89\xc7"  # mov edi, eax
        code += b"\xbe" + struct.pack("<I", base + 0x2000)  # mov esi, .data
        code += b"\xb9" + struct.pack("<I", len(payload))  # mov ecx, len(payload)
        code += b"\xf3\xa4"  # rep movsb
        return code + b"\xc3"

    data, _ = build_pe(32, text=text, data=payload, imports={"kernel32.dll": ["GetProcessHeap", "HeapAlloc"]})
    config["snapshot_memory_regions"] = True
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        report = se.get_report()

    heap_blocks = [r for r in report.entry_points[0].memory.layout if r.tag.startswith("api.heap.HeapAlloc")]
    assert heap_blocks
    assert all(r.data_ref for r in heap_blocks)
    contents = [zlib.decompress(base64.b64decode(report.data[r.data_ref].data)) for r in heap_blocks]
    assert any(c.startswith(payload) for c in contents)


def test_report_data_deduplicates_repeated_regions(report_with_dumps):
    region_refs = [
        region.data_ref
        for ep in report_with_dumps.entry_points
        for region in (ep.memory.layout if ep.memory else [])
        if region.data_ref is not None
    ]
    assert len(set(region_refs)) < len(region_refs)
