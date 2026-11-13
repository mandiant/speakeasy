import base64
import copy
import struct
import zlib

import pytest

from speakeasy import Speakeasy
from tests.pe_builder import build_pe
from tests.test_static_tls import TEMPLATE, build_tls_pe


@pytest.fixture(scope="module")
def report_with_dumps(base_config, load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")

    cfg = copy.deepcopy(base_config)
    cfg["memory"]["final_contents"] = True
    cfg["memory"]["accesses"] = True

    se = Speakeasy(config=cfg)
    try:
        module = se.load_module(data=data)
        se.run_module(module)
        return se.get_report()
    finally:
        se.shutdown()


def get_region_contents(report, region) -> bytes:
    return zlib.decompress(base64.b64decode(report.data[region.data_ref].data))


def test_captured_data_refs_resolve(report_with_dumps):
    assert report_with_dumps.data

    for ep in report_with_dumps.runs:
        if ep.memory:
            for region in ep.memory.layout:
                if region.data_ref is not None:
                    assert region.data_ref in report_with_dumps.data
                    assert report_with_dumps.data[region.data_ref].size == region.size


def test_stack_regions_excluded(report_with_dumps):
    for ep in report_with_dumps.runs:
        if ep.memory:
            for region in ep.memory.layout:
                if (region.tag or "").startswith("emu.stack"):
                    assert region.data_ref is None


def test_only_guest_memory_has_contents(report_with_dumps):
    run = report_with_dumps.runs[0]
    image = run.memory.modules[0].name
    layout = run.memory.layout

    assert all(region.data_ref for region in layout if region.module == image)
    assert any(region.module == "kernel32.dll" for region in layout)
    assert not [region for region in layout if region.module not in (None, image) and region.data_ref]
    assert not [
        region
        for region in layout
        if (region.tag or "").startswith("emu.")
        and not (region.tag or "").startswith("emu.tls.")
        and region.module is None
        and region.data_ref
    ]
    assert any(region.tag == "emu.struct.PEB" for region in layout)


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
    config["memory"]["final_contents"] = True
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        report = se.get_report()

    heap_blocks = [r for r in report.runs[0].memory.layout if r.tag == "api.heap.HeapAlloc"]
    assert heap_blocks
    assert all(r.data_ref for r in heap_blocks)
    contents = [get_region_contents(report, r) for r in heap_blocks]
    assert any(c.startswith(payload) for c in contents)


def test_untagged_api_allocation_captured(config):
    text_value = "allocated by an API handler".encode("utf-16le")

    def text(base, iat):
        code = b"\x68" + struct.pack("<I", len(text_value) // 2)  # push length
        code += b"\x68" + struct.pack("<I", base + 0x2000)  # push .data
        code += b"\xff\x15" + struct.pack("<I", base + iat["oleaut32.dll", "SysAllocStringLen"])
        return code + b"\xc3"

    data, _ = build_pe(32, text=text, data=text_value, imports={"oleaut32.dll": ["SysAllocStringLen"]})
    config["memory"]["final_contents"] = True
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        report = se.get_report()

    untagged = [r for r in report.runs[0].memory.layout if r.tag is None and r.module is None]
    assert untagged
    assert all(r.data_ref for r in untagged)
    assert any(text_value in get_region_contents(report, r) for r in untagged)


def test_static_tls_data_captured(config):
    image, *_ = build_tls_pe(32)
    config["memory"]["final_contents"] = True
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=image))
        report = se.get_report()

    tls = [r for r in report.runs[0].memory.layout if (r.tag or "").startswith("emu.tls.")]
    assert {r.tag.endswith(".data") for r in tls} == {True, False}
    assert all(r.data_ref for r in tls)
    data_block = next(r for r in tls if r.tag.endswith(".data"))
    assert TEMPLATE[4:] in get_region_contents(report, data_block)


def test_report_data_deduplicates_repeated_regions(report_with_dumps):
    region_refs = [
        region.data_ref
        for ep in report_with_dumps.runs
        for region in (ep.memory.layout if ep.memory else [])
        if region.data_ref is not None
    ]
    assert len(set(region_refs)) < len(region_refs)


def test_region_permissions_are_permission_strings(report_with_dumps):
    regions = [region for ep in report_with_dumps.runs for region in (ep.memory.layout if ep.memory else [])]

    assert {region.permissions for region in regions} <= {"---", "r--", "-w-", "--x", "rw-", "r-x", "-wx", "rwx"}
    eprocess = [region for region in regions if region.tag == "emu.struct.EPROCESS"]
    assert eprocess
    assert all(region.permissions == "rwx" for region in eprocess)
