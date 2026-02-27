import base64
import copy
import zlib

import pytest

from speakeasy import Speakeasy


@pytest.fixture(scope="module")
def report_with_dumps(base_config, load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")

    cfg = copy.deepcopy(base_config)
    cfg["capture_memory_dumps"] = True
    cfg["analysis"] = dict(cfg.get("analysis", {}))
    cfg["analysis"]["memory_tracing"] = True

    se = Speakeasy(config=cfg)
    try:
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        return se.get_report()
    finally:
        se.shutdown()


def test_report_has_regions_with_data(report_with_dumps):
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.data is not None:
                    return
    pytest.fail("No memory regions with data found in report")


def test_captured_data_decompresses(report_with_dumps):
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.data is not None:
                    raw = base64.b64decode(region.data)
                    decompressed = zlib.decompress(raw)
                    assert len(decompressed) == region.size


def test_stack_regions_excluded(report_with_dumps):
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.tag.startswith("emu.stack"):
                    assert region.data is None, f"Stack region {region.tag} should not have data"


def test_heap_regions_excluded(report_with_dumps):
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.tag.startswith("api.heap") or region.tag == "emu.process_heap":
                    assert region.data is None, f"Heap region {region.tag} should not have data"


def test_unwritten_regions_included(report_with_dumps):
    found_unwritten_with_data = False
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.accesses and region.accesses.writes == 0:
                    if region.tag.startswith(("emu.stack", "api.heap", "emu.process_heap")):
                        continue
                    if region.data is not None:
                        found_unwritten_with_data = True
    assert found_unwritten_with_data, "Expected at least one unwritten non-excluded region with data"
