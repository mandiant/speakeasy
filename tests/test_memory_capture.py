import copy

import pytest

from speakeasy import Speakeasy


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


def test_heap_regions_excluded(report_with_dumps):
    for ep in report_with_dumps.entry_points:
        if ep.memory:
            for region in ep.memory.layout:
                if region.tag.startswith("api.heap") or region.tag == "emu.process_heap":
                    assert region.data_ref is None


def test_report_data_deduplicates_repeated_regions(report_with_dumps):
    region_refs = [
        region.data_ref
        for ep in report_with_dumps.entry_points
        for region in (ep.memory.layout if ep.memory else [])
        if region.data_ref is not None
    ]
    assert len(set(region_refs)) < len(region_refs)
