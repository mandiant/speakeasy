import copy

import pytest

from speakeasy import Speakeasy

VALID_PROTECTIONS = {"---", "r--", "-w-", "--x", "rw-", "r-x", "-wx", "rwx", "???"}


@pytest.fixture(scope="module")
def memory_report(base_config, load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        return se.get_report()
    finally:
        se.shutdown()


@pytest.fixture(scope="module")
def entry_points_with_memory(memory_report):
    return [ep for ep in memory_report.entry_points if ep.memory is not None]


def test_memory_layout_exists(entry_points_with_memory):
    assert len(entry_points_with_memory) > 0


def test_memory_layout_has_regions(entry_points_with_memory):
    for ep in entry_points_with_memory:
        layout = ep.memory.layout
        assert isinstance(layout, list)
        assert len(layout) > 0

        for region in layout:
            assert region.tag
            assert region.address > 0
            assert region.size > 0
            assert region.prot in VALID_PROTECTIONS


def test_memory_layout_has_modules(entry_points_with_memory):
    for ep in entry_points_with_memory:
        modules = ep.memory.modules
        assert isinstance(modules, list)
        assert len(modules) > 0

        for mod in modules:
            assert mod.name
            assert mod.path is not None
            assert mod.base > 0
            assert mod.size > 0


def test_modules_have_segments(entry_points_with_memory):
    for ep in entry_points_with_memory:
        modules = ep.memory.modules
        modules_with_segments = [module for module in modules if module.segments]
        assert len(modules_with_segments) > 0

        for mod in modules_with_segments:
            for seg in mod.segments:
                assert seg.name
                assert seg.address > 0
                assert seg.size > 0
                assert seg.prot in VALID_PROTECTIONS


def test_module_segments_within_module_bounds(entry_points_with_memory):
    for ep in entry_points_with_memory:
        for mod in ep.memory.modules:
            for seg in mod.segments:
                assert seg.address >= mod.base
                assert seg.address + seg.size <= mod.base + mod.size
